import assert from "node:assert/strict";
import { EventEmitter, once } from "node:events";
import { createServer as createHttpServer, type Server } from "node:http";
import { type Socket } from "node:net";
import { test, type TestContext } from "node:test";
import {
  setImmediate as waitForImmediate,
  setTimeout as waitForTimeout,
} from "node:timers/promises";

import type {
  Browser,
  BrowserContext,
  CDPSession,
  LaunchOptions,
  Page,
  Request,
  Response,
  Route,
  WebSocketRoute,
} from "playwright";

import {
  createDefaultScanConfig,
  parseScanConfig,
  type ScanConfig,
} from "../src/config.ts";
import type { CatalogInspectionPlan, PageId } from "../src/model.ts";
import type {
  BrowserProxyLimitCategory,
  BrowserProxyRequestAttempt,
  ProtectedBrowserProxy,
  ProtectedBrowserProxyCanary,
  ProtectedBrowserProxyUsage,
  ProtectedHttpTransport,
  ProtectedTransportError,
} from "../src/crawl/transport.ts";
import {
  installTransportRuntimeHook,
  setupTransportRuntime,
} from "./support/transport-runtime.ts";

installTransportRuntimeHook();

const { createBrowserPool } = await import("../src/crawl/browser.ts");
const {
  createProtectedHttpTransport,
  ProtectedTransportError: TransportFailure,
} = await import(
  "../src/crawl/transport.ts"
);

type JsonRecord = Record<string, unknown>;

const userAgent =
  "WebsiteTechScraper/0.1.0 (https://contact.website-tech-scraper.dev/crawler)";
const publicAddress = "8.8.8.8";

const inspectionPlan: CatalogInspectionPlan = Object.freeze({
  dom: Object.freeze([Object.freeze({
    selector: "#app",
    facts: Object.freeze([
      Object.freeze({
        kind: "exists" as const,
        name: null,
        locator: "#app",
        demand: Object.freeze({ presence: true, value: false }),
      }),
      Object.freeze({
        kind: "text" as const,
        name: null,
        locator: "#app:text",
        demand: Object.freeze({ presence: false, value: true }),
      }),
      Object.freeze({
        kind: "property" as const,
        name: "constructor",
        locator: "#app:constructor",
        demand: Object.freeze({ presence: true, value: false }),
      }),
    ]),
  })]),
  javascript: Object.freeze([Object.freeze({
    path: "Shopify.theme.name",
    segments: Object.freeze(["Shopify", "theme", "name"]),
    demand: Object.freeze({ presence: false, value: true }),
  }), Object.freeze({
    path: "s_c_il.0.constructor.name",
    segments: Object.freeze(["s_c_il", "0", "constructor", "name"]),
    demand: Object.freeze({ presence: false, value: true }),
  })]),
  probePaths: Object.freeze([]),
  dnsRecordTypes: Object.freeze([]),
  tlsIssuer: false,
});

function setConfigValue(
  value: JsonRecord,
  path: readonly string[],
  replacement: unknown,
): void {
  let current = value;
  for (const key of path.slice(0, -1)) {
    const next = current[key];
    assert.equal(typeof next, "object");
    assert.notEqual(next, null);
    assert.equal(Array.isArray(next), false);
    current = next as JsonRecord;
  }
  const key = path.at(-1);
  assert.notEqual(key, undefined);
  current[key as string] = replacement;
}

function browserConfig(
  replacements: ReadonlyArray<readonly [readonly string[], unknown]> = [],
): ScanConfig {
  const candidate = structuredClone(
    createDefaultScanConfig(userAgent),
  ) as unknown as JsonRecord;
  setConfigValue(candidate, ["limits", "concurrency", "fullScans"], 1);
  setConfigValue(candidate, ["limits", "timeMs", "browserSettle"], 0);
  for (const [path, replacement] of replacements) {
    setConfigValue(candidate, path, replacement);
  }
  return parseScanConfig(candidate);
}

class FakeBrowserProxy implements ProtectedBrowserProxy {
  readonly server = "http://127.0.0.1:45000";
  readonly attempts: BrowserProxyRequestAttempt[] = [];
  readonly lifecycle: string[] = [];
  canaries = 0;
  verifiedCanaries = 0;
  domains = 0;
  finishedDomains = 0;
  closed = false;
  readonly #rejectCanary: boolean;
  #failureController = new AbortController();
  #failure: ProtectedTransportError | null = null;
  #failureOnAttempt: ProtectedTransportError | null = null;
  #activePage: PageId | null = null;
  #activeDomain = false;
  #domainRequests = 0;
  #limitHits = new Set<BrowserProxyLimitCategory>();

  constructor(rejectCanary = false) {
    this.#rejectCanary = rejectCanary;
  }

  activateDomain(signal?: AbortSignal): void {
    signal?.throwIfAborted();
    assert.equal(this.#activeDomain, false);
    this.#failureController = new AbortController();
    this.#failure = null;
    this.#activeDomain = true;
    this.#domainRequests = 0;
    this.#limitHits.clear();
    this.domains += 1;
    this.lifecycle.push(`activateDomain:${this.domains}`);
  }

  startPage(pageId: PageId): void {
    assert.equal(this.#activeDomain, true);
    assert.equal(this.#activePage, null);
    this.#activePage = pageId;
    this.lifecycle.push(`startPage:${pageId}`);
  }

  recordRequestAttempt(attempt: BrowserProxyRequestAttempt): void {
    assert.equal(this.#activePage, attempt.pageId);
    this.attempts.push(Object.freeze({ ...attempt }));
    this.#domainRequests += 1;
    if (this.#failureOnAttempt !== null) {
      const failure = this.#failureOnAttempt;
      this.#failureOnAttempt = null;
      this.fail(failure);
      throw failure;
    }
  }

  async finishPage(pageId: PageId): Promise<void> {
    assert.equal(this.#activePage, pageId);
    this.#activePage = null;
    this.lifecycle.push(`finishPage:${pageId}`);
  }

  async finishDomain(): Promise<void> {
    this.#activePage = null;
    if (this.#activeDomain) {
      this.finishedDomains += 1;
      this.lifecycle.push(`finishDomain:${this.finishedDomains}`);
    }
    this.#activeDomain = false;
  }

  getUsage(): ProtectedBrowserProxyUsage {
    return Object.freeze({
      browserRequests: this.#domainRequests,
      browserTransferredBytes: 0,
    });
  }

  getLimitHits(): readonly BrowserProxyLimitCategory[] {
    return Object.freeze([...this.#limitHits].sort());
  }

  getFailure(): ProtectedTransportError | null {
    return this.#failure;
  }

  getFailureSignal(): AbortSignal {
    return this.#failureController.signal;
  }

  fail(error: ProtectedTransportError): void {
    for (const category of error.browserLimitCategories) {
      this.#limitHits.add(category);
    }
    this.#failure = error;
    this.#failureController.abort(error);
  }

  failOnNextAttempt(error: ProtectedTransportError): void {
    this.#failureOnAttempt = error;
  }

  async prepareCanary(): Promise<ProtectedBrowserProxyCanary> {
    assert.equal(this.#activeDomain, false);
    this.canaries += 1;
    if (this.#rejectCanary) {
      throw new Error("Fake canary preparation failed");
    }
    let closed = false;
    return Object.freeze({
      targetUrl: "http://canary.invalid:32123/",
      chromiumHostResolverArg:
        "--host-resolver-rules=MAP canary.invalid 127.0.0.1",
      verify: (): void => {
        assert.equal(closed, false);
        this.verifiedCanaries += 1;
      },
      close: async (): Promise<void> => {
        closed = true;
      },
    });
  }

  async close(): Promise<void> {
    this.closed = true;
    await this.finishDomain();
  }
}

class FakeCdpSession extends EventEmitter {
  readonly body = "window.FakeTechnology = true;";
  readonly fetchCommands: Array<{
    readonly method: string;
    readonly requestId: string;
  }> = [];
  detached = false;
  getBodyCalls = 0;
  #fetchResolvers = new Map<string, (method: string) => void>();

  async send(method: string, params?: object): Promise<unknown> {
    if (method === "Page.getFrameTree") {
      return { frameTree: { frame: { id: "root-frame" } } };
    }
    if (method === "Network.getResponseBody") {
      this.getBodyCalls += 1;
      return { body: this.body, base64Encoded: false };
    }
    if (
      method === "Fetch.continueRequest"
      || method === "Fetch.continueResponse"
      || method === "Fetch.failRequest"
    ) {
      const requestId = (params as { requestId?: unknown } | undefined)
        ?.requestId;
      assert.equal(typeof requestId, "string");
      this.fetchCommands.push({ method, requestId: requestId as string });
      this.#fetchResolvers.get(requestId as string)?.(method);
      this.#fetchResolvers.delete(requestId as string);
    }
    return {};
  }

  pauseFetch(event: Record<string, unknown>): Promise<string> {
    const requestId = event.requestId;
    assert.equal(typeof requestId, "string");
    return new Promise<string>((resolve) => {
      this.#fetchResolvers.set(requestId as string, resolve);
      this.emit("Fetch.requestPaused", event);
    });
  }

  async detach(): Promise<void> {
    this.detached = true;
  }
}

class FakeRoute {
  readonly fakeRequest: Request;
  continued = false;
  aborted = false;

  constructor(fakeRequest: Request) {
    this.fakeRequest = fakeRequest;
  }

  request(): Request {
    return this.fakeRequest;
  }

  async continue(): Promise<void> {
    this.continued = true;
  }

  async abort(_errorCode?: string): Promise<void> {
    this.aborted = true;
  }
}

class FakeWebSocketRoute {
  readonly targetUrl: string;
  closed = false;

  constructor(targetUrl: string) {
    this.targetUrl = targetUrl;
  }

  url(): string {
    return this.targetUrl;
  }

  async close(): Promise<void> {
    this.closed = true;
  }
}

class FakePage {
  readonly context: FakeContext;
  cdp: FakeCdpSession | null = null;
  currentUrl = "about:blank";
  closed = false;

  constructor(context: FakeContext) {
    this.context = context;
  }

  on(_event: string, _handler: (value: unknown) => void): this {
    return this;
  }

  off(_event: string, _handler: (value: unknown) => void): this {
    return this;
  }

  mainFrame(): object {
    return this;
  }

  async goto(url: string): Promise<Response | null> {
    if (this.context.canary) {
      this.currentUrl = url;
      throw new Error("The canary is intentionally blocked");
    }
    const main = await this.context.dispatchRequest({
      page: this,
      url,
      method: "GET",
      resourceType: "document",
      navigation: true,
      topFrame: true,
    });
    if (!main.continued) {
      throw new Error("Main navigation was blocked");
    }
    let currentUrl = url;
    let currentRequestId = "document-0";
    await this.#pauseRequest({
      requestId: currentRequestId,
      url: currentUrl,
      resourceType: "Document",
    });
    for (let index = 0; index < this.context.topRedirects.length; index += 1) {
      const targetUrl = this.context.topRedirects[index];
      if (targetUrl === undefined) {
        throw new Error("Fake redirect target is missing");
      }
      const responseAction = await this.#pauseResponse({
        requestId: currentRequestId,
        url: currentUrl,
        resourceType: "Document",
        statusCode: 302,
        location: targetUrl,
      });
      if (responseAction === "Fetch.failRequest") {
        throw new Error("Top-level redirect was blocked");
      }
      const nextRequestId = `document-${index + 1}`;
      const requestAction = await this.#pauseRequest({
        requestId: nextRequestId,
        url: targetUrl,
        resourceType: "Document",
        redirectedRequestId: currentRequestId,
      });
      if (requestAction === "Fetch.failRequest") {
        throw new Error("Top-level redirect request was blocked");
      }
      currentUrl = targetUrl;
      currentRequestId = nextRequestId;
    }
    await this.#pauseResponse({
      requestId: currentRequestId,
      url: currentUrl,
      resourceType: "Document",
      statusCode: 200,
    });
    this.currentUrl = currentUrl;
    await this.context.dispatchRequest({
      page: this,
      url: "https://cdn-assets.org/pixel.png",
      method: "GET",
      resourceType: "image",
    });
    await this.context.dispatchRequest({
      page: this,
      url: "http://8.8.4.4/pixel.png",
      method: "GET",
      resourceType: "image",
    });
    await this.context.dispatchRequest({
      page: this,
      url: "https://api-service.org/mutate",
      method: "POST",
      resourceType: "fetch",
    });
    const redirectScript = await this.context.dispatchRequest({
      page: this,
      url: "https://merchant-site.org/redirect-script.js",
      method: "GET",
      resourceType: "script",
    });
    if (redirectScript.continued) {
      await this.#pauseRequest({
        requestId: "redirect-script",
        url: "https://merchant-site.org/redirect-script.js",
        resourceType: "Script",
      });
      const redirectResponse = await this.#pauseResponse({
        requestId: "redirect-script",
        url: "https://merchant-site.org/redirect-script.js",
        resourceType: "Script",
        statusCode: 302,
        location: "https://merchant-site.org/app.js",
      });
      if (redirectResponse !== "Fetch.failRequest") {
        const redirectedRequest = await this.#pauseRequest({
          requestId: "app-script",
          url: "https://merchant-site.org/app.js",
          resourceType: "Script",
          redirectedRequestId: "redirect-script",
        });
        if (redirectedRequest !== "Fetch.failRequest") {
          await this.#pauseResponse({
            requestId: "app-script",
            url: "https://merchant-site.org/app.js",
            resourceType: "Script",
            statusCode: 200,
          });
        }
      }
    }
    await this.context.dispatchRequest({
      page: {} as FakePage,
      url: "https://other-site.org/popup",
      method: "GET",
      resourceType: "document",
      navigation: true,
      topFrame: true,
    });
    await this.context.dispatchWebSocket("wss://socket-service.org/channel");

    const bodyBytes = Buffer.byteLength(this.cdp?.body ?? "", "utf8");
    this.cdp?.emit("Network.responseReceived", {
      type: "Script",
      requestId: "script-1",
      response: { url: "https://merchant-site.org/app.js", status: 200 },
    });
    this.cdp?.emit("Network.dataReceived", {
      requestId: "script-1",
      dataLength: bodyBytes,
      encodedDataLength: bodyBytes,
    });
    this.cdp?.emit("Network.loadingFinished", {
      requestId: "script-1",
      encodedDataLength: bodyBytes,
    });
    for (let index = 2; index <= this.context.scriptCount; index += 1) {
      const scriptUrl = `https://merchant-site.org/app-${String(index).padStart(2, "0")}.js`;
      const requestId = `script-${index}`;
      await this.context.dispatchRequest({
        page: this,
        url: scriptUrl,
        method: "GET",
        resourceType: "script",
      });
      await this.#pauseRequest({
        requestId,
        url: scriptUrl,
        resourceType: "Script",
      });
      await this.#pauseResponse({
        requestId,
        url: scriptUrl,
        resourceType: "Script",
        statusCode: 200,
      });
      this.cdp?.emit("Network.responseReceived", {
        type: "Script",
        requestId,
        response: { url: scriptUrl, status: 200 },
      });
      this.cdp?.emit("Network.dataReceived", {
        requestId,
        dataLength: bodyBytes,
        encodedDataLength: bodyBytes,
      });
      this.cdp?.emit("Network.loadingFinished", {
        requestId,
        encodedDataLength: bodyBytes,
      });
    }
    await this.context.collectionGate;
    return {
      status: (): number => 200,
      url: (): string => this.currentUrl,
      headersArray: async () => [{
        name: "Content-Type",
        value: "text/html; charset=utf-8",
      }],
    } as unknown as Response;
  }

  async #pauseRequest(input: {
    readonly requestId: string;
    readonly url: string;
    readonly resourceType: string;
    readonly redirectedRequestId?: string;
  }): Promise<string> {
    const cdp = this.cdp;
    if (cdp === null) {
      throw new Error("Fake CDP session is not attached");
    }
    return cdp.pauseFetch({
      requestId: input.requestId,
      request: { url: input.url, method: "GET" },
      frameId: "root-frame",
      resourceType: input.resourceType,
      ...(input.redirectedRequestId === undefined
        ? {}
        : { redirectedRequestId: input.redirectedRequestId }),
    });
  }

  async #pauseResponse(input: {
    readonly requestId: string;
    readonly url: string;
    readonly resourceType: string;
    readonly statusCode: number;
    readonly location?: string;
  }): Promise<string> {
    const cdp = this.cdp;
    if (cdp === null) {
      throw new Error("Fake CDP session is not attached");
    }
    return cdp.pauseFetch({
      requestId: input.requestId,
      request: { url: input.url, method: "GET" },
      frameId: "root-frame",
      resourceType: input.resourceType,
      responseStatusCode: input.statusCode,
      responseHeaders: input.location === undefined
        ? input.resourceType.toLowerCase() === "document"
          ? [{ name: "Content-Type", value: "text/html; charset=utf-8" }]
          : []
        : [{ name: "Location", value: input.location }],
    });
  }

  url(): string {
    return this.currentUrl;
  }

  async evaluate(): Promise<unknown> {
    return {
      facts: [
        { scope: "dom", ordinal: 0, kind: "presence" },
        { scope: "dom", ordinal: 1, kind: "value", value: "Rendered" },
        {
          scope: "javascript",
          ordinal: 0,
          kind: "value",
          value: "Dawn",
        },
        {
          scope: "javascript",
          ordinal: 1,
          kind: "value",
          value: "Object",
        },
      ],
      links: [
        "https://merchant-site.org/next#fragment",
        "mailto:sales@merchant-site.org",
        "tel:+37300000000",
        "javascript:void(0)",
      ],
      limitHits: [],
      truncated: false,
    };
  }

  async close(): Promise<void> {
    if (this.context.rejectPageClose) {
      throw new Error("Fake page close failed");
    }
    this.closed = true;
  }
}

interface FakeRequestInput {
  readonly page: FakePage;
  readonly url: string;
  readonly method: string;
  readonly resourceType: string;
  readonly navigation?: boolean;
  readonly topFrame?: boolean;
}

class FakeContext {
  readonly canary: boolean;
  readonly scriptCount: number;
  readonly topRedirects: readonly string[];
  readonly collectionGate: Promise<void>;
  readonly rejectClose: boolean;
  rejectPageClose = false;
  readonly pages: FakePage[] = [];
  closed = false;
  readonly cookieCalls: string[][] = [];
  #routeHandler: ((route: Route) => Promise<void>) | null = null;
  #webSocketHandler:
    | ((route: WebSocketRoute) => Promise<void>)
    | null = null;
  #pageHandler: ((page: Page) => void) | null = null;

  constructor(
    canary: boolean,
    scriptCount: number,
    rejectClose: boolean,
    topRedirects: readonly string[],
    collectionGate: Promise<void>,
  ) {
    this.canary = canary;
    this.scriptCount = scriptCount;
    this.rejectClose = rejectClose;
    this.topRedirects = topRedirects;
    this.collectionGate = collectionGate;
  }

  async route(
    _url: string,
    handler: (route: Route) => Promise<void>,
  ): Promise<void> {
    this.#routeHandler = handler;
  }

  async routeWebSocket(
    _url: string,
    handler: (route: WebSocketRoute) => Promise<void>,
  ): Promise<void> {
    this.#webSocketHandler = handler;
  }

  on(event: string, handler: (value: Page & Request) => void): this {
    if (event === "page") {
      this.#pageHandler = handler as unknown as (page: Page) => void;
    }
    return this;
  }

  async newPage(): Promise<Page> {
    const page = new FakePage(this);
    this.pages.push(page);
    this.#pageHandler?.(page as unknown as Page);
    return page as unknown as Page;
  }

  async newCDPSession(page: Page): Promise<CDPSession> {
    const cdp = new FakeCdpSession();
    (page as unknown as FakePage).cdp = cdp;
    return cdp as unknown as CDPSession;
  }

  async cookies(urls?: string | string[]): Promise<ReturnType<BrowserContext["cookies"]> extends Promise<infer T> ? T : never> {
    const requested = urls === undefined
      ? []
      : Array.isArray(urls) ? [...urls] : [urls];
    this.cookieCalls.push(requested);
    const firstParty = {
      name: "technology_cookie",
      value: "enabled",
      domain: "merchant-site.org",
      path: "/",
      expires: -1,
      httpOnly: false,
      secure: true,
      sameSite: "Lax" as const,
    };
    if (requested.length > 0) {
      return [firstParty];
    }
    return [firstParty, {
      ...firstParty,
      name: "third_party_cookie",
      domain: "cdn-assets.org",
    }];
  }

  async close(): Promise<void> {
    if (this.rejectClose) {
      throw new Error("Fake context close failed");
    }
    this.closed = true;
  }

  async dispatchRequest(input: FakeRequestInput): Promise<FakeRoute> {
    assert.notEqual(this.#routeHandler, null);
    const frame = {
      parentFrame: (): object | null => input.topFrame === true ? null : {},
      page: (): Page => input.page as unknown as Page,
    };
    const request = {
      url: (): string => input.url,
      method: (): string => input.method,
      resourceType: (): string => input.resourceType,
      isNavigationRequest: (): boolean => input.navigation === true,
      frame: (): object => frame,
    } as unknown as Request;
    const route = new FakeRoute(request);
    await this.#routeHandler?.(route as unknown as Route);
    return route;
  }

  async dispatchWebSocket(url: string): Promise<FakeWebSocketRoute> {
    assert.notEqual(this.#webSocketHandler, null);
    const route = new FakeWebSocketRoute(url);
    await this.#webSocketHandler?.(route as unknown as WebSocketRoute);
    return route;
  }
}

class FakeBrowser extends EventEmitter {
  readonly contextOptions: unknown[] = [];
  readonly contexts: FakeContext[] = [];
  connected = true;
  readonly scriptCount: number;
  readonly rejectDomainClose: boolean;
  readonly topRedirects: readonly string[];
  collectionGate: Promise<void>;
  readonly domainContextGate: Promise<void>;

  constructor(
    scriptCount = 1,
    rejectDomainClose = false,
    topRedirects: readonly string[] = [],
    collectionGate: Promise<void> = Promise.resolve(),
    domainContextGate: Promise<void> = Promise.resolve(),
  ) {
    super();
    this.scriptCount = scriptCount;
    this.rejectDomainClose = rejectDomainClose;
    this.topRedirects = topRedirects;
    this.collectionGate = collectionGate;
    this.domainContextGate = domainContextGate;
  }

  async newContext(options?: unknown): Promise<BrowserContext> {
    this.contextOptions.push(structuredClone(options));
    const canary = this.contexts.length === 0;
    const context = new FakeContext(
      canary,
      this.scriptCount,
      !canary && this.rejectDomainClose,
      this.topRedirects,
      this.collectionGate,
    );
    this.contexts.push(context);
    if (!canary) {
      await this.domainContextGate;
    }
    return context as unknown as BrowserContext;
  }

  isConnected(): boolean {
    return this.connected;
  }

  version(): string {
    return "151.0.7922.34";
  }

  async close(): Promise<void> {
    this.connected = false;
  }

  crash(): void {
    this.connected = false;
    this.emit("disconnected");
  }
}

function fakeRuntime(
  beforeLaunch?: (index: number, browser: FakeBrowser) => Promise<void>,
  scriptCount = 1,
  rejectDomainClose = false,
  topRedirects: readonly string[] = [],
  rejectCanary = false,
  collectionGate: Promise<void> = Promise.resolve(),
  domainContextGate: Promise<void> = Promise.resolve(),
) {
  const proxies: FakeBrowserProxy[] = [];
  const browsers: FakeBrowser[] = [];
  const launchOptions: LaunchOptions[] = [];
  const transport = {
    createBrowserProxy: async (): Promise<ProtectedBrowserProxy> => {
      const proxy = new FakeBrowserProxy(rejectCanary);
      proxies.push(proxy);
      return proxy;
    },
  } as unknown as ProtectedHttpTransport;
  const launcher = async (options: LaunchOptions): Promise<Browser> => {
    launchOptions.push(structuredClone(options));
    const browser = new FakeBrowser(
      scriptCount,
      rejectDomainClose,
      topRedirects,
      collectionGate,
      domainContextGate,
    );
    browsers.push(browser);
    await beforeLaunch?.(browsers.length - 1, browser);
    return browser as unknown as Browser;
  };
  return { transport, launcher, proxies, browsers, launchOptions };
}

test("closes the proxy when canary preparation fails", async () => {
  const runtime = fakeRuntime(undefined, 1, false, [], true);
  await assert.rejects(
    createBrowserPool(
      runtime.transport,
      browserConfig(),
      runtime.launcher,
    ),
    /unavailable/i,
  );
  assert.equal(runtime.proxies.length, 1);
  assert.equal(runtime.proxies[0]?.closed, true);
  assert.equal(runtime.browsers.length, 0);
});

test("preflights a safe reusable slot and collects bounded browser facts", async (t) => {
  const runtime = fakeRuntime();
  const pool = await createBrowserPool(
    runtime.transport,
    browserConfig(),
    runtime.launcher,
  );
  t.after(() => pool.close());

  assert.deepEqual(pool.runtime, {
    playwright: "1.62.1",
    chromiumRevision: "1234",
    chromiumVersion: "151.0.7922.34",
  });
  assert.equal(Object.isFrozen(pool.runtime), true);
  assert.deepEqual(runtime.launchOptions[0], {
    headless: true,
    chromiumSandbox: true,
    proxy: { server: "http://127.0.0.1:45000" },
    args: [
      "--disable-quic",
      "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
      "--host-resolver-rules=MAP canary.invalid 127.0.0.1",
    ],
    timeout: 15_000,
  });
  assert.equal(runtime.proxies[0]?.verifiedCanaries, 1);

  const session = await pool.openDomain();
  const allowed: string[] = [];
  const collection = await session.collectPage({
    pageId: "p1",
    url: "https://merchant-site.org/",
    inspectionPlan,
    allowTopLevelUrl: (url) => {
      allowed.push(url);
      return true;
    },
  });
  assert.equal(collection.completed, true);
  assert.deepEqual(collection.errors, []);
  assert.deepEqual(collection.navigationLinks, [
    "https://merchant-site.org/next",
  ]);
  assert.equal(Object.isFrozen(collection.navigationLinks), true);
  assert.deepEqual(collection.limitTelemetry, { hits: [] });
  assert.equal(Object.isFrozen(collection.limitTelemetry), true);
  assert.equal(Object.isFrozen(collection.limitTelemetry.hits), true);
  const result = await session.finish();

  assert.equal(result.completed, true);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(allowed, ["https://merchant-site.org/"]);
  assert.deepEqual(result.pages[0], {
    pageId: "p1",
    finalUrl: "https://merchant-site.org/",
    dom: [
      { pageId: "p1", locator: "#app", fact: { kind: "presence" } },
      {
        pageId: "p1",
        locator: "#app:text",
        fact: { kind: "value", value: "Rendered" },
      },
    ],
    javascript: [
      {
        pageId: "p1",
        path: "Shopify.theme.name",
        fact: { kind: "value", value: "Dawn" },
      },
      {
        pageId: "p1",
        path: "s_c_il.0.constructor.name",
        fact: { kind: "value", value: "Object" },
      },
    ],
    cookies: [{ name: "technology_cookie", value: "enabled" }],
    networkUrls: [
      "http://8.8.4.4/pixel.png",
      "https://cdn-assets.org/pixel.png",
      "https://merchant-site.org/",
      "https://merchant-site.org/app.js",
      "https://merchant-site.org/redirect-script.js",
    ],
    networkHostnames: [
      "api-service.org",
      "cdn-assets.org",
      "merchant-site.org",
      "other-site.org",
      "socket-service.org",
    ],
    scriptUrls: ["https://merchant-site.org/app.js"],
    scriptBodies: [{
      pageId: "p1",
      url: "https://merchant-site.org/app.js",
      content: "window.FakeTechnology = true;",
    }],
    navigationLinks: ["https://merchant-site.org/next"],
    truncated: false,
  });
  assert.equal(
    collection.navigationLinks,
    result.pages[0]?.navigationLinks,
  );
  assert.equal(session.getUsage().browserRequests, 8);
  assert.equal(session.getUsage().scriptBodiesInspected, 1);
  assert.deepEqual(
    runtime.proxies[0]?.attempts.map(({ url, forward }) => ({ url, forward })),
    [
      { url: "https://merchant-site.org/", forward: true },
      { url: "https://cdn-assets.org/pixel.png", forward: false },
      { url: "http://8.8.4.4/pixel.png", forward: false },
      { url: "https://api-service.org/mutate", forward: false },
      { url: "https://merchant-site.org/redirect-script.js", forward: true },
      { url: "https://merchant-site.org/app.js", forward: true },
      { url: "https://other-site.org/popup", forward: false },
      { url: "wss://socket-service.org/channel", forward: false },
    ],
  );

  const contextOptions = runtime.browsers[0]?.contextOptions;
  assert.equal(contextOptions?.length, 2);
  assert.deepEqual(contextOptions?.[1], {
    acceptDownloads: false,
    bypassCSP: false,
    ignoreHTTPSErrors: false,
    permissions: [],
    proxy: {
      server: "http://127.0.0.1:45000",
      bypass: "<-loopback>",
    },
    serviceWorkers: "block",
    userAgent,
  });
  assert.deepEqual(runtime.browsers[0]?.contexts[1]?.cookieCalls, [[
    "https://merchant-site.org/",
  ]]);
});

test("fails closed when a runtime caller returns a promise from the robots gate", async (t) => {
  const runtime = fakeRuntime();
  const pool = await createBrowserPool(
    runtime.transport,
    browserConfig(),
    runtime.launcher,
  );
  t.after(() => pool.close());
  const session = await pool.openDomain();
  const invalidGate = (() => Promise.resolve(true)) as unknown as (
    url: string,
  ) => boolean;
  const collection = await session.collectPage({
    pageId: "p1",
    url: "https://merchant-site.org/",
    inspectionPlan,
    allowTopLevelUrl: invalidGate,
  });
  assert.equal(collection.completed, false);
  assert.deepEqual(collection.navigationLinks, []);
  assert.equal(Object.isFrozen(collection.navigationLinks), true);
  assert.equal(runtime.proxies[0]?.attempts[0]?.forward, false);
  const result = await session.finish();
  assert.equal(result.completed, false);
  assert.equal(result.errors[0]?.code, "BROWSER_NAVIGATION_FAILED");
  assert.equal(result.errors[0]?.retryable, false);
});

test("admits each chained top-level redirect exactly once", async (t) => {
  const redirects = [
    "https://merchant-site.org/step",
    "https://merchant-site.org/final",
  ];
  const runtime = fakeRuntime(undefined, 1, false, redirects);
  const pool = await createBrowserPool(
    runtime.transport,
    browserConfig(),
    runtime.launcher,
  );
  t.after(() => pool.close());
  const session = await pool.openDomain();
  const allowed: string[] = [];
  const collection = await session.collectPage({
    pageId: "p1",
    url: "https://merchant-site.org/start",
    inspectionPlan,
    allowTopLevelUrl: (url) => {
      allowed.push(url);
      return true;
    },
  });
  assert.equal(collection.completed, true);
  const result = await session.finish();
  assert.equal(result.completed, true);
  assert.equal(result.pages[0]?.finalUrl, redirects[1]);
  assert.deepEqual(allowed, [
    "https://merchant-site.org/start",
    ...redirects,
  ]);
  assert.deepEqual(
    runtime.proxies[0]?.attempts
      .filter(({ url }) => redirects.includes(url))
      .map(({ url, forward }) => ({ url, forward })),
    redirects.map((url) => ({ url, forward: true })),
  );
});

test("blocks a redirect before its request when the robots gate is not synchronous", async (t) => {
  const redirect = "https://merchant-site.org/step";
  const runtime = fakeRuntime(undefined, 1, false, [redirect]);
  const pool = await createBrowserPool(
    runtime.transport,
    browserConfig(),
    runtime.launcher,
  );
  t.after(() => pool.close());
  const session = await pool.openDomain();
  const invalidGate = ((url: string) => url === redirect
    ? Promise.resolve(true)
    : true) as unknown as (url: string) => boolean;
  const collection = await session.collectPage({
    pageId: "p1",
    url: "https://merchant-site.org/start",
    inspectionPlan,
    allowTopLevelUrl: invalidGate,
  });
  assert.equal(collection.completed, false);
  assert.equal(
    runtime.proxies[0]?.attempts.some(({ url }) => url === redirect),
    false,
  );
  const result = await session.finish();
  assert.equal(result.completed, false);
  assert.equal(result.errors[0]?.code, "BROWSER_NAVIGATION_FAILED");
  assert.equal(result.errors[0]?.retryable, false);
});

test("enforces ordered page ids, one origin, FIFO admission, and abort cleanup", async (t) => {
  const runtime = fakeRuntime();
  const pool = await createBrowserPool(
    runtime.transport,
    browserConfig(),
    runtime.launcher,
  );
  t.after(() => pool.close());
  const first = await pool.openDomain();

  await assert.rejects(
    first.collectPage({
      pageId: "p2",
      url: "https://merchant-site.org/",
      inspectionPlan,
      allowTopLevelUrl: () => true,
    }),
    /ordered p1 through p3/,
  );
  const p1 = await first.collectPage({
    pageId: "p1",
    url: "https://merchant-site.org/",
    inspectionPlan,
    allowTopLevelUrl: () => true,
  });
  assert.equal(p1.completed, true);
  await assert.rejects(
    first.collectPage({
      pageId: "p2",
      url: "https://different-origin.org/",
      inspectionPlan,
      allowTopLevelUrl: () => true,
    }),
    /domain origin/,
  );

  const queued = pool.openDomain();
  const cancelled = new AbortController();
  const aborted = pool.openDomain(cancelled.signal);
  cancelled.abort(new Error("cancelled queued domain"));
  await assert.rejects(aborted, /cancelled queued domain/);
  await first.finish();
  const firstUsage = first.getUsage();
  assert.equal(firstUsage.browserRequests, 8);
  const second = await queued;
  await second.collectPage({
    pageId: "p1",
    url: "https://merchant-site.org/",
    inspectionPlan,
    allowTopLevelUrl: () => true,
  });
  assert.equal(first.getUsage(), firstUsage);
  assert.equal(first.getUsage().browserRequests, 8);
  await second.finish();
  assert.equal(runtime.proxies[0]?.domains, 2);
  assert.equal(runtime.proxies[0]?.finishedDomains, 2);
});

test("reuses a healthy browser after repeated domain-scoped proxy limits", async (t) => {
  const runtime = fakeRuntime();
  const pool = await createBrowserPool(
    runtime.transport,
    browserConfig(),
    runtime.launcher,
  );
  t.after(() => pool.close());

  for (let attempt = 0; attempt < 4; attempt += 1) {
    const session = await pool.openDomain();
    runtime.proxies[0]?.failOnNextAttempt(new TransportFailure(
      "BROWSER_LIMIT_EXCEEDED",
      "browser",
      false,
      ["proxy.requestsPerPage"],
    ));
    await assert.rejects(
      session.collectPage({
        pageId: "p1",
        url: "https://merchant-site.org/",
        inspectionPlan,
        allowTopLevelUrl: () => true,
      }),
      (error: unknown) =>
        error instanceof TransportFailure
        && error.code === "BROWSER_LIMIT_EXCEEDED",
    );
    assert.deepEqual(session.getFailureLimitTelemetry(), {
      hits: [{
        category: "proxy.requestsPerPage",
        domSelectorOrdinal: null,
      }],
    });
    const result = await session.finish();
    assert.deepEqual(
      result.errors.map(({ code }) => code),
      ["BROWSER_LIMIT_EXCEEDED"],
    );
    assert.equal(pool.isAvailable(), true);
  }

  assert.equal(runtime.browsers.length, 1);
  assert.equal(runtime.proxies.length, 1);
  assert.equal(runtime.proxies[0]?.domains, 4);
  assert.equal(runtime.proxies[0]?.finishedDomains, 4);
});

test("drains a failed proxy collection before retaining its exact diagnosis", async (t) => {
  const runtime = fakeRuntime();
  const pool = await createBrowserPool(
    runtime.transport,
    browserConfig(),
    runtime.launcher,
  );
  t.after(() => pool.close());
  const session = await pool.openDomain();
  runtime.proxies[0]?.failOnNextAttempt(new TransportFailure(
    "BROWSER_PROXY_FAILED",
    "browser",
    true,
  ));

  await assert.rejects(
    session.collectPage({
      pageId: "p1",
      url: "https://merchant-site.org/",
      inspectionPlan,
      allowTopLevelUrl: () => true,
    }),
    (error: unknown) =>
      error instanceof TransportFailure
      && error.code === "BROWSER_PROXY_FAILED",
  );
  assert.deepEqual(session.getFailureLimitTelemetry(), { hits: [] });

  const result = await session.finish();
  assert.deepEqual(
    result.errors.map(({ code }) => code),
    ["BROWSER_PROXY_FAILED"],
  );
  assert.equal(pool.isAvailable(), true);
});

test("replaces a slot aborted during delayed domain-context initialization", async (t) => {
  let releaseDomainContext: (() => void) | undefined;
  const domainContextGate = new Promise<void>((resolve) => {
    releaseDomainContext = resolve;
  });
  const runtime = fakeRuntime(
    undefined,
    1,
    false,
    [],
    false,
    Promise.resolve(),
    domainContextGate,
  );
  const pool = await createBrowserPool(
    runtime.transport,
    browserConfig(),
    runtime.launcher,
  );
  t.after(() => pool.close());
  const controller = new AbortController();
  const cancellation = new Error(
    "cancelled during browser context initialization",
  );
  let admissions = 0;
  const opening = pool.openDomain(controller.signal, () => {
    admissions += 1;
    queueMicrotask(() => controller.abort(cancellation));
  });

  await assert.rejects(opening, (error: unknown) => error === cancellation);

  assert.equal(admissions, 1);
  assert.equal(runtime.browsers.length, 2);
  assert.equal(runtime.browsers[0]?.connected, false);
  assert.equal(runtime.proxies[0]?.finishedDomains, 1);
  assert.equal(runtime.proxies[0]?.closed, true);
  assert.equal(pool.isAvailable(), true);
  const lateContext = runtime.browsers[0]?.contexts[1];
  assert.notEqual(lateContext, undefined);
  assert.equal(lateContext?.pages.length, 0);

  releaseDomainContext?.();
  await waitForImmediate();

  const replacementSession = await pool.openDomain();
  const replacementCollection = await replacementSession.collectPage({
    pageId: "p1",
    url: "https://merchant-site.org/",
    inspectionPlan,
    allowTopLevelUrl: () => true,
  });
  assert.equal(replacementCollection.completed, true);
  const replacementContext = runtime.browsers[1]?.contexts[1];
  assert.notEqual(replacementContext, undefined);
  assert.notEqual(replacementContext, lateContext);
  assert.equal(replacementContext?.pages.length, 1);
  assert.equal(lateContext?.pages.length, 0);
  await replacementSession.finish();
  assert.equal(runtime.proxies[1]?.domains, 1);
  assert.equal(runtime.proxies[1]?.finishedDomains, 1);
});

test("abandons a stuck collection and preserves FIFO admission on a replacement slot", async (t) => {
  const collectionGate = new Promise<void>(() => {});
  const runtime = fakeRuntime(
    async (index, browser) => {
      if (index > 0) browser.collectionGate = Promise.resolve();
    },
    1,
    false,
    [],
    false,
    collectionGate,
  );
  const pool = await createBrowserPool(
    runtime.transport,
    browserConfig(),
    runtime.launcher,
  );
  t.after(() => pool.close());
  const controller = new AbortController();
  const first = await pool.openDomain(controller.signal);
  const collecting = first.collectPage({
    pageId: "p1",
    url: "https://merchant-site.org/",
    inspectionPlan,
    allowTopLevelUrl: () => true,
  });
  void collecting.catch(() => undefined);
  for (
    let attempt = 0;
    attempt < 20 && (runtime.proxies[0]?.attempts.length ?? 0) < 8;
    attempt += 1
  ) {
    await waitForImmediate();
  }
  assert.equal(runtime.proxies[0]?.attempts.length, 8);

  const firstQueued = pool.openDomain();
  const secondQueued = pool.openDomain();
  let secondQueuedActivated = false;
  void secondQueued.then(() => {
    secondQueuedActivated = true;
  });
  controller.abort(new Error("cancelled stuck browser collection"));
  const closing = first.close();
  const closeOutcome = await Promise.race([
    closing.then(() => "closed" as const),
    waitForTimeout(2_500, "timed-out" as const),
  ]);
  assert.equal(closeOutcome, "closed");
  assert.equal(runtime.browsers.length, 2);
  assert.equal(runtime.browsers[0]?.connected, false);
  assert.equal(runtime.proxies[0]?.closed, true);
  assert.equal(runtime.proxies[0]?.attempts.length, 8);

  const replacementFirst = await firstQueued;
  assert.equal(secondQueuedActivated, false);
  const firstReplacementCollection = await replacementFirst.collectPage({
    pageId: "p1",
    url: "https://merchant-site.org/",
    inspectionPlan,
    allowTopLevelUrl: () => true,
  });
  assert.equal(firstReplacementCollection.completed, true);
  await replacementFirst.finish();

  const replacementSecond = await secondQueued;
  const secondReplacementCollection = await replacementSecond.collectPage({
    pageId: "p1",
    url: "https://merchant-site.org/",
    inspectionPlan,
    allowTopLevelUrl: () => true,
  });
  assert.equal(secondReplacementCollection.completed, true);
  await replacementSecond.finish();

  assert.equal(runtime.proxies.length, 2);
  assert.equal(runtime.proxies[0]?.attempts.length, 8);
  assert.equal(runtime.proxies[1]?.attempts.length, 16);
  assert.deepEqual(runtime.proxies[1]?.lifecycle, [
    "activateDomain:1",
    "startPage:p1",
    "finishPage:p1",
    "finishDomain:1",
    "activateDomain:2",
    "startPage:p1",
    "finishPage:p1",
    "finishDomain:2",
  ]);
});

test("replaces a Chromium process disconnected during active collection", async (t) => {
  let releaseCollection: (() => void) | undefined;
  const collectionGate = new Promise<void>((resolve) => {
    releaseCollection = resolve;
  });
  const runtime = fakeRuntime(
    undefined,
    1,
    false,
    [],
    false,
    collectionGate,
  );
  const pool = await createBrowserPool(
    runtime.transport,
    browserConfig(),
    runtime.launcher,
  );
  t.after(() => pool.close());
  const session = await pool.openDomain();
  const collecting = session.collectPage({
    pageId: "p1",
    url: "https://merchant-site.org/",
    inspectionPlan,
    allowTopLevelUrl: () => true,
  });
  for (
    let attempt = 0;
    attempt < 20 && (runtime.proxies[0]?.attempts.length ?? 0) < 8;
    attempt += 1
  ) {
    await waitForImmediate();
  }
  assert.equal(runtime.proxies[0]?.attempts.length, 8);

  runtime.browsers[0]?.crash();
  await assert.rejects(collecting, /unavailable/i);
  releaseCollection?.();
  await session.close();

  assert.equal(runtime.browsers.length, 2);
  assert.equal(runtime.browsers[0]?.connected, false);
  assert.equal(runtime.proxies[0]?.closed, true);
  assert.equal(pool.isAvailable(), true);

  const replacement = await pool.openDomain();
  const replacementCollection = await replacement.collectPage({
    pageId: "p1",
    url: "https://merchant-site.org/",
    inspectionPlan,
    allowTopLevelUrl: () => true,
  });
  assert.equal(replacementCollection.completed, true);
  await replacement.finish();
});

test("bounds a hung browser close before admitting a replacement", async (t) => {
  const runtime = fakeRuntime();
  const pool = await createBrowserPool(
    runtime.transport,
    browserConfig(),
    runtime.launcher,
  );
  t.after(() => pool.close());
  const hungClose = new Promise<void>(() => {});
  const firstBrowser = runtime.browsers[0];
  assert.notEqual(firstBrowser, undefined);
  firstBrowser!.close = async (): Promise<void> => hungClose;

  firstBrowser!.crash();
  const waiterController = new AbortController();
  const queued = pool.openDomain(waiterController.signal);
  const outcome = await Promise.race([
    queued,
    waitForTimeout(2_500, "timed-out" as const),
  ]);
  if (outcome === "timed-out") {
    waiterController.abort(new Error("replacement remained blocked"));
    assert.fail("A hung browser close blocked its bounded replacement");
  }

  assert.equal(runtime.browsers.length, 2);
  assert.equal(runtime.proxies[0]?.closed, true);
  const collection = await outcome.collectPage({
    pageId: "p1",
    url: "https://merchant-site.org/",
    inspectionPlan,
    allowTopLevelUrl: () => true,
  });
  assert.equal(collection.completed, true);
  await outcome.finish();
});

test("bounds a replacement that stalls during browser preflight", async (t) => {
  const stalledPreflight = new Promise<void>(() => {});
  const runtime = fakeRuntime(async (index, browser) => {
    if (index === 1) {
      browser.newContext = async (): Promise<BrowserContext> => {
        await stalledPreflight;
        throw new Error("The stalled preflight unexpectedly resumed");
      };
    }
  });
  const pool = await createBrowserPool(
    runtime.transport,
    browserConfig([[["limits", "timeMs", "browserPage"], 50]]),
    runtime.launcher,
  );
  t.after(() => pool.close());

  runtime.browsers[0]?.crash();
  const waiterController = new AbortController();
  const queued = pool.openDomain(waiterController.signal).then(
    () => "opened" as const,
    (error: unknown) => error,
  );
  const outcome = await Promise.race([
    queued,
    waitForTimeout(1_000, "timed-out" as const),
  ]);
  if (outcome === "timed-out") {
    waiterController.abort(new Error("replacement preflight remained blocked"));
    assert.fail("A stalled replacement preflight blocked the pool");
  }
  assert.notEqual(outcome, "opened");
  assert.match(String(outcome), /unavailable/i);
  assert.equal(pool.isAvailable(), false);
  assert.equal(runtime.browsers.length, 2);
  assert.equal(runtime.browsers[1]?.connected, false);
  assert.equal(runtime.proxies[1]?.closed, true);
});

test("closes a browser that resolves after slot preflight expires", async () => {
  let releaseLaunch: (() => void) | undefined;
  const launchGate = new Promise<void>((resolve) => {
    releaseLaunch = resolve;
  });
  const runtime = fakeRuntime(async () => launchGate);

  await assert.rejects(
    createBrowserPool(
      runtime.transport,
      browserConfig([[["limits", "timeMs", "browserPage"], 50]]),
      runtime.launcher,
    ),
    /unavailable/i,
  );
  assert.equal(runtime.browsers.length, 1);
  assert.equal(runtime.browsers[0]?.connected, true);
  assert.equal(runtime.proxies[0]?.closed, true);

  releaseLaunch?.();
  for (
    let attempt = 0;
    attempt < 20 && runtime.browsers[0]?.connected === true;
    attempt += 1
  ) {
    await waitForImmediate();
  }
  assert.equal(runtime.browsers[0]?.connected, false);
});

test("never requests more than twenty ranked script bodies", async (t) => {
  const runtime = fakeRuntime(undefined, 25);
  const pool = await createBrowserPool(
    runtime.transport,
    browserConfig(),
    runtime.launcher,
  );
  t.after(() => pool.close());
  const session = await pool.openDomain();
  const collection = await session.collectPage({
    pageId: "p1",
    url: "https://merchant-site.org/",
    inspectionPlan,
    allowTopLevelUrl: () => true,
  });
  assert.equal(collection.completed, true);
  assert.deepEqual(collection.limitTelemetry.hits, [{
    category: "scripts.bodiesPerDomain",
    domSelectorOrdinal: null,
  }]);
  const result = await session.finish();
  assert.equal(result.pages[0]?.scriptUrls.length, 25);
  assert.equal(result.pages[0]?.scriptBodies.length, 20);
  assert.equal(
    runtime.browsers[0]?.contexts[1]?.pages[0]?.cdp?.getBodyCalls,
    20,
  );
  assert.equal(session.getUsage().scriptBodiesInspected, 20);
});

test("reports simultaneous silent script byte caps without changing status", async (t) => {
  const runtime = fakeRuntime();
  const pool = await createBrowserPool(
    runtime.transport,
    browserConfig([
      [["limits", "scripts", "bodyBytes"], 1],
      [["limits", "scripts", "totalBodyBytesPerDomain"], 1],
    ]),
    runtime.launcher,
  );
  t.after(() => pool.close());
  const session = await pool.openDomain();
  const collection = await session.collectPage({
    pageId: "p1",
    url: "https://merchant-site.org/",
    inspectionPlan,
    allowTopLevelUrl: () => true,
  });

  assert.equal(collection.completed, true);
  assert.deepEqual(collection.limitTelemetry.hits, [{
    category: "scripts.bodyBytes",
    domSelectorOrdinal: null,
  }, {
    category: "scripts.totalBodyBytesPerDomain",
    domSelectorOrdinal: null,
  }]);
  const result = await session.finish();
  assert.equal(result.completed, true);
  assert.equal(result.pages[0]?.truncated, false);
  assert.deepEqual(result.pages[0]?.scriptBodies, []);
});

test("keeps browser safety-limit details out of persisted error context", async (t) => {
  const cases = [
    {
      replacements: [[
        ["limits", "scripts", "totalBodyBytesPerDomain"],
        1,
      ]] as const,
      expectedLimitHits: ["scripts.totalBodyBytesPerDomain"],
    },
    {
      replacements: [[
        ["limits", "cookies", "nameCodeUnits"],
        1,
      ]] as const,
      expectedLimitHits: ["cookies.name"],
    },
    {
      replacements: [[
        ["limits", "cookies", "valueBytes"],
        1,
      ]] as const,
      expectedLimitHits: ["cookies.value"],
    },
    {
      replacements: [[
        ["limits", "cookies", "totalBytesPerDomain"],
        1,
      ]] as const,
      expectedLimitHits: ["cookies.totalBytesPerDomain"],
    },
    {
      replacements: [
        [["limits", "browser", "networkHostnamesPerDomain"], 1],
        [["limits", "browser", "requestsPerPage"], 1],
        [["limits", "browser", "requestsPerDomain"], 1],
      ] as const,
      expectedLimitHits: [
        "browser.networkHostnamesPerDomain",
        "browser.networkUrlsPerDomain",
      ],
    },
  ];

  for (const testCase of cases) {
    const runtime = fakeRuntime();
    const pool = await createBrowserPool(
      runtime.transport,
      browserConfig(testCase.replacements),
      runtime.launcher,
    );
    t.after(() => pool.close());
    const session = await pool.openDomain();
    const collection = await session.collectPage({
      pageId: "p1",
      url: "https://merchant-site.org/",
      inspectionPlan,
      allowTopLevelUrl: () => true,
    });
    assert.equal(collection.completed, false);
    assert.equal(collection.observationsAdmitted, true);
    assert.equal(collection.continuationAllowed, true);
    assert.equal(collection.errors.some(
      ({ code }) => code === "BROWSER_LIMIT_EXCEEDED",
    ), true);
    assert.equal(collection.errors.every(({ limit }) => limit === null), true);
    assert.deepEqual(
      collection.limitTelemetry.hits,
      testCase.expectedLimitHits.map((category) => ({
        category,
        domSelectorOrdinal: null,
      })),
    );
    const result = await session.finish();
    assert.equal(result.completed, false);
    assert.equal(result.pages.length, 1);
    assert.equal(result.pages[0]?.truncated, true);
  }
});

test("preserves an admitted draft but stops after page cleanup fails", async (t) => {
  const runtime = fakeRuntime();
  const pool = await createBrowserPool(
    runtime.transport,
    browserConfig(),
    runtime.launcher,
  );
  t.after(() => pool.close());
  const session = await pool.openDomain();
  const context = runtime.browsers[0]?.contexts[1];
  assert.notEqual(context, undefined);
  if (context !== undefined) {
    context.rejectPageClose = true;
  }

  const collection = await session.collectPage({
    pageId: "p1",
    url: "https://merchant-site.org/",
    inspectionPlan,
    allowTopLevelUrl: () => true,
  });

  assert.equal(collection.completed, false);
  assert.equal(collection.observationsAdmitted, true);
  assert.equal(collection.continuationAllowed, false);
  assert.equal(
    collection.errors.some(({ code }) => code === "BROWSER_UNAVAILABLE"),
    true,
  );
  const result = await session.finish();
  assert.equal(result.completed, false);
  assert.equal(result.pages.length, 1);
  assert.equal(pool.isAvailable(), true);
});

test("replaces one crashed Chromium process and then degrades unavailable", async (t) => {
  const runtime = fakeRuntime();
  const pool = await createBrowserPool(
    runtime.transport,
    browserConfig(),
    runtime.launcher,
  );
  t.after(() => pool.close());
  runtime.browsers[0]?.crash();
  for (let attempt = 0; attempt < 20 && runtime.browsers.length < 2; attempt += 1) {
    await waitForImmediate();
  }
  assert.equal(runtime.browsers.length, 2);
  assert.equal(pool.isAvailable(), true);

  runtime.browsers[1]?.crash();
  for (let attempt = 0; attempt < 20 && pool.isAvailable(); attempt += 1) {
    await waitForImmediate();
  }
  assert.equal(pool.isAvailable(), false);
  await assert.rejects(pool.openDomain(), /unavailable/i);
});

test("close waits for and destroys an in-flight replacement exactly once", async () => {
  let releaseReplacement: (() => void) | undefined;
  const replacementGate = new Promise<void>((resolve) => {
    releaseReplacement = resolve;
  });
  const runtime = fakeRuntime(async (index) => {
    if (index === 1) {
      await replacementGate;
    }
  });
  const pool = await createBrowserPool(
    runtime.transport,
    browserConfig(),
    runtime.launcher,
  );
  runtime.browsers[0]?.crash();
  for (let attempt = 0; attempt < 20 && runtime.browsers.length < 2; attempt += 1) {
    await waitForImmediate();
  }
  assert.equal(runtime.browsers.length, 2);

  const firstClose = pool.close();
  const secondClose = pool.close();
  assert.equal(firstClose, secondClose);
  releaseReplacement?.();
  await Promise.all([firstClose, secondClose]);
  assert.equal(runtime.browsers[1]?.connected, false);
  assert.equal(runtime.proxies[1]?.closed, true);
});

test("a rejected context close makes the slot unhealthy", async (t) => {
  const runtime = fakeRuntime(undefined, 1, true);
  const pool = await createBrowserPool(
    runtime.transport,
    browserConfig(),
    runtime.launcher,
  );
  t.after(() => pool.close());
  const session = await pool.openDomain();
  await session.close();
  assert.equal(runtime.browsers.length, 2);
  assert.equal(runtime.browsers[0]?.connected, false);
  assert.equal(pool.isAvailable(), true);
});

async function listenOnLoopback(t: TestContext, server: Server): Promise<number> {
  const sockets = new Set<Socket>();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string") {
    assert.fail("The controlled browser server did not expose an IP address");
  }
  t.after(async () => {
    for (const socket of sockets) {
      socket.destroy();
    }
    if (server.listening) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
  return address.port;
}

test("collects a controlled page through the real protected Chromium path", async (t) => {
  const requestedUrls: string[] = [];
  const server = createHttpServer((request, response) => {
    requestedUrls.push(request.url ?? "");
    if (request.url === "/entry") {
      response.writeHead(302, {
        Location: "/landing",
        Connection: "close",
      });
      response.end();
      return;
    }
    if (request.url === "/denied-entry") {
      response.writeHead(302, {
        Location: "/must-not-hit",
        Connection: "close",
      });
      response.end();
      return;
    }
    if (request.url === "/forbidden") {
      response.writeHead(403, {
        "Content-Type": "text/html; charset=utf-8",
        "Set-Cookie": "blocked_technology=present; Path=/",
        Connection: "close",
      });
      response.end(`<div id="app">Blocked page</div><script>
        window.Shopify={theme:{name:'Blocked'}};
        fetch('/must-not-hit-after-denial');
      </script>`);
      return;
    }
    if (request.url === "/not-html") {
      response.writeHead(200, {
        "Content-Type": "application/json",
        "Set-Cookie": "json_technology=present; Path=/",
        Connection: "close",
      });
      response.end('{"html":"<div id=\\"app\\">Not HTML</div>"}');
      return;
    }
    if (request.url === "/late-navigation") {
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        Connection: "close",
      });
      response.end(`<div id="app">Initial page</div><script>
        setTimeout(() => { location.href = '/late-forbidden'; }, 25);
      </script>`);
      return;
    }
    if (request.url === "/history-navigation") {
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        Connection: "close",
      });
      response.end(`<div id="app">Initial history page</div><script>
        setTimeout(() => history.pushState({}, '', '/changed-history'), 25);
      </script>`);
      return;
    }
    if (request.url === "/blob-navigation") {
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        Connection: "close",
      });
      response.end(`<div id="app">Initial blob page</div><script>
        setTimeout(() => {
          const target = URL.createObjectURL(new Blob([
            '<div id="app">Blob replacement</div>'
          ], { type: 'text/html' }));
          location.href = target;
        }, 25);
      </script>`);
      return;
    }
    if (request.url === "/late-forbidden") {
      response.writeHead(403, {
        "Content-Type": "text/html; charset=utf-8",
        Connection: "close",
      });
      response.end("<div id=\"app\">Late blocked page</div>");
      return;
    }
    if (request.url === "/redirect-script.js") {
      response.writeHead(302, {
        Location: "http://cdn-browser-target.org/app.js",
        Connection: "close",
      });
      response.end();
      return;
    }
    if (request.url === "/app.js") {
      response.writeHead(200, {
        "Content-Type": "application/javascript; charset=utf-8",
        Connection: "close",
      });
      response.end("window.ExternalTechnology = 'ready';");
      return;
    }
    if (request.url?.startsWith("/api") === true) {
      response.writeHead(204, { Connection: "close" });
      response.end();
      return;
    }
    if (request.url === "/attribute-after-irrelevant") {
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        Connection: "close",
      });
      response.end(`<!doctype html><body>${Array.from(
        { length: 25 },
        (_, index) => `<div>Item ${index}</div>`,
      ).join("")}<span q:version="after-irrelevant"></span></body>`);
      return;
    }
    if (request.url === "/attribute-none") {
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        Connection: "close",
      });
      response.end(`<!doctype html><body>${Array.from(
        { length: 25 },
        (_, index) => `<div>Item ${index}</div>`,
      ).join("")}</body>`);
      return;
    }
    if (request.url === "/attribute-union") {
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        Connection: "close",
      });
      response.end(`<!doctype html><body>${Array.from(
        { length: 25 },
        (_, index) => `<div>Item ${index}</div>`,
      ).join("")}<span data-first=""></span><span data-second="two"></span></body>`);
      return;
    }
    if (request.url === "/attribute-exact-limit") {
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        Connection: "close",
      });
      response.end(`<!doctype html><body>${Array.from(
        { length: 20 },
        (_, index) => `<div q:version="version-${index}"></div>`,
      ).join("")}</body>`);
      return;
    }
    if (request.url === "/attribute-over-limit") {
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        Connection: "close",
      });
      response.end(`<!doctype html><body>${Array.from(
        { length: 21 },
        (_, index) => `<div q:version="version-${index}"></div>`,
      ).join("")}<a href="/attribute-next">Next</a></body>`);
      return;
    }
    if (request.url === "/attribute-next") {
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        Connection: "close",
      });
      response.end(
        '<!doctype html><body><div q:version="next"></div></body>',
      );
      return;
    }
    response.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Set-Cookie": "technology_cookie=enabled; Path=/; SameSite=Lax",
      Connection: "close",
    });
    response.end(`<!doctype html>
      <div id="app">Rendered</div>
      <a href="/next#fragment">Next</a>
      <a href="/next#fragment">Repeated next</a>
      <script src="/redirect-script.js"></script>
      <script>
        window.Shopify = { theme: { name: "Dawn" } };
        window.s_c_il = [{}];
        fetch("/api?technology=present");
      </script>`);
  });
  const port = await listenOnLoopback(t, server);
  const harness = setupTransportRuntime({
    lookup: () => [{ address: publicAddress, family: 4 }],
    routes: new Map([[publicAddress, { physicalPort: port }]]),
  });
  const config = browserConfig([
    [["limits", "timeMs", "browserSettle"], 100],
  ]);
  const pool = await createBrowserPool(
    createProtectedHttpTransport(config),
    config,
  );
  t.after(() => pool.close());
  const session = await pool.openDomain();
  const allowedTopLevelUrls: string[] = [];
  const collection = await session.collectPage({
    pageId: "p1",
    url: "http://browser-target.org/entry",
    inspectionPlan,
    allowTopLevelUrl: (url) => {
      allowedTopLevelUrls.push(url);
      return url.startsWith("http://browser-target.org/");
    },
  });
  assert.equal(collection.completed, true);
  assert.deepEqual(collection.navigationLinks, [
    "http://browser-target.org/next",
  ]);
  const result = await session.finish();

  assert.equal(result.completed, true);
  assert.deepEqual(result.errors, []);
  assert.equal(result.pages[0]?.finalUrl, "http://browser-target.org/landing");
  assert.deepEqual(allowedTopLevelUrls, [
    "http://browser-target.org/entry",
    "http://browser-target.org/landing",
  ]);
  assert.deepEqual(result.pages[0]?.dom, [
    { pageId: "p1", locator: "#app", fact: { kind: "presence" } },
    {
      pageId: "p1",
      locator: "#app:text",
      fact: { kind: "value", value: "Rendered" },
    },
  ]);
  assert.deepEqual(result.pages[0]?.javascript, [
    {
      pageId: "p1",
      path: "Shopify.theme.name",
      fact: { kind: "value", value: "Dawn" },
    },
    {
      pageId: "p1",
      path: "s_c_il.0.constructor.name",
      fact: { kind: "value", value: "Object" },
    },
  ]);
  assert.deepEqual(result.pages[0]?.cookies, [{
    name: "technology_cookie",
    value: "enabled",
  }]);
  assert.equal(
    result.pages[0]?.networkUrls.includes(
      "http://browser-target.org/api?technology=present",
    ),
    true,
  );
  assert.equal(
    result.pages[0]?.networkUrls.includes(
      "http://browser-target.org/redirect-script.js",
    ),
    true,
  );
  assert.deepEqual(result.pages[0]?.scriptUrls, [
    "http://cdn-browser-target.org/app.js",
  ]);
  assert.deepEqual(result.pages[0]?.scriptBodies, [{
    pageId: "p1",
    url: "http://cdn-browser-target.org/app.js",
    content: "window.ExternalTechnology = 'ready';",
  }]);
  assert.equal(harness.connectCalls.length >= 3, true);
  assert.equal(harness.connectCalls.every((call) => call.address === publicAddress), true);
  assert.equal(requestedUrls.includes("/redirect-script.js"), true);
  assert.equal(requestedUrls.includes("/app.js"), true);

  const wildcardPlan: CatalogInspectionPlan = Object.freeze({
    dom: Object.freeze([Object.freeze({
      selector: "*",
      facts: Object.freeze([Object.freeze({
        kind: "attribute" as const,
        name: "q:version",
        locator: "*:q:version",
        demand: Object.freeze({ presence: false, value: true }),
      })]),
    })]),
    javascript: Object.freeze([]),
    probePaths: Object.freeze([]),
    dnsRecordTypes: Object.freeze([]),
    tlsIssuer: false,
  });
  const afterIrrelevantSession = await pool.openDomain();
  const afterIrrelevantCollection = await afterIrrelevantSession.collectPage({
    pageId: "p1",
    url: "http://browser-target.org/attribute-after-irrelevant",
    inspectionPlan: wildcardPlan,
    allowTopLevelUrl: () => true,
  });
  assert.equal(afterIrrelevantCollection.completed, true);
  assert.equal(afterIrrelevantCollection.observationsAdmitted, true);
  assert.equal(afterIrrelevantCollection.continuationAllowed, true);
  const afterIrrelevantResult = await afterIrrelevantSession.finish();
  assert.deepEqual(afterIrrelevantResult.pages[0]?.dom, [{
    pageId: "p1",
    locator: "*:q:version",
    fact: { kind: "value", value: "after-irrelevant" },
  }]);
  assert.equal(afterIrrelevantResult.pages[0]?.truncated, false);

  const noAttributeSession = await pool.openDomain();
  const noAttributeCollection = await noAttributeSession.collectPage({
    pageId: "p1",
    url: "http://browser-target.org/attribute-none",
    inspectionPlan: wildcardPlan,
    allowTopLevelUrl: () => true,
  });
  assert.equal(noAttributeCollection.completed, true);
  const noAttributeResult = await noAttributeSession.finish();
  assert.deepEqual(noAttributeResult.pages[0]?.dom, []);
  assert.equal(noAttributeResult.pages[0]?.truncated, false);

  const existsOnlyPlan: CatalogInspectionPlan = Object.freeze({
    ...wildcardPlan,
    dom: Object.freeze([Object.freeze({
      selector: "div",
      facts: Object.freeze([
        Object.freeze({
          kind: "exists" as const,
          name: null,
          locator: "div:first-exists-rule",
          demand: Object.freeze({ presence: true, value: false }),
        }),
        Object.freeze({
          kind: "exists" as const,
          name: null,
          locator: "div:second-exists-rule",
          demand: Object.freeze({ presence: true, value: false }),
        }),
      ]),
    })]),
  });
  const expectedExistsFacts = [
    {
      pageId: "p1",
      locator: "div:first-exists-rule",
      fact: { kind: "presence" },
    },
    {
      pageId: "p1",
      locator: "div:second-exists-rule",
      fact: { kind: "presence" },
    },
  ];
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const existsOnlySession = await pool.openDomain();
    const existsOnlyCollection = await existsOnlySession.collectPage({
      pageId: "p1",
      url: "http://browser-target.org/attribute-none",
      inspectionPlan: existsOnlyPlan,
      allowTopLevelUrl: () => true,
    });
    assert.equal(existsOnlyCollection.completed, true);
    assert.equal(existsOnlyCollection.observationsAdmitted, true);
    assert.equal(
      existsOnlyCollection.errors.some(
        ({ code }) => code === "BROWSER_LIMIT_EXCEEDED",
      ),
      false,
    );
    assert.deepEqual(existsOnlyCollection.limitTelemetry.hits, []);
    const existsOnlyResult = await existsOnlySession.finish();
    assert.deepEqual(existsOnlyResult.pages[0]?.dom, expectedExistsFacts);
    assert.equal(existsOnlyResult.pages[0]?.truncated, false);
  }

  const missingExistsPlan: CatalogInspectionPlan = Object.freeze({
    ...wildcardPlan,
    dom: Object.freeze([Object.freeze({
      selector: ".missing-exists-only-selector",
      facts: existsOnlyPlan.dom[0]?.facts ?? Object.freeze([]),
    })]),
  });
  const missingExistsSession = await pool.openDomain();
  const missingExistsCollection = await missingExistsSession.collectPage({
    pageId: "p1",
    url: "http://browser-target.org/attribute-none",
    inspectionPlan: missingExistsPlan,
    allowTopLevelUrl: () => true,
  });
  assert.equal(missingExistsCollection.completed, true);
  assert.equal(missingExistsCollection.observationsAdmitted, true);
  const missingExistsResult = await missingExistsSession.finish();
  assert.deepEqual(missingExistsResult.pages[0]?.dom, []);
  assert.equal(missingExistsResult.pages[0]?.truncated, false);

  const attributeUnionPlan: CatalogInspectionPlan = Object.freeze({
    ...wildcardPlan,
    dom: Object.freeze([Object.freeze({
      selector: "*",
      facts: Object.freeze([
        Object.freeze({
          kind: "attribute" as const,
          name: "data-first",
          locator: "*:data-first",
          demand: Object.freeze({ presence: true, value: false }),
        }),
        Object.freeze({
          kind: "attribute" as const,
          name: "data-second",
          locator: "*:data-second",
          demand: Object.freeze({ presence: false, value: true }),
        }),
      ]),
    })]),
  });
  const attributeUnionSession = await pool.openDomain();
  const attributeUnionCollection = await attributeUnionSession.collectPage({
    pageId: "p1",
    url: "http://browser-target.org/attribute-union",
    inspectionPlan: attributeUnionPlan,
    allowTopLevelUrl: () => true,
  });
  assert.equal(attributeUnionCollection.completed, true);
  const attributeUnionResult = await attributeUnionSession.finish();
  assert.deepEqual(attributeUnionResult.pages[0]?.dom, [
    {
      pageId: "p1",
      locator: "*:data-first",
      fact: { kind: "presence" },
    },
    {
      pageId: "p1",
      locator: "*:data-second",
      fact: { kind: "value", value: "two" },
    },
  ]);

  const mixedPlan: CatalogInspectionPlan = Object.freeze({
    ...wildcardPlan,
    dom: Object.freeze([Object.freeze({
      selector: "div",
      facts: Object.freeze([
        Object.freeze({
          kind: "exists" as const,
          name: null,
          locator: "div",
          demand: Object.freeze({ presence: true, value: false }),
        }),
        Object.freeze({
          kind: "text" as const,
          name: null,
          locator: "div:text",
          demand: Object.freeze({ presence: false, value: true }),
        }),
      ]),
    })]),
  });
  const mixedSession = await pool.openDomain();
  const mixedCollection = await mixedSession.collectPage({
    pageId: "p1",
    url: "http://browser-target.org/attribute-none",
    inspectionPlan: mixedPlan,
    allowTopLevelUrl: () => true,
  });
  assert.equal(mixedCollection.completed, false);
  assert.equal(mixedCollection.observationsAdmitted, true);
  assert.equal(
    mixedCollection.errors.some(
      ({ code }) => code === "BROWSER_LIMIT_EXCEEDED",
    ),
    true,
  );
  assert.deepEqual(mixedCollection.limitTelemetry.hits, [{
    category: "inspection.domMatches",
    domSelectorOrdinal: 0,
  }]);
  const mixedResult = await mixedSession.finish();
  assert.equal(mixedResult.pages[0]?.truncated, true);
  assert.deepEqual(mixedResult.pages[0]?.dom[0], {
    pageId: "p1",
    locator: "div",
    fact: { kind: "presence" },
  });
  assert.equal(
    mixedResult.pages[0]?.dom.filter(
      ({ locator, fact }) => locator === "div:text" && fact.kind === "value",
    ).length,
    20,
  );

  const exactLimitSession = await pool.openDomain();
  const exactLimitCollection = await exactLimitSession.collectPage({
    pageId: "p1",
    url: "http://browser-target.org/attribute-exact-limit",
    inspectionPlan: wildcardPlan,
    allowTopLevelUrl: () => true,
  });
  assert.equal(exactLimitCollection.completed, true);
  assert.equal(exactLimitCollection.observationsAdmitted, true);
  assert.equal(exactLimitCollection.continuationAllowed, true);
  const exactLimitResult = await exactLimitSession.finish();
  assert.deepEqual(
    exactLimitResult.pages[0]?.dom.map(({ fact }) => fact),
    Array.from(
      { length: 20 },
      (_, index) => ({ kind: "value", value: `version-${index}` }),
    ),
  );
  assert.equal(exactLimitResult.pages[0]?.truncated, false);

  const truncatedSession = await pool.openDomain();
  const truncatedCollection = await truncatedSession.collectPage({
    pageId: "p1",
    url: "http://browser-target.org/attribute-over-limit",
    inspectionPlan: wildcardPlan,
    allowTopLevelUrl: () => true,
  });
  assert.equal(truncatedCollection.completed, false);
  assert.equal(truncatedCollection.observationsAdmitted, true);
  assert.equal(truncatedCollection.continuationAllowed, true);
  assert.equal(
    truncatedCollection.errors.some(
      ({ code }) => code === "BROWSER_LIMIT_EXCEEDED",
    ),
    true,
  );
  assert.deepEqual(truncatedCollection.limitTelemetry.hits, [{
    category: "inspection.domMatches",
    domSelectorOrdinal: 0,
  }]);
  const nextCollection = await truncatedSession.collectPage({
    pageId: "p2",
    url: "http://browser-target.org/attribute-next",
    inspectionPlan: wildcardPlan,
    allowTopLevelUrl: () => true,
  });
  assert.equal(nextCollection.completed, true);
  assert.equal(nextCollection.observationsAdmitted, true);
  assert.equal(nextCollection.continuationAllowed, true);
  assert.deepEqual(nextCollection.limitTelemetry.hits, []);
  const truncatedResult = await truncatedSession.finish();
  assert.equal(truncatedResult.completed, false);
  assert.equal(truncatedResult.pages.length, 2);
  assert.equal(truncatedResult.pages[0]?.truncated, true);
  assert.equal(truncatedResult.pages[1]?.truncated, false);
  assert.deepEqual(
    truncatedResult.pages[0]?.dom.map(({ fact }) => fact),
    Array.from(
      { length: 20 },
      (_, index) => ({ kind: "value", value: `version-${index}` }),
    ),
  );
  assert.deepEqual(truncatedResult.pages[1]?.dom, [{
    pageId: "p2",
    locator: "*:q:version",
    fact: { kind: "value", value: "next" },
  }]);

  const deniedSession = await pool.openDomain();
  const deniedCollection = await deniedSession.collectPage({
    pageId: "p1",
    url: "http://browser-target.org/denied-entry",
    inspectionPlan,
    allowTopLevelUrl: (url) => url.endsWith("/denied-entry"),
  });
  assert.equal(deniedCollection.completed, false);
  const deniedResult = await deniedSession.finish();
  assert.equal(deniedResult.completed, false);
  assert.equal(
    deniedResult.errors.some(({ code }) => code === "BROWSER_NAVIGATION_FAILED"),
    true,
  );
  assert.equal(requestedUrls.includes("/must-not-hit"), false);

  for (const path of ["/forbidden", "/not-html"] as const) {
    const rejectedSession = await pool.openDomain();
    const rejectedCollection = await rejectedSession.collectPage({
      pageId: "p1",
      url: `http://browser-target.org${path}`,
      inspectionPlan,
      allowTopLevelUrl: () => true,
    });
    assert.equal(rejectedCollection.completed, false);
    const rejectedResult = await rejectedSession.finish();
    assert.equal(rejectedResult.completed, false);
    assert.deepEqual(rejectedResult.pages, []);
    const navigationError = rejectedResult.errors.find(
      ({ code }) => code === "BROWSER_NAVIGATION_FAILED",
    );
    assert.notEqual(navigationError, undefined);
    assert.equal(navigationError?.retryable, path === "/forbidden" ? false : true);
    assert.equal(requestedUrls.includes(path), true);
  }
  await waitForTimeout(150);
  assert.equal(requestedUrls.includes("/must-not-hit-after-denial"), false);

  const lateNavigationSession = await pool.openDomain();
  const lateNavigationCollection = await lateNavigationSession.collectPage({
    pageId: "p1",
    url: "http://browser-target.org/late-navigation",
    inspectionPlan,
    allowTopLevelUrl: () => true,
  });
  assert.equal(lateNavigationCollection.completed, false);
  const lateNavigationResult = await lateNavigationSession.finish();
  assert.deepEqual(lateNavigationResult.pages, []);
  assert.equal(lateNavigationResult.errors[0]?.retryable, false);
  assert.equal(requestedUrls.includes("/late-forbidden"), false);

  for (const path of ["/history-navigation", "/blob-navigation"] as const) {
    const localNavigationSession = await pool.openDomain();
    const localNavigationCollection = await localNavigationSession.collectPage({
      pageId: "p1",
      url: `http://browser-target.org${path}`,
      inspectionPlan,
      allowTopLevelUrl: () => true,
    });
    assert.equal(localNavigationCollection.completed, false);
    const localNavigationResult = await localNavigationSession.finish();
    assert.deepEqual(localNavigationResult.pages, []);
    assert.equal(localNavigationResult.errors[0]?.retryable, false);
  }
});
