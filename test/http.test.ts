import assert from "node:assert/strict";
import { once } from "node:events";
import {
  createServer as createHttpServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { type Server, type Socket } from "node:net";
import { test, type TestContext } from "node:test";

import {
  createDefaultScanConfig,
  parseScanConfig,
  type ScanConfig,
} from "../src/config.ts";
import type {
  ProtectedTransportRequest,
  ProtectedTransportResponse,
  ProtectedTransportResponseHead,
  ProtectedTransportSession,
  ProtectedTransportUsage,
} from "../src/crawl/transport.ts";
import type {
  RobotsCheck,
  RobotsPolicyService,
} from "../src/crawl/robots.ts";
import {
  installTransportRuntimeHook,
  setupTransportRuntime,
} from "./support/transport-runtime.ts";

installTransportRuntimeHook();

const { collectHttpEntry } = await import("../src/crawl/http.ts");
const {
  createProtectedHttpTransport,
  ProtectedTransportError,
} = await import("../src/crawl/transport.ts");

type JsonRecord = Record<string, unknown>;
type SessionStep = (
  request: ProtectedTransportRequest,
) => ProtectedTransportResponse | Promise<ProtectedTransportResponse>;

const userAgent =
  "WebsiteTechScraper/0.1.0 (https://contact.website-tech-scraper.dev/crawler)";
const publicAddress = "8.8.8.8";

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

  const finalKey = path.at(-1);
  assert.notEqual(finalKey, undefined);
  current[finalKey as string] = replacement;
}

function configWith(
  replacements: ReadonlyArray<readonly [readonly string[], unknown]> = [],
): ScanConfig {
  const value = structuredClone(
    createDefaultScanConfig(userAgent),
  ) as unknown as JsonRecord;

  for (const [path, replacement] of replacements) {
    setConfigValue(value, path, replacement);
  }

  return parseScanConfig(value);
}

function response(
  url: string,
  statusCode: number,
  options: {
    readonly headers?: ReadonlyArray<readonly [string, string]>;
    readonly body?: string | Uint8Array;
    readonly redirectUrl?: string | null;
  } = {},
): ProtectedTransportResponse {
  const body = typeof options.body === "string"
    ? Buffer.from(options.body, "utf8")
    : options.body ?? new Uint8Array();

  return Object.freeze({
    url,
    statusCode,
    headers: Object.freeze(
      (options.headers ?? []).map(([name, value]) =>
        Object.freeze({ name: name.toLowerCase(), value }),
      ),
    ),
    body,
    redirectUrl: options.redirectUrl ?? null,
  });
}

function deliver(
  request: ProtectedTransportRequest,
  source: ProtectedTransportResponse,
  admitted?: boolean[],
): ProtectedTransportResponse {
  let keepBody = source.statusCode >= 200
    && source.statusCode <= 299
    && source.statusCode !== 204
    && source.statusCode !== 205;

  if (keepBody && request.acceptBody !== undefined) {
    const head: ProtectedTransportResponseHead = {
      url: source.url,
      statusCode: source.statusCode,
      headers: source.headers,
    };
    keepBody = request.acceptBody(head);
    admitted?.push(keepBody);
  }

  return Object.freeze({
    ...source,
    body: keepBody ? source.body : new Uint8Array(),
  });
}

class ScriptedSession implements ProtectedTransportSession {
  readonly calls: ProtectedTransportRequest[] = [];
  private readonly steps: readonly SessionStep[];
  private readonly signal: AbortSignal;
  private readonly events: string[] | undefined;
  private index = 0;

  constructor(
    steps: readonly SessionStep[],
    signal: AbortSignal = new AbortController().signal,
    events?: string[],
  ) {
    this.steps = steps;
    this.signal = signal;
    this.events = events;
  }

  async requestHop(
    request: ProtectedTransportRequest,
  ): Promise<ProtectedTransportResponse> {
    this.calls.push(Object.freeze({ ...request }));
    this.events?.push(`request:${request.url}:${request.isRetry === true ? "retry" : "initial"}`);
    const step = this.steps[this.index];
    this.index += 1;

    if (step === undefined) {
      assert.fail(`Unexpected request ${request.url}.`);
    }

    return step(request);
  }

  getSignal(): AbortSignal {
    return this.signal;
  }

  getUsage(): ProtectedTransportUsage {
    return Object.freeze({
      httpRequests: this.calls.length,
      retries: this.calls.filter((call) => call.isRetry === true).length,
      staticTransferredBytes: 0,
    });
  }

  close(): void {}
}

function robotsService(
  options: {
    readonly events?: string[];
    readonly checks?: string[];
    readonly decide?: (url: string) => boolean;
    readonly text?: (url: string) => string | null;
  } = {},
): RobotsPolicyService {
  return {
    async check(_session, url): Promise<RobotsCheck> {
      options.events?.push(`robots:${url}`);
      options.checks?.push(url);
      const origin = new URL(url).origin;
      return Object.freeze({
        allowed: options.decide?.(url) ?? true,
        robotsText: options.text?.(url) ?? null,
        ownerOrigin: origin,
        fetchedUrl: `${origin}/robots.txt`,
      });
    },
    clear(): void {},
  };
}

function deliveredStep(
  source: ProtectedTransportResponse,
  admitted?: boolean[],
): SessionStep {
  return (request) => deliver(request, source, admitted);
}

function errorCodes(result: { readonly errors: readonly { readonly code: string }[] }): string[] {
  return result.errors.map((error) => error.code);
}

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
    assert.fail("The local HTTP server did not expose an IP socket address.");
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

test("falls through a 404 candidate and retains only selected observations", async () => {
  const firstUrl = "https://shop.vendor.tld/";
  const selectedUrl = "https://www.shop.vendor.tld/";
  const checks: string[] = [];
  const session = new ScriptedSession([
    deliveredStep(response(firstUrl, 404, {
      headers: [["x-soft-candidate", "discard-me"]],
    })),
    deliveredStep(response(selectedUrl, 200, {
      headers: [
        ["content-type", "text/html; charset=utf-8"],
        ["x-powered-by", "selected"],
        ["set-cookie", "platform=shop; Path=/"],
      ],
      body: "<html><head><meta name=generator content=Selected></head><body>Ready</body></html>",
    })),
  ]);
  const result = await collectHttpEntry("shop.vendor.tld", {
    config: configWith(),
    session,
    robots: robotsService({
      checks,
      text: (url) => `User-agent: *\n# ${new URL(url).hostname}`,
    }),
  });

  if (result.kind !== "html") {
    assert.fail(`Expected HTML, received ${result.kind}.`);
  }

  assert.deepEqual(checks, [firstUrl, selectedUrl]);
  assert.deepEqual(session.calls.map((call) => call.url), [firstUrl, selectedUrl]);
  assert.equal(result.page.response.finalNetworkUrl, selectedUrl);
  assert.deepEqual(result.page.response.headers, [
    { name: "content-type", value: "text/html; charset=utf-8" },
    { name: "x-powered-by", value: "selected" },
    { name: "set-cookie", value: "platform=shop; Path=/" },
  ]);
  assert.deepEqual(result.page.response.cookies, [{ name: "platform", value: "shop" }]);
  assert.deepEqual(result.page.metadata, [{ key: "generator", value: "Selected" }]);
  assert.equal(result.page.text, "Ready");
  assert.equal(result.robots.length, 1);
  assert.equal(result.robots[0]?.ownerOrigin, "https://www.shop.vendor.tld");
  assert.equal(result.robots[0]?.text.includes("www.shop.vendor.tld"), true);
  assert.deepEqual(result.errors, []);
});

test("checks robots before every retry and redirect request", async () => {
  const entryUrl = "https://shop.vendor.tld/";
  const redirectUrl = "https://cdn.vendor.tld/store";
  const events: string[] = [];
  const session = new ScriptedSession([
    deliveredStep(response(entryUrl, 503)),
    deliveredStep(response(entryUrl, 302, { redirectUrl })),
    deliveredStep(response(redirectUrl, 200, {
      headers: [["content-type", "text/html"]],
      body: "<body>done</body>",
    })),
  ], undefined, events);
  const result = await collectHttpEntry("shop.vendor.tld", {
    config: configWith(),
    session,
    robots: robotsService({ events }),
  });

  if (result.kind !== "html") {
    assert.fail(`Expected HTML, received ${result.kind}.`);
  }

  assert.deepEqual(events, [
    `robots:${entryUrl}`,
    `request:${entryUrl}:initial`,
    `robots:${entryUrl}`,
    `request:${entryUrl}:retry`,
    `robots:${redirectUrl}`,
    `request:${redirectUrl}:initial`,
  ]);
  assert.deepEqual(result.page.response.redirects, [{
    fromUrl: entryUrl,
    statusCode: 302,
    toUrl: redirectUrl,
  }]);
});

test("stops on robots denial, access denial, and invalid redirect chains", async () => {
  const entryUrl = "https://shop.vendor.tld/";
  const blockedUrl = "https://blocked.vendor.tld/landing";

  const redirectSession = new ScriptedSession([
    deliveredStep(response(entryUrl, 302, { redirectUrl: blockedUrl })),
  ]);
  const blocked = await collectHttpEntry("shop.vendor.tld", {
    config: configWith(),
    session: redirectSession,
    robots: robotsService({ decide: (url) => url !== blockedUrl }),
  });
  assert.equal(blocked.kind, "failed");
  assert.deepEqual(errorCodes(blocked), ["ROBOTS_DISALLOWED"]);
  assert.equal(redirectSession.calls.length, 1);

  const deniedSession = new ScriptedSession([
    deliveredStep(response(entryUrl, 403)),
  ]);
  const denied = await collectHttpEntry("shop.vendor.tld", {
    config: configWith(),
    session: deniedSession,
    robots: robotsService(),
  });
  assert.equal(denied.kind, "failed");
  assert.deepEqual(errorCodes(denied), ["TARGET_ACCESS_DENIED"]);
  assert.equal(deniedSession.calls.length, 1);

  for (const candidate of [
    response(entryUrl, 302),
    response(entryUrl, 300),
    response(entryUrl, 302, { redirectUrl: entryUrl }),
  ]) {
    const session = new ScriptedSession([deliveredStep(candidate)]);
    const result = await collectHttpEntry("shop.vendor.tld", {
      config: configWith(),
      session,
      robots: robotsService(),
    });
    assert.equal(result.kind, "failed");
    assert.deepEqual(
      errorCodes(result),
      [candidate.redirectUrl === entryUrl
        ? "TARGET_REDIRECT_LIMIT_EXCEEDED"
        : "TARGET_REDIRECT_INVALID"],
    );
  }
});

test("retries 429 once and treats the repeated response as access denial", async () => {
  const entryUrl = "https://shop.vendor.tld/";
  const checks: string[] = [];
  const session = new ScriptedSession([
    deliveredStep(response(entryUrl, 429, {
      headers: [["retry-after", "0"]],
    })),
    deliveredStep(response(entryUrl, 429)),
  ]);
  const result = await collectHttpEntry("shop.vendor.tld", {
    config: configWith([[ ["limits", "timeMs", "retryAfterCap"], 0 ]]),
    session,
    robots: robotsService({ checks }),
  });

  assert.equal(result.kind, "failed");
  assert.deepEqual(errorCodes(result), ["TARGET_ACCESS_DENIED"]);
  assert.deepEqual(checks, [entryUrl, entryUrl]);
  assert.deepEqual(session.calls.map((call) => call.isRetry === true), [false, true]);
});

test("requires an exact valid HTML media type and never sniffs the body", async () => {
  const entryUrl = "https://shop.vendor.tld/";
  const cases = [
    {
      name: "JSON",
      response: response(entryUrl, 200, {
        headers: [["content-type", "application/json"]],
        body: "<html><body>looks like HTML</body></html>",
      }),
    },
    {
      name: "missing",
      response: response(entryUrl, 200, { body: "<html></html>" }),
    },
    {
      name: "duplicate",
      response: response(entryUrl, 200, {
        headers: [
          ["content-type", "text/html"],
          ["content-type", "text/html"],
        ],
        body: "<html></html>",
      }),
    },
    {
      name: "malformed",
      response: response(entryUrl, 200, {
        headers: [["content-type", "text/html; charset=\"unterminated"]],
        body: "<html></html>",
      }),
    },
    {
      name: "204",
      response: response(entryUrl, 204, {
        headers: [["content-type", "text/html"]],
        body: "<html></html>",
      }),
    },
  ] as const;

  for (const current of cases) {
    const admitted: boolean[] = [];
    const session = new ScriptedSession([
      deliveredStep(current.response, admitted),
    ]);
    const result = await collectHttpEntry("shop.vendor.tld", {
      config: configWith(),
      session,
      robots: robotsService(),
    });
    assert.equal(result.kind, "non-html", current.name);
    assert.deepEqual(errorCodes(result), ["UNSUPPORTED_CONTENT_TYPE"], current.name);
    assert.deepEqual(admitted, current.name === "204" ? [] : [false], current.name);
  }
});

test("keeps Cheerio decoded source and extracts deterministic static signals", async () => {
  const entryUrl = "https://shop.vendor.tld/store/index.html";
  const latin1Source = [
    "<!doctype html><html><head>",
    "<template><base href='https://inert.vendor.tld/'><meta name='generator' content='ignored'>",
    "<script src='ignored.js'></script><link rel='stylesheet' href='ignored.css'>",
    "<img src='ignored.png'><iframe src='ignored-frame'></iframe>",
    "<a href='ignored-link'>ignored link</a>hidden template</template>",
    "<base href='/assets/'>",
    "<base href='https://ignored.vendor.tld/'>",
    "<meta name=' Generator ' property='og:ignored' content='Shopify'>",
    "<meta property='OG:TYPE' content='website'>",
    "<meta property='og:type' content='website'>",
    "<script src='app.js#build'></script>",
    "<link rel='preload stylesheet' href='theme.css'>",
    "<link rel='icon' href='/favicon.ico'>",
    "</head><body>caf\xe9   Visible",
    "<img src='image.png'><iframe src='/frame'></iframe> ",
    "<a href='/next?campaign=1#section'>Next</a> ",
    "<script>hidden script</script><style>hidden style</style>",
    "<noscript>hidden noscript</noscript>",
    " Tail</body></html>",
  ].join("");
  const body = Buffer.from(latin1Source, "latin1");
  const decodedSource = latin1Source.replace("\xe9", "é");
  const session = new ScriptedSession([
    deliveredStep(response(entryUrl, 200, {
      headers: [["content-type", "Text/HTML; charset=windows-1252"]],
      body,
    })),
  ]);
  const result = await collectHttpEntry("shop.vendor.tld", {
    config: configWith(),
    session,
    robots: robotsService(),
  });

  if (result.kind !== "html") {
    assert.fail(`Expected HTML, received ${result.kind}.`);
  }

  assert.equal(result.page.html, decodedSource);
  assert.deepEqual(result.page.metadata, [
    { key: "generator", value: "Shopify" },
    { key: "og:type", value: "website" },
  ]);
  assert.deepEqual(result.page.resources, [
    { kind: "script", url: "https://shop.vendor.tld/assets/app.js" },
    { kind: "stylesheet", url: "https://shop.vendor.tld/assets/theme.css" },
    { kind: "link", url: "https://shop.vendor.tld/favicon.ico" },
    { kind: "image", url: "https://shop.vendor.tld/assets/image.png" },
    { kind: "iframe", url: "https://shop.vendor.tld/frame" },
  ]);
  assert.deepEqual(result.page.navigationLinks, [
    "https://shop.vendor.tld/next?campaign=1",
  ]);
  assert.equal(result.page.text, "café Visible Next Tail");
  assert.equal(result.page.collectionState, "complete");
  assert.deepEqual(result.errors, []);
});

test("keeps strict prefixes for cookie, metadata, URL, and UTF-8 text limits", async () => {
  const entryUrl = "https://shop.vendor.tld/";
  const session = new ScriptedSession([
    deliveredStep(response(entryUrl, 200, {
      headers: [
        ["content-type", "text/html; charset=utf-8"],
        ["set-cookie", "invalid-cookie"],
        ["set-cookie", "a=1; Path=/"],
        ["set-cookie", "long=2; Path=/"],
        ["set-cookie", "b=3; Path=/"],
      ],
      body: [
        "<head><meta name=a content=one><meta name=b content=two></head>",
        "<body>A😀B<script src='/one.js'></script>",
        "<link rel=stylesheet href='/two.css'><a href='/three'>three</a></body>",
      ].join(""),
    })),
  ]);
  const result = await collectHttpEntry("shop.vendor.tld", {
    config: configWith([
      [["limits", "cookies", "nameCodeUnits"], 1],
      [["limits", "pages", "metadataPerPage"], 1],
      [["limits", "pages", "extractedUrlsPerPage"], 2],
      [["limits", "pages", "visibleTextBytesPerPage"], 5],
    ]),
    session,
    robots: robotsService(),
  });

  if (result.kind !== "html") {
    assert.fail(`Expected HTML, received ${result.kind}.`);
  }

  assert.deepEqual(result.page.response.cookies, [{ name: "a", value: "1" }]);
  assert.equal(result.page.response.cookiesTruncated, true);
  assert.deepEqual(result.page.metadata, [{ key: "a", value: "one" }]);
  assert.deepEqual(result.page.resources, [
    { kind: "script", url: "https://shop.vendor.tld/one.js" },
    { kind: "stylesheet", url: "https://shop.vendor.tld/two.css" },
  ]);
  assert.deepEqual(result.page.navigationLinks, []);
  assert.equal(result.page.urlsTruncated, true);
  assert.equal(result.page.text, "A😀");
  assert.equal(result.page.textTruncated, true);
  assert.equal(result.page.collectionState, "truncated");
  assert.deepEqual(errorCodes(result), ["HTTP_RESPONSE_LIMIT_EXCEEDED"]);
});

test("preserves the accepted response head when body collection fails", async () => {
  const entryUrl = "https://shop.vendor.tld/";
  const session = new ScriptedSession([
    (request) => {
      const head: ProtectedTransportResponseHead = {
        url: entryUrl,
        statusCode: 200,
        headers: [
          { name: "content-type", value: "text/html" },
          { name: "x-platform", value: "bounded-head" },
          { name: "set-cookie", value: "platform=shop" },
        ],
      };
      assert.equal(request.acceptBody?.(head), true);
      throw new ProtectedTransportError(
        "HTTP_RESPONSE_LIMIT_EXCEEDED",
        "http",
        false,
      );
    },
  ]);
  const result = await collectHttpEntry("shop.vendor.tld", {
    config: configWith(),
    session,
    robots: robotsService(),
  });

  if (result.kind !== "html") {
    assert.fail(`Expected an incomplete HTML result, received ${result.kind}.`);
  }

  assert.equal(result.page.collectionState, "failed");
  assert.equal(result.page.response.finalNetworkUrl, entryUrl);
  assert.deepEqual(result.page.response.cookies, [{ name: "platform", value: "shop" }]);
  assert.deepEqual(errorCodes(result), ["HTTP_RESPONSE_LIMIT_EXCEEDED"]);
});

test("uses the session signal for preflight and mid-decode cancellation", async () => {
  const entryUrl = "https://shop.vendor.tld/";
  const preflightController = new AbortController();
  preflightController.abort(new Error("cancelled"));
  const preflightSession = new ScriptedSession([], preflightController.signal);
  const preflight = await collectHttpEntry("shop.vendor.tld", {
    config: configWith(),
    session: preflightSession,
    robots: robotsService(),
  });
  assert.equal(preflight.kind, "failed");
  assert.deepEqual(errorCodes(preflight), ["DOMAIN_DEADLINE_EXCEEDED"]);
  assert.equal(preflightSession.calls.length, 0);

  const decodeController = new AbortController();
  const decodeSession = new ScriptedSession([
    (request) => {
      const source = response(entryUrl, 200, {
        headers: [["content-type", "text/html"]],
        body: `<body>${"x".repeat(70_000)}</body>`,
      });
      const delivered = deliver(request, source);
      decodeController.abort(new Error("domain deadline"));
      return delivered;
    },
  ], decodeController.signal);
  const decoded = await collectHttpEntry("shop.vendor.tld", {
    config: configWith(),
    session: decodeSession,
    robots: robotsService(),
  });

  if (decoded.kind !== "html") {
    assert.fail(`Expected an incomplete HTML result, received ${decoded.kind}.`);
  }

  assert.equal(decoded.page.collectionState, "failed");
  assert.equal(decoded.page.response.finalNetworkUrl, entryUrl);
  assert.deepEqual(errorCodes(decoded), ["DOMAIN_DEADLINE_EXCEEDED"]);
});

test("integrates with the protected transport through a controlled HTTP server", async (t) => {
  const requests: Array<{
    readonly host: string | undefined;
    readonly url: string | undefined;
  }> = [];
  const server = createHttpServer(
    (request: IncomingMessage, response: ServerResponse) => {
      requests.push({ host: request.headers.host, url: request.url });
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "X-Collector": "protected",
      });
      response.end("<body>transport integration</body>");
    },
  );
  const port = await listenOnLoopback(t, server);
  let lookups = 0;
  setupTransportRuntime({
    lookup: () => {
      lookups += 1;
      return lookups <= 2 ? [] : [{ address: publicAddress, family: 4 }];
    },
    routes: new Map([[publicAddress, { physicalPort: port }]]),
  });
  const config = configWith([
    [["limits", "http", "transientRetriesPerRequest"], 0],
  ]);
  const session = createProtectedHttpTransport(config).createSession();
  t.after(() => session.close());
  const checks: string[] = [];
  const result = await collectHttpEntry("shop.vendor.tld", {
    config,
    session,
    robots: robotsService({ checks }),
  });

  if (result.kind !== "html") {
    assert.fail(`Expected HTML, received ${result.kind}.`);
  }

  assert.deepEqual(checks, [
    "https://shop.vendor.tld/",
    "https://www.shop.vendor.tld/",
    "http://shop.vendor.tld/",
  ]);
  assert.deepEqual(requests, [{ host: "shop.vendor.tld", url: "/" }]);
  assert.equal(result.page.response.finalNetworkUrl, "http://shop.vendor.tld/");
  assert.equal(result.page.text, "transport integration");
  assert.equal(session.getUsage().httpRequests, 3);
});
