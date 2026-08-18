import { performance } from "node:perf_hooks";
import { isIP } from "node:net";
import { setTimeout as delay } from "node:timers/promises";

import {
  chromium,
  type Browser,
  type BrowserContext,
  type CDPSession,
  type Frame,
  type LaunchOptions,
  type Page,
  type Request,
  type Response,
  type Route,
  type WebSocketRoute,
} from "playwright";

import type { ScanConfig } from "../config.ts";
import type {
  BrowserDomObservation,
  BrowserFact,
  BrowserJavascriptObservation,
  BrowserPageObservations,
  BrowserScriptBodyObservation,
  CatalogDomFact,
  CatalogInspectionPlan,
  CatalogJavascriptInspection,
  HttpCookieObservation,
  PageId,
  ScanError,
} from "../model.ts";
import { isPublicIpAddress, normalizeHostname } from "../network-policy.ts";
import type {
  ProtectedBrowserProxy,
  ProtectedBrowserProxyCanary,
  ProtectedBrowserProxyUsage,
  ProtectedHttpTransport,
  ProtectedTransportError,
} from "./transport.ts";

const SAFE_CHROMIUM_ARGS = Object.freeze([
  "--disable-quic",
  "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
] as const);
const CLEANUP_WATCHDOG_MS = 1_000;
const PAGE_ID_RANK = new Map<PageId, number>([
  ["p1", 0],
  ["p2", 1],
  ["p3", 2],
]);
const ALLOWED_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const ABORTED_RESOURCE_TYPES = new Set(["image", "font", "media"]);
const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);
const ACCESS_DENIAL_STATUS_CODES = new Set([401, 403, 407, 451]);
const HTML_MEDIA_TYPES = new Set(["text/html", "application/xhtml+xml"]);
const MIME_TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const strictUtf8 = new TextDecoder("utf-8", { fatal: true });

const BROWSER_MESSAGES = Object.freeze({
  BROWSER_UNAVAILABLE: "The protected Chromium collector is unavailable.",
  BROWSER_NAVIGATION_FAILED: "The browser could not collect the selected page.",
  BROWSER_TIMEOUT: "The browser page exceeded its deadline.",
  BROWSER_LIMIT_EXCEEDED: "The browser observation exceeded a safety limit.",
  BROWSER_PROXY_FAILED: "The protected browser proxy failed.",
});
const PLAYWRIGHT_VERSION = "1.62.1";
const CHROMIUM_REVISION = "1234";

type BrowserErrorCode = keyof typeof BROWSER_MESSAGES;

export interface BrowserPageInput {
  readonly pageId: PageId;
  readonly url: string;
  readonly inspectionPlan: CatalogInspectionPlan;
  readonly allowTopLevelUrl: (url: string) => boolean;
}

export interface BrowserPageCollection {
  readonly completed: boolean;
  readonly observationsAdmitted: boolean;
  readonly continuationAllowed: boolean;
  readonly errors: readonly ScanError[];
  readonly navigationLinks: readonly string[];
}

export interface BrowserDomainResult {
  readonly pages: readonly BrowserPageObservations[];
  readonly errors: readonly ScanError[];
  readonly completed: boolean;
}

export interface BrowserDomainSession {
  collectPage(input: BrowserPageInput): Promise<BrowserPageCollection>;
  finish(): Promise<BrowserDomainResult>;
  getUsage(): ProtectedBrowserProxyUsage & {
    readonly scriptBodiesInspected: number;
  };
  close(): Promise<void>;
}

export interface BrowserPool {
  readonly runtime: BrowserRuntimeIdentity;
  openDomain(
    signal?: AbortSignal,
    onAdmitted?: () => void,
  ): Promise<BrowserDomainSession>;
  isAvailable(): boolean;
  close(): Promise<void>;
}

export interface BrowserRuntimeIdentity {
  readonly playwright: "1.62.1";
  readonly chromiumRevision: "1234";
  readonly chromiumVersion: string;
}

export type BrowserLauncher = (
  options: LaunchOptions,
) => Promise<Browser>;

interface BrowserSlot {
  readonly id: number;
  proxy: ProtectedBrowserProxy;
  browser: Browser;
  busy: boolean;
  failed: boolean;
  replacementUsed: boolean;
  replacing: Promise<boolean> | null;
  active: BrowserDomainSessionImpl | null;
  disconnectHandler: (() => void) | null;
}

interface PoolWaiter {
  readonly resolve: (slot: BrowserSlot) => void;
  readonly reject: (error: unknown) => void;
  readonly signal: AbortSignal | undefined;
  readonly onAbort: (() => void) | undefined;
}

interface BrowserPageDraft {
  readonly pageId: PageId;
  readonly finalUrl: string;
  readonly dom: readonly BrowserDomObservation[];
  readonly javascript: readonly BrowserJavascriptObservation[];
  readonly cookies: readonly HttpCookieObservation[];
  readonly networkHostnames: readonly string[];
  readonly networkUrls: readonly string[];
  readonly scriptCandidates: readonly ScriptCandidate[];
  readonly navigationLinks: readonly string[];
  readonly truncated: boolean;
}

interface ActivePageState {
  readonly input: BrowserPageInput;
  readonly origin: string;
  readonly networkHostnames: Set<string>;
  readonly networkUrls: Set<string>;
  readonly errors: ScanError[];
  navigationLocked: boolean;
  policyDenied: boolean;
  truncated: boolean;
}

interface ScriptCandidate {
  readonly pageId: PageId;
  readonly url: string;
  readonly sameOrigin: boolean;
  readonly requestId: string;
  readonly session: CDPSession;
  readonly complete: boolean;
  readonly failed: boolean;
  readonly decodedBytes: number;
  readonly encodedBytes: number;
}

interface CdpRedirectAttempt {
  readonly currentUrl: string;
  readonly targetUrl: string | null;
  readonly method: string;
  readonly resourceType: string;
  readonly isTopFrame: boolean;
}

type CdpRedirectGate = (attempt: CdpRedirectAttempt) => boolean;

interface SelectedScript {
  readonly candidate: ScriptCandidate;
  readonly content: string | null;
  readonly bytes: number;
}

interface EvaluationDomFact {
  readonly ordinal: number;
  readonly kind: CatalogDomFact["kind"];
  readonly name: string | null;
  readonly presence: boolean;
  readonly value: boolean;
}

interface EvaluationDomInspection {
  readonly selector: string;
  readonly facts: readonly EvaluationDomFact[];
}

interface EvaluationJavascriptInspection {
  readonly ordinal: number;
  readonly segments: readonly string[];
  readonly presence: boolean;
  readonly value: boolean;
}

interface EvaluationInput {
  readonly dom: readonly EvaluationDomInspection[];
  readonly javascript: readonly EvaluationJavascriptInspection[];
  readonly valueBytes: number;
  readonly totalValueBytes: number;
  readonly matchesPerSelector: number;
  readonly links: number;
  readonly urlCodeUnits: number;
}

interface EvaluationFact {
  readonly scope: "dom" | "javascript";
  readonly ordinal: number;
  readonly kind: "presence" | "value";
  readonly value?: string;
}

interface EvaluationOutput {
  readonly facts: readonly EvaluationFact[];
  readonly links: readonly string[];
  readonly truncated: boolean;
}

interface CdpScriptState {
  readonly requestId: string;
  readonly url: string;
  readonly status: number;
  decodedBytes: number;
  encodedBytes: number;
  complete: boolean;
  failed: boolean;
}

interface CdpRedirectChain {
  readonly depth: number;
  readonly seen: ReadonlySet<string>;
}

interface CdpPendingRedirect {
  readonly targetUrl: string;
  readonly expectedMethod: string;
  readonly frameId: string;
  readonly resourceType: string;
  readonly isTopFrame: boolean;
  readonly chain: CdpRedirectChain;
}

class PageDeadlineMarker extends Error {
  constructor() {
    super("Browser page deadline exceeded");
    this.name = "PageDeadlineMarker";
  }
}

class BrowserAccessDeniedMarker extends Error {
  constructor() {
    super("Browser target denied access");
    this.name = "BrowserAccessDeniedMarker";
  }
}

export class BrowserLifecycleFailure extends Error {
  readonly code: "BROWSER_UNAVAILABLE" | "BROWSER_PROXY_FAILED";

  constructor(
    code: "BROWSER_UNAVAILABLE" | "BROWSER_PROXY_FAILED",
    options?: ErrorOptions,
  ) {
    super(BROWSER_MESSAGES[code], options);
    this.name = "BrowserLifecycleFailure";
    this.code = code;
  }
}

function compareString(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function comparePageId(left: PageId, right: PageId): number {
  return (PAGE_ID_RANK.get(left) ?? Number.MAX_SAFE_INTEGER)
    - (PAGE_ID_RANK.get(right) ?? Number.MAX_SAFE_INTEGER);
}

function browserError(
  code: BrowserErrorCode,
  pageId: PageId | null,
  retryableOverride?: boolean,
): ScanError {
  return Object.freeze({
    stage: "browser",
    code,
    pageId,
    retryable: retryableOverride ?? (
      code === "BROWSER_UNAVAILABLE"
      || code === "BROWSER_NAVIGATION_FAILED"
      || code === "BROWSER_TIMEOUT"
      || code === "BROWSER_PROXY_FAILED"
    ),
    message: BROWSER_MESSAGES[code],
    ruleId: null,
    signal: null,
    limit: null,
    catalogRevision: null,
  });
}

function proxyError(error: ProtectedTransportError, pageId: PageId | null): ScanError {
  return Object.freeze({
    stage: error.stage,
    code: error.code,
    pageId,
    retryable: error.retryable,
    message: error.message,
    ruleId: null,
    signal: null,
    limit: null,
    catalogRevision: null,
  });
}

function isProtectedTransportError(error: unknown): error is ProtectedTransportError {
  return error instanceof Error
    && error.name === "ProtectedTransportError"
    && "code" in error
    && "stage" in error
    && "retryable" in error;
}

function pageOrigin(input: string, maximumCodeUnits: number): string {
  if (
    input.length === 0
    || input.length > maximumCodeUnits
    || !input.isWellFormed()
  ) {
    throw new TypeError("Browser page URL is invalid");
  }
  const url = new URL(input);
  if (
    (url.protocol !== "http:" && url.protocol !== "https:")
    || url.username !== ""
    || url.password !== ""
    || url.port !== ""
  ) {
    throw new TypeError("Browser page URL is invalid");
  }
  return url.origin;
}

function canonicalNetworkHost(
  input: string,
  maximumCodeUnits: number,
): { readonly value: string; readonly family: 0 | 4 | 6 } | null {
  if (input.length === 0 || input.length > maximumCodeUnits || !input.isWellFormed()) {
    return null;
  }
  try {
    const url = new URL(input);
    if (
      !["http:", "https:", "ws:", "wss:"].includes(url.protocol)
      || url.username !== ""
      || url.password !== ""
      || url.port !== ""
    ) {
      return null;
    }
    const hostname = url.hostname.toLowerCase();
    const unbracketed = hostname.startsWith("[") && hostname.endsWith("]")
      ? hostname.slice(1, -1)
      : hostname;
    const family = isIP(unbracketed);
    if (family === 4 || family === 6) {
      return isPublicIpAddress(unbracketed)
        ? Object.freeze({ value: unbracketed, family })
        : null;
    }
    try {
      return Object.freeze({
        value: normalizeHostname(unbracketed, maximumCodeUnits),
        family: 0,
      });
    } catch {
      return null;
    }
  } catch {
    return null;
  }
}

function networkHostname(input: string, maximumCodeUnits: number): string | null {
  const host = canonicalNetworkHost(input, maximumCodeUnits);
  return host?.family === 0 ? host.value : null;
}

function normalizedHttpUrl(input: string, maximumCodeUnits: number): string | null {
  if (input.length === 0 || input.length > maximumCodeUnits || !input.isWellFormed()) {
    return null;
  }
  try {
    const url = new URL(input);
    if (
      (url.protocol !== "http:" && url.protocol !== "https:")
      || url.username !== ""
      || url.password !== ""
      || url.port !== ""
    ) {
      return null;
    }
    const host = canonicalNetworkHost(input, maximumCodeUnits);
    if (host === null) {
      return null;
    }
    url.hostname = host.family === 6 ? `[${host.value}]` : host.value;
    url.hash = "";
    return url.href.length <= maximumCodeUnits ? url.href : null;
  } catch {
    return null;
  }
}

function normalizedRedirectUrl(
  location: string,
  currentUrl: string,
  maximumCodeUnits: number,
): string | null {
  if (
    location.length === 0
    || location.length > maximumCodeUnits
    || !location.isWellFormed()
    || /[\s\p{Cc}]/u.test(location)
    || location.includes("\\")
  ) {
    return null;
  }
  try {
    return normalizedHttpUrl(
      new URL(location, currentUrl).href,
      maximumCodeUnits,
    );
  } catch {
    return null;
  }
}

function uniqueErrors(errors: readonly ScanError[]): readonly ScanError[] {
  const byIdentity = new Map<string, ScanError>();
  for (const error of errors) {
    const identity = JSON.stringify([
      error.stage,
      error.code,
      error.pageId,
      error.limit,
    ]);
    byIdentity.set(identity, error);
  }
  return Object.freeze([...byIdentity.values()].sort((left, right) =>
    comparePageId(left.pageId ?? "p1", right.pageId ?? "p1")
      || compareString(left.stage, right.stage)
      || compareString(left.code, right.code)
      || compareString(left.limit ?? "", right.limit ?? "")));
}

function safeContextOptions(proxy: ProtectedBrowserProxy, config: ScanConfig) {
  return {
    acceptDownloads: false,
    bypassCSP: false,
    ignoreHTTPSErrors: false,
    permissions: [] as string[],
    proxy: {
      server: proxy.server,
      bypass: "<-loopback>",
    },
    serviceWorkers: "block" as const,
    userAgent: config.userAgent,
  };
}

function safeLaunchOptions(
  proxy: ProtectedBrowserProxy,
  chromiumHostResolverArg: string,
  config: ScanConfig,
): LaunchOptions {
  return {
    headless: true,
    chromiumSandbox: true,
    proxy: { server: proxy.server },
    args: [...SAFE_CHROMIUM_ARGS, chromiumHostResolverArg],
    timeout: config.limits.timeMs.browserPage,
  };
}

async function settleWithin<T>(promise: Promise<T>, milliseconds: number): Promise<boolean> {
  const timeout = delay(milliseconds, false, { ref: false });
  return Promise.race([
    promise.then(() => true, () => false),
    timeout,
  ]);
}

function awaitWithSignal<T>(
  promise: Promise<T>,
  signal: AbortSignal | undefined,
): Promise<T> {
  if (signal === undefined) return promise;
  signal.throwIfAborted();
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => {
      signal.removeEventListener("abort", onAbort);
      reject(signal.reason);
    };
    signal.addEventListener("abort", onAbort, { once: true });
    void promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

function inspectRenderedPage(input: EvaluationInput): EvaluationOutput {
  type ElementLike = {
    readonly textContent: string | null;
    matches(selector: string): boolean;
    getAttribute(name: string): string | null;
    hasAttribute(name: string): boolean;
  };
  type AnchorLike = { readonly href: string };
  type TreeWalkerLike = {
    nextNode(): ElementLike | null;
  };
  type DocumentLike = {
    readonly documentElement: ElementLike | null;
    createTreeWalker(root: ElementLike, whatToShow: number): TreeWalkerLike;
    readonly links: ArrayLike<AnchorLike>;
  };
  const pageGlobal = globalThis as unknown as {
    readonly document: DocumentLike;
  };
  const encoder = new TextEncoder();
  const facts: EvaluationFact[] = [];
  let totalBytes = 0;
  let valueBudgetExhausted = false;
  let truncated = false;
  const boundedMatches = (
    selector: string,
    maximum: number,
    demandedAttributes: readonly string[] | null,
  ): readonly ElementLike[] => {
    const root = pageGlobal.document.documentElement;
    if (root === null) {
      return [];
    }
    const walker = pageGlobal.document.createTreeWalker(root, 1);
    const matches: ElementLike[] = [];
    let element: ElementLike | null = root;
    while (element !== null) {
      const candidate = element;
      if (
        candidate.matches(selector)
        && (
          demandedAttributes === null
          || demandedAttributes.some((name) => candidate.hasAttribute(name))
        )
      ) {
        matches.push(candidate);
        if (matches.length > maximum) {
          break;
        }
      }
      element = walker.nextNode();
    }
    return matches;
  };

  const scalar = (value: unknown): string | null => {
    if (
      typeof value === "string"
      || typeof value === "number"
      || typeof value === "boolean"
    ) {
      return String(value);
    }
    return null;
  };
  const append = (
    scope: "dom" | "javascript",
    ordinal: number,
    value: unknown,
    present: boolean,
    needsPresence: boolean,
    needsValue: boolean,
  ): void => {
    if (!present) {
      return;
    }
    const converted = scalar(value);
    if (needsValue && converted !== null && !valueBudgetExhausted) {
      if (
        converted.length > input.valueBytes
        || !converted.isWellFormed()
      ) {
        truncated = true;
        if (needsPresence) {
          facts.push({ scope, ordinal, kind: "presence" });
        }
        return;
      }
      const bytes = encoder.encode(converted);
      if (bytes.length <= input.valueBytes) {
        if (totalBytes + bytes.length <= input.totalValueBytes) {
          totalBytes += bytes.length;
          facts.push({ scope, ordinal, kind: "value", value: converted });
          return;
        }
        valueBudgetExhausted = true;
      }
      truncated = true;
    }
    if (needsPresence) {
      facts.push({ scope, ordinal, kind: "presence" });
    }
  };

  for (const inspection of input.dom) {
    const demandedAttributes: string[] = [];
    let attributeOnly = inspection.facts.length > 0;
    for (const fact of inspection.facts) {
      if (fact.kind !== "attribute" || fact.name === null) {
        attributeOnly = false;
        break;
      }
      demandedAttributes.push(fact.name);
    }
    let elements: readonly ElementLike[];
    try {
      elements = boundedMatches(
        inspection.selector,
        input.matchesPerSelector,
        attributeOnly ? demandedAttributes : null,
      );
    } catch {
      truncated = true;
      continue;
    }
    const count = Math.min(elements.length, input.matchesPerSelector);
    if (elements.length > count) {
      truncated = true;
    }
    for (const fact of inspection.facts) {
      if (fact.kind === "exists") {
        append(
          "dom",
          fact.ordinal,
          null,
          count > 0,
          fact.presence,
          fact.value,
        );
        continue;
      }
      for (let index = 0; index < count; index += 1) {
        const element = elements[index];
        if (element === undefined) {
          continue;
        }
        try {
          if (fact.kind === "text") {
            const value = element.textContent;
            append(
              "dom",
              fact.ordinal,
              value,
              value !== null,
              fact.presence,
              fact.value,
            );
          } else if (fact.kind === "attribute" && fact.name !== null) {
            append(
              "dom",
              fact.ordinal,
              element.getAttribute(fact.name),
              element.hasAttribute(fact.name),
              fact.presence,
              fact.value,
            );
          } else if (fact.kind === "property" && fact.name !== null) {
            const target = element as unknown as object;
            const present = Object.prototype.hasOwnProperty.call(
              target,
              fact.name,
            );
            append(
              "dom",
              fact.ordinal,
              present ? Reflect.get(target, fact.name) : undefined,
              present,
              fact.presence,
              fact.value,
            );
          }
        } catch {
          // A page-owned getter is an unavailable observation, not a reason to
          // execute or stringify more of the object.
        }
      }
    }
  }

  for (const inspection of input.javascript) {
    let current: unknown = globalThis;
    let present = true;
    try {
      for (const segment of inspection.segments) {
        if (
          (typeof current !== "object" || current === null)
          && typeof current !== "function"
        ) {
          present = false;
          break;
        }
        const target = current as object;
        if (!Reflect.has(target, segment)) {
          present = false;
          break;
        }
        current = Reflect.get(target, segment);
      }
    } catch {
      present = false;
    }
    append(
      "javascript",
      inspection.ordinal,
      current,
      present,
      inspection.presence,
      inspection.value,
    );
  }

  const links: string[] = [];
  const linkCount = Math.min(pageGlobal.document.links.length, input.links + 1);
  if (pageGlobal.document.links.length > linkCount) {
    truncated = true;
  }
  for (let index = 0; index < linkCount; index += 1) {
    const href = pageGlobal.document.links[index]?.href;
    if (
      typeof href === "string"
      && href.length > 0
      && href.length <= input.urlCodeUnits
    ) {
      links.push(href);
    } else if (href !== undefined) {
      truncated = true;
    }
  }
  if (links.length > input.links) {
    links.length = input.links;
    truncated = true;
  }

  return { facts, links, truncated };
}

function inspectionEvaluationInput(
  plan: CatalogInspectionPlan,
  config: ScanConfig,
): {
  readonly input: EvaluationInput;
  readonly domByOrdinal: readonly CatalogDomFact[];
  readonly javascriptByOrdinal: readonly CatalogJavascriptInspection[];
} {
  const domByOrdinal: CatalogDomFact[] = [];
  const dom: EvaluationDomInspection[] = plan.dom.map((inspection) => ({
    selector: inspection.selector,
    facts: inspection.facts.map((fact) => {
      const ordinal = domByOrdinal.length;
      domByOrdinal.push(fact);
      return {
        ordinal,
        kind: fact.kind,
        name: fact.name,
        presence: fact.demand.presence,
        value: fact.demand.value,
      };
    }),
  }));
  const javascriptByOrdinal = [...plan.javascript];
  const javascript: EvaluationJavascriptInspection[] = plan.javascript.map(
    (inspection, ordinal) => ({
      ordinal,
      segments: inspection.segments,
      presence: inspection.demand.presence,
      value: inspection.demand.value,
    }),
  );
  return {
    input: {
      dom,
      javascript,
      valueBytes: config.limits.inspection.returnedValueBytes,
      totalValueBytes: config.limits.inspection.returnedValuesBytesPerPage,
      matchesPerSelector: config.limits.inspection.domMatchesPerSelector,
      links: config.limits.pages.extractedUrlsPerPage,
      urlCodeUnits: config.limits.url.codeUnits,
    },
    domByOrdinal,
    javascriptByOrdinal,
  };
}

function validateEvaluationOutput(
  output: EvaluationOutput,
  domByOrdinal: readonly CatalogDomFact[],
  javascriptByOrdinal: readonly CatalogJavascriptInspection[],
  pageId: PageId,
  config: ScanConfig,
): {
  readonly dom: readonly BrowserDomObservation[];
  readonly javascript: readonly BrowserJavascriptObservation[];
  readonly links: readonly string[];
  readonly truncated: boolean;
} {
  const maximumFacts = domByOrdinal.reduce(
    (total, fact) => total + (fact.kind === "exists"
      ? 1
      : config.limits.inspection.domMatchesPerSelector),
    javascriptByOrdinal.length,
  );
  if (
    output === null
    || typeof output !== "object"
    || typeof output.truncated !== "boolean"
    || !Array.isArray(output.facts)
    || output.facts.length > maximumFacts
  ) {
    throw new TypeError("Browser returned an invalid inspection result");
  }
  const dom: BrowserDomObservation[] = [];
  const javascript: BrowserJavascriptObservation[] = [];
  let totalValueBytes = 0;
  for (const raw of output.facts) {
    if (
      raw === null
      || typeof raw !== "object"
      || (raw.scope !== "dom" && raw.scope !== "javascript")
      || !Number.isSafeInteger(raw.ordinal)
      || raw.ordinal < 0
      || (raw.kind !== "presence" && raw.kind !== "value")
    ) {
      throw new TypeError("Browser returned an invalid inspection fact");
    }
    let fact: BrowserFact;
    if (raw.kind === "presence") {
      fact = Object.freeze({ kind: "presence" });
    } else {
      if (
        typeof raw.value !== "string"
        || !raw.value.isWellFormed()
      ) {
        throw new TypeError("Browser returned an invalid inspection value");
      }
      const bytes = Buffer.byteLength(raw.value, "utf8");
      if (
        bytes > config.limits.inspection.returnedValueBytes
        || totalValueBytes + bytes
          > config.limits.inspection.returnedValuesBytesPerPage
      ) {
        throw new TypeError("Browser returned an oversized inspection value");
      }
      totalValueBytes += bytes;
      fact = Object.freeze({ kind: "value", value: raw.value });
    }
    if (raw.scope === "dom") {
      const planFact = domByOrdinal[raw.ordinal];
      if (
        planFact === undefined
        || (raw.kind === "presence" && !planFact.demand.presence)
        || (raw.kind === "value" && !planFact.demand.value)
      ) {
        throw new TypeError("Browser returned an unknown DOM ordinal");
      }
      dom.push(Object.freeze({ pageId, locator: planFact.locator, fact }));
    } else {
      const planFact = javascriptByOrdinal[raw.ordinal];
      if (
        planFact === undefined
        || (raw.kind === "presence" && !planFact.demand.presence)
        || (raw.kind === "value" && !planFact.demand.value)
      ) {
        throw new TypeError("Browser returned an unknown JavaScript ordinal");
      }
      javascript.push(Object.freeze({ pageId, path: planFact.path, fact }));
    }
  }
  if (!Array.isArray(output.links) || output.links.length > config.limits.pages.extractedUrlsPerPage) {
    throw new TypeError("Browser returned too many navigation links");
  }
  for (const link of output.links) {
    if (
      typeof link !== "string"
      || !link.isWellFormed()
      || link.length > config.limits.url.codeUnits
    ) {
      throw new TypeError("Browser returned an invalid navigation link");
    }
  }
  const links = [...new Set(output.links)].sort(compareString);
  return {
    dom: Object.freeze(dom),
    javascript: Object.freeze(javascript),
    links: Object.freeze(links),
    truncated: output.truncated,
  };
}

function recordField(value: unknown, key: string): unknown {
  return typeof value === "object" && value !== null
    ? Reflect.get(value, key)
    : undefined;
}

function finiteNonnegative(value: unknown): number | null {
  return typeof value === "number"
    && Number.isFinite(value)
    && value >= 0
    ? value
    : null;
}

function redirectMethod(statusCode: number, method: string): string {
  if (statusCode === 303 && method !== "HEAD") {
    return "GET";
  }
  if ((statusCode === 301 || statusCode === 302) && method === "POST") {
    return "GET";
  }
  return method;
}

function trimAsciiWhitespace(value: string): string {
  return value.replace(
    /^[\u0009\u000a\u000c\u000d\u0020]+|[\u0009\u000a\u000c\u000d\u0020]+$/gu,
    "",
  );
}

function browserMediaTypeEssence(value: string): string | null {
  const segments: string[] = [];
  let start = 0;
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    const code = value.charCodeAt(index);
    if ((code < 0x20 && code !== 0x09) || code === 0x7f) {
      return null;
    }
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quoted && character === "\\") {
      escaped = true;
      continue;
    }
    if (character === '"') {
      quoted = !quoted;
      continue;
    }
    if (!quoted && character === ";") {
      segments.push(value.slice(start, index));
      start = index + 1;
    }
  }
  if (quoted || escaped) {
    return null;
  }
  segments.push(value.slice(start));

  const essence = trimAsciiWhitespace(segments[0] ?? "");
  const slash = essence.indexOf("/");
  if (
    slash <= 0
    || slash !== essence.lastIndexOf("/")
    || !MIME_TOKEN.test(essence.slice(0, slash))
    || !MIME_TOKEN.test(essence.slice(slash + 1))
  ) {
    return null;
  }
  for (const rawSegment of segments.slice(1)) {
    const segment = trimAsciiWhitespace(rawSegment);
    const separator = segment.indexOf("=");
    if (separator <= 0) {
      return null;
    }
    const name = trimAsciiWhitespace(segment.slice(0, separator));
    const parameter = trimAsciiWhitespace(segment.slice(separator + 1));
    if (!MIME_TOKEN.test(name) || parameter.length === 0) {
      return null;
    }
    if (parameter.startsWith('"')) {
      if (parameter.length < 2 || parameter.at(-1) !== '"') {
        return null;
      }
      for (let index = 1; index < parameter.length - 1; index += 1) {
        const character = parameter[index];
        const code = parameter.charCodeAt(index);
        if (character === '"') {
          return null;
        }
        if (character === "\\") {
          index += 1;
          if (index >= parameter.length - 1) {
            return null;
          }
          const escapedCode = parameter.charCodeAt(index);
          if (
            (escapedCode < 0x20 && escapedCode !== 0x09)
            || escapedCode === 0x7f
          ) {
            return null;
          }
        } else if ((code < 0x20 && code !== 0x09) || code === 0x7f) {
          return null;
        }
      }
    } else if (!MIME_TOKEN.test(parameter)) {
      return null;
    }
  }
  return essence.toLowerCase();
}

async function admitsBrowserDocument(
  response: Response | null,
  finalUrl: string,
  urlCodeUnits: number,
): Promise<"admitted" | "denied" | "rejected"> {
  if (response === null) {
    return "rejected";
  }
  const status = response.status();
  if (ACCESS_DENIAL_STATUS_CODES.has(status)) {
    return "denied";
  }
  if (
    normalizedHttpUrl(response.url(), urlCodeUnits) !== finalUrl
  ) {
    return "rejected";
  }
  const contentTypes = (await response.headersArray())
    .filter(({ name }) => name.toLowerCase() === "content-type")
    .map(({ value }) => value);
  return classifyBrowserDocument(status, contentTypes);
}

function classifyBrowserDocument(
  status: number,
  contentTypes: readonly string[],
): "admitted" | "denied" | "rejected" {
  if (ACCESS_DENIAL_STATUS_CODES.has(status)) {
    return "denied";
  }
  if (
    status < 200
    || status > 299
    || status === 204
    || status === 205
  ) {
    return "rejected";
  }
  if (contentTypes.length !== 1) {
    return "rejected";
  }
  const essence = browserMediaTypeEssence(contentTypes[0] ?? "");
  return essence !== null && HTML_MEDIA_TYPES.has(essence)
    ? "admitted"
    : "rejected";
}

class PageScriptTracker {
  readonly session: CDPSession;
  readonly #states = new Map<string, CdpScriptState>();
  readonly #requestChains = new Map<string, CdpRedirectChain>();
  readonly #pendingRedirects = new Map<string, CdpPendingRedirect>();
  readonly #fetchTasks = new Set<Promise<void>>();
  readonly #config: ScanConfig;
  readonly #redirectGate: CdpRedirectGate;
  readonly #redirectRecorder: (
    attempt: CdpRedirectAttempt,
    forward: boolean,
  ) => boolean;
  readonly #redirectFailure: (policyDenied: boolean) => void;
  readonly #rootFrameId: string;

  private constructor(
    session: CDPSession,
    config: ScanConfig,
    rootFrameId: string,
    redirectGate: CdpRedirectGate,
    redirectRecorder: (
      attempt: CdpRedirectAttempt,
      forward: boolean,
    ) => boolean,
    redirectFailure: (policyDenied: boolean) => void,
  ) {
    this.session = session;
    this.#config = config;
    this.#rootFrameId = rootFrameId;
    this.#redirectGate = redirectGate;
    this.#redirectRecorder = redirectRecorder;
    this.#redirectFailure = redirectFailure;
  }

  static async create(
    context: BrowserContext,
    page: Page,
    config: ScanConfig,
    redirectGate: CdpRedirectGate,
    redirectRecorder: (
      attempt: CdpRedirectAttempt,
      forward: boolean,
    ) => boolean,
    redirectFailure: (policyDenied: boolean) => void,
  ): Promise<PageScriptTracker> {
    const session = await context.newCDPSession(page);
    await session.send("Page.enable");
    const frameTree = await session.send("Page.getFrameTree");
    const frame = recordField(recordField(frameTree, "frameTree"), "frame");
    const rootFrameId = recordField(frame, "id");
    if (typeof rootFrameId !== "string" || rootFrameId.length === 0) {
      await session.detach();
      throw new TypeError("Chromium returned an invalid main frame id");
    }
    const tracker = new PageScriptTracker(
      session,
      config,
      rootFrameId,
      redirectGate,
      redirectRecorder,
      redirectFailure,
    );
    session.on("Network.responseReceived", (event: unknown) => {
      tracker.#onResponse(event);
    });
    session.on("Network.dataReceived", (event: unknown) => {
      tracker.#onData(event);
    });
    session.on("Network.loadingFinished", (event: unknown) => {
      tracker.#onFinished(event);
    });
    session.on("Network.loadingFailed", (event: unknown) => {
      tracker.#onFailed(event);
    });
    session.on("Fetch.requestPaused", (event: unknown) => {
      tracker.#queueFetchEvent(event);
    });
    await session.send("Network.enable", {
      maxTotalBufferSize: config.limits.scripts.totalBodyBytesPerDomain,
      maxResourceBufferSize: config.limits.scripts.bodyBytes,
      maxPostDataSize: 0,
    });
    await session.send("Fetch.enable", {
      patterns: [
        { urlPattern: "*", requestStage: "Request" },
        { urlPattern: "*", requestStage: "Response" },
      ],
      handleAuthRequests: false,
    });
    return tracker;
  }

  candidates(pageId: PageId, origin: string): readonly ScriptCandidate[] {
    const byUrl = new Map<string, ScriptCandidate>();
    for (const state of [...this.#states.values()].sort((left, right) =>
      compareString(left.url, right.url)
        || compareString(left.requestId, right.requestId))) {
      if (state.status < 200 || state.status > 299) {
        continue;
      }
      const url = normalizedHttpUrl(
        state.url,
        this.#config.limits.url.codeUnits,
      );
      if (url === null || byUrl.has(url)) {
        continue;
      }
      byUrl.set(url, Object.freeze({
        pageId,
        url,
        sameOrigin: new URL(url).origin === origin,
        requestId: state.requestId,
        session: this.session,
        complete: state.complete,
        failed: state.failed,
        decodedBytes: state.decodedBytes,
        encodedBytes: state.encodedBytes,
      }));
    }
    return Object.freeze([...byUrl.values()]);
  }

  async detach(): Promise<void> {
    await this.#flushFetchTasks();
    try {
      await this.session.send("Fetch.disable");
    } catch {
      // A closed page has already released all paused requests.
    }
    await this.#flushFetchTasks();
    this.#requestChains.clear();
    this.#pendingRedirects.clear();
    try {
      await this.session.detach();
    } catch {
      // Closing a page detaches its CDP session first.
    }
  }

  async flushRedirects(): Promise<void> {
    await this.#flushFetchTasks();
  }

  #queueFetchEvent(event: unknown): void {
    const task = this.#handleFetchEvent(event).catch(async () => {
      this.#redirectFailure(false);
      const requestId = recordField(event, "requestId");
      if (typeof requestId === "string") {
        await this.#failFetchRequest(requestId);
      }
    });
    this.#fetchTasks.add(task);
    void task.then(
      () => this.#fetchTasks.delete(task),
      () => this.#fetchTasks.delete(task),
    );
  }

  async #flushFetchTasks(): Promise<void> {
    while (this.#fetchTasks.size > 0) {
      await Promise.allSettled([...this.#fetchTasks]);
    }
  }

  async #handleFetchEvent(event: unknown): Promise<void> {
    const requestId = recordField(event, "requestId");
    const request = recordField(event, "request");
    const rawUrl = recordField(request, "url");
    const rawMethod = recordField(request, "method");
    const frameId = recordField(event, "frameId");
    const resourceType = recordField(event, "resourceType");
    if (
      typeof requestId !== "string"
      || typeof rawUrl !== "string"
      || typeof rawMethod !== "string"
      || typeof frameId !== "string"
      || typeof resourceType !== "string"
    ) {
      throw new TypeError("Chromium returned an invalid paused request");
    }
    const responseStatusCode = finiteNonnegative(
      recordField(event, "responseStatusCode"),
    );
    const responseErrorReason = recordField(event, "responseErrorReason");
    const isResponseStage = responseStatusCode !== null
      || typeof responseErrorReason === "string";
    if (isResponseStage) {
      await this.#handleFetchResponse(
        event,
        requestId,
        rawUrl,
        rawMethod.toUpperCase(),
        frameId,
        resourceType,
        responseStatusCode,
      );
      return;
    }
    await this.#handleFetchRequest(
      event,
      requestId,
      rawUrl,
      rawMethod.toUpperCase(),
      frameId,
      resourceType,
    );
  }

  async #handleFetchRequest(
    event: unknown,
    requestId: string,
    rawUrl: string,
    method: string,
    frameId: string,
    resourceType: string,
  ): Promise<void> {
    const redirectedRequestId = recordField(event, "redirectedRequestId");
    const actualUrl = normalizedHttpUrl(
      rawUrl,
      this.#config.limits.url.codeUnits,
    );
    if (redirectedRequestId === undefined) {
      if (actualUrl !== null) {
        this.#requestChains.set(requestId, Object.freeze({
          depth: 0,
          seen: new Set([actualUrl]),
        }));
      }
      // Context routing owns initial-request policy and accounting. This CDP
      // gate only constrains automatic redirect hops that Playwright routing
      // does not expose.
      await this.session.send("Fetch.continueRequest", {
        requestId,
        interceptResponse: true,
      });
      return;
    }

    const pending = typeof redirectedRequestId === "string"
      ? this.#pendingRedirects.get(redirectedRequestId)
      : undefined;
    if (typeof redirectedRequestId === "string") {
      this.#pendingRedirects.delete(redirectedRequestId);
    }
    const isTopFrame = frameId === this.#rootFrameId
      && resourceType.toLowerCase() === "document";
    const attempt: CdpRedirectAttempt = Object.freeze({
      currentUrl: rawUrl,
      targetUrl: actualUrl,
      method,
      resourceType,
      isTopFrame,
    });
    const matches = pending !== undefined
      && actualUrl === pending.targetUrl
      && method === pending.expectedMethod
      && frameId === pending.frameId
      && resourceType === pending.resourceType
      && isTopFrame === pending.isTopFrame
      && ALLOWED_METHODS.has(method)
      && !ABORTED_RESOURCE_TYPES.has(resourceType.toLowerCase());
    const admitted = this.#redirectRecorder(attempt, matches) === true;
    if (!matches || !admitted || pending === undefined) {
      this.#redirectFailure(true);
      await this.#failFetchRequest(requestId);
      return;
    }
    this.#requestChains.set(requestId, pending.chain);
    await this.session.send("Fetch.continueRequest", {
      requestId,
      interceptResponse: true,
    });
  }

  async #handleFetchResponse(
    event: unknown,
    requestId: string,
    rawUrl: string,
    method: string,
    frameId: string,
    resourceType: string,
    statusCode: number | null,
  ): Promise<void> {
    const responseHeaders = recordField(event, "responseHeaders");
    const locations: string[] = [];
    const contentTypes: string[] = [];
    if (Array.isArray(responseHeaders)) {
      for (const header of responseHeaders) {
        const name = recordField(header, "name");
        const value = recordField(header, "value");
        if (
          typeof name === "string"
          && typeof value === "string"
        ) {
          const lowerName = name.toLowerCase();
          if (lowerName === "location") {
            locations.push(value);
          } else if (lowerName === "content-type") {
            contentTypes.push(value);
          }
        }
      }
    }
    const isTopFrame = frameId === this.#rootFrameId
      && resourceType.toLowerCase() === "document";
    if (
      statusCode === null
      || !REDIRECT_STATUS_CODES.has(statusCode)
    ) {
      this.#requestChains.delete(requestId);
      if (isTopFrame && statusCode !== null) {
        const admission = classifyBrowserDocument(statusCode, contentTypes);
        if (admission !== "admitted") {
          this.#redirectFailure(admission === "denied");
          await this.#failFetchRequest(requestId);
          return;
        }
      }
      await this.session.send("Fetch.continueResponse", { requestId });
      return;
    }

    if (locations.length === 0) {
      this.#requestChains.delete(requestId);
      if (isTopFrame) {
        this.#redirectFailure(true);
        await this.#failFetchRequest(requestId);
        return;
      }
      await this.session.send("Fetch.continueResponse", { requestId });
      return;
    }

    const currentUrl = normalizedHttpUrl(
      rawUrl,
      this.#config.limits.url.codeUnits,
    );
    const targetUrl = locations.length === 1 && currentUrl !== null
      ? normalizedRedirectUrl(
          locations[0] as string,
          currentUrl,
          this.#config.limits.url.codeUnits,
        )
      : null;
    const chain = this.#requestChains.get(requestId);
    const attempt: CdpRedirectAttempt = Object.freeze({
      currentUrl: rawUrl,
      targetUrl,
      method,
      resourceType,
      isTopFrame,
    });
    const safe = targetUrl !== null
      && chain !== undefined
      && chain.depth < this.#config.limits.target.redirectsPerChain
      && !chain.seen.has(targetUrl)
      && this.#redirectGate(attempt) === true;
    this.#requestChains.delete(requestId);
    if (!safe || targetUrl === null || chain === undefined) {
      this.#pendingRedirects.delete(requestId);
      this.#redirectFailure(true);
      await this.#failFetchRequest(requestId);
      return;
    }
    this.#pendingRedirects.set(requestId, Object.freeze({
      targetUrl,
      expectedMethod: redirectMethod(statusCode, method),
      frameId,
      resourceType,
      isTopFrame,
      chain: Object.freeze({
        depth: chain.depth + 1,
        seen: new Set([...chain.seen, targetUrl]),
      }),
    }));
    await this.session.send("Fetch.continueResponse", { requestId });
  }

  async #failFetchRequest(requestId: string): Promise<void> {
    try {
      await this.session.send("Fetch.failRequest", {
        requestId,
        errorReason: "BlockedByClient",
      });
    } catch {
      // Closing the page releases paused requests before this cleanup runs.
    }
  }

  #onResponse(event: unknown): void {
    const type = recordField(event, "type");
    const requestId = recordField(event, "requestId");
    const response = recordField(event, "response");
    const url = recordField(response, "url");
    const status = finiteNonnegative(recordField(response, "status"));
    if (
      type !== "Script"
      || typeof requestId !== "string"
      || typeof url !== "string"
      || status === null
    ) {
      return;
    }
    this.#states.set(requestId, {
      requestId,
      url,
      status,
      decodedBytes: 0,
      encodedBytes: 0,
      complete: false,
      failed: false,
    });
  }

  #onData(event: unknown): void {
    const requestId = recordField(event, "requestId");
    const state = typeof requestId === "string"
      ? this.#states.get(requestId)
      : undefined;
    if (state === undefined) {
      return;
    }
    const dataLength = finiteNonnegative(recordField(event, "dataLength"));
    const encodedDataLength = finiteNonnegative(
      recordField(event, "encodedDataLength"),
    );
    if (dataLength !== null) {
      state.decodedBytes = Math.min(
        Number.MAX_SAFE_INTEGER,
        state.decodedBytes + dataLength,
      );
    }
    if (encodedDataLength !== null) {
      state.encodedBytes = Math.min(
        Number.MAX_SAFE_INTEGER,
        state.encodedBytes + encodedDataLength,
      );
    }
  }

  #onFinished(event: unknown): void {
    const requestId = recordField(event, "requestId");
    const state = typeof requestId === "string"
      ? this.#states.get(requestId)
      : undefined;
    if (state === undefined) {
      return;
    }
    const encoded = finiteNonnegative(recordField(event, "encodedDataLength"));
    if (encoded !== null) {
      state.encodedBytes = Math.max(state.encodedBytes, encoded);
    }
    state.complete = true;
  }

  #onFailed(event: unknown): void {
    const requestId = recordField(event, "requestId");
    const state = typeof requestId === "string"
      ? this.#states.get(requestId)
      : undefined;
    if (state !== undefined) {
      state.failed = true;
    }
  }
}

function compareScriptCandidate(left: ScriptCandidate, right: ScriptCandidate): number {
  return comparePageId(left.pageId, right.pageId)
    || Number(right.sameOrigin) - Number(left.sameOrigin)
    || compareString(left.url, right.url)
    || compareString(left.requestId, right.requestId);
}

async function readMeasuredScript(
  candidate: ScriptCandidate,
  config: ScanConfig,
): Promise<{ readonly content: string; readonly bytes: number } | null> {
  if (
    !candidate.complete
    || candidate.failed
    || !Number.isSafeInteger(candidate.decodedBytes)
    || candidate.decodedBytes > config.limits.scripts.bodyBytes
    || !Number.isSafeInteger(candidate.encodedBytes)
    || candidate.encodedBytes > config.limits.scripts.bodyBytes
  ) {
    return null;
  }
  let response: unknown;
  try {
    response = await candidate.session.send("Network.getResponseBody", {
      requestId: candidate.requestId,
    });
  } catch {
    return null;
  }
  const body = recordField(response, "body");
  const base64Encoded = recordField(response, "base64Encoded");
  if (typeof body !== "string" || typeof base64Encoded !== "boolean") {
    return null;
  }
  let bytes: Buffer;
  try {
    const maximumBodyCodeUnits = base64Encoded
      ? Math.ceil(config.limits.scripts.bodyBytes / 3) * 4
      : config.limits.scripts.bodyBytes;
    if (body.length > maximumBodyCodeUnits || !body.isWellFormed()) {
      return null;
    }
    if (base64Encoded) {
      if (
        body.length % 4 !== 0
        || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(body)
      ) {
        return null;
      }
      bytes = Buffer.from(body, "base64");
    } else {
      bytes = Buffer.from(body, "utf8");
    }
    if (
      bytes.length > config.limits.scripts.bodyBytes
      || bytes.length !== candidate.decodedBytes
    ) {
      return null;
    }
    const content = strictUtf8.decode(bytes);
    if (!content.isWellFormed()) {
      return null;
    }
    return { content, bytes: bytes.length };
  } catch {
    return null;
  }
}

class BrowserPoolImpl implements BrowserPool {
  readonly #transport: ProtectedHttpTransport;
  readonly #config: ScanConfig;
  readonly #launcher: BrowserLauncher;
  readonly #slots: BrowserSlot[] = [];
  readonly #waiters: PoolWaiter[] = [];
  #runtime: BrowserRuntimeIdentity | null = null;
  #closing = false;
  #unavailable = false;
  #closePromise: Promise<void> | null = null;

  private constructor(
    transport: ProtectedHttpTransport,
    config: ScanConfig,
    launcher: BrowserLauncher,
  ) {
    this.#transport = transport;
    this.#config = config;
    this.#launcher = launcher;
  }

  static async create(
    transport: ProtectedHttpTransport,
    config: ScanConfig,
    launcher: BrowserLauncher,
    signal?: AbortSignal,
  ): Promise<BrowserPoolImpl> {
    const pool = new BrowserPoolImpl(transport, config, launcher);
    try {
      for (let id = 0; id < config.limits.concurrency.fullScans; id += 1) {
        signal?.throwIfAborted();
        const slot = await pool.#createSlot(id, false, signal);
        if (signal?.aborted === true) {
          await pool.#destroySlot(slot);
          signal.throwIfAborted();
        }
        pool.#slots.push(slot);
      }
      const versions = new Set(pool.#slots.map((slot) => slot.browser.version()));
      const chromiumVersion = versions.size === 1 ? [...versions][0] : undefined;
      if (
        chromiumVersion === undefined
        || chromiumVersion.length === 0
        || chromiumVersion.length > 128
        || !chromiumVersion.isWellFormed()
      ) {
        throw new BrowserLifecycleFailure("BROWSER_UNAVAILABLE");
      }
      pool.#runtime = Object.freeze({
        playwright: PLAYWRIGHT_VERSION,
        chromiumRevision: CHROMIUM_REVISION,
        chromiumVersion,
      });
      return pool;
    } catch (error) {
      await pool.close();
      throw error;
    }
  }

  get runtime(): BrowserRuntimeIdentity {
    if (this.#runtime === null) {
      throw new BrowserLifecycleFailure("BROWSER_UNAVAILABLE");
    }
    return this.#runtime;
  }

  async openDomain(
    signal?: AbortSignal,
    onAdmitted?: () => void,
  ): Promise<BrowserDomainSession> {
    signal?.throwIfAborted();
    if (this.#closing || this.#unavailable) {
      throw new BrowserLifecycleFailure("BROWSER_UNAVAILABLE");
    }
    const slot = await this.#acquire(signal);
    let context: BrowserContext | undefined;
    let domainActivated = false;
    let initializationPhase: "context" | "session" | null = null;
    try {
      signal?.throwIfAborted();
      onAdmitted?.();
      signal?.throwIfAborted();
      slot.proxy.activateDomain(signal);
      domainActivated = true;
      const failureController = new AbortController();
      const proxySignal = slot.proxy.getFailureSignal();
      const combinedSignal = signal === undefined
        ? AbortSignal.any([failureController.signal, proxySignal])
        : AbortSignal.any([signal, failureController.signal, proxySignal]);
      initializationPhase = "context";
      context = await awaitWithSignal(
        slot.browser.newContext(safeContextOptions(slot.proxy, this.#config)),
        signal,
      );
      initializationPhase = "session";
      const session = await awaitWithSignal(
        BrowserDomainSessionImpl.create(
          this,
          slot,
          context,
          this.#config,
          combinedSignal,
          failureController,
        ),
        signal,
      );
      initializationPhase = null;
      slot.active = session;
      return session;
    } catch (error) {
      slot.failed = (signal?.aborted === true && initializationPhase !== null)
        || !slot.browser.isConnected()
        || slot.proxy.getFailure() !== null;
      if (context !== undefined) {
        const closed = await settleWithin(
          context.close({ reason: "Browser domain initialization failed" }),
          CLEANUP_WATCHDOG_MS,
        );
        if (!closed) {
          slot.failed = true;
        }
      }
      if (domainActivated) {
        try {
          await slot.proxy.finishDomain();
        } catch {
          slot.failed = true;
        }
      }
      await this.release(slot, slot.failed);
      throw error;
    }
  }

  isAvailable(): boolean {
    return !this.#closing
      && !this.#unavailable
      && this.#slots.some((slot) => !slot.failed || slot.replacing !== null);
  }

  close(): Promise<void> {
    if (this.#closePromise !== null) {
      return this.#closePromise;
    }
    this.#closePromise = this.#closeInternal();
    return this.#closePromise;
  }

  async #closeInternal(): Promise<void> {
    this.#closing = true;
    this.#unavailable = true;
    for (const waiter of this.#waiters.splice(0)) {
      if (waiter.onAbort !== undefined) {
        waiter.signal?.removeEventListener("abort", waiter.onAbort);
      }
      waiter.reject(new BrowserLifecycleFailure("BROWSER_UNAVAILABLE"));
    }
    const active = this.#slots
      .map((slot) => slot.active)
      .filter((session): session is BrowserDomainSessionImpl => session !== null);
    await Promise.allSettled(active.map((session) => session.close()));
    await Promise.allSettled(this.#slots
      .map((slot) => slot.replacing)
      .filter((replacement): replacement is Promise<boolean> =>
        replacement !== null));
    await Promise.allSettled(this.#slots.map((slot) => this.#destroySlot(slot)));
    this.#slots.length = 0;
  }

  async release(slot: BrowserSlot, unhealthy: boolean): Promise<void> {
    slot.active = null;
    if (this.#closing) {
      slot.busy = false;
      return;
    }
    if (unhealthy || slot.failed || !slot.browser.isConnected()) {
      slot.failed = true;
      slot.busy = false;
      await this.#replaceOrRemove(slot);
      return;
    }
    slot.busy = false;
    this.#dispatch();
  }

  markBrowserFailed(slot: BrowserSlot): void {
    if (this.#closing || slot.failed) {
      return;
    }
    slot.failed = true;
    slot.active?.abortLifecycle("BROWSER_UNAVAILABLE");
    if (!slot.busy) {
      void this.#replaceOrRemove(slot);
    }
  }

  #acquire(signal: AbortSignal | undefined): Promise<BrowserSlot> {
    const available = this.#slots.find((slot) =>
      !slot.busy && !slot.failed && slot.replacing === null);
    if (available !== undefined) {
      available.busy = true;
      return Promise.resolve(available);
    }
    return new Promise<BrowserSlot>((resolve, reject) => {
      let waiter: PoolWaiter;
      const onAbort = signal === undefined
        ? undefined
        : (): void => {
            const index = this.#waiters.indexOf(waiter);
            if (index >= 0) {
              this.#waiters.splice(index, 1);
            }
            reject(signal.reason);
          };
      waiter = { resolve, reject, signal, onAbort };
      signal?.addEventListener("abort", onAbort as () => void, { once: true });
      this.#waiters.push(waiter);
    });
  }

  #dispatch(): void {
    while (this.#waiters.length > 0) {
      const slot = this.#slots.find((candidate) =>
        !candidate.busy && !candidate.failed && candidate.replacing === null);
      if (slot === undefined) {
        if (this.#slots.length === 0) {
          this.#latchUnavailable();
        }
        return;
      }
      const waiter = this.#waiters.shift();
      if (waiter === undefined) {
        return;
      }
      if (waiter.onAbort !== undefined) {
        waiter.signal?.removeEventListener("abort", waiter.onAbort);
      }
      if (waiter.signal?.aborted) {
        waiter.reject(waiter.signal.reason);
        continue;
      }
      slot.busy = true;
      waiter.resolve(slot);
    }
  }

  #latchUnavailable(): void {
    this.#unavailable = true;
    for (const waiter of this.#waiters.splice(0)) {
      if (waiter.onAbort !== undefined) {
        waiter.signal?.removeEventListener("abort", waiter.onAbort);
      }
      waiter.reject(new BrowserLifecycleFailure("BROWSER_UNAVAILABLE"));
    }
  }

  async #replaceOrRemove(slot: BrowserSlot): Promise<boolean> {
    if (slot.replacing !== null) {
      return slot.replacing;
    }
    if (slot.replacementUsed || this.#closing) {
      await this.#removeSlot(slot);
      return false;
    }
    slot.replacementUsed = true;
    slot.replacing = (async (): Promise<boolean> => {
      await this.#destroySlot(slot);
      if (this.#closing) {
        return false;
      }
      try {
        const replacement = await this.#createSlot(slot.id, true);
        if (
          this.#runtime !== null
          && replacement.browser.version() !== this.#runtime.chromiumVersion
        ) {
          await this.#destroySlot(replacement);
          throw new BrowserLifecycleFailure("BROWSER_UNAVAILABLE");
        }
        const index = this.#slots.indexOf(slot);
        if (this.#closing || index < 0) {
          await this.#destroySlot(replacement);
          return false;
        }
        this.#slots[index] = replacement;
        this.#dispatch();
        return true;
      } catch {
        await this.#removeSlot(slot);
        return false;
      }
    })();
    const replaced = await slot.replacing;
    slot.replacing = null;
    return replaced;
  }

  async #removeSlot(slot: BrowserSlot): Promise<void> {
    await this.#destroySlot(slot);
    const index = this.#slots.indexOf(slot);
    if (index >= 0) {
      this.#slots.splice(index, 1);
    }
    if (this.#slots.length === 0) {
      this.#latchUnavailable();
    } else {
      this.#dispatch();
    }
  }

  async #createSlot(
    id: number,
    replacementUsed: boolean,
    callerSignal?: AbortSignal,
  ): Promise<BrowserSlot> {
    const preflightTimeout = AbortSignal.timeout(
      this.#config.limits.timeMs.browserPage,
    );
    const preflightSignal = callerSignal === undefined
      ? preflightTimeout
      : AbortSignal.any([callerSignal, preflightTimeout]);
    const proxyPromise = this.#transport.createBrowserProxy();
    let proxy: ProtectedBrowserProxy | undefined;
    let canary: ProtectedBrowserProxyCanary | undefined;
    let browserPromise: Promise<Browser> | undefined;
    let browser: Browser | undefined;
    let context: BrowserContext | undefined;
    let page: Page | undefined;
    try {
      proxy = await awaitWithSignal(proxyPromise, preflightSignal);
      canary = await awaitWithSignal(
        proxy.prepareCanary(),
        preflightSignal,
      );
      browserPromise = this.#launcher(
        safeLaunchOptions(proxy, canary.chromiumHostResolverArg, this.#config),
      );
      browser = await awaitWithSignal(
        browserPromise,
        preflightSignal,
      );
      context = await awaitWithSignal(
        browser.newContext(safeContextOptions(proxy, this.#config)),
        preflightSignal,
      );
      page = await awaitWithSignal(context.newPage(), preflightSignal);
      try {
        await awaitWithSignal(
          page.goto(canary.targetUrl, {
            waitUntil: "domcontentloaded",
            timeout: this.#config.limits.timeMs.browserPage,
          }),
          preflightSignal,
        );
      } catch {
        // A protected canary navigation is expected to fail at the proxy.
      }
      preflightSignal.throwIfAborted();
      canary.verify();
      await awaitWithSignal(page.close(), preflightSignal);
      page = undefined;
      await awaitWithSignal(context.close(), preflightSignal);
      context = undefined;
      await awaitWithSignal(canary.close(), preflightSignal);
      const slot: BrowserSlot = {
        id,
        proxy,
        browser,
        busy: false,
        failed: false,
        replacementUsed,
        replacing: null,
        active: null,
        disconnectHandler: null,
      };
      const disconnectHandler = (): void => this.markBrowserFailed(slot);
      slot.disconnectHandler = disconnectHandler;
      browser.on("disconnected", disconnectHandler);
      return slot;
    } catch (error) {
      if (proxy === undefined) {
        void proxyPromise.then(async (lateProxy) => {
          await settleWithin(
            lateProxy.close(),
            CLEANUP_WATCHDOG_MS,
          );
        }, () => undefined);
      }
      if (browser === undefined && browserPromise !== undefined) {
        void browserPromise.then(async (lateBrowser) => {
          await settleWithin(
            lateBrowser.close({
              reason: "Browser slot preflight expired during launch",
            }),
            CLEANUP_WATCHDOG_MS,
          );
        }, () => undefined);
      }
      await settleWithin(
        Promise.allSettled([
          page?.close() ?? Promise.resolve(),
          context?.close() ?? Promise.resolve(),
          canary?.close() ?? Promise.resolve(),
          browser?.close() ?? Promise.resolve(),
          proxy?.close() ?? Promise.resolve(),
        ]).then(() => undefined),
        CLEANUP_WATCHDOG_MS,
      );
      callerSignal?.throwIfAborted();
      throw new BrowserLifecycleFailure("BROWSER_UNAVAILABLE", { cause: error });
    }
  }

  async #destroySlot(slot: BrowserSlot): Promise<void> {
    if (slot.disconnectHandler !== null) {
      slot.browser.off("disconnected", slot.disconnectHandler);
      slot.disconnectHandler = null;
    }
    await settleWithin(
      Promise.allSettled([
        slot.browser.close({ reason: "Protected browser slot closed" }),
        slot.proxy.close(),
      ]).then(() => undefined),
      CLEANUP_WATCHDOG_MS,
    );
  }
}

class BrowserDomainSessionImpl implements BrowserDomainSession {
  readonly #pool: BrowserPoolImpl;
  readonly #slot: BrowserSlot;
  readonly #context: BrowserContext;
  readonly #config: ScanConfig;
  readonly #domainSignal: AbortSignal;
  readonly #failureController: AbortController;
  readonly #drafts: BrowserPageDraft[] = [];
  readonly #errors: ScanError[] = [];
  readonly #seenPageIds = new Set<PageId>();
  readonly #cookieIdentities = new Set<string>();
  readonly #networkHostnames = new Set<string>();
  readonly #networkUrls = new Set<string>();
  readonly #scriptCandidates = new Map<string, ScriptCandidate>();
  readonly #scriptBodyAttempts = new Set<string>();
  #selectedScripts = new Map<string, SelectedScript>();
  #scriptBodyBytesRead = 0;
  #cookieBytes = 0;
  #domainOrigin: string | null = null;
  #activeState: ActivePageState | null = null;
  #activePage: Page | null = null;
  #expectingPage = false;
  #lastPageRank = -1;
  #hadCollectionFailure = false;
  #contextUsable = true;
  #unhealthy = false;
  #finished = false;
  #released = false;
  #finishPromise: Promise<BrowserDomainResult> | null = null;
  #closePromise: Promise<void> | null = null;
  #activeCollectionPromise: Promise<BrowserPageCollection> | null = null;
  #contextClosePromise: Promise<boolean> | null = null;
  #usageSnapshot: (ProtectedBrowserProxyUsage & {
    readonly scriptBodiesInspected: number;
  }) | null = null;
  #domainAbortListener: (() => void) | null = null;

  private constructor(
    pool: BrowserPoolImpl,
    slot: BrowserSlot,
    context: BrowserContext,
    config: ScanConfig,
    domainSignal: AbortSignal,
    failureController: AbortController,
  ) {
    this.#pool = pool;
    this.#slot = slot;
    this.#context = context;
    this.#config = config;
    this.#domainSignal = domainSignal;
    this.#failureController = failureController;
  }

  static async create(
    pool: BrowserPoolImpl,
    slot: BrowserSlot,
    context: BrowserContext,
    config: ScanConfig,
    domainSignal: AbortSignal,
    failureController: AbortController,
  ): Promise<BrowserDomainSessionImpl> {
    const session = new BrowserDomainSessionImpl(
      pool,
      slot,
      context,
      config,
      domainSignal,
      failureController,
    );
    await session.#initialize();
    return session;
  }

  collectPage(input: BrowserPageInput): Promise<BrowserPageCollection> {
    if (
      this.#finished
      || this.#closePromise !== null
      || this.#activeCollectionPromise !== null
    ) {
      return Promise.reject(new TypeError(
        "The browser domain session is already finalized or collecting",
      ));
    }
    const collection = this.#collectPageInternal(input);
    this.#activeCollectionPromise = collection;
    void collection.then(
      () => {
        if (this.#activeCollectionPromise === collection) {
          this.#activeCollectionPromise = null;
        }
      },
      () => {
        if (this.#activeCollectionPromise === collection) {
          this.#activeCollectionPromise = null;
        }
      },
    );
    return awaitWithSignal(collection, this.#domainSignal);
  }

  async #collectPageInternal(
    input: BrowserPageInput,
  ): Promise<BrowserPageCollection> {
    const normalizedInputUrl = normalizedHttpUrl(
      input.url,
      this.#config.limits.url.codeUnits,
    );
    if (normalizedInputUrl === null) {
      throw new TypeError("Browser page URL is invalid");
    }
    const origin = pageOrigin(
      normalizedInputUrl,
      this.#config.limits.url.codeUnits,
    );
    if (this.#domainOrigin !== null && origin !== this.#domainOrigin) {
      throw new TypeError("Every browser page must use the domain origin");
    }
    const pageRank = PAGE_ID_RANK.get(input.pageId);
    if (
      pageRank === undefined
      || pageRank !== this.#lastPageRank + 1
      || this.#seenPageIds.has(input.pageId)
      || this.#seenPageIds.size >= this.#config.limits.pages.topLevelPerDomain
      || this.#activeState !== null
    ) {
      throw new TypeError("Browser pages must be unique and ordered p1 through p3");
    }
    this.#seenPageIds.add(input.pageId);
    this.#lastPageRank = pageRank;
    this.#domainOrigin ??= origin;

    if (!this.#contextUsable || this.#domainSignal.aborted) {
      const error = this.#errorForFailure(
        this.#domainSignal.reason,
        input.pageId,
      );
      this.#errors.push(error);
      this.#hadCollectionFailure = true;
      return Object.freeze({
        completed: false,
        observationsAdmitted: false,
        continuationAllowed: false,
        errors: [error],
        navigationLinks: Object.freeze([]),
      });
    }

    const pageErrors: ScanError[] = [];
    const state: ActivePageState = {
      input,
      origin,
      networkHostnames: new Set<string>(),
      networkUrls: new Set<string>(),
      errors: pageErrors,
      navigationLocked: false,
      policyDenied: false,
      truncated: false,
    };
    this.#activeState = state;

    const deadline = new AbortController();
    const deadlineReason = new PageDeadlineMarker();
    const startedAt = performance.now();
    const deadlineTimer = setTimeout(() => {
      deadline.abort(deadlineReason);
    }, this.#config.limits.timeMs.browserPage);
    deadlineTimer.unref();
    const pageSignal = AbortSignal.any([
      this.#domainSignal,
      deadline.signal,
    ]);
    const onPageAbort = (): void => {
      this.#contextUsable = false;
      void this.#closeContextBounded("Browser page aborted");
    };
    pageSignal.addEventListener("abort", onPageAbort, { once: true });

    let page: Page | null = null;
    let tracker: PageScriptTracker | null = null;
    let onFrameNavigated: ((frame: Frame) => void) | null = null;
    let completed = false;
    let observationsAdmitted = false;
    let continuationAllowed = false;
    let admittedNavigationLinks: readonly string[] = Object.freeze([]);

    try {
      this.#slot.proxy.startPage(input.pageId);
      pageSignal.throwIfAborted();
      this.#expectingPage = true;
      page = await this.#context.newPage();
      if (this.#activePage === null && this.#expectingPage) {
        this.#activePage = page;
        this.#expectingPage = false;
      }
      if (this.#activePage !== page) {
        throw new BrowserLifecycleFailure("BROWSER_UNAVAILABLE");
      }

      tracker = await PageScriptTracker.create(
        this.#context,
        page,
        this.#config,
        (attempt) => this.#approveCdpRedirect(state, attempt),
        (attempt, forward) => this.#recordCdpRedirect(
          state,
          attempt,
          forward,
        ),
        (policyDenied) => {
          state.policyDenied ||= policyDenied;
          state.errors.push(browserError(
            "BROWSER_NAVIGATION_FAILED",
            state.input.pageId,
            policyDenied ? false : undefined,
          ));
        },
      );
      pageSignal.throwIfAborted();
      const navigationResponse = await page.goto(normalizedInputUrl, {
        waitUntil: "domcontentloaded",
        signal: pageSignal,
        timeout: this.#remainingPageMs(startedAt),
      });

      const finalUrl = normalizedHttpUrl(
        page.url(),
        this.#config.limits.url.codeUnits,
      );
      if (finalUrl === null || new URL(finalUrl).origin !== origin) {
        throw new TypeError("Browser left the selected origin");
      }
      const documentAdmission = await admitsBrowserDocument(
        navigationResponse,
        finalUrl,
        this.#config.limits.url.codeUnits,
      );
      if (documentAdmission === "denied") {
        throw new BrowserAccessDeniedMarker();
      }
      if (documentAdmission !== "admitted") {
        throw new TypeError("Browser target is not a supported HTML response");
      }
      state.navigationLocked = true;
      const admittedPage = page;
      const documentRemainsAdmitted = (): boolean =>
        !state.policyDenied
        && normalizedHttpUrl(
          admittedPage.url(),
          this.#config.limits.url.codeUnits,
        ) === finalUrl;
      onFrameNavigated = (frame): void => {
        if (frame !== admittedPage.mainFrame() || documentRemainsAdmitted()) {
          return;
        }
        state.policyDenied = true;
        state.errors.push(browserError(
          "BROWSER_NAVIGATION_FAILED",
          state.input.pageId,
          false,
        ));
        void admittedPage.close({
          reason: "Top-level navigation changed the admitted browser document",
        }).catch(() => undefined);
      };
      admittedPage.on("framenavigated", onFrameNavigated);

      const settleMs = Math.min(
        this.#config.limits.timeMs.browserSettle,
        this.#remainingPageMs(startedAt),
      );
      if (settleMs > 0) {
        await delay(settleMs, undefined, { signal: pageSignal, ref: false });
      }
      await tracker.flushRedirects();
      pageSignal.throwIfAborted();
      if (!documentRemainsAdmitted()) {
        state.policyDenied = true;
        throw new BrowserAccessDeniedMarker();
      }

      const evaluation = inspectionEvaluationInput(
        input.inspectionPlan,
        this.#config,
      );
      const raw = await page.evaluate(inspectRenderedPage, evaluation.input);
      pageSignal.throwIfAborted();
      if (!documentRemainsAdmitted()) {
        state.policyDenied = true;
        throw new BrowserAccessDeniedMarker();
      }
      const inspected = validateEvaluationOutput(
        raw,
        evaluation.domByOrdinal,
        evaluation.javascriptByOrdinal,
        input.pageId,
        this.#config,
      );
      if (inspected.truncated) {
        state.truncated = true;
        pageErrors.push(browserError(
          "BROWSER_LIMIT_EXCEEDED",
          input.pageId,
        ));
      }

      const navigationLinks = this.#normalizeLinks(
        inspected.links,
      );
      const cookies = await this.#collectCookies(input.pageId, finalUrl, state);
      await tracker.flushRedirects();
      pageSignal.throwIfAborted();
      if (!documentRemainsAdmitted()) {
        state.policyDenied = true;
        throw new BrowserAccessDeniedMarker();
      }
      const network = this.#admitNetworkFacts(state);
      const scriptCandidates = tracker.candidates(input.pageId, origin);
      await this.#mergeScriptCandidates(scriptCandidates, state);
      pageSignal.throwIfAborted();
      if (!documentRemainsAdmitted()) {
        state.policyDenied = true;
        throw new BrowserAccessDeniedMarker();
      }

      this.#drafts.push(Object.freeze({
        pageId: input.pageId,
        finalUrl,
        dom: inspected.dom,
        javascript: inspected.javascript,
        cookies,
        networkHostnames: network.hostnames,
        networkUrls: network.urls,
        scriptCandidates,
        navigationLinks,
        truncated: state.truncated,
      }));
      admittedNavigationLinks = navigationLinks;
      observationsAdmitted = true;
      completed = pageErrors.length === 0;
      if (!completed) {
        this.#hadCollectionFailure = true;
      }
    } catch (error) {
      const failure = this.#errorForFailure(
        deadline.signal.aborted ? deadlineReason : error,
        input.pageId,
        state.policyDenied,
      );
      pageErrors.push(failure);
      this.#hadCollectionFailure = true;
      if (
        deadline.signal.aborted
        || this.#domainSignal.aborted
        || error instanceof BrowserLifecycleFailure
        || !this.#slot.browser.isConnected()
      ) {
        this.#contextUsable = false;
      }
    } finally {
      clearTimeout(deadlineTimer);
      pageSignal.removeEventListener("abort", onPageAbort);
      this.#expectingPage = false;
      if (tracker !== null) {
        await tracker.detach();
      }
      if (page !== null) {
        if (onFrameNavigated !== null) {
          page.off("framenavigated", onFrameNavigated);
        }
        const pageClosed = await this.#closePageBounded(page);
        if (!pageClosed) {
          pageErrors.push(browserError("BROWSER_UNAVAILABLE", input.pageId));
        }
      }
      this.#activePage = null;
      try {
        await this.#slot.proxy.finishPage(input.pageId);
      } catch (error) {
        const proxyFailure = this.#slot.proxy.getFailure();
        if (proxyFailure !== null) {
          pageErrors.push(proxyError(proxyFailure, input.pageId));
          this.#hadCollectionFailure = true;
          this.#contextUsable = false;
        } else if (!this.#domainSignal.aborted) {
          pageErrors.push(this.#errorForFailure(error, input.pageId));
          this.#hadCollectionFailure = true;
          this.#contextUsable = false;
        }
      }
      this.#activeState = null;
    }

    const errors = uniqueErrors(pageErrors);
    const onlyRecoverableTruncation = state.truncated
      && errors.every((error) =>
        error.stage === "browser"
        && error.code === "BROWSER_LIMIT_EXCEEDED");
    continuationAllowed = observationsAdmitted
      && this.#contextUsable
      && !this.#domainSignal.aborted
      && this.#slot.browser.isConnected()
      && this.#slot.proxy.getFailure() === null
      && !this.#unhealthy
      && (errors.length === 0 || onlyRecoverableTruncation);
    completed = completed && errors.length === 0 && continuationAllowed;
    if (!completed) {
      this.#hadCollectionFailure = true;
    }
    this.#errors.push(...errors);
    return Object.freeze({
      completed,
      observationsAdmitted,
      continuationAllowed,
      errors,
      navigationLinks: admittedNavigationLinks,
    });
  }

  finish(): Promise<BrowserDomainResult> {
    if (this.#finishPromise !== null) {
      return this.#finishPromise;
    }
    if (
      this.#closePromise !== null
      || this.#activeState !== null
      || this.#activeCollectionPromise !== null
    ) {
      return Promise.reject(new TypeError(
        "The browser domain session cannot finish in its current state",
      ));
    }
    this.#finished = true;
    this.#finishPromise = this.#finishInternal();
    return this.#finishPromise;
  }

  getUsage(): ProtectedBrowserProxyUsage & {
    readonly scriptBodiesInspected: number;
  } {
    if (this.#usageSnapshot !== null) {
      return this.#usageSnapshot;
    }
    const proxyUsage = this.#slot.proxy.getUsage();
    return Object.freeze({
      ...proxyUsage,
      scriptBodiesInspected: [...this.#selectedScripts.values()].filter(
        (script) => script.content !== null,
      ).length,
    });
  }

  close(): Promise<void> {
    if (this.#closePromise !== null) {
      return this.#closePromise;
    }
    if (this.#finishPromise !== null) {
      this.#closePromise = this.#finishPromise.then(
        () => undefined,
        async () => this.#closeInternal(),
      );
      return this.#closePromise;
    }
    this.#finished = true;
    this.#closePromise = this.#closeInternal();
    return this.#closePromise;
  }

  abortLifecycle(code: "BROWSER_UNAVAILABLE" | "BROWSER_PROXY_FAILED"): void {
    this.#unhealthy = code === "BROWSER_UNAVAILABLE";
    this.#contextUsable = false;
    if (!this.#failureController.signal.aborted) {
      this.#failureController.abort(new BrowserLifecycleFailure(code));
    }
    void this.#closeContextBounded("Browser lifecycle failed");
  }

  async #initialize(): Promise<void> {
    await this.#context.route("**/*", async (route) => {
      await this.#handleRoute(route);
    });
    await this.#context.routeWebSocket("**/*", async (route) => {
      await this.#handleWebSocket(route);
    });
    this.#context.on("page", (page) => {
      if (this.#expectingPage && this.#activePage === null) {
        this.#activePage = page;
        this.#expectingPage = false;
        return;
      }
      void page.close({ reason: "Popups are disabled" }).catch(() => undefined);
    });
    this.#domainAbortListener = (): void => {
      this.#contextUsable = false;
      void this.#closeContextBounded("Browser domain aborted");
    };
    this.#domainSignal.addEventListener("abort", this.#domainAbortListener, {
      once: true,
    });
    if (this.#domainSignal.aborted) {
      this.#domainAbortListener();
    }
  }

  async #handleRoute(route: Route): Promise<void> {
    const state = this.#activeState;
    const request = route.request();
    if (state === null) {
      await route.abort("blockedbyclient").catch(() => undefined);
      return;
    }

    const rawUrl = request.url();
    const method = request.method().toUpperCase();
    const hostname = networkHostname(
      rawUrl,
      this.#config.limits.url.codeUnits,
    );
    if (hostname !== null) {
      state.networkHostnames.add(hostname);
    }
    const url = normalizedHttpUrl(
      rawUrl,
      this.#config.limits.url.codeUnits,
    );
    const allowedMethod = ALLOWED_METHODS.has(method);
    let forward = url !== null
      && allowedMethod
      && !ABORTED_RESOURCE_TYPES.has(request.resourceType());
    let publishUrl = url !== null && allowedMethod;

    if (this.#isTopFrameNavigation(request)) {
      let ownsPage = false;
      try {
        ownsPage = request.frame().page() === this.#activePage;
      } catch {
        ownsPage = false;
      }
      const sameOrigin = url !== null && new URL(url).origin === state.origin;
      publishUrl = publishUrl && ownsPage && sameOrigin;
      forward = forward && ownsPage && sameOrigin;
      if (ownsPage && state.navigationLocked) {
        forward = false;
      }
      if (forward && url !== null) {
        try {
          forward = state.input.allowTopLevelUrl(url) === true;
        } catch {
          forward = false;
        }
      }
      if (ownsPage && !forward) {
        state.policyDenied = true;
        if (state.navigationLocked) {
          state.errors.push(browserError(
            "BROWSER_NAVIGATION_FAILED",
            state.input.pageId,
            false,
          ));
        }
      }
    }
    if (publishUrl && url !== null) {
      state.networkUrls.add(url);
    }

    try {
      if (this.#activeState !== state || this.#domainSignal.aborted) {
        forward = false;
      }
      this.#slot.proxy.recordRequestAttempt({
        pageId: state.input.pageId,
        url: rawUrl,
        forward,
      });
    } catch (error) {
      const failure = this.#slot.proxy.getFailure();
      if (failure !== null) {
        state.errors.push(proxyError(failure, state.input.pageId));
      } else if (isProtectedTransportError(error)) {
        state.errors.push(proxyError(error, state.input.pageId));
      }
      forward = false;
    }

    try {
      if (forward) {
        await route.continue();
      } else {
        await route.abort("blockedbyclient");
      }
    } catch {
      await route.abort("blockedbyclient").catch(() => undefined);
    }
  }

  #approveCdpRedirect(
    state: ActivePageState,
    attempt: CdpRedirectAttempt,
  ): boolean {
    const targetUrl = attempt.targetUrl;
    if (this.#activeState !== state || this.#domainSignal.aborted) {
      return false;
    }
    if (
      targetUrl === null
      || !ALLOWED_METHODS.has(attempt.method)
      || ABORTED_RESOURCE_TYPES.has(attempt.resourceType.toLowerCase())
    ) {
      state.policyDenied = true;
      return false;
    }
    if (!attempt.isTopFrame) {
      return true;
    }
    if (new URL(targetUrl).origin !== state.origin) {
      state.policyDenied = true;
      return false;
    }
    try {
      const admitted = state.input.allowTopLevelUrl(targetUrl) === true;
      if (!admitted) {
        state.policyDenied = true;
      }
      return admitted;
    } catch {
      state.policyDenied = true;
      return false;
    }
  }

  #recordCdpRedirect(
    state: ActivePageState,
    attempt: CdpRedirectAttempt,
    forward: boolean,
  ): boolean {
    const targetUrl = attempt.targetUrl;
    const observedUrl = targetUrl ?? attempt.currentUrl;
    const hostname = networkHostname(
      observedUrl,
      this.#config.limits.url.codeUnits,
    );
    if (hostname !== null) {
      state.networkHostnames.add(hostname);
    }
    if (forward && targetUrl !== null) {
      state.networkUrls.add(targetUrl);
    }
    let admitted = forward
      && targetUrl !== null
      && this.#activeState === state
      && !this.#domainSignal.aborted;
    try {
      this.#slot.proxy.recordRequestAttempt({
        pageId: state.input.pageId,
        url: observedUrl,
        forward: admitted,
      });
    } catch (error) {
      const failure = this.#slot.proxy.getFailure();
      if (failure !== null) {
        state.errors.push(proxyError(failure, state.input.pageId));
      } else if (isProtectedTransportError(error)) {
        state.errors.push(proxyError(error, state.input.pageId));
      }
      admitted = false;
    }
    return admitted;
  }

  async #handleWebSocket(route: WebSocketRoute): Promise<void> {
    const state = this.#activeState;
    if (state !== null) {
      const url = route.url();
      const hostname = networkHostname(
        url,
        this.#config.limits.url.codeUnits,
      );
      if (hostname !== null) {
        state.networkHostnames.add(hostname);
      }
      try {
        this.#slot.proxy.recordRequestAttempt({
          pageId: state.input.pageId,
          url,
          forward: false,
        });
      } catch (error) {
        const failure = this.#slot.proxy.getFailure();
        if (failure !== null) {
          state.errors.push(proxyError(failure, state.input.pageId));
        } else if (isProtectedTransportError(error)) {
          state.errors.push(proxyError(error, state.input.pageId));
        }
      }
    }
    await route.close({ code: 1008, reason: "WebSockets are disabled" })
      .catch(() => undefined);
  }

  #isTopFrameNavigation(request: Request): boolean {
    if (!request.isNavigationRequest()) {
      return false;
    }
    try {
      return request.frame().parentFrame() === null;
    } catch {
      return false;
    }
  }

  #remainingPageMs(startedAt: number): number {
    const remaining = this.#config.limits.timeMs.browserPage
      - (performance.now() - startedAt);
    if (remaining <= 0) {
      throw new PageDeadlineMarker();
    }
    return Math.max(1, Math.floor(remaining));
  }

  #normalizeLinks(
    links: readonly string[],
  ): readonly string[] {
    const normalized = new Set<string>();
    for (const link of links) {
      const url = normalizedHttpUrl(link, this.#config.limits.url.codeUnits);
      if (url !== null) {
        normalized.add(url);
      }
    }
    return Object.freeze([...normalized].sort(compareString));
  }

  async #collectCookies(
    pageId: PageId,
    finalUrl: string,
    state: ActivePageState,
  ): Promise<readonly HttpCookieObservation[]> {
    const collected: HttpCookieObservation[] = [];
    const cookies = await this.#context.cookies([finalUrl]);
    cookies.sort((left, right) =>
      compareString(left.name.toLowerCase(), right.name.toLowerCase())
        || compareString(left.name, right.name)
        || compareString(left.value, right.value)
        || compareString(left.domain, right.domain)
        || compareString(left.path, right.path));
    for (const cookie of cookies) {
      const identity = JSON.stringify([
        cookie.domain,
        cookie.path,
        cookie.name,
      ]);
      if (this.#cookieIdentities.has(identity)) {
        continue;
      }
      const valueBytes = Buffer.byteLength(cookie.value, "utf8");
      const cookieBytes = Buffer.byteLength(cookie.name, "utf8") + valueBytes;
      let limit: string | null = null;
      if (
        cookie.name.length === 0
        || cookie.name.length > this.#config.limits.cookies.nameCodeUnits
        || !cookie.name.isWellFormed()
      ) {
        limit = "cookies.nameCodeUnits";
      } else if (
        !cookie.value.isWellFormed()
        || valueBytes > this.#config.limits.cookies.valueBytes
      ) {
        limit = "cookies.valueBytes";
      } else if (
        this.#cookieIdentities.size >= this.#config.limits.cookies.perDomain
      ) {
        limit = "cookies.perDomain";
      } else if (
        this.#cookieBytes + cookieBytes
          > this.#config.limits.cookies.totalBytesPerDomain
      ) {
        limit = "cookies.totalBytesPerDomain";
      }
      if (limit !== null) {
        state.truncated = true;
        state.errors.push(browserError(
          "BROWSER_LIMIT_EXCEEDED",
          pageId,
        ));
        continue;
      }
      this.#cookieIdentities.add(identity);
      this.#cookieBytes += cookieBytes;
      collected.push(Object.freeze({
        name: cookie.name,
        value: cookie.value,
      }));
    }
    return Object.freeze(collected);
  }

  #admitNetworkFacts(state: ActivePageState): {
    readonly hostnames: readonly string[];
    readonly urls: readonly string[];
  } {
    const hostnames: string[] = [];
    for (const hostname of [...state.networkHostnames].sort(compareString)) {
      if (
        this.#networkHostnames.has(hostname)
        || this.#networkHostnames.size
          < this.#config.limits.browser.networkHostnamesPerDomain
      ) {
        this.#networkHostnames.add(hostname);
        hostnames.push(hostname);
      } else {
        state.truncated = true;
        state.errors.push(browserError(
          "BROWSER_LIMIT_EXCEEDED",
          state.input.pageId,
        ));
      }
    }
    const urls: string[] = [];
    for (const url of [...state.networkUrls].sort(compareString)) {
      if (
        this.#networkUrls.has(url)
        || this.#networkUrls.size < this.#config.limits.browser.requestsPerDomain
      ) {
        this.#networkUrls.add(url);
        urls.push(url);
      } else {
        state.truncated = true;
        state.errors.push(browserError(
          "BROWSER_LIMIT_EXCEEDED",
          state.input.pageId,
        ));
      }
    }
    return {
      hostnames: Object.freeze(hostnames),
      urls: Object.freeze(urls),
    };
  }

  async #mergeScriptCandidates(
    candidates: readonly ScriptCandidate[],
    state: ActivePageState,
  ): Promise<void> {
    for (const candidate of candidates) {
      const current = this.#scriptCandidates.get(candidate.url);
      if (current === undefined || compareScriptCandidate(candidate, current) < 0) {
        this.#scriptCandidates.set(candidate.url, candidate);
      }
    }
    const ranked = [...this.#scriptCandidates.values()]
      .sort(compareScriptCandidate)
      .slice(0, this.#config.limits.scripts.bodiesPerDomain);
    const next = new Map<string, SelectedScript>();
    let retainedBytes = 0;

    for (const candidate of ranked) {
      const current = this.#selectedScripts.get(candidate.url);
      let selected: SelectedScript;
      if (current?.candidate.requestId === candidate.requestId) {
        selected = current;
      } else {
        const attemptIdentity = `${candidate.pageId}\0${candidate.requestId}`;
        const measurable = candidate.complete
          && !candidate.failed
          && Number.isSafeInteger(candidate.decodedBytes)
          && candidate.decodedBytes > 0
          && candidate.decodedBytes <= this.#config.limits.scripts.bodyBytes
          && Number.isSafeInteger(candidate.encodedBytes)
          && candidate.encodedBytes <= this.#config.limits.scripts.bodyBytes;
        const alreadyAttempted = this.#scriptBodyAttempts.has(attemptIdentity);
        const countExhausted = this.#scriptBodyAttempts.size
          >= this.#config.limits.scripts.bodiesPerDomain;
        const byteBudgetExhausted = this.#scriptBodyBytesRead
          + candidate.decodedBytes
          > this.#config.limits.scripts.totalBodyBytesPerDomain;
        const mayRead = measurable
          && !alreadyAttempted
          && !countExhausted
          && !byteBudgetExhausted;
        if (mayRead) {
          this.#scriptBodyAttempts.add(attemptIdentity);
          this.#scriptBodyBytesRead += candidate.decodedBytes;
          const body = await readMeasuredScript(candidate, this.#config);
          selected = Object.freeze({
            candidate,
            content: body?.content ?? null,
            bytes: body?.bytes ?? 0,
          });
        } else {
          selected = Object.freeze({ candidate, content: null, bytes: 0 });
          if (measurable && !alreadyAttempted) {
            state.truncated = true;
            state.errors.push(browserError(
              "BROWSER_LIMIT_EXCEEDED",
              state.input.pageId,
            ));
          }
        }
      }
      if (selected.content !== null
        && retainedBytes + selected.bytes
          > this.#config.limits.scripts.totalBodyBytesPerDomain) {
        selected = Object.freeze({ candidate, content: null, bytes: 0 });
      }
      retainedBytes += selected.bytes;
      next.set(candidate.url, selected);
    }
    this.#selectedScripts = next;
  }

  async #finishInternal(): Promise<BrowserDomainResult> {
    const scriptUrlsByPage = new Map<PageId, string[]>();
    const scriptBodiesByPage = new Map<PageId, BrowserScriptBodyObservation[]>();
    const rankedUrls = [...this.#scriptCandidates.values()]
      .sort(compareScriptCandidate)
      .slice(0, this.#config.limits.scripts.urlCandidatesPerDomain);
    for (const candidate of rankedUrls) {
      const pageUrls = scriptUrlsByPage.get(candidate.pageId) ?? [];
      pageUrls.push(candidate.url);
      scriptUrlsByPage.set(candidate.pageId, pageUrls);
    }
    for (const selected of [...this.#selectedScripts.values()]
      .sort((left, right) => compareScriptCandidate(
        left.candidate,
        right.candidate,
      ))) {
      if (selected.content === null) {
        continue;
      }
      const pageBodies = scriptBodiesByPage.get(selected.candidate.pageId) ?? [];
      pageBodies.push(Object.freeze({
        pageId: selected.candidate.pageId,
        url: selected.candidate.url,
        content: selected.content,
      }));
      scriptBodiesByPage.set(selected.candidate.pageId, pageBodies);
    }

    const pages: BrowserPageObservations[] = this.#drafts
      .slice()
      .sort((left, right) => comparePageId(left.pageId, right.pageId))
      .map((draft) => Object.freeze({
        pageId: draft.pageId,
        finalUrl: draft.finalUrl,
        dom: draft.dom,
        javascript: draft.javascript,
        cookies: draft.cookies,
        networkUrls: draft.networkUrls,
        networkHostnames: draft.networkHostnames,
        scriptUrls: Object.freeze(
          (scriptUrlsByPage.get(draft.pageId) ?? []).sort(compareString),
        ),
        scriptBodies: Object.freeze(
          (scriptBodiesByPage.get(draft.pageId) ?? []).sort((left, right) =>
            compareString(left.url, right.url)),
        ),
        navigationLinks: draft.navigationLinks,
        truncated: draft.truncated,
      }));

    await this.#finalizeResources();
    const errors = uniqueErrors(this.#errors);
    return Object.freeze({
      pages: Object.freeze(pages),
      errors,
      completed: !this.#hadCollectionFailure,
    });
  }

  async #closeInternal(): Promise<void> {
    const activeCollection = this.#activeCollectionPromise;
    if (activeCollection !== null) {
      this.#contextUsable = false;
      if (!this.#failureController.signal.aborted) {
        this.#failureController.abort(
          new BrowserLifecycleFailure("BROWSER_UNAVAILABLE"),
        );
      }
      await this.#closeContextBounded("Browser domain closed while collecting");
      const collectionSettled = await settleWithin(
        activeCollection.then(() => undefined, () => undefined),
        CLEANUP_WATCHDOG_MS,
      );
      if (!collectionSettled) {
        this.#unhealthy = true;
        this.#slot.failed = true;
        void this.#slot.browser.close({
          reason: "Browser collection cleanup exceeded its deadline",
        }).catch(() => undefined);
      }
    }
    await this.#finalizeResources();
  }

  async #finalizeResources(): Promise<void> {
    if (this.#domainAbortListener !== null) {
      this.#domainSignal.removeEventListener(
        "abort",
        this.#domainAbortListener,
      );
      this.#domainAbortListener = null;
    }
    await this.#closeContextBounded("Browser domain finished");
    try {
      await this.#slot.proxy.finishDomain();
    } catch (error) {
      const failure = this.#slot.proxy.getFailure();
      if (failure !== null) {
        this.#errors.push(proxyError(failure, null));
        this.#hadCollectionFailure = true;
      } else if (!this.#domainSignal.aborted) {
        this.#errors.push(this.#errorForFailure(error, null));
        this.#hadCollectionFailure = true;
      }
    } finally {
      if (this.#usageSnapshot === null) {
        this.#usageSnapshot = Object.freeze({
          ...this.#slot.proxy.getUsage(),
          scriptBodiesInspected: [...this.#selectedScripts.values()].filter(
            (script) => script.content !== null,
          ).length,
        });
      }
    }
    if (!this.#released) {
      this.#released = true;
      await this.#pool.release(
        this.#slot,
        this.#unhealthy || !this.#slot.browser.isConnected(),
      );
    }
  }

  #closeContextBounded(reason: string): Promise<boolean> {
    if (this.#contextClosePromise !== null) {
      return this.#contextClosePromise;
    }
    const closing = this.#context.close({ reason });
    this.#contextClosePromise = (async (): Promise<boolean> => {
      const closed = await settleWithin(closing, CLEANUP_WATCHDOG_MS);
      if (!closed) {
        this.#unhealthy = true;
        this.#slot.failed = true;
        void this.#slot.browser.close({
          reason: "Browser context cleanup exceeded its deadline",
        }).catch(() => undefined);
      }
      return closed;
    })();
    return this.#contextClosePromise;
  }

  async #closePageBounded(page: Page): Promise<boolean> {
    const closed = await settleWithin(
      page.close({ reason: "Browser page collection finished" }),
      CLEANUP_WATCHDOG_MS,
    );
    if (!closed) {
      this.#unhealthy = true;
      this.#slot.failed = true;
      this.#contextUsable = false;
      void this.#slot.browser.close({
        reason: "Browser page cleanup exceeded its deadline",
      }).catch(() => undefined);
    }
    return closed;
  }

  #errorForFailure(
    error: unknown,
    pageId: PageId | null,
    policyDenied = false,
  ): ScanError {
    const proxyFailure = this.#slot.proxy.getFailure();
    if (proxyFailure !== null) {
      return proxyError(proxyFailure, pageId);
    }
    if (isProtectedTransportError(error)) {
      return proxyError(error, pageId);
    }
    if (error instanceof PageDeadlineMarker) {
      return browserError("BROWSER_TIMEOUT", pageId);
    }
    if (error instanceof BrowserAccessDeniedMarker) {
      return browserError(
        "BROWSER_NAVIGATION_FAILED",
        pageId,
        false,
      );
    }
    if (error instanceof BrowserLifecycleFailure) {
      return browserError(error.code, pageId);
    }
    if (!this.#slot.browser.isConnected()) {
      this.#unhealthy = true;
      return browserError("BROWSER_UNAVAILABLE", pageId);
    }
    if (policyDenied) {
      return browserError(
        "BROWSER_NAVIGATION_FAILED",
        pageId,
        false,
      );
    }
    return browserError("BROWSER_NAVIGATION_FAILED", pageId);
  }
}

export function createBrowserPool(
  transport: ProtectedHttpTransport,
  config: ScanConfig,
  launcher: BrowserLauncher = (options) => chromium.launch(options),
  signal?: AbortSignal,
): Promise<BrowserPool> {
  return BrowserPoolImpl.create(transport, config, launcher, signal);
}
