import assert from "node:assert/strict";
import { test } from "node:test";

import {
  computeConfigDigest,
  createDefaultScanConfig,
  parseScanConfig,
  type ScanConfig,
} from "../src/config.ts";
import type {
  BrowserDomainResult,
  BrowserDomainSession,
  BrowserLimitHit,
  BrowserPageCollection,
  BrowserPageInput,
  BrowserPool,
  BrowserRuntimeIdentity,
} from "../src/crawl/browser.ts";
import { ProtectedTransportError } from "../src/crawl/transport.ts";
import type {
  ProtectedBrowserProxy,
  ProtectedDnsRecordAdmission,
  ProtectedHttpTransport,
  ProtectedTransportRequest,
  ProtectedTransportResponse,
  ProtectedTransportResponseHead,
  ProtectedTransportSession,
  ProtectedTransportSessionOptions,
  ProtectedTransportUsage,
} from "../src/crawl/transport.ts";
import type {
  RobotsCheck,
  RobotsPolicyService,
} from "../src/crawl/robots.ts";
import type {
  CompiledFingerprintCatalog,
  CompiledFingerprintRule,
} from "../src/detect/catalog.ts";
import type {
  DetectorCandidate,
  DetectorMatchResult,
  DetectorPool,
} from "../src/detect/pool.ts";
import type { ShadowEvaluationSnapshot } from "../src/evaluation.ts";
import {
  sanitizeUrl,
  validateDomainResult,
  type BrowserPageObservations,
  type DnsRecordObservation,
  type HttpPageResult,
  type PageId,
  type Provenance,
  type ScanError,
} from "../src/model.ts";
import {
  remapHttpPageResultPageId,
  scanDomain,
  selectInternalPages,
  selectTier2InternalPage,
} from "../src/pipeline.ts";

type JsonRecord = Record<string, unknown>;
type ResponseFactory = (
  request: ProtectedTransportRequest,
  signal: AbortSignal,
) => ProtectedTransportResponse | Promise<ProtectedTransportResponse>;
type ResponseItem = ProtectedTransportResponse
  | ProtectedTransportError
  | ResponseFactory;
type ResponseStep = readonly [
  url: string,
  response: ResponseItem,
];
type RecordedDetectorCandidate = DetectorCandidate & {
  readonly collector?: "http" | "browser" | "dns" | "tls";
  readonly pageId?: PageId | null;
};

const USER_AGENT =
  "WebsiteTechScraper/0.1.0 (https://contact.website-tech-scraper.dev/crawler)";
const RUN_ID = "37937a78-f39d-49ed-a51d-6d398ae45a20";
const SCANNED_AT = "2026-08-18T10:11:12.345Z";
const DOMAIN = "shop.vendor.tld";
const ENTRY_URL = `https://${DOMAIN}/`;
const CATALOG_DIGEST = `sha256:${"a".repeat(64)}`;

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

function configWith(
  replacements: ReadonlyArray<readonly [readonly string[], unknown]> = [],
): ScanConfig {
  const value = structuredClone(
    createDefaultScanConfig(USER_AGENT),
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
    readonly contentType?: string;
    readonly body?: string;
    readonly tlsIssuer?: string | null;
    readonly tlsHandshakeMs?: number | null;
  } = {},
): ProtectedTransportResponse {
  const headers = options.contentType === undefined
    ? []
    : [{ name: "content-type", value: options.contentType }];

  return Object.freeze({
    url,
    statusCode,
    headers: Object.freeze(headers),
    body: Buffer.from(options.body ?? "", "utf8"),
    redirectUrl: null,
    tlsIssuer: options.tlsIssuer ?? null,
    tlsHandshakeMs: options.tlsHandshakeMs ?? null,
  });
}

function htmlResponse(
  url: string,
  body = "<html><body>fixture</body></html>",
  options: {
    readonly tlsIssuer?: string | null;
    readonly tlsHandshakeMs?: number | null;
  } = {},
): ProtectedTransportResponse {
  return response(url, 200, {
    contentType: "text/html; charset=utf-8",
    body,
    ...options,
  });
}

class ScriptedSession implements ProtectedTransportSession {
  readonly calls: ProtectedTransportRequest[] = [];
  closeCount = 0;
  readonly #responses = new Map<
    string,
    ResponseItem[]
  >();
  readonly #signal: AbortSignal;
  readonly #events: string[] | undefined;
  #retries = 0;
  #staticTransferredBytes = 0;

  constructor(
    steps: readonly ResponseStep[],
    signal?: AbortSignal,
    events?: string[],
  ) {
    this.#signal = signal ?? new AbortController().signal;
    this.#events = events;
    for (const [url, item] of steps) {
      const queued = this.#responses.get(url) ?? [];
      queued.push(item);
      this.#responses.set(url, queued);
    }
  }

  async requestHop(
    request: ProtectedTransportRequest,
  ): Promise<ProtectedTransportResponse> {
    this.#signal.throwIfAborted();
    this.#events?.push(`http:${request.url}`);
    this.calls.push(Object.freeze({ ...request }));
    if (request.isRetry === true) {
      this.#retries += 1;
    }

    const queued = this.#responses.get(request.url);
    const scripted = queued?.shift();
    assert.notEqual(scripted, undefined, `Unexpected HTTP request: ${request.url}`);
    const source = typeof scripted === "function"
      ? await scripted(request, this.#signal)
      : scripted;
    if (source instanceof ProtectedTransportError) throw source;

    let bodyAccepted = source!.statusCode >= 200
      && source!.statusCode <= 299
      && source!.statusCode !== 204
      && source!.statusCode !== 205;
    if (bodyAccepted && request.acceptBody !== undefined) {
      const head: ProtectedTransportResponseHead = {
        url: source!.url,
        statusCode: source!.statusCode,
        headers: source!.headers,
        tlsIssuer: source!.tlsIssuer,
        tlsHandshakeMs: source!.tlsHandshakeMs,
      };
      bodyAccepted = request.acceptBody(head);
    }

    const body = bodyAccepted ? source!.body : new Uint8Array();
    this.#staticTransferredBytes += body.byteLength;
    return Object.freeze({ ...source!, body });
  }

  admitDnsRecords(
    records: readonly DnsRecordObservation[],
  ): ProtectedDnsRecordAdmission {
    this.#signal.throwIfAborted();
    return Object.freeze({
      records: Object.freeze([...records]),
      limitExceeded: false,
    });
  }

  getSignal(): AbortSignal {
    return this.#signal;
  }

  getUsage(): ProtectedTransportUsage {
    return Object.freeze({
      httpRequests: this.calls.length,
      retries: this.#retries,
      probesIssued: this.calls.filter((call) => call.purpose === "probe").length,
      staticTransferredBytes: this.#staticTransferredBytes,
    });
  }

  close(): void {
    this.closeCount += 1;
  }
}

class ScriptedTransport implements ProtectedHttpTransport {
  readonly sessions: ScriptedSession[] = [];
  readonly #steps: readonly ResponseStep[];
  readonly #sessionSignal: AbortSignal | undefined;
  readonly #events: string[] | undefined;

  constructor(
    steps: readonly ResponseStep[],
    sessionSignal?: AbortSignal,
    events?: string[],
  ) {
    this.#steps = steps;
    this.#sessionSignal = sessionSignal;
    this.#events = events;
  }

  createSession(options?: ProtectedTransportSessionOptions): ScriptedSession {
    const session = new ScriptedSession(
      this.#steps,
      this.#sessionSignal ?? options?.signal,
      this.#events,
    );
    this.sessions.push(session);
    return session;
  }

  createBrowserProxy(): Promise<ProtectedBrowserProxy> {
    return Promise.reject(new Error("The pipeline must use its preflighted browser pool."));
  }
}

class FakeRobotsService implements RobotsPolicyService {
  readonly checks: string[] = [];
  readonly cachedChecks: string[] = [];
  clearCount = 0;
  readonly #denied: ReadonlySet<string>;
  readonly #failures: ReadonlyMap<string, ProtectedTransportError>;
  readonly #texts: Map<string, Array<string | null>>;
  readonly #events: string[] | undefined;

  constructor(
    denied: readonly string[] = [],
    failures: ReadonlyMap<string, ProtectedTransportError> = new Map(),
    texts: ReadonlyMap<string, readonly (string | null)[]> = new Map(),
    events?: string[],
  ) {
    this.#denied = new Set(denied);
    this.#failures = failures;
    this.#texts = new Map(
      [...texts].map(([url, values]) => [url, [...values]]),
    );
    this.#events = events;
  }

  async check(
    _session: ProtectedTransportSession,
    url: string,
  ): Promise<RobotsCheck> {
    this.#events?.push(`robots:${url}`);
    this.checks.push(url);
    const failure = this.#failures.get(url);
    if (failure !== undefined) throw failure;
    const robotsText = this.#texts.get(url)?.shift() ?? null;
    return Object.freeze({
      allowed: !this.#denied.has(url),
      robotsText,
      ownerOrigin: new URL(url).origin,
      fetchedUrl: `${new URL(url).origin}/robots.txt`,
    });
  }

  allowsCached(url: string): boolean {
    this.cachedChecks.push(url);
    return !this.#denied.has(url);
  }

  clear(): void {
    this.clearCount += 1;
  }
}

function scanError(
  stage: ScanError["stage"],
  code: ScanError["code"],
  pageId: PageId | null,
  message: string,
  retryable = false,
): ScanError {
  return Object.freeze({
    stage,
    code,
    pageId,
    retryable,
    message,
    ruleId: null,
    signal: null,
    limit: null,
    catalogRevision: null,
  });
}

interface FakeBrowserScenario {
  readonly navigationLinks?: Partial<Record<PageId, readonly string[]>>;
  readonly pageErrors?: Partial<Record<PageId, ScanError>>;
  readonly admittedPages?: readonly PageId[];
  readonly continuationPages?: readonly PageId[];
  readonly finishErrors?: readonly ScanError[];
  readonly throwOnPage?: PageId;
  readonly onClose?: () => void;
  readonly events?: string[];
  readonly limitHits?: Partial<Record<PageId, readonly BrowserLimitHit[]>>;
  readonly usage?: {
    readonly browserRequests: number;
    readonly browserTransferredBytes: number;
    readonly scriptBodiesInspected: number;
  };
}

class FakeBrowserSession implements BrowserDomainSession {
  readonly inputs: BrowserPageInput[] = [];
  finishCount = 0;
  closeCount = 0;
  readonly #scenario: FakeBrowserScenario;
  readonly #admittedPageIds = new Set<PageId>();

  constructor(scenario: FakeBrowserScenario = {}) {
    this.#scenario = scenario;
  }

  async collectPage(input: BrowserPageInput): Promise<BrowserPageCollection> {
    this.#scenario.events?.push(`browser:${input.pageId}`);
    this.inputs.push(input);
    assert.equal(input.allowTopLevelUrl(input.url), true);
    if (this.#scenario.throwOnPage === input.pageId) {
      throw new Error("Controlled browser lifecycle failure.");
    }

    const error = this.#scenario.pageErrors?.[input.pageId];
    const observationsAdmitted = error === undefined
      || this.#scenario.admittedPages?.includes(input.pageId) === true;
    const continuationAllowed = error === undefined
      || this.#scenario.continuationPages?.includes(input.pageId) === true;
    if (observationsAdmitted) {
      this.#admittedPageIds.add(input.pageId);
    }
    const navigationLinks = Object.freeze([
      ...(this.#scenario.navigationLinks?.[input.pageId] ?? []),
    ]);
    return Object.freeze({
      completed: error === undefined,
      observationsAdmitted,
      continuationAllowed,
      errors: error === undefined ? Object.freeze([]) : Object.freeze([error]),
      navigationLinks,
      limitTelemetry: Object.freeze({
        hits: Object.freeze([...(this.#scenario.limitHits?.[input.pageId] ?? [])]),
      }),
    });
  }

  async finish(): Promise<BrowserDomainResult> {
    this.finishCount += 1;
    const pages: BrowserPageObservations[] = this.inputs
      .filter((input) => this.#admittedPageIds.has(input.pageId))
      .map((input) => Object.freeze({
        pageId: input.pageId,
        finalUrl: input.url,
        dom: Object.freeze([]),
        javascript: Object.freeze([]),
        cookies: Object.freeze([]),
        networkUrls: Object.freeze([]),
        networkHostnames: Object.freeze([]),
        scriptUrls: Object.freeze([]),
        scriptBodies: Object.freeze([]),
        navigationLinks: Object.freeze([
          ...(this.#scenario.navigationLinks?.[input.pageId] ?? []),
        ]),
        truncated: this.#scenario.pageErrors?.[input.pageId] !== undefined,
      }));
    const pageErrors = this.inputs.flatMap((input) => {
      const error = this.#scenario.pageErrors?.[input.pageId];
      return error === undefined ? [] : [error];
    });
    const errors = Object.freeze([
      ...pageErrors,
      ...(this.#scenario.finishErrors ?? []),
    ]);
    return Object.freeze({
      pages: Object.freeze(pages),
      errors,
      completed: errors.length === 0,
    });
  }

  getUsage() {
    return Object.freeze(this.#scenario.usage ?? {
      browserRequests: this.inputs.length,
      browserTransferredBytes: this.inputs.length * 100,
      scriptBodiesInspected: 0,
    });
  }

  async close(): Promise<void> {
    this.closeCount += 1;
    this.#scenario.onClose?.();
  }
}

class FakeBrowserPool implements BrowserPool {
  readonly runtime: BrowserRuntimeIdentity = Object.freeze({
    playwright: "1.62.1",
    chromiumRevision: "1234",
    chromiumVersion: "Chromium 1234",
  });
  readonly session: FakeBrowserSession;
  openCount = 0;
  closeCount = 0;
  available = true;
  openError: Error | null = null;
  afterAdmission: ((signal?: AbortSignal) => Promise<void>) | null = null;

  constructor(scenario: FakeBrowserScenario = {}) {
    this.session = new FakeBrowserSession(scenario);
  }

  async openDomain(
    signal?: AbortSignal,
    onAdmitted?: () => void,
  ): Promise<BrowserDomainSession> {
    signal?.throwIfAborted();
    this.openCount += 1;
    if (this.openError !== null) {
      throw this.openError;
    }
    onAdmitted?.();
    if (this.afterAdmission !== null) await this.afterAdmission(signal);
    signal?.throwIfAborted();
    return this.session;
  }

  isAvailable(): boolean {
    return this.available;
  }

  async close(): Promise<void> {
    this.closeCount += 1;
  }
}

function catalogWith(
  options: {
    readonly tlsIssuer?: boolean;
    readonly probePaths?: readonly string[];
  } = {},
): CompiledFingerprintCatalog {
  return {
    source: "test/pipeline",
    revision: "fixture-v1",
    digest: CATALOG_DIGEST,
    categories: Object.freeze([]),
    technologies: Object.freeze([]),
    rules: Object.freeze([]),
    indexes: Object.freeze([]),
    inspectionPlan: Object.freeze({
      dom: Object.freeze([]),
      javascript: Object.freeze([]),
      probePaths: Object.freeze([...(options.probePaths ?? [])]),
      dnsRecordTypes: Object.freeze([]),
      tlsIssuer: options.tlsIssuer ?? false,
    }),
    declarationCount: 0,
    relationshipCount: 0,
    regexSourceCount: 0,
    regexSourceCodeUnits: 0,
  };
}

class RecordingDetectorPool implements DetectorPool {
  readonly catalog: CompiledFingerprintCatalog;
  readonly calls: RecordedDetectorCandidate[][] = [];
  closeCount = 0;
  available = true;
  result: DetectorMatchResult = Object.freeze({
    matches: Object.freeze([]),
    errors: Object.freeze([]),
    completed: true,
    executions: 0,
  });

  constructor(catalog: CompiledFingerprintCatalog) {
    this.catalog = catalog;
  }

  async match(
    candidates: readonly DetectorCandidate[],
    signal?: AbortSignal,
  ): Promise<DetectorMatchResult> {
    signal?.throwIfAborted();
    this.calls.push([...candidates] as RecordedDetectorCandidate[]);
    return this.result;
  }

  isAvailable(): boolean {
    return this.available;
  }

  async close(): Promise<void> {
    this.closeCount += 1;
  }
}

function isolatedShadowDetectorPools(catalog: CompiledFingerprintCatalog) {
  return Object.freeze({
    t1: new RecordingDetectorPool(catalog),
    t2: new RecordingDetectorPool(catalog),
  });
}

function provenanceFor(
  config: ScanConfig,
  catalog: CompiledFingerprintCatalog,
): Provenance {
  return Object.freeze({
    scannerVersion: "0.1.0",
    runtime: Object.freeze({
      node: "24.19.0",
      playwright: "1.62.1",
      chromiumRevision: "1234",
    }),
    catalog: Object.freeze({
      source: catalog.source,
      revision: catalog.revision,
      digest: catalog.digest,
    }),
    configDigest: computeConfigDigest(config),
  });
}

function deterministicOptions(signal?: AbortSignal) {
  let monotonic = 0;
  return {
    ...(signal === undefined ? {} : { signal }),
    wallClock: (): Date => new Date(SCANNED_AT),
    monotonicClock: (): number => {
      monotonic += 5;
      return monotonic;
    },
  };
}

function assertValidResult(
  result: Awaited<ReturnType<typeof scanDomain>>,
  config: ScanConfig,
  signalAdmitted: boolean,
): void {
  assert.equal(
    validateDomainResult(result, {
      scanConfig: config,
      expectedConfigDigest: computeConfigDigest(config),
      signalAdmitted,
    }),
    result,
  );
}

test("selects deterministic detail and listing pages from static and rendered links", () => {
  const config = configWith();
  const staticLinks = [
    `${ENTRY_URL}products/zeta`,
    `${ENTRY_URL}collections/sale`,
    `${ENTRY_URL}products/a`,
    `${ENTRY_URL}account/profile`,
    `${ENTRY_URL}manual.pdf`,
    `https://other.vendor.tld/products/a`,
  ];
  const renderedLinks = [
    `${ENTRY_URL}collections/a`,
    `${ENTRY_URL}products/a`,
    `${ENTRY_URL}checkout`,
    `${ENTRY_URL}search?q=widget`,
  ];

  const selected = selectInternalPages(
    ENTRY_URL,
    staticLinks,
    renderedLinks,
    config,
  );
  const reversed = selectInternalPages(
    ENTRY_URL,
    [...staticLinks].reverse(),
    [...renderedLinks].reverse(),
    config,
  );

  assert.deepEqual(selected, [
    { role: "listing", url: `${ENTRY_URL}collections/a` },
    { role: "detail", url: `${ENTRY_URL}products/a` },
  ]);
  assert.deepEqual(reversed, selected);
  assert.equal(Object.isFrozen(selected), true);
  assert.equal(Object.isFrozen(selected[0]), true);
});

test("selects T2 from static p1 links and excludes rendered-only links", () => {
  const config = configWith();
  const staticLinks = [
    `${ENTRY_URL}products/zeta`,
    `${ENTRY_URL}collections/zeta`,
    `${ENTRY_URL}products/a`,
  ];
  const renderedListing = `${ENTRY_URL}collections/a`;

  const selected = selectTier2InternalPage(ENTRY_URL, staticLinks, config);
  const reversed = selectTier2InternalPage(
    ENTRY_URL,
    [...staticLinks].reverse(),
    config,
  );
  const fullSelection = selectInternalPages(
    ENTRY_URL,
    staticLinks,
    [renderedListing],
    config,
  );

  assert.deepEqual(selected, {
    role: "listing",
    url: `${ENTRY_URL}collections/zeta`,
  });
  assert.deepEqual(reversed, selected);
  assert.deepEqual(fullSelection[0], {
    role: "listing",
    url: renderedListing,
  });
  assert.equal(Object.isFrozen(selected), true);
});

test("remaps an internal result without mutating the provisional T2 identity", () => {
  const original = Object.freeze({
    kind: "failed" as const,
    pageId: "p2" as const,
    requestedUrl: `${ENTRY_URL}products/zeta`,
    response: null,
    robots: Object.freeze([]),
    errors: Object.freeze([scanError(
      "http",
      "HTTP_REQUEST_FAILED",
      "p2",
      "The HTTP request failed.",
      true,
    )]) as readonly [ScanError],
  }) satisfies HttpPageResult;

  const remapped = remapHttpPageResultPageId(original, "p3");

  assert.notEqual(remapped, original);
  assert.equal(original.pageId, "p2");
  assert.equal(original.errors[0].pageId, "p2");
  assert.equal(remapped.kind, "failed");
  assert.equal(remapped.kind === "failed" ? remapped.pageId : null, "p3");
  assert.equal(remapped.errors[0]?.pageId, "p3");
  assert.equal(Object.isFrozen(remapped), true);
  assert.equal(Object.isFrozen(remapped.errors), true);
});

test("keeps the detail slot empty and uses only the listing slot for content fallback", () => {
  const config = configWith();
  const fallbackOnly = selectInternalPages(
    ENTRY_URL,
    [
      `${ENTRY_URL}about/company`,
      `${ENTRY_URL}about`,
      `${ENTRY_URL}privacy`,
      `${ENTRY_URL}admin`,
    ],
    [],
    config,
  );
  const detailAndFallback = selectInternalPages(
    ENTRY_URL,
    [`${ENTRY_URL}products/widget`, `${ENTRY_URL}about`],
    [],
    config,
  );

  assert.deepEqual(fallbackOnly, [
    { role: "content", url: `${ENTRY_URL}about` },
  ]);
  assert.deepEqual(detailAndFallback, [
    { role: "content", url: `${ENTRY_URL}about` },
    { role: "detail", url: `${ENTRY_URL}products/widget` },
  ]);
});

test("rejects unsafe, off-origin, queried, sensitive, and file page candidates", () => {
  const selected = selectInternalPages(
    ENTRY_URL,
    [
      ENTRY_URL,
      `http://${DOMAIN}/products/widget`,
      `https://other.vendor.tld/products/widget`,
      `https://user:secret@${DOMAIN}/products/widget`,
      `${ENTRY_URL}products/widget?variant=1`,
      `${ENTRY_URL}products/widget#reviews`,
      `${ENTRY_URL}account/profile`,
      `${ENTRY_URL}admin/settings`,
      `${ENTRY_URL}cart`,
      `${ENTRY_URL}checkout`,
      `${ENTRY_URL}logout`,
      `${ENTRY_URL}search`,
      `${ENTRY_URL}privacy`,
      `${ENTRY_URL}catalog.pdf`,
      "mailto:sales@vendor.tld",
    ],
    [],
    configWith(),
  );

  assert.deepEqual(selected, []);
});

test("orchestrates p1-p3 once and combines HTTP, browser, TLS, usage, and provenance", async () => {
  const config = configWith();
  const catalog = catalogWith({ tlsIssuer: true });
  const detailUrl = `${ENTRY_URL}products/widget`;
  const listingUrl = `${ENTRY_URL}collections/all`;
  const entryBody = `<html><body><a href="${detailUrl}">Widget</a></body></html>`;
  const listingBody = "<html><body>All products</body></html>";
  const detailBody = "<html><body>Widget detail</body></html>";
  const transport = new ScriptedTransport([
    [ENTRY_URL, htmlResponse(ENTRY_URL, entryBody, {
      tlsIssuer: "CN=Trusted Pipeline CA",
      tlsHandshakeMs: 7,
    })],
    [listingUrl, htmlResponse(listingUrl, listingBody)],
    [detailUrl, htmlResponse(detailUrl, detailBody)],
  ]);
  const robots = new FakeRobotsService();
  const browserPool = new FakeBrowserPool({
    navigationLinks: { p1: [listingUrl] },
    usage: {
      browserRequests: 6,
      browserTransferredBytes: 600,
      scriptBodiesInspected: 0,
    },
  });
  const detectorPool = new RecordingDetectorPool(catalog);
  const provenance = provenanceFor(config, catalog);

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance,
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "success");
  assert.equal(result.scannedAt, SCANNED_AT);
  assert.equal(result.finalUrl, ENTRY_URL);
  assert.deepEqual(result.pages, [
    {
      id: "p1",
      role: "entry",
      url: ENTRY_URL,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
    {
      id: "p2",
      role: "listing",
      url: listingUrl,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
    {
      id: "p3",
      role: "detail",
      url: detailUrl,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
  ]);
  assert.deepEqual(
    transport.sessions[0]?.calls.map((call) => call.url),
    [ENTRY_URL, detailUrl, listingUrl],
  );
  assert.deepEqual(
    browserPool.session.inputs.map(({ pageId, url }) => ({ pageId, url })),
    [
      { pageId: "p1", url: ENTRY_URL },
      { pageId: "p2", url: listingUrl },
      { pageId: "p3", url: detailUrl },
    ],
  );
  assert.equal(browserPool.openCount, 1);
  assert.equal(browserPool.session.finishCount, 1);
  assert.equal(browserPool.session.closeCount, 1);
  assert.equal(transport.sessions[0]?.closeCount, 1);
  assert.equal(browserPool.closeCount, 0);
  assert.equal(detectorPool.closeCount, 0);
  assert.equal(robots.clearCount, 0);

  const candidates = detectorPool.calls[0] ?? [];
  assert.equal(
    candidates.some((candidate) => candidate.source === "tls_issuer"),
    true,
  );
  assert.deepEqual(
    candidates
      .filter((candidate) => candidate.source === "url")
      .map((candidate) => [candidate.collector, candidate.pageId, candidate.value]),
    [
      ["http", "p1", ENTRY_URL],
      ["http", "p2", listingUrl],
      ["http", "p3", detailUrl],
      ["browser", "p1", ENTRY_URL],
      ["browser", "p2", listingUrl],
      ["browser", "p3", detailUrl],
    ],
  );

  const expectedStaticBytes = Buffer.byteLength(entryBody)
    + Buffer.byteLength(listingBody)
    + Buffer.byteLength(detailBody);
  assert.deepEqual(result.usage, {
    httpRequests: 3,
    browserRequests: 6,
    retries: 0,
    pagesVisited: 3,
    probesIssued: 0,
    scriptBodiesInspected: 0,
    staticTransferredBytes: expectedStaticBytes,
    browserTransferredBytes: 600,
  });
  assert.equal(result.timings.dnsMs, null);
  assert.equal(result.timings.tlsMs, 7);
  for (const key of [
    "targetMs",
    "robotsMs",
    "httpMs",
    "browserMs",
    "detectMs",
  ] as const) {
    assert.notEqual(result.timings[key], null, key);
    assert.ok((result.timings[key] ?? 0) <= result.timings.totalMs, key);
  }
  assert.deepEqual(result.provenance, provenance);
  assert.deepEqual(result.detectionStats, {
    rawDirect: 0,
    gatedDirect: 0,
    suppressedDirect: 0,
    retainedDirect: 0,
  });
  assertValidResult(result, config, true);
});

test("keeps the static T2 reservation when rendered p1 finds a better detail", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const reservedDetailUrl = `${ENTRY_URL}products/zeta`;
  const renderedDetailUrl = `${ENTRY_URL}product/a`;
  const renderedListingUrl = `${ENTRY_URL}collections/a`;
  const transport = new ScriptedTransport([
    [ENTRY_URL, htmlResponse(
      ENTRY_URL,
      `<html><body><a href="${reservedDetailUrl}">Static detail</a></body></html>`,
    )],
    [renderedListingUrl, htmlResponse(renderedListingUrl)],
    [reservedDetailUrl, htmlResponse(reservedDetailUrl)],
  ]);
  const robots = new FakeRobotsService();
  const browserPool = new FakeBrowserPool({
    navigationLinks: { p1: [renderedDetailUrl, renderedListingUrl] },
  });

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool: new RecordingDetectorPool(catalog),
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "success");
  assert.deepEqual(result.pages, [
    {
      id: "p1",
      role: "entry",
      url: ENTRY_URL,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
    {
      id: "p2",
      role: "listing",
      url: renderedListingUrl,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
    {
      id: "p3",
      role: "detail",
      url: reservedDetailUrl,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
  ]);
  assert.deepEqual(robots.checks, [
    ENTRY_URL,
    reservedDetailUrl,
    renderedListingUrl,
  ]);
  assert.deepEqual(
    browserPool.session.inputs.map(({ pageId, url }) => ({ pageId, url })),
    [
      { pageId: "p1", url: ENTRY_URL },
      { pageId: "p2", url: renderedListingUrl },
      { pageId: "p3", url: reservedDetailUrl },
    ],
  );
  assertValidResult(result, config, true);
});

test("collects the exact T2 prefix and infrastructure before browser p1", async () => {
  const events: string[] = [];
  const config = configWith();
  const detailUrl = `${ENTRY_URL}products/zeta`;
  const listingUrl = `${ENTRY_URL}collections/a`;
  const probePath = "/exists.svg";
  const probeUrl = new URL(probePath, ENTRY_URL).href;
  const baseCatalog = catalogWith({
    tlsIssuer: true,
    probePaths: [probePath],
  });
  const inspectionPlan = new Proxy(baseCatalog.inspectionPlan, {
    get(target, property, receiver): unknown {
      if (property === "tlsIssuer") events.push("infrastructure");
      return Reflect.get(target, property, receiver);
    },
  });
  const catalog: CompiledFingerprintCatalog = Object.freeze({
    ...baseCatalog,
    inspectionPlan,
  });
  const transport = new ScriptedTransport([
    [ENTRY_URL, htmlResponse(
      ENTRY_URL,
      `<html><body><a href="${detailUrl}">Detail</a></body></html>`,
      { tlsIssuer: "CN=Fixture", tlsHandshakeMs: 2 },
    )],
    [detailUrl, htmlResponse(detailUrl)],
    [probeUrl, response(probeUrl, 204)],
    [listingUrl, htmlResponse(listingUrl)],
  ], undefined, events);
  const robots = new FakeRobotsService([], new Map(), new Map(), events);
  const browserPool = new FakeBrowserPool({
    events,
    navigationLinks: { p1: [listingUrl] },
  });

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool: new RecordingDetectorPool(catalog),
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "success");
  assert.deepEqual(events, [
    `robots:${ENTRY_URL}`,
    `http:${ENTRY_URL}`,
    "infrastructure",
    `robots:${detailUrl}`,
    `http:${detailUrl}`,
    `robots:${probeUrl}`,
    `http:${probeUrl}`,
    "browser:p1",
    `robots:${listingUrl}`,
    `http:${listingUrl}`,
    "browser:p2",
    "browser:p3",
  ]);
  assert.deepEqual(result.pages.map(({ id, url }) => ({ id, url })), [
    { id: "p1", url: ENTRY_URL },
    { id: "p2", url: listingUrl },
    { id: "p3", url: detailUrl },
  ]);
  assertValidResult(result, config, true);
});

test("runs independent raw-free shadow detections without changing the full result", async () => {
  const config = configWith([
    [["limits", "output", "technologiesPerDomain"], 3],
  ]);
  const detailUrl = `${ENTRY_URL}products/static`;
  const listingUrl = `${ENTRY_URL}collections/rendered`;
  const probePath = "/shadow-probe.txt";
  const probeUrl = new URL(probePath, ENTRY_URL).href;
  const rawMarker = "RAW_SHADOW_MARKER_MUST_NOT_ESCAPE";
  const category = Object.freeze({ id: 1, name: "Fixture category" });
  const rules: readonly CompiledFingerprintRule[] = Object.freeze([
    Object.freeze({
      ruleId: `sha256:${"1".repeat(64)}`,
      namespace: "test/pipeline:shadow-v1",
      technology: "Entry Parent",
      source: "html" as const,
      locator: null,
      locatorPattern: null,
      original: "entry-signal",
      pattern: "entry-signal",
      matchMode: "regex" as const,
      confidence: 100,
      versionTemplate: null,
    }),
    Object.freeze({
      ruleId: `sha256:${"2".repeat(64)}`,
      namespace: "test/pipeline:shadow-v1",
      technology: "Probe Tech",
      source: "probe" as const,
      locator: probePath,
      locatorPattern: null,
      original: "probe-signal",
      pattern: "probe-signal",
      matchMode: "regex" as const,
      confidence: 100,
      versionTemplate: null,
    }),
    Object.freeze({
      ruleId: `sha256:${"3".repeat(64)}`,
      namespace: "test/pipeline:shadow-v1",
      technology: "Browser Tech",
      source: "url" as const,
      locator: null,
      locatorPattern: null,
      original: "https://",
      pattern: "https://",
      matchMode: "regex" as const,
      confidence: 100,
      versionTemplate: null,
    }),
  ]);
  const baseCatalog = catalogWith({ tlsIssuer: true, probePaths: [probePath] });
  const catalog: CompiledFingerprintCatalog = Object.freeze({
    ...baseCatalog,
    categories: Object.freeze([category]),
    technologies: Object.freeze([
      Object.freeze({
        name: "Entry Parent",
        categories: Object.freeze([category]),
        requires: Object.freeze([]),
        requiresCategory: Object.freeze([]),
        implies: Object.freeze([Object.freeze({
          technology: "Implied Child",
          ruleId: `sha256:${"4".repeat(64)}`,
          confidence: 100,
          version: null,
        })]),
        excludes: Object.freeze([]),
      }),
      Object.freeze({
        name: "Implied Child",
        categories: Object.freeze([category]),
        requires: Object.freeze([]),
        requiresCategory: Object.freeze([]),
        implies: Object.freeze([]),
        excludes: Object.freeze([]),
      }),
      ...["Probe Tech", "Browser Tech"].map((name) => Object.freeze({
        name,
        categories: Object.freeze([category]),
        requires: Object.freeze([]),
        requiresCategory: Object.freeze([]),
        implies: Object.freeze([]),
        excludes: Object.freeze([]),
      })),
    ]),
    rules,
    declarationCount: rules.length,
    relationshipCount: 1,
    regexSourceCount: rules.length,
    regexSourceCodeUnits: rules.reduce(
      (total, rule) => total + (rule.pattern?.length ?? 0),
      0,
    ),
  });

  const run = async (shadow: boolean) => {
    const fullCalls: RecordedDetectorCandidate[][] = [];
    const t1Calls: RecordedDetectorCandidate[][] = [];
    const t2Calls: RecordedDetectorCandidate[][] = [];
    const fullSignals: Array<AbortSignal | undefined> = [];
    const t1Signals: Array<AbortSignal | undefined> = [];
    const t2Signals: Array<AbortSignal | undefined> = [];
    const makeDetectorPool = (
      calls: RecordedDetectorCandidate[][],
      signals: Array<AbortSignal | undefined>,
    ): DetectorPool => ({
      catalog,
      async match(candidates, signal): Promise<DetectorMatchResult> {
        signals.push(signal);
        calls.push([...candidates] as RecordedDetectorCandidate[]);
        const matches: DetectorMatchResult["matches"][number][] = [];
        const addMatch = (
          ruleOrdinal: number,
          predicate: (candidate: RecordedDetectorCandidate) => boolean,
          marker: string,
        ): void => {
          const candidateOrdinal = candidates.findIndex((candidate) =>
            predicate(candidate as RecordedDetectorCandidate)
            && candidate.value.includes(marker));
          if (candidateOrdinal < 0) return;
          const index = candidates[candidateOrdinal]!.value.indexOf(marker);
          matches.push(Object.freeze({
            ruleOrdinal,
            candidateOrdinal,
            index,
            length: marker.length,
            version: null,
          }));
        };
        addMatch(0, (candidate) => candidate.source === "html", "entry-signal");
        addMatch(1, (candidate) => candidate.source === "probe", "probe-signal");
        addMatch(
          2,
          (candidate) =>
            candidate.source === "url" && candidate.collector === "browser",
          "https://",
        );
        return Object.freeze({
          matches: Object.freeze(matches),
          errors: Object.freeze([]),
          completed: true,
          executions: matches.length,
        });
      },
      isAvailable: () => true,
      close: () => Promise.resolve(),
    });
    const detectorPool = makeDetectorPool(fullCalls, fullSignals);
    const shadowDetectorPools = Object.freeze({
      t1: makeDetectorPool(t1Calls, t1Signals),
      t2: makeDetectorPool(t2Calls, t2Signals),
    });
    const transport = new ScriptedTransport([
      [ENTRY_URL, htmlResponse(
        ENTRY_URL,
        `<html><head><meta name="fixture" content="${rawMarker}"></head>`
          + `<body>entry-signal<a href="${detailUrl}">Detail</a></body></html>`,
        { tlsIssuer: "CN=Shadow Fixture", tlsHandshakeMs: 2 },
      )],
      [detailUrl, htmlResponse(detailUrl, `<html>${rawMarker}</html>`)],
      [probeUrl, response(probeUrl, 200, { body: `probe-signal ${rawMarker}` })],
      [listingUrl, htmlResponse(listingUrl)],
    ]);
    const browserPool = new FakeBrowserPool({
      navigationLinks: { p1: [listingUrl] },
      limitHits: {
        p1: [Object.freeze({
          category: "inspection.domMatches",
          domSelectorOrdinal: 7,
        })],
        p2: [Object.freeze({
          category: "proxy.requestsPerPage",
          domSelectorOrdinal: null,
        })],
      },
      usage: {
        browserRequests: 9,
        browserTransferredBytes: 900,
        scriptBodiesInspected: 0,
      },
    });
    const snapshots: ShadowEvaluationSnapshot[] = [];
    const result = await scanDomain(DOMAIN, {
      runId: RUN_ID,
      config,
      provenance: provenanceFor(config, catalog),
      transport,
      robots: new FakeRobotsService(),
      browserPool,
      detectorPool,
      catalog,
    }, {
      ...deterministicOptions(),
      ...(shadow
        ? {
            shadowDetectorPools,
            onShadowSnapshot: (snapshot: ShadowEvaluationSnapshot) => {
              snapshots.push(snapshot);
            },
          }
        : {}),
    });
    return {
      calls: [fullCalls[0] ?? [], t1Calls[0] ?? [], t2Calls[0] ?? []],
      result,
      signals: [fullSignals[0], t1Signals[0], t2Signals[0]],
      snapshots,
    };
  };

  const enabled = await run(true);
  const disabled = await run(false);

  assert.equal(JSON.stringify(enabled.result), JSON.stringify(disabled.result));
  assert.equal(enabled.result.status, "partial");
  assert.equal(enabled.snapshots.length, 1);
  assert.equal(enabled.calls.length, 3);
  assert.deepEqual(enabled.signals.map((signal) => signal !== undefined), [
    true,
    false,
    false,
  ]);

  const [fullCandidates, t1Candidates, t2Candidates] = enabled.calls;
  assert.equal(
    fullCandidates?.some((candidate) => candidate.collector === "browser"),
    true,
  );
  assert.equal(
    t1Candidates?.some((candidate) =>
      candidate.source === "probe"
      || candidate.collector === "browser"
      || candidate.pageId === "p2"
      || candidate.pageId === "p3"),
    false,
  );
  assert.equal(
    t2Candidates?.some((candidate) => candidate.source === "probe"),
    true,
  );
  assert.equal(
    t2Candidates?.some((candidate) => candidate.pageId === "p2"),
    true,
  );
  assert.equal(
    t2Candidates?.some((candidate) =>
      candidate.collector === "browser" || candidate.pageId === "p3"),
    false,
  );

  const snapshot = enabled.snapshots[0]!;
  assert.deepEqual(snapshot.t1, {
    state: "available",
    directNames: ["Entry Parent"],
    inferredNames: ["Implied Child"],
    detectionStats: {
      rawDirect: 1,
      gatedDirect: 0,
      suppressedDirect: 0,
      retainedDirect: 1,
    },
    completed: true,
    errors: [],
  });
  assert.deepEqual(snapshot.t2, {
    state: "available",
    directNames: ["Entry Parent", "Probe Tech"],
    inferredNames: ["Implied Child"],
    detectionStats: {
      rawDirect: 2,
      gatedDirect: 0,
      suppressedDirect: 0,
      retainedDirect: 2,
    },
    completed: true,
    errors: [],
  });
  assert.deepEqual(snapshot.full, {
    directNames: [],
    inferredNames: [],
    status: "partial",
  });
  assert.deepEqual(snapshot.preBrowser, {
    entryOutcome: "html",
    entryStatusClass: "2xx",
    entryHtmlBytes: Buffer.byteLength(
      `<html><head><meta name="fixture" content="${rawMarker}"></head>`
        + `<body>entry-signal<a href="${detailUrl}">Detail</a></body></html>`,
      "utf8",
    ),
    entryTextCodePoints: "entry-signalDetail".length,
    staticNavigationLinks: 1,
    metadataEntries: 1,
    resourceEntries: 0,
    dnsRecords: 0,
    tlsIssuerPresent: true,
    t2Selected: true,
    t2Role: "detail",
    t2Outcome: "html",
    probesObserved: 1,
    httpRequests: 3,
    staticTransferredBytes: enabled.result.usage.staticTransferredBytes
      - Buffer.byteLength("<html><body>fixture</body></html>", "utf8"),
  });
  assert.deepEqual(snapshot.fullCost, {
    browserPagesAttempted: 3,
    browserPagesAdmitted: 3,
    browserRequests: 9,
    browserTransferredBytes: 900,
    browserMs: enabled.result.timings.browserMs,
  });
  assert.deepEqual(snapshot.browserLimitHits, [
    {
      pageId: "p1",
      category: "inspection.domMatches",
      domSelectorOrdinal: 7,
    },
    {
      pageId: "p2",
      category: "proxy.requestsPerPage",
      domSelectorOrdinal: null,
    },
  ]);
  assert.equal(JSON.stringify(snapshot).includes(rawMarker), false);
  assert.equal(Object.isFrozen(snapshot), true);
});

test("emits one shadow snapshot for controlled success, partial, and failed results", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const cases = [
    {
      expected: "success" as const,
      browserPool: new FakeBrowserPool(),
    },
    {
      expected: "partial" as const,
      browserPool: new FakeBrowserPool({
        pageErrors: {
          p1: scanError(
            "browser",
            "BROWSER_TIMEOUT",
            "p1",
            "The browser page exceeded its deadline.",
            true,
          ),
        },
        admittedPages: ["p1"],
      }),
    },
    {
      expected: "failed" as const,
      browserPool: new FakeBrowserPool(),
    },
  ];
  cases[2]!.browserPool.available = false;

  for (const [index, fixture] of cases.entries()) {
    const snapshots: ShadowEvaluationSnapshot[] = [];
    const transport = new ScriptedTransport(
      fixture.expected === "failed"
        ? []
        : [[ENTRY_URL, htmlResponse(ENTRY_URL)]],
    );
    const result = await scanDomain(DOMAIN, {
      runId: RUN_ID,
      config,
      provenance: provenanceFor(config, catalog),
      transport,
      robots: new FakeRobotsService(),
      browserPool: fixture.browserPool,
      detectorPool: new RecordingDetectorPool(catalog),
      catalog,
    }, {
      ...deterministicOptions(),
      shadowDetectorPools: isolatedShadowDetectorPools(catalog),
      onShadowSnapshot: (snapshot) => {
        snapshots.push(snapshot);
      },
    });

    assert.equal(result.status, fixture.expected, `case ${index}`);
    assert.equal(snapshots.length, 1, `case ${index}`);
    assert.equal(snapshots[0]?.full.status, fixture.expected, `case ${index}`);
  }
  assert.deepEqual(cases[2]!.browserPool.session.inputs, []);
});

test("propagates a shadow snapshot sink failure after closing domain resources", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const transport = new ScriptedTransport([
    [ENTRY_URL, htmlResponse(ENTRY_URL)],
  ]);
  const browserPool = new FakeBrowserPool();
  const sinkError = new Error("shadow sink rejected the snapshot");

  await assert.rejects(
    scanDomain(DOMAIN, {
      runId: RUN_ID,
      config,
      provenance: provenanceFor(config, catalog),
      transport,
      robots: new FakeRobotsService(),
      browserPool,
      detectorPool: new RecordingDetectorPool(catalog),
      catalog,
    }, {
      ...deterministicOptions(),
      shadowDetectorPools: isolatedShadowDetectorPools(catalog),
      onShadowSnapshot: () => {
        throw sinkError;
      },
    }),
    (error: unknown) => error === sinkError,
  );
  assert.equal(transport.sessions[0]?.closeCount, 1);
  assert.equal(browserPool.session.closeCount, 1);
});

test("continues the browser prefix after admitting a truncated browser draft", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const listingUrl = `${ENTRY_URL}collections/all`;
  const detailUrl = `${ENTRY_URL}products/widget`;
  const browserLimit = scanError(
    "browser",
    "BROWSER_LIMIT_EXCEEDED",
    "p1",
    "The browser observation exceeded a safety limit.",
  );
  const transport = new ScriptedTransport([
    [ENTRY_URL, htmlResponse(
      ENTRY_URL,
      `<html><body><a href="${detailUrl}">Detail</a></body></html>`,
    )],
    [listingUrl, htmlResponse(listingUrl, "<html><body>Listing</body></html>")],
    [detailUrl, htmlResponse(detailUrl, "<html><body>Detail</body></html>")],
  ]);
  const browserPool = new FakeBrowserPool({
    navigationLinks: { p1: [listingUrl] },
    pageErrors: { p1: browserLimit },
    admittedPages: ["p1"],
    continuationPages: ["p1"],
  });

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots: new FakeRobotsService(),
    browserPool,
    detectorPool: new RecordingDetectorPool(catalog),
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "partial");
  assert.deepEqual(result.pages, [
    {
      id: "p1",
      role: "entry",
      url: ENTRY_URL,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
    {
      id: "p2",
      role: "listing",
      url: listingUrl,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
    {
      id: "p3",
      role: "detail",
      url: detailUrl,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
  ]);
  assert.deepEqual(
    browserPool.session.inputs.map(({ pageId, url }) => ({ pageId, url })),
    [
      { pageId: "p1", url: ENTRY_URL },
      { pageId: "p2", url: listingUrl },
      { pageId: "p3", url: detailUrl },
    ],
  );
  assert.deepEqual(
    result.errors.map(({ stage, code }) => [stage, code]),
    [["browser", "BROWSER_LIMIT_EXCEEDED"]],
  );
  assertValidResult(result, config, true);
});

test("keeps an admitted browser draft but closes the prefix after a terminal failure", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const listingUrl = `${ENTRY_URL}collections/all`;
  const proxyFailure = scanError(
    "browser",
    "BROWSER_PROXY_FAILED",
    "p1",
    "The protected browser proxy failed.",
    true,
  );
  const transport = new ScriptedTransport([
    [ENTRY_URL, htmlResponse(ENTRY_URL, "<html><body>Entry</body></html>")],
    [listingUrl, htmlResponse(listingUrl, "<html><body>Listing</body></html>")],
  ]);
  const browserPool = new FakeBrowserPool({
    navigationLinks: { p1: [listingUrl] },
    pageErrors: { p1: proxyFailure },
    admittedPages: ["p1"],
  });

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots: new FakeRobotsService(),
    browserPool,
    detectorPool: new RecordingDetectorPool(catalog),
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "partial");
  assert.deepEqual(result.pages, [
    {
      id: "p1",
      role: "entry",
      url: ENTRY_URL,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
    {
      id: "p2",
      role: "listing",
      url: listingUrl,
      httpStatus: 200,
      collectors: ["http"],
    },
  ]);
  assert.deepEqual(
    browserPool.session.inputs.map(({ pageId, url }) => ({ pageId, url })),
    [{ pageId: "p1", url: ENTRY_URL }],
  );
  assert.deepEqual(
    result.errors.map(({ stage, code }) => [stage, code]),
    [["browser", "BROWSER_PROXY_FAILED"]],
  );
  assertValidResult(result, config, true);
});

test("collects bounded catalog probes before the single detector pass", async () => {
  const config = configWith();
  const probePaths = [
    "/exists.svg",
    "/magento_version",
    "/missing",
  ] as const;
  const catalog = catalogWith({ probePaths });
  const entryBody = "<html><body>fixture</body></html>";
  const probeUrls = probePaths.map((path) => new URL(path, ENTRY_URL).href);
  const transport = new ScriptedTransport([
    [ENTRY_URL, htmlResponse(ENTRY_URL, entryBody)],
    [probeUrls[0]!, response(probeUrls[0]!, 204)],
    [probeUrls[1]!, response(probeUrls[1]!, 200, {
      contentType: "application/octet-stream",
      body: "release=MAGENTO 2",
    })],
    [probeUrls[2]!, response(probeUrls[2]!, 404)],
  ]);
  const robots = new FakeRobotsService();
  const browserPool = new FakeBrowserPool();
  const detectorPool = new RecordingDetectorPool(catalog);

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "success");
  assert.deepEqual(
    transport.sessions[0]?.calls.map(({ url, purpose }) => [url, purpose]),
    [
      [ENTRY_URL, "page"],
      [probeUrls[0], "probe"],
      [probeUrls[1], "probe"],
      [probeUrls[2], "probe"],
    ],
  );
  assert.deepEqual(robots.checks, [ENTRY_URL, ...probeUrls]);
  assert.deepEqual(
    detectorPool.calls[0]
      ?.filter((candidate) => candidate.source === "probe")
      .map(({ collector, kind, pageId, key, value }) => [
        collector,
        kind,
        pageId,
        key,
        value,
      ]),
    [
      ["http", "value", null, probePaths[0], ""],
      ["http", "value", null, probePaths[1], "release=MAGENTO 2"],
    ],
  );
  assert.equal(result.pages.length, 1);
  assert.equal(result.usage.pagesVisited, 1);
  assert.equal(result.usage.httpRequests, 4);
  assert.equal(result.usage.probesIssued, 3);
  assert.equal(
    result.usage.staticTransferredBytes,
    Buffer.byteLength(entryBody) + Buffer.byteLength("release=MAGENTO 2"),
  );
  assert.equal(detectorPool.calls.length, 1);
  assertValidResult(result, config, true);
});

test("keeps an admitted probe and attributes a session deadline to HTTP", async () => {
  const config = configWith();
  const probePaths = ["/first", "/later"] as const;
  const catalog = catalogWith({ probePaths });
  const controller = new AbortController();
  const firstProbeUrl = new URL(probePaths[0], ENTRY_URL).href;
  const laterProbeUrl = new URL(probePaths[1], ENTRY_URL).href;
  const transport = new ScriptedTransport([
    [ENTRY_URL, htmlResponse(ENTRY_URL)],
    [firstProbeUrl, (request) => {
      controller.abort(new DOMException(
        "The active domain deadline was exceeded.",
        "TimeoutError",
      ));
      return response(request.url, 200, { body: "first" });
    }],
    [laterProbeUrl, response(laterProbeUrl, 200, { body: "unused" })],
  ], controller.signal);
  const robots = new FakeRobotsService();
  const browserPool = new FakeBrowserPool();
  const detectorPool = new RecordingDetectorPool(catalog);

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "partial");
  assert.deepEqual(
    transport.sessions[0]?.calls.map(({ url, purpose }) => [url, purpose]),
    [
      [ENTRY_URL, "page"],
      [firstProbeUrl, "probe"],
    ],
  );
  assert.deepEqual(
    detectorPool.calls[0]
      ?.filter((candidate) => candidate.source === "probe")
      .map(({ key, value }) => [key, value]),
    [[probePaths[0], "first"]],
  );
  assert.deepEqual(result.errors.map((error) => [
    error.stage,
    error.code,
    error.retryable,
  ]), [["http", "DOMAIN_DEADLINE_EXCEEDED", true]]);
  assert.equal(result.usage.probesIssued, 1);
  assert.equal(result.timings.detectMs === null, false);
  assertValidResult(result, config, true);
});

test("returns partial for a final non-HTML response after full-slot admission", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const transport = new ScriptedTransport([
    [ENTRY_URL, response(ENTRY_URL, 200, {
      contentType: "application/json",
      body: "{}",
    })],
  ]);
  const robots = new FakeRobotsService();
  const browserPool = new FakeBrowserPool();
  const detectorPool = new RecordingDetectorPool(catalog);

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "partial");
  assert.equal(result.finalUrl, ENTRY_URL);
  assert.deepEqual(result.pages, []);
  assert.deepEqual(result.technologies, []);
  assert.deepEqual(result.errors.map((error: ScanError) => error.code), [
    "UNSUPPORTED_CONTENT_TYPE",
  ]);
  assert.equal(browserPool.openCount, 1);
  assert.notEqual(result.timings.browserMs, null);
  assert.equal(result.usage.pagesVisited, 0);
  assert.equal(transport.sessions[0]?.closeCount, 1);
  assert.equal(detectorPool.calls.length, 1);
  assertValidResult(result, config, true);
});

test("returns failed when target discovery produced no detector signal", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const candidateUrls = [
    `https://${DOMAIN}/`,
    `https://www.${DOMAIN}/`,
    `http://${DOMAIN}/`,
    `http://www.${DOMAIN}/`,
  ];
  const transport = new ScriptedTransport(candidateUrls.map((url) =>
    [url, response(url, 404)] as const
  ));
  const robots = new FakeRobotsService();
  const browserPool = new FakeBrowserPool();
  const detectorPool = new RecordingDetectorPool(catalog);

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "failed");
  assert.equal(result.finalUrl, null);
  assert.deepEqual(result.pages, []);
  assert.deepEqual(result.technologies, []);
  assert.deepEqual(
    result.errors.map((error: ScanError) => error.code),
    ["TARGET_NOT_FOUND"],
  );
  assert.equal(result.usage.httpRequests, 4);
  assert.equal(browserPool.openCount, 1);
  assert.equal(detectorPool.calls.length, 0);
  assert.equal(transport.sessions[0]?.closeCount, 1);
  assert.deepEqual(result.detectionStats, {
    rawDirect: 0,
    gatedDirect: 0,
    suppressedDirect: 0,
    retainedDirect: 0,
  });
  assertValidResult(result, config, false);
});

test("preserves bounded signals and sorts deduplicated stage errors in a partial result", async () => {
  const config = configWith([
    [["limits", "pages", "visibleTextBytesPerPage"], 1],
  ]);
  const catalog = catalogWith({ tlsIssuer: true });
  const browserError = scanError(
    "browser",
    "BROWSER_LIMIT_EXCEEDED",
    "p1",
    "The browser observation exceeded a safety limit.",
  );
  const detectorError = scanError(
    "detect",
    "REGEX_WORKER_CRASH",
    null,
    "A detector worker stopped unexpectedly.",
    true,
  );
  const transport = new ScriptedTransport([
    [ENTRY_URL, htmlResponse(
      ENTRY_URL,
      "<html><body>long visible text</body></html>",
      { tlsIssuer: "x".repeat(config.limits.tls.issuerBytes + 1), tlsHandshakeMs: 3 },
    )],
  ]);
  const robots = new FakeRobotsService();
  const browserPool = new FakeBrowserPool({
    pageErrors: { p1: browserError },
    finishErrors: [browserError],
  });
  const detectorPool = new RecordingDetectorPool(catalog);
  detectorPool.result = Object.freeze({
    matches: Object.freeze([]),
    errors: Object.freeze([detectorError]),
    completed: false,
    executions: 1,
  });

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "partial");
  assert.deepEqual(result.pages, [{
    id: "p1",
    role: "entry",
    url: ENTRY_URL,
    httpStatus: 200,
    collectors: ["http"],
  }]);
  assert.deepEqual(
    result.errors.map((error: ScanError) => [error.stage, error.code]),
    [
      ["http", "HTTP_RESPONSE_LIMIT_EXCEEDED"],
      ["tls", "TLS_LIMIT_EXCEEDED"],
      ["browser", "BROWSER_LIMIT_EXCEEDED"],
      ["detect", "REGEX_WORKER_CRASH"],
    ],
  );
  assert.equal(
    result.errors.filter(
      (error: ScanError) => error.code === "BROWSER_LIMIT_EXCEEDED",
    ).length,
    1,
  );
  assert.equal(browserPool.session.finishCount, 1);
  assert.equal(browserPool.session.closeCount, 1);
  assert.equal(transport.sessions[0]?.closeCount, 1);
  assertValidResult(result, config, true);
});

test("fails before active-domain work when browser slot acquisition fails", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const transport = new ScriptedTransport([
    [ENTRY_URL, htmlResponse(ENTRY_URL)],
  ]);
  const robots = new FakeRobotsService();
  const browserPool = new FakeBrowserPool();
  browserPool.openError = new Error("Controlled browser slot failure.");
  const detectorPool = new RecordingDetectorPool(catalog);

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "failed");
  assert.deepEqual(result.pages, []);
  assert.equal(
    result.errors.some((error: ScanError) => error.code === "BROWSER_UNAVAILABLE"),
    true,
  );
  assert.notEqual(result.timings.browserMs, null);
  assert.equal(transport.sessions.length, 0);
  assert.equal(browserPool.closeCount, 0);
  assert.equal(detectorPool.closeCount, 0);
  assert.equal(robots.clearCount, 0);
  assertValidResult(result, config, false);
});

test("propagates a pre-aborted caller reason without starting domain work", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const transport = new ScriptedTransport([]);
  const robots = new FakeRobotsService();
  const browserPool = new FakeBrowserPool();
  const detectorPool = new RecordingDetectorPool(catalog);
  const controller = new AbortController();
  const reason = new DOMException("Controlled cancellation.", "AbortError");
  controller.abort(reason);

  await assert.rejects(
    scanDomain(DOMAIN, {
      runId: RUN_ID,
      config,
      provenance: provenanceFor(config, catalog),
      transport,
      robots,
      browserPool,
      detectorPool,
      catalog,
    }, deterministicOptions(controller.signal)),
    (error: unknown) => {
      assert.equal(error, reason);
      return true;
    },
  );

  assert.equal(transport.sessions.length, 0);
  assert.equal(robots.checks.length, 0);
  assert.equal(robots.cachedChecks.length, 0);
  assert.equal(browserPool.openCount, 0);
  assert.equal(detectorPool.calls.length, 0);
});

test("does not backfill after the reserved T2 page is denied by robots", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const listingUrl = `${ENTRY_URL}shop/a`;
  const deniedDetailUrl = `${ENTRY_URL}product/a`;
  const backupDetailUrl = `${ENTRY_URL}products/b`;
  const contentUrl = `${ENTRY_URL}about`;
  const transport = new ScriptedTransport([
    [ENTRY_URL, htmlResponse(
      ENTRY_URL,
      `<html><body>
        <a href="${deniedDetailUrl}">Preferred detail</a>
        <a href="${backupDetailUrl}">Backup detail</a>
        <a href="${listingUrl}">Listing</a>
        <a href="${contentUrl}">About</a>
      </body></html>`,
    )],
    [listingUrl, htmlResponse(listingUrl)],
  ]);
  const robots = new FakeRobotsService([deniedDetailUrl]);
  const browserPool = new FakeBrowserPool();
  const detectorPool = new RecordingDetectorPool(catalog);

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "success");
  assert.deepEqual(result.pages, [
    {
      id: "p1",
      role: "entry",
      url: ENTRY_URL,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
    {
      id: "p2",
      role: "listing",
      url: listingUrl,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
  ]);
  assert.deepEqual(robots.checks, [
    ENTRY_URL,
    deniedDetailUrl,
    listingUrl,
  ]);
  assert.equal(robots.checks.includes(backupDetailUrl), false);
  assert.equal(robots.checks.includes(contentUrl), false);
  assert.deepEqual(
    transport.sessions[0]?.calls.map((call) => call.url),
    [ENTRY_URL, listingUrl],
  );
  assert.deepEqual(
    browserPool.session.inputs.map(({ pageId, url }) => ({ pageId, url })),
    [
      { pageId: "p1", url: ENTRY_URL },
      { pageId: "p2", url: listingUrl },
    ],
  );
  assert.equal(browserPool.openCount, 1);
  assert.equal(browserPool.session.finishCount, 1);
  assert.equal(browserPool.session.closeCount, 1);
  assert.equal(transport.sessions[0]?.closeCount, 1);
  assertValidResult(result, config, true);
});

test("stops the browser prefix after a p2 HTTP failure while continuing p3 static collection", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const listingUrl = `${ENTRY_URL}collections/a`;
  const detailUrl = `${ENTRY_URL}products/a`;
  const transport = new ScriptedTransport([
    [ENTRY_URL, htmlResponse(
      ENTRY_URL,
      `<html><body>
        <a href="${listingUrl}">Listing</a>
        <a href="${detailUrl}">Detail</a>
      </body></html>`,
    )],
    [listingUrl, response(listingUrl, 404)],
    [detailUrl, htmlResponse(detailUrl)],
  ]);
  const robots = new FakeRobotsService();
  const browserPool = new FakeBrowserPool();
  const detectorPool = new RecordingDetectorPool(catalog);

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "partial");
  assert.deepEqual(result.pages, [
    {
      id: "p1",
      role: "entry",
      url: ENTRY_URL,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
    {
      id: "p2",
      role: "listing",
      url: listingUrl,
      httpStatus: 404,
      collectors: [],
    },
    {
      id: "p3",
      role: "detail",
      url: detailUrl,
      httpStatus: 200,
      collectors: ["http"],
    },
  ]);
  assert.deepEqual(
    result.errors.map((error: ScanError) => [error.code, error.pageId]),
    [["HTTP_REQUEST_FAILED", "p2"]],
  );
  assert.deepEqual(
    transport.sessions[0]?.calls.map((call) => call.url),
    [ENTRY_URL, listingUrl, detailUrl],
  );
  assert.deepEqual(
    browserPool.session.inputs.map(({ pageId, url }) => ({ pageId, url })),
    [{ pageId: "p1", url: ENTRY_URL }],
  );
  assert.equal(browserPool.openCount, 1);
  assert.equal(browserPool.session.finishCount, 1);
  assert.equal(browserPool.session.closeCount, 1);
  assert.equal(transport.sessions[0]?.closeCount, 1);
  assertValidResult(result, config, true);
});

test("rejects provenance and catalog identity mismatches before network work", async () => {
  const makeFixture = () => {
    const config = configWith();
    const catalog = catalogWith();
    const transport = new ScriptedTransport([]);
    const robots = new FakeRobotsService();
    const browserPool = new FakeBrowserPool();
    const detectorPool = new RecordingDetectorPool(catalog);
    return {
      runId: RUN_ID,
      config,
      catalog,
      transport,
      robots,
      browserPool,
      detectorPool,
      provenance: provenanceFor(config, catalog),
    };
  };
  const assertNoWork = (fixture: ReturnType<typeof makeFixture>): void => {
    assert.equal(fixture.transport.sessions.length, 0);
    assert.equal(fixture.robots.checks.length, 0);
    assert.equal(fixture.robots.cachedChecks.length, 0);
    assert.equal(fixture.browserPool.openCount, 0);
    assert.equal(fixture.detectorPool.calls.length, 0);
  };

  {
    const fixture = makeFixture();
    const provenance: Provenance = Object.freeze({
      ...fixture.provenance,
      configDigest: `sha256:${"b".repeat(64)}`,
    });

    await assert.rejects(
      scanDomain(DOMAIN, { ...fixture, provenance }, deterministicOptions()),
      /Provenance config digest does not match ScanConfig/u,
    );
    assertNoWork(fixture);
  }

  {
    const fixture = makeFixture();
    const provenance: Provenance = Object.freeze({
      ...fixture.provenance,
      catalog: Object.freeze({
        ...fixture.provenance.catalog,
        revision: "fixture-v2",
      }),
    });

    await assert.rejects(
      scanDomain(DOMAIN, { ...fixture, provenance }, deterministicOptions()),
      /Provenance catalog does not match the compiled catalog/u,
    );
    assertNoWork(fixture);
  }

  {
    const fixture = makeFixture();
    const mismatchedDetectorPool = new RecordingDetectorPool(catalogWith());

    await assert.rejects(
      scanDomain(DOMAIN, {
        ...fixture,
        detectorPool: mismatchedDetectorPool,
      }, deterministicOptions()),
      /Detector pool and catalog must share the same instance/u,
    );
    assertNoWork(fixture);
    assert.equal(mismatchedDetectorPool.calls.length, 0);
  }
});

test("returns an early failed record when the detector pool is unavailable", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const transport = new ScriptedTransport([]);
  const robots = new FakeRobotsService();
  const browserPool = new FakeBrowserPool();
  const detectorPool = new RecordingDetectorPool(catalog);
  detectorPool.available = false;

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "failed");
  assert.equal(result.finalUrl, null);
  assert.deepEqual(result.pages, []);
  assert.deepEqual(result.technologies, []);
  assert.deepEqual(result.errors.map((error: ScanError) => error.code), [
    "DETECTOR_UNAVAILABLE",
  ]);
  assert.equal(result.timings.detectMs, 0);
  assert.deepEqual(result.usage, {
    httpRequests: 0,
    browserRequests: 0,
    retries: 0,
    pagesVisited: 0,
    probesIssued: 0,
    scriptBodiesInspected: 0,
    staticTransferredBytes: 0,
    browserTransferredBytes: 0,
  });
  assert.equal(transport.sessions.length, 0);
  assert.equal(robots.checks.length, 0);
  assert.deepEqual(result.detectionStats, {
    rawDirect: 0,
    gatedDirect: 0,
    suppressedDirect: 0,
    retainedDirect: 0,
  });
  assert.equal(browserPool.openCount, 0);
  assert.equal(browserPool.session.finishCount, 0);
  assert.equal(browserPool.session.closeCount, 0);
  assert.equal(detectorPool.calls.length, 0);
  assertValidResult(result, config, false);
});

test("drops an internal candidate whose sanitized URL collides with the entry page", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const opaqueEntryUrl = `${ENTRY_URL}0123456789abcdef`;
  const collidingCandidateUrl = `${ENTRY_URL}fedcba9876543210`;
  const sanitizedUrl = `${ENTRY_URL}%5Bredacted%5D`;
  const redirect = Object.freeze({
    ...response(ENTRY_URL, 302),
    redirectUrl: opaqueEntryUrl,
  });
  const transport = new ScriptedTransport([
    [ENTRY_URL, redirect],
    [opaqueEntryUrl, htmlResponse(
      opaqueEntryUrl,
      `<html><body><a href="${collidingCandidateUrl}">Candidate</a></body></html>`,
    )],
  ]);
  const robots = new FakeRobotsService();
  const browserPool = new FakeBrowserPool();
  const detectorPool = new RecordingDetectorPool(catalog);

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "success");
  assert.equal(result.finalUrl, sanitizedUrl);
  assert.deepEqual(result.pages, [{
    id: "p1",
    role: "entry",
    url: sanitizedUrl,
    httpStatus: 200,
    collectors: ["http", "browser"],
  }]);
  assert.deepEqual(
    transport.sessions[0]?.calls.map((call) => call.url),
    [ENTRY_URL, opaqueEntryUrl],
  );
  assert.deepEqual(robots.checks, [
    ENTRY_URL,
    opaqueEntryUrl,
    collidingCandidateUrl,
  ]);
  assert.deepEqual(
    browserPool.session.inputs.map(({ pageId, url }) => ({ pageId, url })),
    [{ pageId: "p1", url: opaqueEntryUrl }],
  );
  assert.equal(browserPool.openCount, 1);
  assert.equal(browserPool.session.finishCount, 1);
  assert.equal(browserPool.session.closeCount, 1);
  assert.equal(transport.sessions[0]?.closeCount, 1);
  assertValidResult(result, config, true);
});

test("materializes a bounded final URL after redirect sanitization expands", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const expandingFinalUrl = `${ENTRY_URL}?${Array.from(
    { length: 200 },
    (_value, index) => `k${index}=`,
  ).join("&")}`;
  const redirect = Object.freeze({
    ...response(ENTRY_URL, 302),
    redirectUrl: expandingFinalUrl,
  });
  const transport = new ScriptedTransport([
    [ENTRY_URL, redirect],
    [expandingFinalUrl, response(expandingFinalUrl, 200, {
      contentType: "application/json",
      body: "{}",
    })],
  ]);
  const robots = new FakeRobotsService();
  const browserPool = new FakeBrowserPool();
  const detectorPool = new RecordingDetectorPool(catalog);

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "partial");
  const finalUrl = result.finalUrl;
  assert.ok(finalUrl !== null);
  assert.ok(finalUrl.length <= config.limits.url.codeUnits);
  assert.equal(sanitizeUrl(finalUrl), finalUrl);
  assert.deepEqual(result.pages, []);
  assert.deepEqual(result.errors.map((error: ScanError) => error.code), [
    "UNSUPPORTED_CONTENT_TYPE",
  ]);
  assert.deepEqual(
    transport.sessions[0]?.calls.map((call) => call.url),
    [ENTRY_URL, expandingFinalUrl],
  );
  assert.equal(browserPool.session.inputs.length, 0);
  assert.equal(browserPool.session.finishCount, 1);
  assert.equal(browserPool.session.closeCount, 1);
  assert.equal(transport.sessions[0]?.closeCount, 1);
  assertValidResult(result, config, true);
});

test("assigns p2 and p3 after ordering candidates by their sanitized public URLs", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const detailUrl = `${ENTRY_URL}a/Z/products/x`;
  const listingUrl = `${ENTRY_URL}a/ffffffffffffffff/collection`;
  const publicListingUrl = `${ENTRY_URL}a/%5Bredacted%5D/collection`;
  const transport = new ScriptedTransport([
    [ENTRY_URL, htmlResponse(
      ENTRY_URL,
      `<html><body>
        <a href="${detailUrl}">Detail</a>
        <a href="${listingUrl}">Listing</a>
      </body></html>`,
    )],
    [listingUrl, htmlResponse(listingUrl)],
    [detailUrl, htmlResponse(detailUrl)],
  ]);
  const robots = new FakeRobotsService();
  const browserPool = new FakeBrowserPool();
  const detectorPool = new RecordingDetectorPool(catalog);

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "success");
  assert.deepEqual(result.pages, [
    {
      id: "p1",
      role: "entry",
      url: ENTRY_URL,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
    {
      id: "p2",
      role: "listing",
      url: publicListingUrl,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
    {
      id: "p3",
      role: "detail",
      url: detailUrl,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
  ]);
  assert.deepEqual(
    transport.sessions[0]?.calls.map((call) => call.url),
    [ENTRY_URL, detailUrl, listingUrl],
  );
  assert.deepEqual(
    browserPool.session.inputs.map(({ pageId, url }) => ({ pageId, url })),
    [
      { pageId: "p1", url: ENTRY_URL },
      { pageId: "p2", url: listingUrl },
      { pageId: "p3", url: detailUrl },
    ],
  );
  assertValidResult(result, config, true);
});

test("reuses p2 after a redirect becomes robots-disallowed and keeps the browser prefix open", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const listingUrl = `${ENTRY_URL}collections/a`;
  const deniedRedirectUrl = `${ENTRY_URL}collections/blocked`;
  const detailUrl = `${ENTRY_URL}products/a`;
  const redirect = Object.freeze({
    ...response(listingUrl, 302),
    redirectUrl: deniedRedirectUrl,
  });
  const transport = new ScriptedTransport([
    [ENTRY_URL, htmlResponse(
      ENTRY_URL,
      `<html><body>
        <a href="${listingUrl}">Listing</a>
        <a href="${detailUrl}">Detail</a>
      </body></html>`,
    )],
    [listingUrl, redirect],
    [detailUrl, htmlResponse(detailUrl)],
  ]);
  const robots = new FakeRobotsService([deniedRedirectUrl]);
  const browserPool = new FakeBrowserPool();
  const detectorPool = new RecordingDetectorPool(catalog);

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "success");
  assert.deepEqual(result.pages, [
    {
      id: "p1",
      role: "entry",
      url: ENTRY_URL,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
    {
      id: "p2",
      role: "detail",
      url: detailUrl,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
  ]);
  assert.deepEqual(
    transport.sessions[0]?.calls.map((call) => call.url),
    [ENTRY_URL, listingUrl, detailUrl],
  );
  assert.deepEqual(robots.checks, [
    ENTRY_URL,
    listingUrl,
    deniedRedirectUrl,
    detailUrl,
  ]);
  assert.deepEqual(
    browserPool.session.inputs.map(({ pageId, url }) => ({ pageId, url })),
    [
      { pageId: "p1", url: ENTRY_URL },
      { pageId: "p2", url: detailUrl },
    ],
  );
  assert.equal(browserPool.session.finishCount, 1);
  assert.equal(browserPool.session.closeCount, 1);
  assert.equal(transport.sessions[0]?.closeCount, 1);
  assertValidResult(result, config, true);
});

test("preserves a protected DNS failure from p1 and exposes DNS timing", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const failure = new ProtectedTransportError(
    "DNS_LOOKUP_FAILED",
    "dns",
    false,
  );
  const transport = new ScriptedTransport([[ENTRY_URL, failure]]);
  const robots = new FakeRobotsService();
  const browserPool = new FakeBrowserPool();
  const detectorPool = new RecordingDetectorPool(catalog);

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "failed");
  assert.deepEqual(
    result.errors.map((error: ScanError) => [
      error.stage,
      error.code,
      error.retryable,
    ]),
    [["dns", "DNS_LOOKUP_FAILED", false]],
  );
  assert.notEqual(result.timings.dnsMs, null);
  assert.equal(result.timings.tlsMs, null);
  assert.deepEqual(
    transport.sessions[0]?.calls.map((call) => call.url),
    [ENTRY_URL],
  );
  assert.equal(browserPool.openCount, 1);
  assert.equal(browserPool.session.finishCount, 1);
  assert.equal(browserPool.session.closeCount, 1);
  assert.equal(transport.sessions[0]?.closeCount, 1);
  assertValidResult(result, config, false);
});

test("preserves a protected TLS failure from structural precheck with measured timing", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const failingListingUrl = `${ENTRY_URL}collections/a`;
  const detailUrl = `${ENTRY_URL}products/a`;
  const failure = new ProtectedTransportError(
    "TLS_CERTIFICATE_INVALID",
    "tls",
    false,
  );
  const transport = new ScriptedTransport([
    [ENTRY_URL, htmlResponse(
      ENTRY_URL,
      `<html><body>
        <a href="${failingListingUrl}">Listing</a>
        <a href="${detailUrl}">Detail</a>
      </body></html>`,
    )],
    [detailUrl, htmlResponse(detailUrl)],
  ]);
  const robots = new FakeRobotsService(
    [],
    new Map([[failingListingUrl, failure]]),
  );
  const browserPool = new FakeBrowserPool();
  const detectorPool = new RecordingDetectorPool(catalog);

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "partial");
  assert.deepEqual(result.pages, [
    {
      id: "p1",
      role: "entry",
      url: ENTRY_URL,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
    {
      id: "p2",
      role: "detail",
      url: detailUrl,
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
  ]);
  assert.deepEqual(
    result.errors.map((error: ScanError) => [
      error.stage,
      error.code,
      error.retryable,
    ]),
    [["tls", "TLS_CERTIFICATE_INVALID", false]],
  );
  assert.notEqual(result.timings.tlsMs, null);
  assert.ok((result.timings.tlsMs ?? 0) > 0);
  assert.deepEqual(
    transport.sessions[0]?.calls.map((call) => call.url),
    [ENTRY_URL, detailUrl],
  );
  assert.deepEqual(
    browserPool.session.inputs.map(({ pageId, url }) => ({ pageId, url })),
    [
      { pageId: "p1", url: ENTRY_URL },
      { pageId: "p2", url: detailUrl },
    ],
  );
  assertValidResult(result, config, true);
});

test("materializes a bounded partial result when JSONL output overflows", async () => {
  const config = configWith([
    [["limits", "output", "jsonlRecordBytes"], 65_536],
  ]);
  const ruleCount = config.limits.output.evidencePerTechnology;
  const technologyName = "Overflow fixture";
  const pattern = "x".repeat(config.limits.evidence.matchCodePoints);
  const rules: readonly CompiledFingerprintRule[] = Object.freeze(
    Array.from({ length: ruleCount }, (_, index) => Object.freeze({
      ruleId: `sha256:${index.toString(16).padStart(64, "0")}`,
      namespace: "test/pipeline:rule-v1",
      technology: technologyName,
      source: "html" as const,
      locator: null,
      locatorPattern: null,
      original: pattern,
      pattern,
      matchMode: "regex" as const,
      confidence: 100,
      versionTemplate: null,
    })),
  );
  const category = Object.freeze({ id: 1, name: "Fixture category" });
  const baseCatalog = catalogWith();
  const catalog: CompiledFingerprintCatalog = Object.freeze({
    ...baseCatalog,
    categories: Object.freeze([category]),
    technologies: Object.freeze([Object.freeze({
      name: technologyName,
      categories: Object.freeze([category]),
      requires: Object.freeze([]),
      requiresCategory: Object.freeze([]),
      implies: Object.freeze([]),
      excludes: Object.freeze([]),
    })]),
    rules,
    declarationCount: rules.length,
    regexSourceCount: rules.length,
    regexSourceCodeUnits: rules.length * pattern.length,
  });
  const transport = new ScriptedTransport([
    [ENTRY_URL, htmlResponse(
      ENTRY_URL,
      `<html><body>${"x".repeat(1_024)}</body></html>`,
    )],
  ]);
  const robots = new FakeRobotsService();
  const browserPool = new FakeBrowserPool();
  const detectorCalls: DetectorCandidate[][] = [];
  const detectorPool: DetectorPool = {
    catalog,
    async match(candidates, signal): Promise<DetectorMatchResult> {
      signal?.throwIfAborted();
      detectorCalls.push([...candidates]);
      const candidateOrdinal = candidates.findIndex(
        (candidate) => candidate.source === "html",
      );
      assert.notEqual(candidateOrdinal, -1);
      const candidate = candidates[candidateOrdinal];
      assert.notEqual(candidate, undefined);
      const matchIndex = candidate!.value.indexOf(pattern);
      assert.notEqual(matchIndex, -1);
      return Object.freeze({
        matches: Object.freeze(rules.map((_rule, ruleOrdinal) => Object.freeze({
          ruleOrdinal,
          candidateOrdinal,
          index: matchIndex,
          length: pattern.length,
          version: null,
        }))),
        errors: Object.freeze([]),
        completed: true,
        executions: rules.length,
      });
    },
    isAvailable: () => true,
    close: async () => {},
  };

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(detectorCalls.length, 1);
  assert.equal(result.status, "partial");
  assert.deepEqual(result.technologies, []);
  assert.deepEqual(result.errors.map((error: ScanError) => error.code), [
    "RESULT_LIMIT_EXCEEDED",
  ]);
  assert.deepEqual(result.detectionStats, {
    rawDirect: 1,
    gatedDirect: 0,
    suppressedDirect: 0,
    retainedDirect: 1,
  });
  assert.ok(
    Buffer.byteLength(`${JSON.stringify(result)}\n`, "utf8")
      <= config.limits.output.jsonlRecordBytes,
  );
  assertValidResult(result, config, true);
});

test("starts the active-domain deadline at browser admission before context setup", async () => {
  const config = configWith([
    [["limits", "timeMs", "activeDomain"], 1],
  ]);
  const catalog = catalogWith();
  const transport = new ScriptedTransport([]);
  const robots = new FakeRobotsService();
  const browserPool = new FakeBrowserPool();
  const detectorPool = new RecordingDetectorPool(catalog);
  let contextSetupStarted = false;
  browserPool.afterAdmission = async (signal) => {
    contextSetupStarted = true;
    await new Promise<void>((resolve) => {
      if (signal?.aborted === true) {
        resolve();
        return;
      }
      const fallback = setTimeout(resolve, 50);
      signal?.addEventListener("abort", () => {
        clearTimeout(fallback);
        resolve();
      }, { once: true });
    });
  };

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(contextSetupStarted, true);
  assert.equal(result.status, "failed");
  assert.deepEqual(result.errors.map((error: ScanError) => [
    error.stage,
    error.code,
  ]), [["browser", "DOMAIN_DEADLINE_EXCEEDED"]]);
  assert.ok(result.timings.totalMs > 0);
  assert.notEqual(result.timings.browserMs, null);
  assert.equal(transport.sessions.length, 0);
  assert.equal(robots.checks.length, 0);
  assert.equal(browserPool.openCount, 1);
  assert.equal(detectorPool.calls.length, 0);
  assertValidResult(result, config, false);
});

test("reports a deadline exceeded when synchronous materialization crosses the active budget", async () => {
  const config = configWith();
  const catalog = catalogWith();
  const transport = new ScriptedTransport([
    [ENTRY_URL, htmlResponse(ENTRY_URL)],
  ]);
  const robots = new FakeRobotsService();
  let domainWorkClosed = false;
  const browserPool = new FakeBrowserPool({
    onClose: () => {
      domainWorkClosed = true;
    },
  });
  const detectorPool = new RecordingDetectorPool(catalog);
  let monotonicReads = 0;
  let postWorkReads = 0;
  let admissionStartObserved = false;
  const monotonicClock = (): number => {
    monotonicReads += 1;
    if (!domainWorkClosed) return 0;
    postWorkReads += 1;
    return config.limits.timeMs.activeDomain + postWorkReads;
  };
  browserPool.afterAdmission = async () => {
    assert.equal(domainWorkClosed, false);
    assert.equal(monotonicReads, 1);
    admissionStartObserved = true;
  };

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, {
    wallClock: (): Date => new Date(SCANNED_AT),
    monotonicClock,
  });

  assert.equal(admissionStartObserved, true);
  assert.equal(domainWorkClosed, true);
  assert.ok(postWorkReads > 0);
  assert.equal(result.status, "partial");
  assert.deepEqual(result.pages, [{
    id: "p1",
    role: "entry",
    url: ENTRY_URL,
    httpStatus: 200,
    collectors: ["http", "browser"],
  }]);
  assert.deepEqual(result.errors.map((error: ScanError) => [
    error.stage,
    error.code,
  ]), [["detect", "DOMAIN_DEADLINE_EXCEEDED"]]);
  assert.ok(result.timings.totalMs >= config.limits.timeMs.activeDomain);
  assert.equal(browserPool.openCount, 1);
  assert.equal(browserPool.session.finishCount, 1);
  assert.equal(browserPool.session.closeCount, 1);
  assert.equal(transport.sessions[0]?.closeCount, 1);
  assertValidResult(result, config, true);
});

test("feeds the single reserved-page robots check into detector evidence", async () => {
  const config = configWith();
  const detailUrl = `${ENTRY_URL}products/a`;
  const marker = "technology-marker";
  const robotsText = `User-agent: *\n# ${marker}`;
  const ruleId = `sha256:${"b".repeat(64)}`;
  const category = Object.freeze({ id: 1, name: "Fixture category" });
  const rule: CompiledFingerprintRule = Object.freeze({
    ruleId,
    namespace: "test/pipeline:rule-v1",
    technology: "Robots fixture",
    source: "robots",
    locator: null,
    locatorPattern: null,
    original: marker,
    pattern: marker,
    matchMode: "regex",
    confidence: 100,
    versionTemplate: null,
  });
  const baseCatalog = catalogWith();
  const catalog: CompiledFingerprintCatalog = Object.freeze({
    ...baseCatalog,
    categories: Object.freeze([category]),
    technologies: Object.freeze([Object.freeze({
      name: "Robots fixture",
      categories: Object.freeze([category]),
      requires: Object.freeze([]),
      requiresCategory: Object.freeze([]),
      implies: Object.freeze([]),
      excludes: Object.freeze([]),
    })]),
    rules: Object.freeze([rule]),
    declarationCount: 1,
    regexSourceCount: 1,
    regexSourceCodeUnits: marker.length,
  });
  const transport = new ScriptedTransport([
    [ENTRY_URL, htmlResponse(
      ENTRY_URL,
      `<html><body><a href="${detailUrl}">Detail</a></body></html>`,
    )],
    [detailUrl, htmlResponse(detailUrl)],
  ]);
  const robots = new FakeRobotsService(
    [],
    new Map(),
    new Map([[detailUrl, [robotsText]]]),
  );
  const browserPool = new FakeBrowserPool();
  let detectorCandidates: readonly DetectorCandidate[] = Object.freeze([]);
  const detectorPool: DetectorPool = {
    catalog,
    async match(candidates, signal): Promise<DetectorMatchResult> {
      signal?.throwIfAborted();
      detectorCandidates = Object.freeze([...candidates]);
      const candidateOrdinal = candidates.findIndex(
        (candidate) =>
          candidate.source === "robots" && candidate.value === robotsText,
      );
      assert.notEqual(candidateOrdinal, -1);
      const matchIndex = candidates[candidateOrdinal]?.value.indexOf(marker) ?? -1;
      assert.notEqual(matchIndex, -1);
      return Object.freeze({
        matches: Object.freeze([Object.freeze({
          ruleOrdinal: 0,
          candidateOrdinal,
          index: matchIndex,
          length: marker.length,
          version: null,
        })]),
        errors: Object.freeze([]),
        completed: true,
        executions: 1,
      });
    },
    isAvailable: () => true,
    close: async () => {},
  };

  const result = await scanDomain(DOMAIN, {
    runId: RUN_ID,
    config,
    provenance: provenanceFor(config, catalog),
    transport,
    robots,
    browserPool,
    detectorPool,
    catalog,
  }, deterministicOptions());

  assert.equal(result.status, "success");
  assert.equal(
    robots.checks.filter((url) => url === detailUrl).length,
    1,
  );
  assert.deepEqual(
    detectorCandidates
      .filter((candidate) => candidate.source === "robots")
      .map((candidate) => candidate.value),
    [robotsText],
  );
  assert.equal(result.technologies[0]?.name, "Robots fixture");
  assert.deepEqual(result.detectionStats, {
    rawDirect: 1,
    gatedDirect: 0,
    suppressedDirect: 0,
    retainedDirect: 1,
  });
  assert.deepEqual(result.technologies[0]?.evidence, [
    {
      collector: "http",
      source: "robots",
      pageId: null,
      key: null,
      match: {
        kind: "redacted",
        value: null,
        truncated: false,
      },
      ruleId,
      pattern: marker,
      confidence: 100,
      version: null,
    },
  ]);
  assertValidResult(result, config, true);
});
