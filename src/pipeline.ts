import { computeConfigDigest, type ScanConfig } from "./config.ts";
import {
  BrowserLifecycleFailure,
  type BrowserDomainResult,
  type BrowserDomainSession,
  type BrowserPageCollection,
  type BrowserPool,
} from "./crawl/browser.ts";
import {
  collectHttpEntry,
  collectHttpPage,
} from "./crawl/http.ts";
import { collectInfrastructure } from "./crawl/infrastructure.ts";
import { collectCatalogProbes } from "./crawl/probe.ts";
import type {
  RobotsCheck,
  RobotsPolicyService,
} from "./crawl/robots.ts";
import { RobotsPolicyError } from "./crawl/robots.ts";
import type {
  ProtectedHttpTransport,
  ProtectedTransportSession,
} from "./crawl/transport.ts";
import { ProtectedTransportError } from "./crawl/transport.ts";
import type { CompiledFingerprintCatalog } from "./detect/catalog.ts";
import { detectHttp, type DetectHttpResult } from "./detect/engine.ts";
import type { DetectorPool } from "./detect/pool.ts";
import {
  createShadowEvaluationSnapshot,
  SHADOW_EVALUATION_PROTOCOL_REVISION,
  shadowDetectorView,
  shadowFullLabel,
  unavailableShadowDetectorView,
  type ShadowBrowserLimitHit,
  type ShadowDetectorView,
  type ShadowEvaluationSnapshot,
  type ShadowInternalOutcome,
  type ShadowPreBrowserFeatures,
  type ShadowStatusClass,
} from "./evaluation.ts";
import {
  ERROR_STAGES,
  sanitizeUrl,
  validateDomainResult,
  type DomainResult,
  type DetectionStats,
  type DomainStatus,
  type ErrorCode,
  type ErrorStage,
  type HttpEntryResult,
  type HttpPageResult,
  type HttpProbeResult,
  type HttpRobotsObservation,
  type InfrastructureResult,
  type PageCollectors,
  type PageId,
  type PageRecord,
  type PageRole,
  type Provenance,
  type ScanError,
  type Technology,
  type Timings,
  type Usage,
} from "./model.ts";
import { normalizeHostname } from "./network-policy.ts";

const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SENSITIVE_SEGMENTS = new Set([
  "auth",
  "login",
  "log-in",
  "signin",
  "sign-in",
  "signup",
  "register",
  "account",
  "admin",
  "wp-admin",
  "cart",
  "basket",
  "bag",
  "checkout",
  "logout",
  "search",
  "legal",
  "privacy",
  "terms",
  "policy",
  "cookie",
  "cookies",
]);
const DETAIL_SEGMENTS = ["product", "products", "item", "items"] as const;
const LISTING_SEGMENTS = [
  "shop",
  "store",
  "catalog",
  "category",
  "categories",
  "collection",
  "collections",
  "product-category",
] as const;
const FILE_SUFFIX = /\.[A-Za-z0-9]+$/u;
const PIPELINE_MESSAGES = Object.freeze({
  BROWSER_UNAVAILABLE: "The protected Chromium collector is unavailable.",
  BROWSER_NAVIGATION_FAILED: "The browser could not collect the selected page.",
  BROWSER_PROXY_FAILED: "The protected browser proxy failed.",
  DETECTOR_UNAVAILABLE: "The isolated detector pool is unavailable.",
  DOMAIN_DEADLINE_EXCEEDED: "The active domain deadline was exceeded.",
  ROBOTS_UNAVAILABLE: "The robots policy is unavailable.",
  RESULT_LIMIT_EXCEEDED: "The result exceeded a materialization output limit.",
});
const stageRank = new Map(
  ERROR_STAGES.map((stage, index) => [stage, index]),
);

export interface ScanDomainContext {
  readonly runId: string;
  readonly config: ScanConfig;
  readonly provenance: Provenance;
  readonly transport: ProtectedHttpTransport;
  readonly robots: RobotsPolicyService;
  readonly browserPool: BrowserPool;
  readonly detectorPool: DetectorPool;
  readonly catalog: CompiledFingerprintCatalog;
}

export interface ScanDomainOptions {
  readonly signal?: AbortSignal;
  readonly wallClock?: () => Date;
  readonly monotonicClock?: () => number;
  readonly shadowDetectorPools?: ShadowDetectorPools;
  readonly onShadowSnapshot?: (
    snapshot: ShadowEvaluationSnapshot,
  ) => void | Promise<void>;
}

export interface ShadowDetectorPools {
  readonly t1: DetectorPool;
  readonly t2: DetectorPool;
}

export interface SelectedInternalPage {
  readonly role: "detail" | "listing" | "content";
  readonly url: string;
}

interface RankedPage extends SelectedInternalPage {
  readonly tokenRank: number;
  readonly pathnameLength: number;
}

interface PlannedInternalPage extends SelectedInternalPage {
  readonly reservedForTier2: boolean;
}

interface CollectedInternalPage {
  readonly candidate: PlannedInternalPage;
  readonly publicUrl: string | null;
  readonly result: HttpPageResult | null;
  readonly outcome: Exclude<ShadowInternalOutcome, "not-selected">;
  readonly completed: boolean;
}

interface TierObservationView {
  readonly httpPages: readonly HttpPageResult[];
  readonly probes: HttpProbeResult["observations"];
  readonly robots: readonly HttpRobotsObservation[];
  readonly browserPages: BrowserDomainResult["pages"];
  readonly infrastructure: InfrastructureResult["observations"];
}

interface TierObservationViews {
  readonly t1: TierObservationView;
  readonly t2: TierObservationView;
  readonly full: TierObservationView;
}

interface MeasuredRobots {
  readonly service: RobotsPolicyService;
  elapsed(): number;
}

function compareString(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareNullableString(
  left: string | null,
  right: string | null,
): number {
  if (left === right) return 0;
  if (left === null) return -1;
  if (right === null) return 1;
  return compareString(left, right);
}

function compareErrors(left: ScanError, right: ScanError): number {
  return (stageRank.get(left.stage) ?? Number.MAX_SAFE_INTEGER)
      - (stageRank.get(right.stage) ?? Number.MAX_SAFE_INTEGER)
    || compareString(left.code, right.code)
    || compareNullableString(left.pageId, right.pageId)
    || compareNullableString(left.ruleId, right.ruleId)
    || compareString(left.message, right.message);
}

function scanError(
  stage: ErrorStage,
  code: ErrorCode,
  retryable: boolean,
  pageId: PageId | null = null,
): ScanError {
  const message = PIPELINE_MESSAGES[
    code as keyof typeof PIPELINE_MESSAGES
  ];
  if (message === undefined) {
    throw new TypeError(`Pipeline has no controlled message for ${code}`);
  }
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

function observedError(
  error: ProtectedTransportError | RobotsPolicyError,
  pageId: PageId | null = null,
): ScanError {
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

function sanitizationLimits(config: ScanConfig) {
  return Object.freeze({
    urlCodeUnits: config.limits.url.codeUnits,
    safePathSegmentCodeUnits: config.limits.evidence.safePathSegmentCodeUnits,
    hexTokenMinCodeUnits: config.limits.evidence.hexTokenMinCodeUnits,
    base64UrlTokenMinCodeUnits:
      config.limits.evidence.base64UrlTokenMinCodeUnits,
  });
}

function sanitizeNetworkUrl(value: string, config: ScanConfig): string {
  return sanitizeUrl(value, sanitizationLimits(config));
}

function decodedSegments(url: URL): readonly string[] | null {
  const segments: string[] = [];
  for (const encoded of url.pathname.split("/")) {
    if (encoded === "") continue;
    let decoded: string;
    try {
      decoded = decodeURIComponent(encoded).toLowerCase();
    } catch {
      return null;
    }
    if (decoded === "" || decoded.includes("/") || decoded.includes("\\")) {
      return null;
    }
    segments.push(decoded);
  }
  return segments;
}

function firstRank(
  segments: readonly string[],
  tokens: readonly string[],
  requireFollower: boolean,
): number | null {
  let best: number | null = null;
  for (let index = 0; index < segments.length; index += 1) {
    if (requireFollower && index + 1 >= segments.length) continue;
    const rank = tokens.indexOf(segments[index] ?? "");
    if (rank >= 0 && (best === null || rank < best)) best = rank;
  }
  return best;
}

function rankCandidate(
  entry: URL,
  value: string,
  config: ScanConfig,
): RankedPage | null {
  if (
    value.length === 0
    || value.length > config.limits.url.codeUnits
    || !value.isWellFormed()
  ) {
    return null;
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (
    (url.protocol !== "http:" && url.protocol !== "https:")
    || url.origin !== entry.origin
    || url.username !== ""
    || url.password !== ""
    || url.search !== ""
    || url.hash !== ""
  ) {
    return null;
  }
  const canonical = url.href;
  if (
    canonical.length > config.limits.url.codeUnits
    || canonical === entry.href
    || url.pathname === "/"
  ) {
    return null;
  }
  const segments = decodedSegments(url);
  if (
    segments === null
    || segments.length === 0
    || segments.some((segment) => SENSITIVE_SEGMENTS.has(segment))
    || FILE_SUFFIX.test(segments.at(-1) ?? "")
  ) {
    return null;
  }
  const detailRank = firstRank(segments, DETAIL_SEGMENTS, true);
  if (detailRank !== null) {
    return {
      role: "detail",
      url: canonical,
      tokenRank: detailRank,
      pathnameLength: url.pathname.length,
    };
  }
  const listingRank = firstRank(segments, LISTING_SEGMENTS, false);
  return {
    role: listingRank === null ? "content" : "listing",
    url: canonical,
    tokenRank: listingRank ?? 0,
    pathnameLength: url.pathname.length,
  };
}

function compareRanked(left: RankedPage, right: RankedPage): number {
  return left.tokenRank - right.tokenRank
    || left.pathnameLength - right.pathnameLength
    || compareString(left.url, right.url);
}

export function selectInternalPages(
  entryUrl: string,
  staticLinks: readonly string[],
  renderedLinks: readonly string[],
  config: ScanConfig,
): readonly SelectedInternalPage[] {
  let entry: URL;
  try {
    entry = new URL(entryUrl);
  } catch {
    return Object.freeze([]);
  }
  const byUrl = new Map<string, RankedPage>();
  for (const value of [...staticLinks, ...renderedLinks]) {
    const candidate = rankCandidate(entry, value, config);
    if (candidate !== null) byUrl.set(candidate.url, candidate);
  }
  const candidates = [...byUrl.values()];
  const detail = candidates
    .filter((candidate) => candidate.role === "detail")
    .sort(compareRanked)[0];
  const listing = candidates
    .filter((candidate) => candidate.role === "listing")
    .sort(compareRanked)[0]
    ?? candidates
      .filter((candidate) => candidate.role === "content")
      .sort(compareRanked)[0];
  const cap = Math.max(0, config.limits.pages.topLevelPerDomain - 1);
  return Object.freeze(
    [detail, listing]
      .filter((candidate): candidate is RankedPage => candidate !== undefined)
      .sort((left, right) => compareString(left.url, right.url))
      .slice(0, cap)
      .map((candidate) => Object.freeze({
        role: candidate.role,
        url: candidate.url,
      })),
  );
}

export function selectTier2InternalPage(
  entryUrl: string,
  staticLinks: readonly string[],
  config: ScanConfig,
): SelectedInternalPage | null {
  return selectInternalPages(entryUrl, staticLinks, [], config)[0] ?? null;
}

function planFullInternalPages(
  entryUrl: string,
  staticLinks: readonly string[],
  renderedLinks: readonly string[],
  reservedForTier2: SelectedInternalPage | null,
  config: ScanConfig,
): readonly PlannedInternalPage[] {
  const cap = Math.max(0, config.limits.pages.topLevelPerDomain - 1);
  if (cap === 0) return Object.freeze([]);

  const fullCandidates = selectInternalPages(
    entryUrl,
    staticLinks,
    renderedLinks,
    config,
  );
  if (reservedForTier2 === null) {
    return Object.freeze(fullCandidates.slice(0, cap).map((candidate) =>
      Object.freeze({
        ...candidate,
        reservedForTier2: false,
      })));
  }

  const reservedUsesDetailSlot = reservedForTier2.role === "detail";
  const additional = fullCandidates.find((candidate) =>
    candidate.url !== reservedForTier2.url
    && (candidate.role === "detail") !== reservedUsesDetailSlot);
  return Object.freeze([
    Object.freeze({
      ...reservedForTier2,
      reservedForTier2: true,
    }),
    ...(additional === undefined
      ? []
      : [Object.freeze({
        ...additional,
        reservedForTier2: false,
      })]),
  ].slice(0, cap));
}

function robotsObservation(check: RobotsCheck): HttpRobotsObservation | null {
  return check.robotsText === null
    ? null
    : Object.freeze({
      ownerOrigin: check.ownerOrigin,
      fetchedUrl: check.fetchedUrl,
      text: check.robotsText,
    });
}

function robotsServiceWithInitialCheck(
  source: RobotsPolicyService,
  initialUrl: string,
  initialCheck: RobotsCheck,
): RobotsPolicyService {
  return Object.freeze({
    check(
      session: ProtectedTransportSession,
      url: string,
    ): Promise<RobotsCheck> {
      return url === initialUrl
        ? Promise.resolve(initialCheck)
        : source.check(session, url);
    },
    allowsCached(url: string): boolean {
      return source.allowsCached(url);
    },
    clear(): void {
      source.clear();
    },
  });
}

function remapErrorPageId(
  error: ScanError,
  from: PageId,
  to: PageId,
): ScanError {
  return error.pageId !== from
    ? error
    : Object.freeze({ ...error, pageId: to });
}

export function remapHttpPageResultPageId(
  result: HttpPageResult,
  pageId: PageId,
): HttpPageResult {
  const currentPageId = result.kind === "html"
    ? result.page.pageId
    : result.pageId;
  if (currentPageId === pageId) return result;
  const remapErrors = (): readonly ScanError[] => Object.freeze(
    result.errors.map((error) => remapErrorPageId(error, currentPageId, pageId)),
  );

  if (result.kind === "html") {
    return Object.freeze({
      ...result,
      page: Object.freeze({ ...result.page, pageId }),
      errors: remapErrors(),
    });
  }
  if (result.kind === "non-html") {
    return Object.freeze({
      ...result,
      pageId,
      errors: remapErrors(),
    });
  }
  if (result.kind === "failed") {
    return Object.freeze({
      ...result,
      pageId,
      errors: remapErrors() as readonly [ScanError],
    });
  }
  return Object.freeze({ ...result, pageId });
}

function tierObservationView(
  values: TierObservationView,
): TierObservationView {
  return Object.freeze({
    httpPages: Object.freeze([...values.httpPages]),
    probes: Object.freeze([...values.probes]),
    robots: Object.freeze([...values.robots]),
    browserPages: Object.freeze([...values.browserPages]),
    infrastructure: values.infrastructure,
  });
}

function elapsed(
  now: () => number,
  started: number,
): number {
  return Math.ceil(Math.max(0, now() - started));
}

function measuredRobotsService(
  source: RobotsPolicyService,
  now: () => number,
): MeasuredRobots {
  let milliseconds = 0;
  const recordElapsed = (started: number): void => {
    milliseconds += Math.max(0, now() - started);
  };
  const service: RobotsPolicyService = Object.freeze({
    async check(
      session: ProtectedTransportSession,
      url: string,
    ): Promise<RobotsCheck> {
      const started = now();
      try {
        return await source.check(session, url);
      } finally {
        recordElapsed(started);
      }
    },
    allowsCached(url: string): boolean {
      const started = now();
      try {
        return source.allowsCached(url) === true;
      } finally {
        recordElapsed(started);
      }
    },
    clear(): void {
      source.clear();
    },
  });
  return Object.freeze({
    service,
    elapsed: (): number => Math.ceil(milliseconds),
  });
}

function deduplicateErrors(
  values: readonly ScanError[],
): readonly ScanError[] {
  const unique = new Map<string, ScanError>();
  for (const error of values) {
    unique.set(JSON.stringify([
      error.stage,
      error.code,
      error.pageId,
      error.ruleId,
      error.message,
    ]), error);
  }
  return Object.freeze([...unique.values()].sort(compareErrors));
}

function boundErrors(
  values: readonly ScanError[],
  config: ScanConfig,
): { readonly errors: readonly ScanError[]; readonly overflow: boolean } {
  const errors = deduplicateErrors(values);
  if (errors.length <= config.limits.output.errorsPerDomain) {
    return { errors, overflow: false };
  }
  const limit = scanError("detect", "RESULT_LIMIT_EXCEEDED", false);
  const prefix = errors.slice(0, Math.max(0, config.limits.output.errorsPerDomain - 1));
  return {
    errors: deduplicateErrors([...prefix, limit]),
    overflow: true,
  };
}

function preflight(context: ScanDomainContext): void {
  if (!RUN_ID.test(context.runId)) {
    throw new TypeError("runId must be a canonical UUID v4");
  }
  const digest = computeConfigDigest(context.config);
  if (context.provenance.configDigest !== digest) {
    throw new TypeError("Provenance config digest does not match ScanConfig");
  }
  if (
    context.provenance.catalog.source !== context.catalog.source
    || context.provenance.catalog.revision !== context.catalog.revision
    || context.provenance.catalog.digest !== context.catalog.digest
  ) {
    throw new TypeError("Provenance catalog does not match the compiled catalog");
  }
  if (context.detectorPool.catalog !== context.catalog) {
    throw new TypeError("Detector pool and catalog must share the same instance");
  }
  if (
    context.provenance.runtime.node !== process.versions.node
    || context.provenance.runtime.playwright
      !== context.browserPool.runtime.playwright
    || context.provenance.runtime.chromiumRevision
      !== context.browserPool.runtime.chromiumRevision
  ) {
    throw new TypeError("Runtime provenance does not match the active runtime");
  }
}

function stageTiming(
  stage: ErrorStage,
): keyof Timings {
  return `${stage === "target" ? "target" : stage}Ms` as keyof Timings;
}

function zeroUsage(): Usage {
  return Object.freeze({
    httpRequests: 0,
    browserRequests: 0,
    retries: 0,
    pagesVisited: 0,
    probesIssued: 0,
    scriptBodiesInspected: 0,
    staticTransferredBytes: 0,
    browserTransferredBytes: 0,
  });
}

function zeroDetectionStats(): DetectionStats {
  return Object.freeze({
    rawDirect: 0,
    gatedDirect: 0,
    suppressedDirect: 0,
    retainedDirect: 0,
  });
}

function earlyFailure(
  domain: string,
  context: ScanDomainContext,
  error: ScanError,
  scannedAt: string,
  totalMs = 0,
): DomainResult {
  const values: Record<keyof Timings, number | null> = {
    totalMs,
    targetMs: null,
    robotsMs: null,
    httpMs: null,
    dnsMs: null,
    tlsMs: null,
    browserMs: null,
    detectMs: null,
  };
  values[stageTiming(error.stage)] = totalMs;
  const result: DomainResult = Object.freeze({
    schemaVersion: 1 as const,
    runId: context.runId,
    domain,
    scannedAt,
    status: "failed" as const,
    finalUrl: null,
    scanMode: "full" as const,
    pages: Object.freeze([]),
    technologies: Object.freeze([]),
    detectionStats: zeroDetectionStats(),
    errors: Object.freeze([error]),
    timings: Object.freeze(values as unknown as Timings),
    usage: zeroUsage(),
    provenance: context.provenance,
  });
  return validateDomainResult(result, {
    scanConfig: context.config,
    expectedConfigDigest: context.provenance.configDigest,
    signalAdmitted: false,
  });
}

function responseFor(result: HttpPageResult) {
  return result.kind === "html" ? result.page.response
    : result.kind === "non-html" || result.kind === "failed"
    ? result.response
    : null;
}

function collectorsForHttp(result: HttpPageResult): PageCollectors {
  if (result.kind === "html") {
    return result.page.collectionState === "failed"
      ? Object.freeze([])
      : Object.freeze(["http"] as const);
  }
  return result.kind === "non-html"
    ? Object.freeze(["http"] as const)
    : Object.freeze([]);
}

function freezePage(
  id: PageId,
  role: PageRole,
  url: string,
  status: number | null,
  collectors: PageCollectors,
): PageRecord {
  return Object.freeze({ id, role, url, httpStatus: status, collectors });
}

function withBrowser(page: PageRecord): PageRecord {
  return freezePage(
    page.id,
    page.role,
    page.url,
    page.httpStatus,
    Object.freeze(["http", "browser"] as const),
  );
}

function clampTiming(value: number | null, total: number): number | null {
  return value === null ? null : Math.min(total, Math.max(0, value));
}

function statusClass(statusCode: number | null): ShadowStatusClass {
  if (statusCode === null) return null;
  const group = Math.floor(statusCode / 100);
  return group >= 2 && group <= 5
    ? `${group}xx` as ShadowStatusClass
    : null;
}

function codePointCount(value: string): number {
  let count = 0;
  for (const _codePoint of value) count += 1;
  return count;
}

function entryPrefixCompleted(entry: HttpEntryResult): boolean {
  return entry.kind === "html"
    ? entry.page.collectionState === "complete" && entry.errors.length === 0
    : entry.kind === "non-html" && entry.errors.length === 0;
}

function pagePrefixCompleted(result: HttpPageResult): boolean {
  if (result.kind === "html") {
    return result.page.collectionState === "complete"
      && result.errors.length === 0;
  }
  return result.kind === "non-html"
    ? result.errors.length === 0
    : result.kind === "skipped";
}

function compareShadowBrowserLimitHit(
  left: ShadowBrowserLimitHit,
  right: ShadowBrowserLimitHit,
): number {
  return compareString(left.pageId, right.pageId)
    || compareString(left.category, right.category)
    || (left.domSelectorOrdinal ?? -1) - (right.domSelectorOrdinal ?? -1);
}

function shadowFullCost(
  result: DomainResult,
  browserPagesAttempted: number,
  browserPagesAdmitted: number,
): ShadowEvaluationSnapshot["fullCost"] {
  return Object.freeze({
    browserPagesAttempted,
    browserPagesAdmitted,
    browserRequests: result.usage.browserRequests,
    browserTransferredBytes: result.usage.browserTransferredBytes,
    browserMs: result.timings.browserMs ?? 0,
  });
}

async function emitUnavailableShadowSnapshot(
  result: DomainResult,
  options: ScanDomainOptions,
  reason: "prefix-unavailable" | "detector-unavailable",
): Promise<DomainResult> {
  if (options.onShadowSnapshot === undefined) return result;
  options.signal?.throwIfAborted();
  const unavailable = unavailableShadowDetectorView(reason);
  await options.onShadowSnapshot(createShadowEvaluationSnapshot({
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    runId: result.runId,
    domain: result.domain,
    t1: unavailable,
    t2: unavailable,
    preBrowser: null,
    full: shadowFullLabel(result),
    fullCost: shadowFullCost(result, 0, 0),
    browserLimitHits: Object.freeze([]),
  }));
  return result;
}

async function detectShadowTier(
  entry: HttpEntryResult,
  view: TierObservationView,
  context: ScanDomainContext,
  pool: DetectorPool,
  callerSignal: AbortSignal | undefined,
  prefixErrors: readonly ScanError[],
  prefixCompleted: boolean,
): Promise<ShadowDetectorView> {
  try {
    const detected = await detectHttp(entry, {
      catalog: context.catalog,
      pool,
      config: context.config,
      ...view,
      ...(callerSignal === undefined ? {} : { signal: callerSignal }),
    });
    return shadowDetectorView(detected, {
      errors: prefixErrors,
      completed: prefixCompleted && detected.completed,
    });
  } catch {
    callerSignal?.throwIfAborted();
    return unavailableShadowDetectorView("detector-unavailable");
  }
}

export async function scanDomain(
  inputDomain: string,
  context: ScanDomainContext,
  options: ScanDomainOptions = {},
): Promise<DomainResult> {
  preflight(context);
  if (
    (options.onShadowSnapshot === undefined)
      !== (options.shadowDetectorPools === undefined)
  ) {
    throw new TypeError(
      "Shadow evaluation requires both a snapshot sink and isolated detector pools",
    );
  }
  if (
    options.shadowDetectorPools !== undefined
    && (
      options.shadowDetectorPools.t1.catalog !== context.catalog
      || options.shadowDetectorPools.t2.catalog !== context.catalog
      || options.shadowDetectorPools.t1 === context.detectorPool
      || options.shadowDetectorPools.t2 === context.detectorPool
      || options.shadowDetectorPools.t1 === options.shadowDetectorPools.t2
    )
  ) {
    throw new TypeError(
      "Shadow detector pools must be distinct and share the compiled catalog",
    );
  }
  const domain = normalizeHostname(
    inputDomain,
    context.config.limits.hostname.inputCodeUnits,
  );
  const wallClock = options.wallClock ?? (() => new Date());
  const now = options.monotonicClock ?? (() => performance.now());
  const preflightScannedAt = wallClock().toISOString();
  options.signal?.throwIfAborted();
  if (!context.detectorPool.isAvailable()) {
    return emitUnavailableShadowSnapshot(earlyFailure(
      domain,
      context,
      scanError("detect", "DETECTOR_UNAVAILABLE", true),
      preflightScannedAt,
    ), options, "detector-unavailable");
  }
  if (!context.browserPool.isAvailable()) {
    return emitUnavailableShadowSnapshot(earlyFailure(
      domain,
      context,
      scanError("browser", "BROWSER_UNAVAILABLE", true),
      preflightScannedAt,
    ), options, "prefix-unavailable");
  }

  const deadline = new AbortController();
  const signal = options.signal === undefined
    ? deadline.signal
    : AbortSignal.any([options.signal, deadline.signal]);
  let deadlineFired = false;
  let deadlineTimer: NodeJS.Timeout | null = null;
  let scanTimestamp: string | null = null;
  let scanStarted: number | null = null;
  const startActiveDomain = (): void => {
    if (scanTimestamp !== null || scanStarted !== null) return;
    scanTimestamp = wallClock().toISOString();
    scanStarted = now();
    deadlineTimer = setTimeout(() => {
      deadlineFired = true;
      deadline.abort(new DOMException(
        PIPELINE_MESSAGES.DOMAIN_DEADLINE_EXCEEDED,
        "TimeoutError",
      ));
    }, context.config.limits.timeMs.activeDomain);
  };
  let browserSession: BrowserDomainSession;
  try {
    browserSession = await context.browserPool.openDomain(
      signal,
      startActiveDomain,
    );
  } catch (error) {
    if (deadlineTimer !== null) clearTimeout(deadlineTimer);
    options.signal?.throwIfAborted();
    const activeMs = scanStarted === null ? 0 : elapsed(now, scanStarted);
    const failureTimestamp = scanTimestamp ?? wallClock().toISOString();
    if (deadlineFired) {
      return emitUnavailableShadowSnapshot(earlyFailure(
        domain,
        context,
        scanError(
          scanStarted === null ? "target" : "browser",
          "DOMAIN_DEADLINE_EXCEEDED",
          true,
        ),
        failureTimestamp,
        activeMs,
      ), options, "prefix-unavailable");
    }
    const observed = error instanceof ProtectedTransportError
      ? observedError(error)
      : error instanceof BrowserLifecycleFailure
      ? scanError("browser", error.code, true)
      : scanError("browser", "BROWSER_UNAVAILABLE", true);
    return emitUnavailableShadowSnapshot(earlyFailure(
      domain,
      context,
      observed,
      failureTimestamp,
      activeMs,
    ), options, "prefix-unavailable");
  }

  if (scanTimestamp === null || scanStarted === null) {
    await browserSession.close();
    throw new TypeError("Browser pool did not admit the active domain");
  }
  const scannedAt = scanTimestamp;
  const totalStarted = scanStarted;
  let session: ProtectedTransportSession;
  try {
    session = context.transport.createSession({ signal });
  } catch (error) {
    if (deadlineTimer !== null) clearTimeout(deadlineTimer);
    await browserSession.close();
    throw error;
  }
  const measuredRobots = measuredRobotsService(context.robots, now);
  const errors: ScanError[] = [];
  const httpPages: HttpPageResult[] = [];
  const precheckRobots: HttpRobotsObservation[] = [];
  const tier2Robots: HttpRobotsObservation[] = [];
  const tier1PrefixErrors: ScanError[] = [];
  const tier2PrefixErrors: ScanError[] = [];
  const browserLimitHits: ShadowBrowserLimitHit[] = [];
  const pages: PageRecord[] = [];
  let entry: HttpEntryResult | null = null;
  let tier2HttpPage: HttpPageResult | null = null;
  let tierViews: TierObservationViews | null = null;
  let preBrowserFeatures: ShadowPreBrowserFeatures | null = null;
  let tier1PrefixCompleted = false;
  let tier2PrefixCompleted = false;
  let browserPagesAttempted = 0;
  let browserPagesAdmitted = 0;
  let browserResult: BrowserDomainResult = Object.freeze({
    pages: Object.freeze([]),
    errors: Object.freeze([]),
    completed: true,
  });
  let infrastructure: InfrastructureResult = Object.freeze({
    observations: Object.freeze({
      dnsRecords: Object.freeze([]),
      tlsIssuer: null,
    }),
    errors: Object.freeze([]),
    dnsMs: null,
    tlsMs: null,
    completed: true,
  });
  let probeResult: HttpProbeResult = Object.freeze({
    observations: Object.freeze([]),
    robots: Object.freeze([]),
    errors: Object.freeze([]),
    completed: true,
  });
  let detection: DetectHttpResult = Object.freeze({
    technologies: Object.freeze([]),
    detectionStats: zeroDetectionStats(),
    errors: Object.freeze([]),
    signalAdmitted: false,
    completed: true,
  });
  let finalUrl: string | null = null;
  let targetMs: number | null = null;
  let httpMs: number | null = null;
  let browserMs: number | null = elapsed(now, totalStarted);
  let detectMs: number | null = null;
  let dnsErrorMs: number | null = null;
  let tlsErrorMs: number | null = null;
  let browserPrefixOpen = true;

  const recordNetworkErrorTimings = (
    values: readonly ScanError[],
    duration: number,
  ): void => {
    if (values.some((error) => error.stage === "dns")) {
      dnsErrorMs ??= duration;
    }
    if (values.some((error) => error.stage === "tls")) {
      tlsErrorMs ??= duration;
    }
  };

  const collectMeasured = async <T>(operation: () => Promise<T>): Promise<T> => {
    const started = now();
    const robotsBefore = measuredRobots.elapsed();
    try {
      return await operation();
    } finally {
      const duration = elapsed(now, started);
      const robotsDuration = measuredRobots.elapsed() - robotsBefore;
      httpMs = (httpMs ?? 0) + Math.max(0, duration - robotsDuration);
    }
  };

  const collectBrowser = async (
    pageId: PageId,
    url: string,
  ): Promise<BrowserPageCollection | null> => {
    const started = now();
    browserPagesAttempted += 1;
    try {
      const collected = await browserSession.collectPage({
        pageId,
        url,
        inspectionPlan: context.catalog.inspectionPlan,
        allowTopLevelUrl: (candidate) =>
          measuredRobots.service.allowsCached(candidate) === true,
      });
      if (collected.observationsAdmitted) browserPagesAdmitted += 1;
      for (const hit of collected.limitTelemetry.hits) {
        browserLimitHits.push(Object.freeze({ ...hit, pageId }));
      }
      recordNetworkErrorTimings(collected.errors, elapsed(now, started));
      return collected;
    } catch {
      for (const hit of browserSession.getFailureLimitTelemetry().hits) {
        browserLimitHits.push(Object.freeze({ ...hit, pageId }));
      }
      options.signal?.throwIfAborted();
      if (
        deadlineFired
        && !errors.some((error) => error.code === "DOMAIN_DEADLINE_EXCEEDED")
      ) {
        errors.push(scanError(
          "browser",
          "DOMAIN_DEADLINE_EXCEEDED",
          true,
          pageId,
        ));
      } else if (!signal.aborted) {
        errors.push(scanError(
          "browser",
          "BROWSER_NAVIGATION_FAILED",
          true,
          pageId,
        ));
      }
      return null;
    } finally {
      browserMs = (browserMs ?? 0) + elapsed(now, started);
    }
  };

  const collectPlannedPage = async (
    candidate: PlannedInternalPage,
    pageId: PageId,
    usedPublicUrls: Set<string>,
    robotsTargets: readonly HttpRobotsObservation[][],
  ): Promise<CollectedInternalPage> => {
    const robotsStarted = now();
    let check: RobotsCheck;
    try {
      check = await measuredRobots.service.check(session, candidate.url);
    } catch (error) {
      if (
        error instanceof ProtectedTransportError
        || error instanceof RobotsPolicyError
      ) {
        errors.push(observedError(error));
        if (error.stage === "dns") {
          dnsErrorMs ??= elapsed(now, robotsStarted);
        } else if (error.stage === "tls") {
          tlsErrorMs ??= elapsed(now, robotsStarted);
        }
      } else {
        errors.push(scanError("robots", "ROBOTS_UNAVAILABLE", false));
      }
      return Object.freeze({
        candidate,
        publicUrl: null,
        result: null,
        outcome: "skipped" as const,
        completed: false,
      });
    }

    const observation = robotsObservation(check);
    if (observation !== null) {
      for (const target of robotsTargets) target.push(observation);
    }
    if (!check.allowed) {
      return Object.freeze({
        candidate,
        publicUrl: null,
        result: Object.freeze({
          kind: "skipped" as const,
          pageId,
          requestedUrl: candidate.url,
          robots: observation === null
            ? Object.freeze([])
            : Object.freeze([observation]),
          errors: Object.freeze([]) as readonly [],
        }),
        outcome: "denied" as const,
        completed: true,
      });
    }

    const publicUrl = sanitizeNetworkUrl(candidate.url, context.config);
    if (usedPublicUrls.has(publicUrl)) {
      return Object.freeze({
        candidate,
        publicUrl: null,
        result: null,
        outcome: "skipped" as const,
        completed: true,
      });
    }
    usedPublicUrls.add(publicUrl);

    const pageStarted = now();
    const result = await collectMeasured(() => collectHttpPage(
      candidate.url,
      pageId,
      {
        config: context.config,
        session,
        robots: robotsServiceWithInitialCheck(
          measuredRobots.service,
          candidate.url,
          check,
        ),
      },
    ));
    recordNetworkErrorTimings(result.errors, elapsed(now, pageStarted));
    return Object.freeze({
      candidate,
      publicUrl,
      result,
      outcome: result.kind,
      completed: pagePrefixCompleted(result),
    });
  };

  try {
    const targetStarted = now();
    try {
      entry = await collectMeasured(() => collectHttpEntry(domain, {
        config: context.config,
        session,
        robots: measuredRobots.service,
      }));
    } finally {
      targetMs = elapsed(now, targetStarted);
    }
    errors.push(...entry.errors);
    tier1PrefixErrors.push(...entry.errors);
    tier2PrefixErrors.push(...entry.errors);
    recordNetworkErrorTimings(entry.errors, targetMs ?? 0);

    const entryResponse = entry.kind === "html"
      ? entry.page.response
      : entry.response;
    if (entryResponse !== null) {
      finalUrl = sanitizeNetworkUrl(
        entryResponse.finalNetworkUrl,
        context.config,
      );
    }

    infrastructure = await collectInfrastructure(domain, {
      config: context.config,
      session,
      inspectionPlan: context.catalog.inspectionPlan,
      httpResult: entry,
    });
    errors.push(...infrastructure.errors);
    tier1PrefixErrors.push(...infrastructure.errors);
    tier2PrefixErrors.push(...infrastructure.errors);
    tier1PrefixCompleted = entryPrefixCompleted(entry)
      && infrastructure.completed;

    let renderedLinks: readonly string[] = Object.freeze([]);
    let reservedForTier2: SelectedInternalPage | null = null;
    let tier2Outcome: ShadowInternalOutcome = "not-selected";
    let tier2CollectionCompleted = true;
    const collectedInternalPages: CollectedInternalPage[] = [];
    const usedPublicUrls = new Set<string>();

    if (entry.kind === "html") {
      const entryNetworkUrl = entry.page.response.finalNetworkUrl;
      const entryCollectors: PageCollectors = entry.page.collectionState === "failed"
        ? Object.freeze([])
        : Object.freeze(["http"] as const);
      pages.push(freezePage(
        "p1",
        "entry",
        finalUrl ?? sanitizeNetworkUrl(
          entry.page.response.finalNetworkUrl,
          context.config,
        ),
        entry.page.response.statusCode,
        entryCollectors,
      ));
      usedPublicUrls.add((pages[0] as PageRecord).url);

      reservedForTier2 = selectTier2InternalPage(
        entryNetworkUrl,
        entry.page.navigationLinks,
        context.config,
      );
      if (reservedForTier2 !== null) {
        const errorCountBeforeCollection = errors.length;
        const collected = await collectPlannedPage(
          Object.freeze({ ...reservedForTier2, reservedForTier2: true }),
          "p2",
          usedPublicUrls,
          [tier2Robots, precheckRobots],
        );
        collectedInternalPages.push(collected);
        tier2Outcome = collected.outcome;
        tier2CollectionCompleted = collected.completed;
        tier2PrefixErrors.push(
          ...errors.slice(errorCountBeforeCollection),
          ...(collected.result?.errors ?? []),
        );
        if (
          collected.publicUrl !== null
          && collected.result !== null
        ) {
          tier2HttpPage = collected.result;
        }
      }

      if (context.catalog.inspectionPlan.probePaths.length > 0) {
        const probeStarted = now();
        probeResult = await collectMeasured(() => collectCatalogProbes(
          entryNetworkUrl,
          {
            config: context.config,
            session,
            robots: measuredRobots.service,
            probePaths: context.catalog.inspectionPlan.probePaths,
            ...(options.signal === undefined
              ? {}
              : { callerSignal: options.signal }),
          },
        ));
        errors.push(...probeResult.errors);
        tier2PrefixErrors.push(...probeResult.errors);
        tier2Robots.push(...probeResult.robots);
        precheckRobots.push(...probeResult.robots);
        recordNetworkErrorTimings(
          probeResult.errors,
          elapsed(now, probeStarted),
        );
      }
    }

    tier2PrefixCompleted = tier1PrefixCompleted
      && tier2CollectionCompleted
      && probeResult.completed;
    const preBrowserUsage = session.getUsage();
    preBrowserFeatures = Object.freeze({
      entryOutcome: entry.kind,
      entryStatusClass: statusClass(entryResponse?.statusCode ?? null),
      entryHtmlBytes: entry.kind === "html"
        ? Buffer.byteLength(entry.page.html, "utf8")
        : 0,
      entryTextCodePoints: entry.kind === "html"
        ? codePointCount(entry.page.text)
        : 0,
      staticNavigationLinks: entry.kind === "html"
        ? entry.page.navigationLinks.length
        : 0,
      metadataEntries: entry.kind === "html" ? entry.page.metadata.length : 0,
      resourceEntries: entry.kind === "html" ? entry.page.resources.length : 0,
      dnsRecords: infrastructure.observations.dnsRecords.length,
      tlsIssuerPresent: infrastructure.observations.tlsIssuer !== null,
      t2Selected: reservedForTier2 !== null,
      t2Role: reservedForTier2?.role ?? null,
      t2Outcome: tier2Outcome,
      probesObserved: probeResult.observations.length,
      httpRequests: preBrowserUsage.httpRequests,
      staticTransferredBytes: preBrowserUsage.staticTransferredBytes,
    });

    if (entry.kind === "html") {
      if (entry.page.collectionState !== "failed") {
        const collected = await collectBrowser(
          "p1",
          entry.page.response.finalNetworkUrl,
        );
        if (collected === null) {
          browserPrefixOpen = false;
        } else if (collected.observationsAdmitted) {
          pages[0] = withBrowser(pages[0] as PageRecord);
          renderedLinks = collected.navigationLinks;
        }
        if (collected !== null && !collected.continuationAllowed) {
          browserPrefixOpen = false;
        }
        if (collected !== null) errors.push(...collected.errors);
      } else {
        browserPrefixOpen = false;
      }

      const structurallySelected = planFullInternalPages(
        entry.page.response.finalNetworkUrl,
        entry.page.navigationLinks,
        renderedLinks,
        reservedForTier2,
        context.config,
      );
      for (let index = 0; index < structurallySelected.length; index += 1) {
        const candidate = structurallySelected[index] as PlannedInternalPage;
        if (candidate.reservedForTier2) continue;
        collectedInternalPages.push(await collectPlannedPage(
          candidate,
          `p${index + 2}` as PageId,
          usedPublicUrls,
          [precheckRobots],
        ));
      }

      const admitted = collectedInternalPages
        .filter((collected): collected is CollectedInternalPage & {
          readonly publicUrl: string;
          readonly result: Exclude<HttpPageResult, { readonly kind: "skipped" }>;
        } => collected.publicUrl !== null
          && collected.result !== null
          && collected.result.kind !== "skipped")
        .sort((left, right) => compareString(left.publicUrl, right.publicUrl));

      for (let index = 0; index < admitted.length; index += 1) {
        const collected = admitted[index]!;
        const pageId = `p${index + 2}` as PageId;
        const pageResult = remapHttpPageResultPageId(collected.result, pageId);
        httpPages.push(pageResult);
        errors.push(...pageResult.errors);
        const response = responseFor(pageResult);
        let page = freezePage(
          pageId,
          collected.candidate.role,
          collected.publicUrl,
          response?.statusCode ?? null,
          collectorsForHttp(pageResult),
        );
        pages.push(page);
        if (
          browserPrefixOpen
          && pageResult.kind === "html"
          && pageResult.page.collectionState !== "failed"
        ) {
          const browserPage = await collectBrowser(
            pageId,
            pageResult.page.response.finalNetworkUrl,
          );
          if (browserPage === null) {
            browserPrefixOpen = false;
          } else if (browserPage.observationsAdmitted) {
            page = withBrowser(page);
            pages[pages.length - 1] = page;
          }
          if (browserPage !== null && !browserPage.continuationAllowed) {
            browserPrefixOpen = false;
          }
          if (browserPage !== null) errors.push(...browserPage.errors);
        } else {
          browserPrefixOpen = false;
        }
      }
    } else {
      browserPrefixOpen = false;
    }

    const finishStarted = now();
    try {
      browserResult = await browserSession.finish();
      errors.push(...browserResult.errors);
      recordNetworkErrorTimings(
        browserResult.errors,
        elapsed(now, finishStarted),
      );
    } catch {
      options.signal?.throwIfAborted();
      if (
        deadlineFired
        && !errors.some((error) => error.code === "DOMAIN_DEADLINE_EXCEEDED")
      ) {
        errors.push(scanError("browser", "DOMAIN_DEADLINE_EXCEEDED", true));
      } else if (!signal.aborted) {
        errors.push(scanError("browser", "BROWSER_UNAVAILABLE", true));
      }
    } finally {
      browserMs = (browserMs ?? 0) + elapsed(now, finishStarted);
    }

    tierViews = Object.freeze({
      t1: tierObservationView({
        httpPages: Object.freeze([]),
        probes: Object.freeze([]),
        robots: Object.freeze([]),
        browserPages: Object.freeze([]),
        infrastructure: infrastructure.observations,
      }),
      t2: tierObservationView({
        httpPages: tier2HttpPage === null
          ? Object.freeze([])
          : Object.freeze([tier2HttpPage]),
        probes: probeResult.observations,
        robots: tier2Robots,
        browserPages: Object.freeze([]),
        infrastructure: infrastructure.observations,
      }),
      full: tierObservationView({
        httpPages,
        probes: probeResult.observations,
        robots: precheckRobots,
        browserPages: browserResult.pages,
        infrastructure: infrastructure.observations,
      }),
    });

    const detectStarted = now();
    try {
      detection = await detectHttp(entry, {
        catalog: context.catalog,
        pool: context.detectorPool,
        config: context.config,
        ...tierViews.full,
        priorityObservations: tierViews.t2,
        signal,
      });
      errors.push(...detection.errors);
    } catch {
      options.signal?.throwIfAborted();
      if (
        deadlineFired
        && !errors.some((error) => error.code === "DOMAIN_DEADLINE_EXCEEDED")
      ) {
        errors.push(scanError("detect", "DOMAIN_DEADLINE_EXCEEDED", true));
      } else if (!signal.aborted) {
        errors.push(scanError("detect", "DETECTOR_UNAVAILABLE", true));
      }
    } finally {
      detectMs = elapsed(now, detectStarted);
    }
  } catch (error) {
    if (options.signal?.aborted === true) {
      if (deadlineTimer !== null) clearTimeout(deadlineTimer);
      throw error;
    }
    if (deadlineFired) {
      const stage: ErrorStage = entry === null ? "target" : "detect";
      errors.push(scanError(stage, "DOMAIN_DEADLINE_EXCEEDED", true));
      if (stage === "target") targetMs ??= 0;
      if (stage === "detect") detectMs ??= 0;
    } else {
      if (deadlineTimer !== null) clearTimeout(deadlineTimer);
      throw error;
    }
  } finally {
    session.close();
    try {
      await browserSession.close();
    } catch {
      errors.push(scanError("browser", "BROWSER_UNAVAILABLE", true));
      browserMs ??= 0;
    }
  }

  try {
    options.signal?.throwIfAborted();
  if (
    deadlineFired
    && !errors.some((error) => error.code === "DOMAIN_DEADLINE_EXCEEDED")
  ) {
    errors.push(scanError("detect", "DOMAIN_DEADLINE_EXCEEDED", true));
    detectMs ??= 0;
  }

  let totalMs = elapsed(now, totalStarted);
  const bounded = boundErrors(errors, context.config);
  let boundedErrors = bounded.errors;
  let resultOverflow = bounded.overflow;
  const signalAdmitted = detection.signalAdmitted
    || (entry !== null && (
      entry.kind === "html"
      || entry.response !== null
    ))
    || httpPages.some((page) =>
      page.kind === "html"
      || ((page.kind === "non-html" || page.kind === "failed")
        && page.response !== null))
    || (entry?.robots.length ?? 0) > 0
    || precheckRobots.length > 0
    || httpPages.some((page) => page.robots.length > 0)
    || probeResult.observations.length > 0
    || probeResult.robots.length > 0
    || browserResult.pages.length > 0
    || infrastructure.observations.dnsRecords.length > 0
    || infrastructure.observations.tlsIssuer !== null;
  let status: DomainStatus = boundedErrors.length === 0
    ? "success"
    : signalAdmitted ? "partial" : "failed";
  if (status === "success" && (
    finalUrl === null
    || pages.length === 0
    || pages.some((page) =>
      page.httpStatus === null
      || page.httpStatus < 200
      || page.httpStatus > 299
      || page.collectors.length !== 2)
  )) {
    const synthetic = scanError(
      "browser",
      "BROWSER_NAVIGATION_FAILED",
      false,
      pages.find((page) => page.collectors.length !== 2)?.id ?? null,
    );
    const rebound = boundErrors([...boundedErrors, synthetic], context.config);
    boundedErrors = rebound.errors;
    resultOverflow = resultOverflow || rebound.overflow;
    status = signalAdmitted ? "partial" : "failed";
  }
  const transportUsage = session.getUsage();
  const browserUsage = browserSession.getUsage();
  let outputPages: readonly PageRecord[] = status === "failed"
    ? Object.freeze([])
    : Object.freeze(pages);
  let outputFinalUrl = status === "failed" ? null : finalUrl;
  let technologies: readonly Technology[] = status === "failed" || resultOverflow
    ? Object.freeze([])
    : detection.technologies;
  const createTimings = (measuredTotalMs: number): Timings => Object.freeze({
    totalMs: measuredTotalMs,
    targetMs: clampTiming(targetMs, measuredTotalMs),
    robotsMs: measuredRobots.elapsed() === 0 && entry === null
      ? null
      : clampTiming(measuredRobots.elapsed(), measuredTotalMs),
    httpMs: clampTiming(httpMs, measuredTotalMs),
    dnsMs: clampTiming(
      infrastructure.dnsMs
        ?? dnsErrorMs
        ?? (boundedErrors.some((error) => error.stage === "dns") ? 0 : null),
      measuredTotalMs,
    ),
    tlsMs: clampTiming(
      infrastructure.tlsMs
        ?? tlsErrorMs
        ?? (boundedErrors.some((error) => error.stage === "tls") ? 0 : null),
      measuredTotalMs,
    ),
    browserMs: clampTiming(browserMs, measuredTotalMs),
    detectMs: clampTiming(detectMs, measuredTotalMs),
  });
  const createUsage = (): Usage => Object.freeze({
    httpRequests: transportUsage.httpRequests,
    browserRequests: browserUsage.browserRequests,
    retries: transportUsage.retries,
    pagesVisited: outputPages.length,
    probesIssued: transportUsage.probesIssued,
    scriptBodiesInspected: browserUsage.scriptBodiesInspected,
    staticTransferredBytes: transportUsage.staticTransferredBytes,
    browserTransferredBytes: browserUsage.browserTransferredBytes,
  });
  const materialize = (measuredTotalMs: number): DomainResult => Object.freeze({
    schemaVersion: 1 as const,
    runId: context.runId,
    domain,
    scannedAt,
    status,
    finalUrl: outputFinalUrl,
    scanMode: "full" as const,
    pages: outputPages,
    technologies,
    detectionStats: detection.detectionStats,
    errors: boundedErrors,
    timings: createTimings(measuredTotalMs),
    usage: createUsage(),
    provenance: context.provenance,
  });
  const recordBytes = (value: DomainResult): number =>
    Buffer.byteLength(`${JSON.stringify(value)}\n`, "utf8");
  let result = materialize(totalMs);
  let limitError: ScanError | null = null;
  const enforceActiveDeadline = (): boolean => {
    const exceeded = deadlineFired
      || Math.max(0, now() - totalStarted)
        >= context.config.limits.timeMs.activeDomain;
    if (
      !exceeded
      || boundedErrors.some((error) =>
        error.code === "DOMAIN_DEADLINE_EXCEEDED")
    ) {
      return false;
    }
    const rebound = boundErrors([
      ...boundedErrors,
      scanError("detect", "DOMAIN_DEADLINE_EXCEEDED", true),
    ], context.config);
    boundedErrors = rebound.errors;
    resultOverflow = resultOverflow || rebound.overflow;
    status = signalAdmitted ? "partial" : "failed";
    if (status === "failed") {
      outputPages = Object.freeze([]);
      outputFinalUrl = null;
    }
    if (status === "failed" || resultOverflow) {
      technologies = Object.freeze([]);
    }
    detectMs ??= 0;
    return true;
  };
  const enforceRecordLimit = (): void => {
    if (recordBytes(result) <= context.config.limits.output.jsonlRecordBytes) {
      return;
    }
    limitError ??= scanError("detect", "RESULT_LIMIT_EXCEEDED", false);
    const rebound = boundErrors([...boundedErrors, limitError], context.config);
    boundedErrors = rebound.errors;
    technologies = Object.freeze([]);
    status = signalAdmitted ? "partial" : "failed";
    if (status === "failed") {
      outputPages = Object.freeze([]);
      outputFinalUrl = null;
    }
    result = materialize(totalMs);
    if (recordBytes(result) > context.config.limits.output.jsonlRecordBytes) {
      boundedErrors = Object.freeze([limitError]);
      result = materialize(totalMs);
    }
  };
  enforceRecordLimit();
  totalMs = elapsed(now, totalStarted);
  if (enforceActiveDeadline()) {
    totalMs = elapsed(now, totalStarted);
  }
  result = materialize(totalMs);
  enforceRecordLimit();
  let validated = validateDomainResult(result, {
    scanConfig: context.config,
    expectedConfigDigest: context.provenance.configDigest,
    signalAdmitted,
  });
  if (enforceActiveDeadline()) {
    totalMs = elapsed(now, totalStarted);
    result = materialize(totalMs);
    enforceRecordLimit();
    validated = validateDomainResult(result, {
      scanConfig: context.config,
      expectedConfigDigest: context.provenance.configDigest,
      signalAdmitted,
    });
  }
  if (deadlineTimer !== null) {
    clearTimeout(deadlineTimer);
    deadlineTimer = null;
  }
  if (options.onShadowSnapshot !== undefined) {
    options.signal?.throwIfAborted();
    let t1: ShadowDetectorView;
    let t2: ShadowDetectorView;
    if (entry === null || tierViews === null) {
      t1 = unavailableShadowDetectorView("prefix-unavailable");
      t2 = unavailableShadowDetectorView("prefix-unavailable");
    } else {
      [t1, t2] = await Promise.all([
        detectShadowTier(
          entry,
          tierViews.t1,
          context,
          options.shadowDetectorPools!.t1,
          options.signal,
          tier1PrefixErrors,
          tier1PrefixCompleted,
        ),
        detectShadowTier(
          entry,
          tierViews.t2,
          context,
          options.shadowDetectorPools!.t2,
          options.signal,
          tier2PrefixErrors,
          tier2PrefixCompleted,
        ),
      ]);
    }
    const uniqueLimitHits = new Map<string, ShadowBrowserLimitHit>();
    for (const hit of browserLimitHits) {
      uniqueLimitHits.set(JSON.stringify([
        hit.pageId,
        hit.category,
        hit.domSelectorOrdinal,
      ]), hit);
    }
    const snapshot = createShadowEvaluationSnapshot({
      protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
      runId: context.runId,
      domain,
      t1,
      t2,
      preBrowser: preBrowserFeatures,
      full: shadowFullLabel(validated),
      fullCost: shadowFullCost(
        validated,
        browserPagesAttempted,
        browserPagesAdmitted,
      ),
      browserLimitHits: Object.freeze([...uniqueLimitHits.values()]
        .sort(compareShadowBrowserLimitHit)),
    });
    await options.onShadowSnapshot(snapshot);
  }
  return validated;
  } finally {
    if (deadlineTimer !== null) clearTimeout(deadlineTimer);
  }
}
