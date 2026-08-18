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
}

export interface SelectedInternalPage {
  readonly role: "detail" | "listing" | "content";
  readonly url: string;
}

interface RankedPage extends SelectedInternalPage {
  readonly tokenRank: number;
  readonly pathnameLength: number;
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

export async function scanDomain(
  inputDomain: string,
  context: ScanDomainContext,
  options: ScanDomainOptions = {},
): Promise<DomainResult> {
  preflight(context);
  const domain = normalizeHostname(
    inputDomain,
    context.config.limits.hostname.inputCodeUnits,
  );
  const wallClock = options.wallClock ?? (() => new Date());
  const now = options.monotonicClock ?? (() => performance.now());
  const preflightScannedAt = wallClock().toISOString();
  options.signal?.throwIfAborted();
  if (!context.detectorPool.isAvailable()) {
    return earlyFailure(
      domain,
      context,
      scanError("detect", "DETECTOR_UNAVAILABLE", true),
      preflightScannedAt,
    );
  }
  if (!context.browserPool.isAvailable()) {
    return earlyFailure(
      domain,
      context,
      scanError("browser", "BROWSER_UNAVAILABLE", true),
      preflightScannedAt,
    );
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
      return earlyFailure(
        domain,
        context,
        scanError(
          scanStarted === null ? "target" : "browser",
          "DOMAIN_DEADLINE_EXCEEDED",
          true,
        ),
        failureTimestamp,
        activeMs,
      );
    }
    const observed = error instanceof ProtectedTransportError
      ? observedError(error)
      : error instanceof BrowserLifecycleFailure
      ? scanError("browser", error.code, true)
      : scanError("browser", "BROWSER_UNAVAILABLE", true);
    return earlyFailure(
      domain,
      context,
      observed,
      failureTimestamp,
      activeMs,
    );
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
  const pages: PageRecord[] = [];
  let entry: HttpEntryResult | null = null;
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
    try {
      const collected = await browserSession.collectPage({
        pageId,
        url,
        inspectionPlan: context.catalog.inspectionPlan,
        allowTopLevelUrl: (candidate) =>
          measuredRobots.service.allowsCached(candidate) === true,
      });
      recordNetworkErrorTimings(collected.errors, elapsed(now, started));
      return collected;
    } catch {
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

    let renderedLinks: readonly string[] = Object.freeze([]);
    if (entry.kind === "html") {
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

      const structurallySelected = selectInternalPages(
        entry.page.response.finalNetworkUrl,
        entry.page.navigationLinks,
        renderedLinks,
        context.config,
      );
      const selected: Array<SelectedInternalPage & {
        readonly publicUrl: string;
      }> = [];
      const sanitized = new Set(pages.map((page) => page.url));
      for (const candidate of structurallySelected.slice(0, 2)) {
        const robotsStarted = now();
        try {
          const check = await measuredRobots.service.check(session, candidate.url);
          if (check.robotsText !== null) {
            precheckRobots.push(Object.freeze({
              ownerOrigin: check.ownerOrigin,
              fetchedUrl: check.fetchedUrl,
              text: check.robotsText,
            }));
          }
          if (!check.allowed) continue;
          const publicUrl = sanitizeNetworkUrl(candidate.url, context.config);
          if (sanitized.has(publicUrl)) continue;
          sanitized.add(publicUrl);
          selected.push(Object.freeze({ ...candidate, publicUrl }));
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
        }
      }
      selected.sort((left, right) => compareString(left.publicUrl, right.publicUrl));

      let nextPageRank = 2;
      for (const candidate of selected) {
        const pageId = `p${nextPageRank}` as PageId;
        const pageStarted = now();
        const pageResult = await collectMeasured(() => collectHttpPage(
          candidate.url,
          pageId,
          {
            config: context.config,
            session,
            robots: measuredRobots.service,
          },
        ));
        httpPages.push(pageResult);
        errors.push(...pageResult.errors);
        recordNetworkErrorTimings(
          pageResult.errors,
          elapsed(now, pageStarted),
        );
        if (pageResult.kind === "skipped") {
          continue;
        }
        nextPageRank += 1;
        const response = responseFor(pageResult);
        let page = freezePage(
          pageId,
          candidate.role,
          candidate.publicUrl,
          response?.statusCode ?? null,
          collectorsForHttp(pageResult),
        );
        pages.push(page);
        if (
          browserPrefixOpen
          && pageResult.kind === "html"
          && pageResult.page.collectionState !== "failed"
        ) {
          const collected = await collectBrowser(
            pageId,
            pageResult.page.response.finalNetworkUrl,
          );
          if (collected === null) {
            browserPrefixOpen = false;
          } else if (collected.observationsAdmitted) {
            page = withBrowser(page);
            pages[pages.length - 1] = page;
          }
          if (collected !== null && !collected.continuationAllowed) {
            browserPrefixOpen = false;
          }
          if (collected !== null) errors.push(...collected.errors);
        } else {
          browserPrefixOpen = false;
        }
      }
    } else {
      browserPrefixOpen = false;
    }

    const probeFinalUrl = entry.kind === "html"
      ? entry.page.response.finalNetworkUrl
      : null;
    if (
      probeFinalUrl !== null
      && context.catalog.inspectionPlan.probePaths.length > 0
    ) {
      const probeStarted = now();
      probeResult = await collectMeasured(() => collectCatalogProbes(
        probeFinalUrl,
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
      precheckRobots.push(...probeResult.robots);
      recordNetworkErrorTimings(
        probeResult.errors,
        elapsed(now, probeStarted),
      );
    }

    infrastructure = await collectInfrastructure(domain, {
      config: context.config,
      session,
      inspectionPlan: context.catalog.inspectionPlan,
      httpResult: entry,
    });
    errors.push(...infrastructure.errors);

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

    const detectStarted = now();
    try {
      detection = await detectHttp(entry, {
        catalog: context.catalog,
        pool: context.detectorPool,
        config: context.config,
        httpPages,
        probes: probeResult.observations,
        robots: Object.freeze([...precheckRobots]),
        browserPages: browserResult.pages,
        infrastructure: infrastructure.observations,
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
  return validated;
  } finally {
    if (deadlineTimer !== null) clearTimeout(deadlineTimer);
  }
}
