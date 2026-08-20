import {
  BROWSER_LIMIT_CATEGORIES,
  type BrowserLimitCategory,
} from "./crawl/browser.ts";
import type { DetectHttpResult } from "./detect/engine.ts";
import {
  ERROR_CODES,
  ERROR_STAGES,
  type DetectionStats,
  type DomainResult,
  type DomainStatus,
  type ErrorCode,
  type ErrorStage,
  type PageId,
  type PageRole,
  type Provenance,
  type ScanError,
  type Technology,
} from "./model.ts";

export const SHADOW_EVALUATION_SCHEMA_VERSION = 1 as const;
export const SHADOW_EVALUATION_PROTOCOL_REVISION = "2026-08-20.1";
export const SHADOW_EVALUATION_DOMAIN_COUNT = 200;
export const SHADOW_EVALUATION_FOLD_COUNT = 5;
export const SHADOW_TRIGGER_DOMAIN_CAP = 38;
export const SHADOW_CONTROL_DOMAIN_COUNT = 2;
export const SHADOW_EVALUATION_IDENTITY_VALUE_CAP = 10_000;

export type ShadowEntryOutcome =
  | "html"
  | "non-html"
  | "failed";

export type ShadowInternalOutcome =
  | "not-selected"
  | "denied"
  | "html"
  | "non-html"
  | "failed"
  | "skipped";

export type ShadowStatusClass = "2xx" | "3xx" | "4xx" | "5xx" | null;

export interface ShadowErrorCount {
  readonly stage: ErrorStage;
  readonly code: ErrorCode;
  readonly retryable: boolean;
  readonly count: number;
}

export interface AvailableShadowDetectorView {
  readonly state: "available";
  readonly directNames: readonly string[];
  readonly inferredNames: readonly string[];
  readonly detectionStats: DetectionStats;
  readonly completed: boolean;
  readonly errors: readonly ShadowErrorCount[];
}

export interface UnavailableShadowDetectorView {
  readonly state: "unavailable";
  readonly reason: "prefix-unavailable" | "detector-unavailable";
}

export type ShadowDetectorView =
  | AvailableShadowDetectorView
  | UnavailableShadowDetectorView;

export interface ShadowPreBrowserFeatures {
  readonly entryOutcome: ShadowEntryOutcome;
  readonly entryStatusClass: ShadowStatusClass;
  readonly entryHtmlBytes: number;
  readonly entryTextCodePoints: number;
  readonly staticNavigationLinks: number;
  readonly metadataEntries: number;
  readonly resourceEntries: number;
  readonly dnsRecords: number;
  readonly tlsIssuerPresent: boolean;
  readonly t2Selected: boolean;
  readonly t2Role: Exclude<PageRole, "entry"> | null;
  readonly t2Outcome: ShadowInternalOutcome;
  readonly probesObserved: number;
  readonly httpRequests: number;
  readonly staticTransferredBytes: number;
}

export interface ShadowFullLabel {
  readonly directNames: readonly string[];
  readonly inferredNames: readonly string[];
  readonly status: DomainStatus;
}

export interface ShadowFullCost {
  readonly browserPagesAttempted: number;
  readonly browserPagesAdmitted: number;
  readonly browserRequests: number;
  readonly browserTransferredBytes: number;
  readonly browserMs: number;
}

export interface ShadowBrowserLimitHit {
  readonly pageId: PageId;
  readonly category: BrowserLimitCategory;
  readonly domSelectorOrdinal: number | null;
}

export interface ShadowEvaluationSnapshot {
  readonly protocolRevision: typeof SHADOW_EVALUATION_PROTOCOL_REVISION;
  readonly runId: string;
  readonly domain: string;
  readonly t1: ShadowDetectorView;
  readonly t2: ShadowDetectorView;
  readonly preBrowser: ShadowPreBrowserFeatures | null;
  readonly full: ShadowFullLabel;
  readonly fullCost: ShadowFullCost;
  readonly browserLimitHits: readonly ShadowBrowserLimitHit[];
}

export interface ShadowLimitAggregate {
  readonly category: BrowserLimitCategory;
  readonly domSelectorOrdinal: number | null;
  readonly affectedDomains: number;
  readonly affectedPages: number;
  readonly hits: number;
}

export interface ShadowEvaluationArtifact {
  readonly schemaVersion: typeof SHADOW_EVALUATION_SCHEMA_VERSION;
  readonly protocolRevision: typeof SHADOW_EVALUATION_PROTOCOL_REVISION;
  readonly runId: string;
  readonly inputDomains: number;
  readonly provenance: Provenance;
  readonly snapshots: readonly ShadowEvaluationSnapshot[];
  readonly browserLimitAggregates: readonly ShadowLimitAggregate[];
}

export interface ShadowEvaluationAccumulator {
  readonly size: number;
  add(snapshot: ShadowEvaluationSnapshot): void;
  build(inputDomains: number): ShadowEvaluationArtifact;
}

export interface ShadowDetectorViewOptions {
  readonly errors?: readonly ScanError[];
  readonly completed?: boolean;
}

interface MutableLimitAggregate {
  hits: number;
  readonly domains: Set<string>;
  readonly pages: Set<string>;
  readonly category: BrowserLimitCategory;
  readonly domSelectorOrdinal: number | null;
}

const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ERROR_STAGE_SET = new Set<string>(ERROR_STAGES);
const ERROR_CODE_SET = new Set<string>(ERROR_CODES);
const BROWSER_LIMIT_CATEGORY_SET = new Set<string>(BROWSER_LIMIT_CATEGORIES);
const ENTRY_OUTCOMES = new Set<string>(["html", "non-html", "failed"]);
const INTERNAL_OUTCOMES = new Set<string>([
  "not-selected",
  "denied",
  "html",
  "non-html",
  "failed",
  "skipped",
]);
const STATUS_CLASSES = new Set<unknown>([null, "2xx", "3xx", "4xx", "5xx"]);
const PAGE_ROLES = new Set<unknown>([null, "detail", "listing", "content"]);
const DOMAIN_STATUSES = new Set<string>(["success", "partial", "failed"]);

function compareString(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareNullableNumber(left: number | null, right: number | null): number {
  if (left === right) return 0;
  if (left === null) return -1;
  if (right === null) return 1;
  return left - right;
}

function uniqueSortedNames(technologies: readonly Technology[]): readonly string[] {
  return Object.freeze([...new Set(technologies.map(({ name }) => name))]
    .sort(compareString));
}

function groupedErrors(errors: readonly ScanError[]): readonly ShadowErrorCount[] {
  const grouped = new Map<string, ShadowErrorCount>();
  for (const error of errors) {
    const key = JSON.stringify([error.stage, error.code, error.retryable]);
    const previous = grouped.get(key);
    grouped.set(key, Object.freeze({
      stage: error.stage,
      code: error.code,
      retryable: error.retryable,
      count: (previous?.count ?? 0) + 1,
    }));
  }
  return Object.freeze([...grouped.values()].sort((left, right) =>
    compareString(left.stage, right.stage)
    || compareString(left.code, right.code)
    || Number(left.retryable) - Number(right.retryable)));
}

export function shadowDetectorView(
  result: DetectHttpResult,
  options: ShadowDetectorViewOptions = {},
): AvailableShadowDetectorView {
  return Object.freeze({
    state: "available" as const,
    directNames: uniqueSortedNames(
      result.technologies.filter(({ type }) => type === "direct"),
    ),
    inferredNames: uniqueSortedNames(
      result.technologies.filter(({ type }) => type === "inferred"),
    ),
    detectionStats: Object.freeze({
      rawDirect: result.detectionStats.rawDirect,
      gatedDirect: result.detectionStats.gatedDirect,
      suppressedDirect: result.detectionStats.suppressedDirect,
      retainedDirect: result.detectionStats.retainedDirect,
    }),
    completed: options.completed ?? result.completed,
    errors: groupedErrors([
      ...(options.errors ?? []),
      ...result.errors,
    ]),
  });
}

export function unavailableShadowDetectorView(
  reason: UnavailableShadowDetectorView["reason"],
): UnavailableShadowDetectorView {
  return Object.freeze({ state: "unavailable", reason });
}

export function shadowFullLabel(result: DomainResult): ShadowFullLabel {
  return Object.freeze({
    directNames: uniqueSortedNames(
      result.technologies.filter(({ type }) => type === "direct"),
    ),
    inferredNames: uniqueSortedNames(
      result.technologies.filter(({ type }) => type === "inferred"),
    ),
    status: result.status,
  });
}

function assertSafeCount(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${label} must be a non-negative safe integer`);
  }
}

function assertSortedUnique(values: readonly string[], label: string): void {
  let previous: string | undefined;
  for (const value of values) {
    if (value.length === 0 || !value.isWellFormed()) {
      throw new TypeError(`${label} contains an invalid name`);
    }
    if (previous !== undefined && compareString(previous, value) >= 0) {
      throw new TypeError(`${label} must be strictly sorted and unique`);
    }
    previous = value;
  }
}

function assertDetectorView(view: ShadowDetectorView, label: string): void {
  if (view.state !== "available" && view.state !== "unavailable") {
    throw new TypeError(`${label}.state is invalid`);
  }
  if (view.state === "unavailable") {
    if (
      view.reason !== "prefix-unavailable"
      && view.reason !== "detector-unavailable"
    ) {
      throw new TypeError(`${label}.reason is invalid`);
    }
    return;
  }
  assertSortedUnique(view.directNames, `${label}.directNames`);
  assertSortedUnique(view.inferredNames, `${label}.inferredNames`);
  if (typeof view.completed !== "boolean") {
    throw new TypeError(`${label}.completed is invalid`);
  }
  for (const value of Object.values(view.detectionStats)) {
    assertSafeCount(value, `${label}.detectionStats`);
  }
  for (const error of view.errors) {
    if (
      !ERROR_STAGE_SET.has(error.stage)
      || !ERROR_CODE_SET.has(error.code)
      || typeof error.retryable !== "boolean"
    ) {
      throw new TypeError(`${label}.errors contains an invalid error`);
    }
    assertSafeCount(error.count, `${label}.errors.count`);
    if (error.count === 0) {
      throw new TypeError(`${label}.errors.count must be positive`);
    }
  }
}

function assertSnapshot(snapshot: ShadowEvaluationSnapshot): void {
  if (snapshot.protocolRevision !== SHADOW_EVALUATION_PROTOCOL_REVISION) {
    throw new TypeError("Shadow evaluation protocol revision does not match");
  }
  if (snapshot.domain.length === 0 || !snapshot.domain.isWellFormed()) {
    throw new TypeError("Shadow evaluation domain is invalid");
  }
  if (!RUN_ID.test(snapshot.runId)) {
    throw new TypeError("Shadow evaluation runId is invalid");
  }
  assertDetectorView(snapshot.t1, "t1");
  assertDetectorView(snapshot.t2, "t2");
  assertSortedUnique(snapshot.full.directNames, "full.directNames");
  assertSortedUnique(snapshot.full.inferredNames, "full.inferredNames");
  if (!DOMAIN_STATUSES.has(snapshot.full.status)) {
    throw new TypeError("Shadow full status is invalid");
  }
  for (const [key, value] of Object.entries(snapshot.fullCost)) {
    assertSafeCount(value, `fullCost.${key}`);
  }
  if (snapshot.preBrowser !== null) {
    if (
      !ENTRY_OUTCOMES.has(snapshot.preBrowser.entryOutcome)
      || !STATUS_CLASSES.has(snapshot.preBrowser.entryStatusClass)
      || !PAGE_ROLES.has(snapshot.preBrowser.t2Role)
      || !INTERNAL_OUTCOMES.has(snapshot.preBrowser.t2Outcome)
      || typeof snapshot.preBrowser.tlsIssuerPresent !== "boolean"
      || typeof snapshot.preBrowser.t2Selected !== "boolean"
      || snapshot.preBrowser.t2Selected !== (snapshot.preBrowser.t2Role !== null)
      || (snapshot.preBrowser.t2Selected
        ? snapshot.preBrowser.t2Outcome === "not-selected"
        : snapshot.preBrowser.t2Outcome !== "not-selected")
    ) {
      throw new TypeError("Shadow pre-browser features are invalid");
    }
    for (const [key, value] of Object.entries(snapshot.preBrowser)) {
      if (typeof value === "number") {
        assertSafeCount(value, `preBrowser.${key}`);
      }
    }
  }
  const seenHits = new Set<string>();
  for (const hit of snapshot.browserLimitHits) {
    if (
      !BROWSER_LIMIT_CATEGORY_SET.has(hit.category)
      || !["p1", "p2", "p3"].includes(hit.pageId)
      || (
        hit.domSelectorOrdinal !== null
        && (!Number.isSafeInteger(hit.domSelectorOrdinal)
          || hit.domSelectorOrdinal < 0)
      )
      || ((hit.category === "inspection.domMatches"
          || hit.category === "inspection.domAccess")
        ? hit.domSelectorOrdinal === null
        : hit.domSelectorOrdinal !== null)
    ) {
      throw new TypeError("Shadow browser limit hit is invalid");
    }
    const key = JSON.stringify([
      hit.pageId,
      hit.category,
      hit.domSelectorOrdinal,
    ]);
    if (seenHits.has(key)) {
      throw new TypeError("Shadow browser limit hits must be unique per page");
    }
    seenHits.add(key);
  }
}

function snapshotIdentityValues(snapshot: ShadowEvaluationSnapshot): number {
  const detectorValues = (view: ShadowDetectorView): number =>
    view.state === "unavailable"
      ? 1
      : view.directNames.length + view.inferredNames.length + view.errors.length;
  return 1
    + detectorValues(snapshot.t1)
    + detectorValues(snapshot.t2)
    + snapshot.full.directNames.length
    + snapshot.full.inferredNames.length
    + snapshot.browserLimitHits.length;
}

function cloneDetectorView(view: ShadowDetectorView): ShadowDetectorView {
  if (view.state === "unavailable") {
    return Object.freeze({ state: "unavailable" as const, reason: view.reason });
  }
  return Object.freeze({
    state: "available" as const,
    directNames: Object.freeze([...view.directNames]),
    inferredNames: Object.freeze([...view.inferredNames]),
    detectionStats: Object.freeze({
      rawDirect: view.detectionStats.rawDirect,
      gatedDirect: view.detectionStats.gatedDirect,
      suppressedDirect: view.detectionStats.suppressedDirect,
      retainedDirect: view.detectionStats.retainedDirect,
    }),
    completed: view.completed,
    errors: Object.freeze(view.errors.map((error) => Object.freeze({
      stage: error.stage,
      code: error.code,
      retryable: error.retryable,
      count: error.count,
    }))),
  });
}

export function createShadowEvaluationSnapshot(
  snapshot: ShadowEvaluationSnapshot,
): ShadowEvaluationSnapshot {
  assertSnapshot(snapshot);
  return Object.freeze({
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    runId: snapshot.runId,
    domain: snapshot.domain,
    t1: cloneDetectorView(snapshot.t1),
    t2: cloneDetectorView(snapshot.t2),
    preBrowser: snapshot.preBrowser === null
      ? null
      : Object.freeze({
          entryOutcome: snapshot.preBrowser.entryOutcome,
          entryStatusClass: snapshot.preBrowser.entryStatusClass,
          entryHtmlBytes: snapshot.preBrowser.entryHtmlBytes,
          entryTextCodePoints: snapshot.preBrowser.entryTextCodePoints,
          staticNavigationLinks: snapshot.preBrowser.staticNavigationLinks,
          metadataEntries: snapshot.preBrowser.metadataEntries,
          resourceEntries: snapshot.preBrowser.resourceEntries,
          dnsRecords: snapshot.preBrowser.dnsRecords,
          tlsIssuerPresent: snapshot.preBrowser.tlsIssuerPresent,
          t2Selected: snapshot.preBrowser.t2Selected,
          t2Role: snapshot.preBrowser.t2Role,
          t2Outcome: snapshot.preBrowser.t2Outcome,
          probesObserved: snapshot.preBrowser.probesObserved,
          httpRequests: snapshot.preBrowser.httpRequests,
          staticTransferredBytes: snapshot.preBrowser.staticTransferredBytes,
        }),
    full: Object.freeze({
      directNames: Object.freeze([...snapshot.full.directNames]),
      inferredNames: Object.freeze([...snapshot.full.inferredNames]),
      status: snapshot.full.status,
    }),
    fullCost: Object.freeze({
      browserPagesAttempted: snapshot.fullCost.browserPagesAttempted,
      browserPagesAdmitted: snapshot.fullCost.browserPagesAdmitted,
      browserRequests: snapshot.fullCost.browserRequests,
      browserTransferredBytes: snapshot.fullCost.browserTransferredBytes,
      browserMs: snapshot.fullCost.browserMs,
    }),
    browserLimitHits: Object.freeze(snapshot.browserLimitHits.map((hit) =>
      Object.freeze({
        pageId: hit.pageId,
        category: hit.category,
        domSelectorOrdinal: hit.domSelectorOrdinal,
      }))),
  });
}

function compareLimitAggregate(
  left: Pick<ShadowLimitAggregate, "category" | "domSelectorOrdinal">,
  right: Pick<ShadowLimitAggregate, "category" | "domSelectorOrdinal">,
): number {
  return compareString(left.category, right.category)
    || compareNullableNumber(left.domSelectorOrdinal, right.domSelectorOrdinal);
}

export function createShadowEvaluationAccumulator(input: {
  readonly runId: string;
  readonly provenance: Provenance;
}): ShadowEvaluationAccumulator {
  const snapshots = new Map<string, ShadowEvaluationSnapshot>();
  let identityValues = 0;
  const provenance = Object.freeze({
    scannerVersion: input.provenance.scannerVersion,
    runtime: Object.freeze({
      node: input.provenance.runtime.node,
      playwright: input.provenance.runtime.playwright,
      chromiumRevision: input.provenance.runtime.chromiumRevision,
    }),
    catalog: Object.freeze({
      source: input.provenance.catalog.source,
      revision: input.provenance.catalog.revision,
      digest: input.provenance.catalog.digest,
    }),
    configDigest: input.provenance.configDigest,
  });

  return Object.freeze({
    get size(): number {
      return snapshots.size;
    },
    add(snapshot: ShadowEvaluationSnapshot): void {
      assertSnapshot(snapshot);
      if (snapshot.runId !== input.runId) {
        throw new TypeError("Shadow snapshot runId does not match the accumulator");
      }
      if (snapshots.has(snapshot.domain)) {
        throw new TypeError("Shadow evaluation contains a duplicate domain");
      }
      if (snapshots.size >= SHADOW_EVALUATION_DOMAIN_COUNT) {
        throw new TypeError("Shadow evaluation exceeds the fixed cohort cap");
      }
      const nextIdentityValues = identityValues + snapshotIdentityValues(snapshot);
      if (
        !Number.isSafeInteger(nextIdentityValues)
        || nextIdentityValues > SHADOW_EVALUATION_IDENTITY_VALUE_CAP
      ) {
        throw new TypeError("Shadow evaluation exceeds the identity value cap");
      }
      snapshots.set(snapshot.domain, createShadowEvaluationSnapshot(snapshot));
      identityValues = nextIdentityValues;
    },
    build(inputDomains: number): ShadowEvaluationArtifact {
      assertSafeCount(inputDomains, "inputDomains");
      if (
        inputDomains !== SHADOW_EVALUATION_DOMAIN_COUNT
        || snapshots.size !== inputDomains
      ) {
        throw new TypeError("Shadow evaluation requires the exact 200-domain cohort");
      }

      const orderedSnapshots = Object.freeze([...snapshots.values()]
        .sort((left, right) => compareString(left.domain, right.domain)));
      const aggregates = new Map<string, MutableLimitAggregate>();
      for (const snapshot of orderedSnapshots) {
        for (const hit of snapshot.browserLimitHits) {
          const key = JSON.stringify([hit.category, hit.domSelectorOrdinal]);
          let aggregate = aggregates.get(key);
          if (aggregate === undefined) {
            aggregate = {
              hits: 0,
              domains: new Set<string>(),
              pages: new Set<string>(),
              category: hit.category,
              domSelectorOrdinal: hit.domSelectorOrdinal,
            };
            aggregates.set(key, aggregate);
          }
          aggregate.hits += 1;
          aggregate.domains.add(snapshot.domain);
          aggregate.pages.add(`${snapshot.domain}\0${hit.pageId}`);
        }
      }
      const browserLimitAggregates = Object.freeze([...aggregates.values()]
        .map((aggregate): ShadowLimitAggregate => Object.freeze({
          category: aggregate.category,
          domSelectorOrdinal: aggregate.domSelectorOrdinal,
          affectedDomains: aggregate.domains.size,
          affectedPages: aggregate.pages.size,
          hits: aggregate.hits,
        }))
        .sort(compareLimitAggregate));

      return Object.freeze({
        schemaVersion: SHADOW_EVALUATION_SCHEMA_VERSION,
        protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
        runId: input.runId,
        inputDomains,
        provenance,
        snapshots: orderedSnapshots,
        browserLimitAggregates,
      });
    },
  });
}
