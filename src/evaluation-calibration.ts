import { createHash } from "node:crypto";

import {
  SHADOW_CONTROL_DOMAIN_COUNT,
  SHADOW_EVALUATION_DOMAIN_COUNT,
  SHADOW_EVALUATION_FOLD_COUNT,
  SHADOW_EVALUATION_PROTOCOL_REVISION,
  SHADOW_TRIGGER_DOMAIN_CAP,
  type AvailableShadowDetectorView,
  type ShadowEvaluationArtifact,
  type ShadowDetectorView,
  type ShadowEvaluationSnapshot,
  type ShadowPreBrowserFeatures,
} from "./evaluation.ts";
import { computeDomainSetDigest } from "./domain-set.ts";
import type { CatalogProvenance, Provenance } from "./model.ts";

export const SHADOW_CALIBRATION_REVISION = "2026-08-20.2";
export const SHADOW_CALIBRATION_SMOOTHING_PRIOR = 4;
export const SHADOW_RECURRING_NAME_MINIMUM_SUPPORT = 2;
export const SHADOW_REAL_BROWSER_COST_MAXIMUM = 0.3;
export const SHADOW_PROVISIONAL_GUARDRAILS = Object.freeze({
  canonicalDirectNameRetentionMinimum: 0.95,
  domainTechnologyPairRetentionMinimum: 0.8,
  routedDomainMaximum: 40,
  realBrowserCostMaximum: SHADOW_REAL_BROWSER_COST_MAXIMUM,
});

const SHADOW_MODEL_KIND = "bounded-multiobjective-trigger-v2" as const;
export const SHADOW_MODEL_TOKEN_CAP = 20_000;
export const SHADOW_MODEL_RECURRING_NAME_CAP = 10_000;
export const SHADOW_MODEL_RECURRING_TARGET_CAP = 50_000;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export const SHADOW_CALIBRATION_SALTS = Object.freeze({
  fold: "website-technologies-scraper/shadow/2026-08-20.1/fold/v1",
  scoreTieBreak:
    "website-technologies-scraper/shadow/2026-08-20.1/score-tie/v1",
  control: "website-technologies-scraper/shadow/2026-08-20.1/control/v1",
  random: "website-technologies-scraper/shadow/2026-08-20.1/random/v1",
  greedyTieBreak:
    "website-technologies-scraper/shadow/2026-08-20.1/greedy-tie/v1",
});

export interface ShadowFoldModelMetadata {
  readonly fold: number;
  readonly trainingDomains: number;
  readonly heldOutDomains: number;
  readonly trainingIncrementalPairLift: number;
  readonly globalMeanIncrementalPairLift: number;
  readonly trainingRareSingletonLift: number;
  readonly globalMeanRareSingletonLift: number;
  readonly recurringNameHeads: number;
  readonly pairDeficit: number;
  readonly nameDeficit: number;
  readonly featureTokenCount: number;
  readonly smoothingPrior: number;
}

export interface ShadowRecurringTokenTarget {
  readonly head: number;
  readonly targetSum: number;
}

export interface ShadowDeploymentToken {
  readonly token: string;
  readonly domains: number;
  readonly pairTargetSum: number;
  readonly rareTargetSum: number;
  readonly recurringTargetSums: readonly ShadowRecurringTokenTarget[];
}

export interface ShadowRecurringNameHead {
  readonly name: string;
  readonly support: number;
}

export interface ShadowTrainingObjectives {
  readonly fullPairs: number;
  readonly baselineRetainedPairs: number;
  readonly pairDeficit: number;
  readonly fullCanonicalNames: number;
  readonly baselineRetainedNames: number;
  readonly nameDeficit: number;
}

export interface ShadowCandidateTrainingIdentity {
  readonly artifactDigest: string;
  readonly domainSetDigest: string;
  readonly schemaVersion: 1;
  readonly protocolRevision: typeof SHADOW_EVALUATION_PROTOCOL_REVISION;
  readonly runId: string;
  readonly provenance: Provenance;
}

export interface ShadowCandidateEvaluationCompatibility {
  readonly schemaVersion: 1;
  readonly protocolRevision: typeof SHADOW_EVALUATION_PROTOCOL_REVISION;
  readonly scannerVersion: string;
  readonly catalog: CatalogProvenance;
  readonly configDigest: string;
}

export interface ShadowFrozenCandidate {
  readonly kind: typeof SHADOW_MODEL_KIND;
  readonly calibrationRevision: typeof SHADOW_CALIBRATION_REVISION;
  readonly protocolRevision: typeof SHADOW_EVALUATION_PROTOCOL_REVISION;
  readonly trainingDomains: typeof SHADOW_EVALUATION_DOMAIN_COUNT;
  readonly objectives: {
    readonly canonicalDirectNameRetentionMinimum: 0.95;
    readonly domainTechnologyPairRetentionMinimum: 0.8;
  };
  readonly recurringNameMinimumSupport:
    typeof SHADOW_RECURRING_NAME_MINIMUM_SUPPORT;
  readonly trainingIncrementalPairLift: number;
  readonly trainingRareSingletonLift: number;
  readonly globalMeanIncrementalPairLift: number;
  readonly globalMeanRareSingletonLift: number;
  readonly smoothingPrior: typeof SHADOW_CALIBRATION_SMOOTHING_PRIOR;
  readonly trainingIdentity: ShadowCandidateTrainingIdentity;
  readonly evaluationCompatibility: ShadowCandidateEvaluationCompatibility;
  readonly trainingObjectives: ShadowTrainingObjectives;
  readonly recurringNames: readonly ShadowRecurringNameHead[];
  readonly tokens: readonly ShadowDeploymentToken[];
}

/** @deprecated Use ShadowFrozenCandidate. */
export type ShadowDeploymentModel = ShadowFrozenCandidate;

export interface ShadowDevelopmentCalibrationOptions {
  readonly trainingArtifactDigest: string;
  readonly expectedEvaluationScannerVersion: string;
  readonly expectedEvaluationConfigDigest: string;
}

export interface ShadowRecurringNamePrediction {
  readonly name: string;
  readonly probability: number;
}

export interface ShadowTriggerPrediction {
  readonly pairLift: number;
  readonly rareNovelty: number;
  readonly recurringNames: readonly ShadowRecurringNamePrediction[];
  readonly featureTokens: number;
}

export interface ShadowOofPrediction {
  readonly domain: string;
  readonly fold: number;
  readonly score: number;
  readonly pairLift: number;
  readonly rareNovelty: number;
  readonly recurringExpectedLift: number;
  readonly featureTokens: number;
}

export type ShadowSelectionSource = "trigger" | "control";

export interface ShadowSelectedDomain {
  readonly rank: number;
  readonly domain: string;
  readonly fold: number;
  readonly score: number;
  readonly source: ShadowSelectionSource;
}

export interface ShadowRatioMetric {
  readonly retained: number;
  readonly total: number;
  readonly ratio: number | null;
}

export interface ShadowMacroMetric {
  readonly eligible: number;
  readonly meanRecall: number | null;
}

export interface ShadowExtraPair {
  readonly domain: string;
  readonly technology: string;
}

export interface ShadowRetentionMetrics {
  readonly canonicalDirectNames: ShadowRatioMetric;
  readonly domainTechnologyPairs: ShadowRatioMetric;
  readonly macroDomains: ShadowMacroMetric;
  readonly macroTechnologies: ShadowMacroMetric;
  readonly emptyFullLabelDomains: number;
  readonly extraDirectNames: readonly string[];
  readonly extraDomainTechnologyPairs: readonly ShadowExtraPair[];
}

export interface ShadowCostMetric {
  readonly selected: number;
  readonly full: number;
  readonly relative: number | null;
}

export interface ShadowBrowserCostMetrics {
  readonly browserDomains: ShadowCostMetric;
  readonly browserPagesAttempted: ShadowCostMetric;
  readonly browserPagesAdmitted: ShadowCostMetric;
  readonly browserRequests: ShadowCostMetric;
  readonly browserTransferredBytes: ShadowCostMetric;
  readonly browserMs: ShadowCostMetric;
}

export interface ShadowSelectionMetrics {
  readonly routedDomains: number;
  readonly retention: ShadowRetentionMetrics;
  readonly costs: ShadowBrowserCostMetrics;
}

export interface ShadowMinimumGuardrailVerdict {
  readonly actual: number | null;
  readonly minimum: number;
  readonly passed: boolean;
}

export interface ShadowMaximumGuardrailVerdict {
  readonly actual: number;
  readonly maximum: number;
  readonly passed: boolean;
}

export interface ShadowProvisionalGuardrailVerdict {
  readonly scope: "provisional-shadow-challenge";
  readonly canonicalDirectNames: ShadowMinimumGuardrailVerdict;
  readonly domainTechnologyPairs: ShadowMinimumGuardrailVerdict;
  readonly routedDomains: ShadowMaximumGuardrailVerdict;
  readonly realBrowserCosts: ShadowRealBrowserCostGuardrailVerdict;
  readonly passed: boolean;
}

export interface ShadowCostGuardrailVerdict {
  readonly selected: number;
  readonly full: number;
  readonly actual: number | null;
  readonly maximum: typeof SHADOW_REAL_BROWSER_COST_MAXIMUM;
  readonly passed: boolean;
}

export interface ShadowRealBrowserCostGuardrailVerdict {
  readonly browserPagesAttempted: ShadowCostGuardrailVerdict;
  readonly browserPagesAdmitted: ShadowCostGuardrailVerdict;
  readonly browserRequests: ShadowCostGuardrailVerdict;
  readonly browserTransferredBytes: ShadowCostGuardrailVerdict;
  readonly browserMs: ShadowCostGuardrailVerdict;
  readonly passed: boolean;
}

export interface ShadowDeployableEvaluation {
  readonly name: "development-oof-trigger" | "frozen-holdout-trigger";
  readonly triggerDomainCount: number;
  readonly controlDomainCount: number;
  readonly selected: readonly ShadowSelectedDomain[];
  readonly metrics: ShadowSelectionMetrics;
  readonly provisionalGuardrails: ShadowProvisionalGuardrailVerdict;
}

export interface ShadowComparatorEvaluation {
  readonly name:
    | "deterministic-label-blind-random"
    | "label-aware-greedy";
  readonly selectedDomains: readonly string[];
  readonly metrics: ShadowSelectionMetrics;
}

export interface ShadowGreedyStep {
  readonly rank: number;
  readonly domain: string;
  readonly incrementalPairLift: number;
  readonly incrementalNameLift: number;
}

export interface ShadowGreedyEvaluation extends ShadowComparatorEvaluation {
  readonly name: "label-aware-greedy";
  readonly objective:
    "incremental-domain-technology-pairs-then-canonical-names";
  readonly steps: readonly ShadowGreedyStep[];
}

interface ShadowCalibrationReportBase {
  readonly calibrationRevision: typeof SHADOW_CALIBRATION_REVISION;
  readonly protocolRevision: typeof SHADOW_EVALUATION_PROTOCOL_REVISION;
  readonly runId: string;
  readonly evaluationProvenance: Provenance;
  readonly cohortDomains: typeof SHADOW_EVALUATION_DOMAIN_COUNT;
  readonly foldCount: typeof SHADOW_EVALUATION_FOLD_COUNT;
  readonly salts: typeof SHADOW_CALIBRATION_SALTS;
  readonly model: {
    readonly kind: typeof SHADOW_MODEL_KIND;
    readonly targets: readonly [
      "incremental-domain-technology-pairs",
      "recurring-canonical-name-presence",
      "rare-singleton-novelty",
    ];
    readonly smoothingPrior: typeof SHADOW_CALIBRATION_SMOOTHING_PRIOR;
    readonly folds: readonly ShadowFoldModelMetadata[];
  };
  readonly oofPredictions: readonly ShadowOofPrediction[];
  readonly deployable: ShadowDeployableEvaluation;
  readonly deterministicRandom: ShadowComparatorEvaluation;
  readonly labelAwareGreedy: ShadowGreedyEvaluation;
}


export interface ShadowDevelopmentCalibrationReport
  extends ShadowCalibrationReportBase {
  readonly mode: "development-oof";
  readonly trainingArtifactDigest: string;
  readonly candidate: ShadowFrozenCandidate | null;
  /** @deprecated Use candidate. */
  readonly deploymentModel: ShadowFrozenCandidate | null;
}

export interface ShadowDevelopmentSourceReport
  extends ShadowCalibrationReportBase {
  readonly mode: "development-source";
}

export interface ShadowFrozenHoldoutReport {
  readonly mode: "frozen-holdout";
  readonly calibrationRevision: typeof SHADOW_CALIBRATION_REVISION;
  readonly protocolRevision: typeof SHADOW_EVALUATION_PROTOCOL_REVISION;
  readonly runId: string;
  readonly cohortDomains: typeof SHADOW_EVALUATION_DOMAIN_COUNT;
  readonly salts: typeof SHADOW_CALIBRATION_SALTS;
  readonly candidateDigest: string;
  readonly trainingIdentity: ShadowCandidateTrainingIdentity;
  readonly evaluationProvenance: Provenance;
  readonly predictions: readonly ShadowOofPrediction[];
  readonly deployable: ShadowDeployableEvaluation;
}

export type ShadowCalibrationReport =
  | ShadowDevelopmentSourceReport
  | ShadowDevelopmentCalibrationReport;

interface TokenAggregate {
  domains: number;
  pairTargetSum: number;
  rareTargetSum: number;
  readonly recurringTargetSums: Map<number, number>;
}

interface FoldModel {
  readonly model: TrainedMultiHeadModel;
  readonly metadata: ShadowFoldModelMetadata;
}

interface TrainedMultiHeadModel {
  readonly trainingDomains: number;
  readonly trainingIncrementalPairLift: number;
  readonly trainingRareSingletonLift: number;
  readonly globalMeanIncrementalPairLift: number;
  readonly globalMeanRareSingletonLift: number;
  readonly trainingObjectives: ShadowTrainingObjectives;
  readonly recurringNames: readonly ShadowRecurringNameHead[];
  readonly tokens: ReadonlyMap<string, TokenAggregate>;
}

interface ScoredSnapshot {
  readonly snapshot: ShadowEvaluationSnapshot;
  readonly prediction: InternalShadowPrediction;
}

interface InternalShadowPrediction extends ShadowOofPrediction {
  readonly recurringNames: readonly ShadowRecurringNamePrediction[];
}

interface ShadowFoldQuota {
  readonly fold: number;
  readonly domains: number;
  readonly routed: number;
  readonly trigger: number;
  readonly control: number;
}

interface MutableCostTotals {
  browserPagesAttempted: number;
  browserPagesAdmitted: number;
  browserRequests: number;
  browserTransferredBytes: number;
  browserMs: number;
}

function compareString(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function saltedHash(salt: string, domain: string): Buffer {
  return createHash("sha256")
    .update(salt)
    .update("\0")
    .update(domain)
    .digest();
}

function saltedHashHex(salt: string, domain: string): string {
  return saltedHash(salt, domain).toString("hex");
}

export function shadowFoldForDomain(domain: string): number {
  return saltedHash(SHADOW_CALIBRATION_SALTS.fold, domain).readUInt32BE(0)
    % SHADOW_EVALUATION_FOLD_COUNT;
}

function countBin(value: number): string {
  if (value === 0) return "0";
  if (value === 1) return "1";
  const exponent = Math.floor(Math.log2(value));
  const lower = 2 ** exponent;
  const upper = Math.min(Number.MAX_SAFE_INTEGER, (2 ** (exponent + 1)) - 1);
  return `${lower}-${upper}`;
}

function directNames(view: ShadowDetectorView): readonly string[] {
  return view.state === "available" ? view.directNames : Object.freeze([]);
}

function addDetectorTokens(
  target: Set<string>,
  prefix: "t1" | "t2",
  view: ShadowDetectorView,
): void {
  target.add(`${prefix}.state=${view.state}`);
  if (view.state === "unavailable") {
    target.add(`${prefix}.reason=${view.reason}`);
    return;
  }

  target.add(`${prefix}.completed=${String(view.completed)}`);
  target.add(`${prefix}.direct.count=${countBin(view.directNames.length)}`);
  for (const name of view.directNames) {
    target.add(`${prefix}.direct=${JSON.stringify(name)}`);
  }
  const detectionStats = Object.entries(view.detectionStats)
    .sort(([left], [right]) => compareString(left, right));
  for (const [name, value] of detectionStats) {
    target.add(`${prefix}.detection.${name}=${countBin(value)}`);
  }
  for (const error of view.errors) {
    target.add(
      `${prefix}.error=${error.stage}:${error.code}:${String(error.retryable)}`,
    );
    target.add(
      `${prefix}.error.count=${error.stage}:${error.code}:` +
        `${String(error.retryable)}:${countBin(error.count)}`,
    );
  }
}

function addPreBrowserTokens(
  target: Set<string>,
  features: ShadowPreBrowserFeatures | null,
): void {
  if (features === null) {
    target.add("preBrowser=null");
    return;
  }

  target.add(`preBrowser.entryOutcome=${features.entryOutcome}`);
  target.add(`preBrowser.entryStatusClass=${features.entryStatusClass ?? "null"}`);
  target.add(`preBrowser.tlsIssuerPresent=${String(features.tlsIssuerPresent)}`);
  target.add(`preBrowser.t2Selected=${String(features.t2Selected)}`);
  target.add(`preBrowser.t2Role=${features.t2Role ?? "null"}`);
  target.add(`preBrowser.t2Outcome=${features.t2Outcome}`);
  const numeric: ReadonlyArray<readonly [string, number]> = [
    ["entryHtmlBytes", features.entryHtmlBytes],
    ["entryTextCodePoints", features.entryTextCodePoints],
    ["staticNavigationLinks", features.staticNavigationLinks],
    ["metadataEntries", features.metadataEntries],
    ["resourceEntries", features.resourceEntries],
    ["dnsRecords", features.dnsRecords],
    ["probesObserved", features.probesObserved],
    ["httpRequests", features.httpRequests],
    ["staticTransferredBytes", features.staticTransferredBytes],
  ];
  for (const [name, value] of numeric) {
    target.add(`preBrowser.${name}=${countBin(value)}`);
  }
}

/**
 * Returns the complete deployable feature surface. Its input type deliberately
 * excludes the full label, browser costs, and browser-limit telemetry.
 */
export function shadowTriggerFeatureTokens(
  snapshot: Pick<ShadowEvaluationSnapshot, "t1" | "t2" | "preBrowser">,
): readonly string[] {
  const tokens = new Set<string>();
  addDetectorTokens(tokens, "t1", snapshot.t1);
  addDetectorTokens(tokens, "t2", snapshot.t2);
  addPreBrowserTokens(tokens, snapshot.preBrowser);

  if (snapshot.t1.state === "available" && snapshot.t2.state === "available") {
    const t1Names = new Set(snapshot.t1.directNames);
    for (const name of snapshot.t2.directNames) {
      if (!t1Names.has(name)) {
        tokens.add(`t2.incrementalDirect=${JSON.stringify(name)}`);
      }
    }
    tokens.add(
      `t2.incrementalDirect.count=${countBin(
        snapshot.t2.directNames.length -
          snapshot.t2.directNames.filter((name) => t1Names.has(name)).length,
      )}`,
    );
  }

  return Object.freeze([...tokens].sort(compareString));
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

function assertAvailableView(
  view: AvailableShadowDetectorView,
  label: string,
): void {
  assertSortedUnique(view.directNames, `${label}.directNames`);
  for (const [name, value] of Object.entries(view.detectionStats)) {
    assertSafeCount(value, `${label}.detectionStats.${name}`);
  }
  for (const error of view.errors) {
    assertSafeCount(error.count, `${label}.errors.count`);
    if (error.count === 0) {
      throw new TypeError(`${label}.errors.count must be positive`);
    }
  }
}

function assertPrefixConsistency(snapshot: ShadowEvaluationSnapshot): void {
  if (snapshot.preBrowser === null) {
    if (
      snapshot.t1.state !== "unavailable"
      || snapshot.t1.reason !== "prefix-unavailable"
      || snapshot.t2.state !== "unavailable"
      || snapshot.t2.reason !== "prefix-unavailable"
    ) {
      throw new TypeError(
        "A null preBrowser prefix requires unavailable T1 and T2 prefixes",
      );
    }
    return;
  }

  if (
    snapshot.t1.state === "unavailable"
    && snapshot.t1.reason === "prefix-unavailable"
  ) {
    throw new TypeError("A prefix-unavailable T1 requires null preBrowser data");
  }
  if (
    snapshot.t2.state === "unavailable"
    && snapshot.t2.reason === "prefix-unavailable"
  ) {
    throw new TypeError("A prefix-unavailable T2 requires null preBrowser data");
  }
  if (snapshot.t1.state === "unavailable" && snapshot.t2.state === "available") {
    throw new TypeError("T2 cannot be available when T1 is unavailable");
  }
}

function validateSnapshots(
  snapshots: readonly ShadowEvaluationSnapshot[],
): readonly ShadowEvaluationSnapshot[] {
  if (snapshots.length !== SHADOW_EVALUATION_DOMAIN_COUNT) {
    throw new TypeError("Calibration requires the exact 200-domain cohort");
  }

  const ordered = [...snapshots].sort((left, right) =>
    compareString(left.domain, right.domain));
  const runId = ordered[0]?.runId;
  let previousDomain: string | undefined;
  for (const snapshot of ordered) {
    if (snapshot.protocolRevision !== SHADOW_EVALUATION_PROTOCOL_REVISION) {
      throw new TypeError("Calibration protocol revision does not match");
    }
    if (snapshot.runId !== runId) {
      throw new TypeError("Calibration snapshots must share one runId");
    }
    if (snapshot.domain.length === 0 || !snapshot.domain.isWellFormed()) {
      throw new TypeError("Calibration contains an invalid domain");
    }
    if (snapshot.domain === previousDomain) {
      throw new TypeError("Calibration contains a duplicate domain");
    }
    previousDomain = snapshot.domain;

    assertPrefixConsistency(snapshot);
    if (snapshot.t1.state === "unavailable" || snapshot.t2.state === "unavailable") {
      throw new TypeError("Calibration requires complete T1 and T2 shadow captures");
    }
    if (snapshot.t1.state === "available") assertAvailableView(snapshot.t1, "t1");
    if (snapshot.t2.state === "available") assertAvailableView(snapshot.t2, "t2");
    assertSortedUnique(snapshot.full.directNames, "full.directNames");
    for (const [name, value] of Object.entries(snapshot.fullCost)) {
      assertSafeCount(value, `fullCost.${name}`);
    }
    if (snapshot.preBrowser !== null) {
      for (const [name, value] of Object.entries(snapshot.preBrowser)) {
        if (typeof value === "number") {
          assertSafeCount(value, `preBrowser.${name}`);
        }
      }
    }
  }
  return Object.freeze(ordered);
}

function validateArtifact(
  artifact: ShadowEvaluationArtifact,
): readonly ShadowEvaluationSnapshot[] {
  if (
    artifact.schemaVersion !== 1
    || artifact.protocolRevision !== SHADOW_EVALUATION_PROTOCOL_REVISION
    || artifact.inputDomains !== SHADOW_EVALUATION_DOMAIN_COUNT
    || !RUN_ID.test(artifact.runId)
  ) {
    throw new TypeError("Shadow evaluation artifact identity does not match");
  }
  const snapshots = validateSnapshots(artifact.snapshots);
  if (snapshots[0]?.runId !== artifact.runId) {
    throw new TypeError("Shadow evaluation artifact runId does not match snapshots");
  }
  return snapshots;
}

function normalizeSha256Digest(value: string, label: string): string {
  if (!SHA256_DIGEST.test(value)) {
    throw new TypeError(`${label} must be a SHA-256 digest`);
  }
  return value;
}

function cloneCatalog(catalog: CatalogProvenance): CatalogProvenance {
  return Object.freeze({
    source: catalog.source,
    revision: catalog.revision,
    digest: catalog.digest,
  });
}

function cloneProvenance(provenance: Provenance): Provenance {
  return Object.freeze({
    scannerVersion: provenance.scannerVersion,
    runtime: Object.freeze({
      node: provenance.runtime.node,
      playwright: provenance.runtime.playwright,
      chromiumRevision: provenance.runtime.chromiumRevision,
    }),
    catalog: cloneCatalog(provenance.catalog),
    configDigest: provenance.configDigest,
  });
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
  label: string,
): Record<string, unknown> {
  if (
    typeof value !== "object"
    || value === null
    || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype
      && Object.getPrototypeOf(value) !== null)
  ) {
    throw new TypeError(`${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort(compareString);
  const expected = [...keys].sort(compareString);
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    throw new TypeError(`${label} does not have the exact frozen shape`);
  }
  return value as Record<string, unknown>;
}

function boundedString(value: unknown, label: string, maximum = 65_536): string {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > maximum
    || !value.isWellFormed()
  ) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function safeCount(value: unknown, label: string): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value < 0
    || Object.is(value, -0)
  ) {
    throw new TypeError(`${label} must be a non-negative safe integer`);
  }
  return value;
}

function finiteNonNegative(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new TypeError(`${label} must be finite and non-negative`);
  }
  return value;
}

function canonicalProvenance(value: unknown, label: string): Provenance {
  const provenance = exactRecord(
    value,
    ["scannerVersion", "runtime", "catalog", "configDigest"],
    label,
  );
  const runtime = exactRecord(
    provenance.runtime,
    ["node", "playwright", "chromiumRevision"],
    `${label}.runtime`,
  );
  const catalog = exactRecord(
    provenance.catalog,
    ["source", "revision", "digest"],
    `${label}.catalog`,
  );
  return cloneProvenance({
    scannerVersion: boundedString(provenance.scannerVersion, `${label}.scannerVersion`, 128),
    runtime: {
      node: boundedString(runtime.node, `${label}.runtime.node`, 128),
      playwright: boundedString(runtime.playwright, `${label}.runtime.playwright`, 128),
      chromiumRevision: boundedString(
        runtime.chromiumRevision,
        `${label}.runtime.chromiumRevision`,
        128,
      ),
    },
    catalog: {
      source: boundedString(catalog.source, `${label}.catalog.source`, 1_024),
      revision: boundedString(catalog.revision, `${label}.catalog.revision`, 1_024),
      digest: normalizeSha256Digest(
        boundedString(catalog.digest, `${label}.catalog.digest`, 128),
        `${label}.catalog.digest`,
      ),
    },
    configDigest: normalizeSha256Digest(
      boundedString(provenance.configDigest, `${label}.configDigest`, 128),
      `${label}.configDigest`,
    ),
  });
}

function incrementalPairLift(snapshot: ShadowEvaluationSnapshot): number {
  const baseline = new Set(directNames(snapshot.t2));
  let lift = 0;
  for (const name of snapshot.full.directNames) {
    if (!baseline.has(name)) lift += 1;
  }
  return lift;
}

function requiredRetention(total: number, numerator: number, denominator: number): number {
  const required = (
    (BigInt(total) * BigInt(numerator)) + BigInt(denominator - 1)
  ) / BigInt(denominator);
  const result = Number(required);
  assertSafeCount(result, "Required retention");
  return result;
}

function trainingObjectives(
  snapshots: readonly ShadowEvaluationSnapshot[],
): ShadowTrainingObjectives {
  const fullNames = new Set<string>();
  const baselineNames = new Set<string>();
  let fullPairs = 0;
  let baselineRetainedPairs = 0;
  for (const snapshot of snapshots) {
    const baseline = new Set(directNames(snapshot.t2));
    for (const name of snapshot.full.directNames) {
      fullNames.add(name);
      fullPairs += 1;
      if (baseline.has(name)) baselineRetainedPairs += 1;
    }
    for (const name of baseline) baselineNames.add(name);
  }
  let baselineRetainedNames = 0;
  for (const name of fullNames) {
    if (baselineNames.has(name)) baselineRetainedNames += 1;
  }
  return Object.freeze({
    fullPairs,
    baselineRetainedPairs,
    pairDeficit: Math.max(
      1,
      requiredRetention(fullPairs, 4, 5) - baselineRetainedPairs,
    ),
    fullCanonicalNames: fullNames.size,
    baselineRetainedNames,
    nameDeficit: Math.max(
      1,
      requiredRetention(fullNames.size, 19, 20) - baselineRetainedNames,
    ),
  });
}

function trainMultiHeadModel(
  snapshots: readonly ShadowEvaluationSnapshot[],
): TrainedMultiHeadModel {
  if (snapshots.length === 0) {
    throw new TypeError("A calibration model requires training domains");
  }
  const globalT2Names = new Set<string>();
  for (const snapshot of snapshots) {
    for (const name of directNames(snapshot.t2)) globalT2Names.add(name);
  }
  const novelByDomain = new Map<string, readonly string[]>();
  const novelSupport = new Map<string, number>();
  for (const snapshot of snapshots) {
    const novel = snapshot.full.directNames.filter((name) => !globalT2Names.has(name));
    novelByDomain.set(snapshot.domain, novel);
    for (const name of novel) {
      novelSupport.set(name, (novelSupport.get(name) ?? 0) + 1);
    }
  }
  const recurringNames = Object.freeze([...novelSupport.entries()]
    .filter(([, support]) => support >= SHADOW_RECURRING_NAME_MINIMUM_SUPPORT)
    .sort(([left], [right]) => compareString(left, right))
    .map(([name, support]) => Object.freeze({ name, support })));
  if (recurringNames.length > SHADOW_MODEL_RECURRING_NAME_CAP) {
    throw new TypeError("Calibration recurring-name model exceeds its bound");
  }
  const recurringIndex = new Map(
    recurringNames.map(({ name }, index) => [name, index] as const),
  );
  const tokenAggregates = new Map<string, TokenAggregate>();
  let pairTargetSum = 0;
  let rareTargetSum = 0;
  let recurringTargets = 0;
  for (const snapshot of snapshots) {
    const pairTarget = incrementalPairLift(snapshot);
    pairTargetSum += pairTarget;
    const positiveHeads: number[] = [];
    let rareTarget = 0;
    for (const name of novelByDomain.get(snapshot.domain) ?? []) {
      const head = recurringIndex.get(name);
      if (head === undefined) rareTarget += 1;
      else positiveHeads.push(head);
    }
    rareTargetSum += rareTarget;
    for (const token of shadowTriggerFeatureTokens(snapshot)) {
      const aggregate = tokenAggregates.get(token) ?? {
        domains: 0,
        pairTargetSum: 0,
        rareTargetSum: 0,
        recurringTargetSums: new Map<number, number>(),
      };
      aggregate.domains += 1;
      aggregate.pairTargetSum += pairTarget;
      aggregate.rareTargetSum += rareTarget;
      for (const head of positiveHeads) {
        if (!aggregate.recurringTargetSums.has(head)) recurringTargets += 1;
        aggregate.recurringTargetSums.set(
          head,
          (aggregate.recurringTargetSums.get(head) ?? 0) + 1,
        );
      }
      tokenAggregates.set(token, aggregate);
    }
  }
  if (
    tokenAggregates.size > SHADOW_MODEL_TOKEN_CAP
    || recurringTargets > SHADOW_MODEL_RECURRING_TARGET_CAP
  ) {
    throw new TypeError("Calibration token model exceeds its bound");
  }
  return Object.freeze({
    trainingDomains: snapshots.length,
    trainingIncrementalPairLift: pairTargetSum,
    trainingRareSingletonLift: rareTargetSum,
    globalMeanIncrementalPairLift: pairTargetSum / snapshots.length,
    globalMeanRareSingletonLift: rareTargetSum / snapshots.length,
    trainingObjectives: trainingObjectives(snapshots),
    recurringNames,
    tokens: tokenAggregates,
  });
}

function serializedTokens(
  model: TrainedMultiHeadModel,
): readonly ShadowDeploymentToken[] {
  return Object.freeze([...model.tokens.entries()]
    .sort(([left], [right]) => compareString(left, right))
    .map(([token, aggregate]): ShadowDeploymentToken => Object.freeze({
      token,
      domains: aggregate.domains,
      pairTargetSum: aggregate.pairTargetSum,
      rareTargetSum: aggregate.rareTargetSum,
      recurringTargetSums: Object.freeze([...aggregate.recurringTargetSums]
        .sort(([left], [right]) => left - right)
        .map(([head, targetSum]) => Object.freeze({ head, targetSum }))),
    })));
}

function buildFrozenCandidate(
  model: TrainedMultiHeadModel,
  artifact: ShadowEvaluationArtifact,
  options: ShadowDevelopmentCalibrationOptions,
): ShadowFrozenCandidate {
  if (model.trainingDomains !== SHADOW_EVALUATION_DOMAIN_COUNT) {
    throw new TypeError("A frozen candidate requires the full development cohort");
  }
  const expectedScannerVersion = boundedString(
    options.expectedEvaluationScannerVersion,
    "Expected evaluation scanner version",
    128,
  );
  const trainingProvenance = canonicalProvenance(
    artifact.provenance,
    "Training provenance",
  );
  const expectedConfigDigest = normalizeSha256Digest(
    options.expectedEvaluationConfigDigest,
    "Expected evaluation config digest",
  );
  return Object.freeze({
    kind: SHADOW_MODEL_KIND,
    calibrationRevision: SHADOW_CALIBRATION_REVISION,
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    trainingDomains: SHADOW_EVALUATION_DOMAIN_COUNT,
    objectives: Object.freeze({
      canonicalDirectNameRetentionMinimum: 0.95 as const,
      domainTechnologyPairRetentionMinimum: 0.8 as const,
    }),
    recurringNameMinimumSupport: SHADOW_RECURRING_NAME_MINIMUM_SUPPORT,
    trainingIncrementalPairLift: model.trainingIncrementalPairLift,
    trainingRareSingletonLift: model.trainingRareSingletonLift,
    globalMeanIncrementalPairLift: model.globalMeanIncrementalPairLift,
    globalMeanRareSingletonLift: model.globalMeanRareSingletonLift,
    smoothingPrior: SHADOW_CALIBRATION_SMOOTHING_PRIOR,
    trainingIdentity: Object.freeze({
      artifactDigest: normalizeSha256Digest(
        options.trainingArtifactDigest,
        "Training artifact digest",
      ),
      domainSetDigest: computeDomainSetDigest(
        artifact.snapshots.map(({ domain }) => domain),
      ),
      schemaVersion: 1 as const,
      protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
      runId: artifact.runId,
      provenance: trainingProvenance,
    }),
    evaluationCompatibility: Object.freeze({
      schemaVersion: 1 as const,
      protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
      scannerVersion: expectedScannerVersion,
      catalog: cloneCatalog(trainingProvenance.catalog),
      configDigest: expectedConfigDigest,
    }),
    trainingObjectives: model.trainingObjectives,
    recurringNames: model.recurringNames,
    tokens: serializedTokens(model),
  });
}

export function validateShadowFrozenCandidate(value: unknown): ShadowFrozenCandidate {
  const candidate = exactRecord(value, [
    "kind",
    "calibrationRevision",
    "protocolRevision",
    "trainingDomains",
    "objectives",
    "recurringNameMinimumSupport",
    "trainingIncrementalPairLift",
    "trainingRareSingletonLift",
    "globalMeanIncrementalPairLift",
    "globalMeanRareSingletonLift",
    "smoothingPrior",
    "trainingIdentity",
    "evaluationCompatibility",
    "trainingObjectives",
    "recurringNames",
    "tokens",
  ], "Frozen candidate");
  if (
    candidate.kind !== SHADOW_MODEL_KIND
    || candidate.calibrationRevision !== SHADOW_CALIBRATION_REVISION
    || candidate.protocolRevision !== SHADOW_EVALUATION_PROTOCOL_REVISION
    || candidate.trainingDomains !== SHADOW_EVALUATION_DOMAIN_COUNT
    || candidate.recurringNameMinimumSupport
      !== SHADOW_RECURRING_NAME_MINIMUM_SUPPORT
    || candidate.smoothingPrior !== SHADOW_CALIBRATION_SMOOTHING_PRIOR
  ) {
    throw new TypeError("Frozen candidate revision or constants do not match");
  }
  const objectives = exactRecord(candidate.objectives, [
    "canonicalDirectNameRetentionMinimum",
    "domainTechnologyPairRetentionMinimum",
  ], "Frozen candidate objectives");
  if (
    objectives.canonicalDirectNameRetentionMinimum !== 0.95
    || objectives.domainTechnologyPairRetentionMinimum !== 0.8
  ) {
    throw new TypeError("Frozen candidate objectives do not match");
  }
  const pairLift = safeCount(
    candidate.trainingIncrementalPairLift,
    "Frozen candidate pair target",
  );
  const rareLift = safeCount(
    candidate.trainingRareSingletonLift,
    "Frozen candidate rare target",
  );
  const pairMean = finiteNonNegative(
    candidate.globalMeanIncrementalPairLift,
    "Frozen candidate pair mean",
  );
  const rareMean = finiteNonNegative(
    candidate.globalMeanRareSingletonLift,
    "Frozen candidate rare mean",
  );
  if (
    pairMean !== pairLift / SHADOW_EVALUATION_DOMAIN_COUNT
    || rareMean !== rareLift / SHADOW_EVALUATION_DOMAIN_COUNT
  ) {
    throw new TypeError("Frozen candidate target means are inconsistent");
  }

  const identity = exactRecord(candidate.trainingIdentity, [
    "artifactDigest",
    "domainSetDigest",
    "schemaVersion",
    "protocolRevision",
    "runId",
    "provenance",
  ], "Frozen candidate training identity");
  if (
    identity.schemaVersion !== 1
    || identity.protocolRevision !== SHADOW_EVALUATION_PROTOCOL_REVISION
  ) {
    throw new TypeError("Frozen candidate training identity does not match");
  }
  const trainingProvenance = canonicalProvenance(
    identity.provenance,
    "Frozen candidate training provenance",
  );
  const compatibility = exactRecord(candidate.evaluationCompatibility, [
    "schemaVersion",
    "protocolRevision",
    "scannerVersion",
    "catalog",
    "configDigest",
  ], "Frozen candidate evaluation compatibility");
  if (
    compatibility.schemaVersion !== 1
    || compatibility.protocolRevision !== SHADOW_EVALUATION_PROTOCOL_REVISION
  ) {
    throw new TypeError("Frozen candidate evaluation compatibility does not match");
  }
  const compatibilityCatalogRecord = exactRecord(
    compatibility.catalog,
    ["source", "revision", "digest"],
    "Frozen candidate evaluation catalog",
  );
  const compatibilityCatalog = cloneCatalog({
    source: boundedString(
      compatibilityCatalogRecord.source,
      "Frozen candidate evaluation catalog source",
      1_024,
    ),
    revision: boundedString(
      compatibilityCatalogRecord.revision,
      "Frozen candidate evaluation catalog revision",
      1_024,
    ),
    digest: normalizeSha256Digest(
      boundedString(
        compatibilityCatalogRecord.digest,
        "Frozen candidate evaluation catalog digest",
        128,
      ),
      "Frozen candidate evaluation catalog digest",
    ),
  });
  if (
    compatibilityCatalog.source !== trainingProvenance.catalog.source
    || compatibilityCatalog.revision !== trainingProvenance.catalog.revision
    || compatibilityCatalog.digest !== trainingProvenance.catalog.digest
  ) {
    throw new TypeError("Frozen candidate catalogs are inconsistent");
  }

  const objectiveRecord = exactRecord(candidate.trainingObjectives, [
    "fullPairs",
    "baselineRetainedPairs",
    "pairDeficit",
    "fullCanonicalNames",
    "baselineRetainedNames",
    "nameDeficit",
  ], "Frozen candidate training objectives");
  const trainingObjective: ShadowTrainingObjectives = Object.freeze({
    fullPairs: safeCount(objectiveRecord.fullPairs, "Training full pairs"),
    baselineRetainedPairs: safeCount(
      objectiveRecord.baselineRetainedPairs,
      "Training baseline pairs",
    ),
    pairDeficit: safeCount(objectiveRecord.pairDeficit, "Training pair deficit"),
    fullCanonicalNames: safeCount(
      objectiveRecord.fullCanonicalNames,
      "Training full names",
    ),
    baselineRetainedNames: safeCount(
      objectiveRecord.baselineRetainedNames,
      "Training baseline names",
    ),
    nameDeficit: safeCount(objectiveRecord.nameDeficit, "Training name deficit"),
  });
  if (
    trainingObjective.baselineRetainedPairs > trainingObjective.fullPairs
    || trainingObjective.baselineRetainedNames
      > trainingObjective.fullCanonicalNames
    || trainingObjective.pairDeficit !== Math.max(
      1,
      requiredRetention(trainingObjective.fullPairs, 4, 5)
        - trainingObjective.baselineRetainedPairs,
    )
    || trainingObjective.nameDeficit !== Math.max(
      1,
      requiredRetention(trainingObjective.fullCanonicalNames, 19, 20)
        - trainingObjective.baselineRetainedNames,
    )
  ) {
    throw new TypeError("Frozen candidate training objectives are inconsistent");
  }

  if (
    !Array.isArray(candidate.recurringNames)
    || candidate.recurringNames.length > SHADOW_MODEL_RECURRING_NAME_CAP
  ) {
    throw new TypeError("Frozen candidate recurring-name heads exceed their bound");
  }
  let previousName: string | undefined;
  const recurringNames = candidate.recurringNames.map((value, index) => {
    const head = exactRecord(value, ["name", "support"], `Recurring head ${index}`);
    const name = boundedString(head.name, `Recurring head ${index} name`, 4_096);
    const support = safeCount(head.support, `Recurring head ${index} support`);
    if (
      support < SHADOW_RECURRING_NAME_MINIMUM_SUPPORT
      || support > SHADOW_EVALUATION_DOMAIN_COUNT
      || (previousName !== undefined && compareString(previousName, name) >= 0)
    ) {
      throw new TypeError("Frozen candidate recurring-name heads are invalid");
    }
    previousName = name;
    return Object.freeze({ name, support });
  });
  const recurringSupport = recurringNames.reduce(
    (sum, { support }) => sum + support,
    0,
  );
  if (
    !Number.isSafeInteger(recurringSupport)
    || !Number.isSafeInteger(recurringSupport + rareLift)
    || recurringSupport + rareLift > pairLift
  ) {
    throw new TypeError("Frozen candidate breadth targets exceed pair lift");
  }

  if (!Array.isArray(candidate.tokens) || candidate.tokens.length > SHADOW_MODEL_TOKEN_CAP) {
    throw new TypeError("Frozen candidate tokens exceed their bound");
  }
  let previousToken: string | undefined;
  let recurringTargetCount = 0;
  const tokens = candidate.tokens.map((value, tokenIndex) => {
    const token = exactRecord(value, [
      "token",
      "domains",
      "pairTargetSum",
      "rareTargetSum",
      "recurringTargetSums",
    ], `Frozen candidate token ${tokenIndex}`);
    const tokenName = boundedString(
      token.token,
      `Frozen candidate token ${tokenIndex} name`,
    );
    const domains = safeCount(token.domains, `Frozen candidate token ${tokenIndex} domains`);
    if (
      domains === 0
      || domains > SHADOW_EVALUATION_DOMAIN_COUNT
      || (previousToken !== undefined && compareString(previousToken, tokenName) >= 0)
    ) {
      throw new TypeError("Frozen candidate tokens are invalid or unsorted");
    }
    previousToken = tokenName;
    if (!Array.isArray(token.recurringTargetSums)) {
      throw new TypeError("Frozen candidate recurring targets must be an array");
    }
    recurringTargetCount += token.recurringTargetSums.length;
    if (recurringTargetCount > SHADOW_MODEL_RECURRING_TARGET_CAP) {
      throw new TypeError("Frozen candidate recurring targets exceed their bound");
    }
    let previousHead = -1;
    const recurringTargetSums = token.recurringTargetSums.map((target, targetIndex) => {
      const record = exactRecord(
        target,
        ["head", "targetSum"],
        `Frozen candidate token ${tokenIndex} recurring target ${targetIndex}`,
      );
      const head = safeCount(record.head, "Frozen candidate recurring target head");
      const targetSum = safeCount(
        record.targetSum,
        "Frozen candidate recurring target sum",
      );
      if (
        head <= previousHead
        || head >= recurringNames.length
        || targetSum === 0
        || targetSum > domains
        || targetSum > (recurringNames[head]?.support ?? -1)
      ) {
        throw new TypeError("Frozen candidate recurring targets are invalid");
      }
      previousHead = head;
      return Object.freeze({ head, targetSum });
    });
    const tokenPairTarget = safeCount(
      token.pairTargetSum,
      `Frozen candidate token ${tokenIndex} pair target`,
    );
    const tokenRareTarget = safeCount(
      token.rareTargetSum,
      `Frozen candidate token ${tokenIndex} rare target`,
    );
    if (tokenPairTarget > pairLift || tokenRareTarget > rareLift) {
      throw new TypeError("Frozen candidate token targets exceed training totals");
    }
    return Object.freeze({
      token: tokenName,
      domains,
      pairTargetSum: tokenPairTarget,
      rareTargetSum: tokenRareTarget,
      recurringTargetSums: Object.freeze(recurringTargetSums),
    });
  });
  const artifactDigest = normalizeSha256Digest(
    boundedString(identity.artifactDigest, "Training artifact digest", 128),
    "Training artifact digest",
  );
  const domainSetDigest = normalizeSha256Digest(
    boundedString(identity.domainSetDigest, "Training domain-set digest", 128),
    "Training domain-set digest",
  );
  const canonical = Object.freeze({
    kind: SHADOW_MODEL_KIND,
    calibrationRevision: SHADOW_CALIBRATION_REVISION,
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    trainingDomains: SHADOW_EVALUATION_DOMAIN_COUNT,
    objectives: Object.freeze({
      canonicalDirectNameRetentionMinimum: 0.95 as const,
      domainTechnologyPairRetentionMinimum: 0.8 as const,
    }),
    recurringNameMinimumSupport: SHADOW_RECURRING_NAME_MINIMUM_SUPPORT,
    trainingIncrementalPairLift: pairLift,
    trainingRareSingletonLift: rareLift,
    globalMeanIncrementalPairLift: pairMean,
    globalMeanRareSingletonLift: rareMean,
    smoothingPrior: SHADOW_CALIBRATION_SMOOTHING_PRIOR,
    trainingIdentity: Object.freeze({
      artifactDigest,
      domainSetDigest,
      schemaVersion: 1 as const,
      protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
      runId: (() => {
        const runId = boundedString(identity.runId, "Training runId", 128);
        if (!RUN_ID.test(runId)) throw new TypeError("Training runId is invalid");
        return runId;
      })(),
      provenance: trainingProvenance,
    }),
    evaluationCompatibility: Object.freeze({
      schemaVersion: 1 as const,
      protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
      scannerVersion: boundedString(
        compatibility.scannerVersion,
        "Expected evaluation scanner version",
        128,
      ),
      catalog: compatibilityCatalog,
      configDigest: normalizeSha256Digest(
        boundedString(
          compatibility.configDigest,
          "Expected evaluation config digest",
          128,
        ),
        "Expected evaluation config digest",
      ),
    }),
    trainingObjectives: trainingObjective,
    recurringNames: Object.freeze(recurringNames),
    tokens: Object.freeze(tokens),
  });
  return canonical;
}

function modelFromCandidate(candidate: ShadowFrozenCandidate): TrainedMultiHeadModel {
  return Object.freeze({
    trainingDomains: candidate.trainingDomains,
    trainingIncrementalPairLift: candidate.trainingIncrementalPairLift,
    trainingRareSingletonLift: candidate.trainingRareSingletonLift,
    globalMeanIncrementalPairLift: candidate.globalMeanIncrementalPairLift,
    globalMeanRareSingletonLift: candidate.globalMeanRareSingletonLift,
    trainingObjectives: candidate.trainingObjectives,
    recurringNames: candidate.recurringNames,
    tokens: new Map(candidate.tokens.map((token) => [token.token, {
      domains: token.domains,
      pairTargetSum: token.pairTargetSum,
      rareTargetSum: token.rareTargetSum,
      recurringTargetSums: new Map(
        token.recurringTargetSums.map(({ head, targetSum }) => [head, targetSum]),
      ),
    }] as const)),
  });
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort(compareString).map((key) =>
    `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

export function canonicalizeShadowFrozenCandidate(value: unknown): string {
  return canonicalJson(validateShadowFrozenCandidate(value));
}

export function digestShadowFrozenCandidate(value: unknown): string {
  return `sha256:${createHash("sha256")
    .update(canonicalizeShadowFrozenCandidate(value), "utf8")
    .digest("hex")}`;
}

export interface ShadowFrozenCandidateCompatibilityInput {
  readonly schemaVersion: 1;
  readonly protocolRevision: typeof SHADOW_EVALUATION_PROTOCOL_REVISION;
  readonly scannerVersion: string;
  readonly catalog: CatalogProvenance;
  readonly configDigest: string;
}

export interface ShadowFrozenHoldoutOptions {
  readonly candidateDigest: string;
}

export function assertShadowFrozenCandidateCompatibility(
  value: unknown,
  evaluation: ShadowFrozenCandidateCompatibilityInput,
): ShadowFrozenCandidate {
  const candidate = validateShadowFrozenCandidate(value);
  const expected = candidate.evaluationCompatibility;
  if (
    evaluation.schemaVersion !== expected.schemaVersion
    || evaluation.protocolRevision !== expected.protocolRevision
    || evaluation.scannerVersion !== expected.scannerVersion
    || evaluation.catalog.source !== expected.catalog.source
    || evaluation.catalog.revision !== expected.catalog.revision
    || evaluation.catalog.digest !== expected.catalog.digest
    || evaluation.configDigest !== expected.configDigest
  ) {
    throw new TypeError("Frozen candidate is incompatible with the evaluation run");
  }
  return candidate;
}

export function predictShadowSnapshot(
  value: unknown,
  snapshot: Pick<ShadowEvaluationSnapshot, "t1" | "t2" | "preBrowser">,
): ShadowTriggerPrediction {
  return predictWithModel(modelFromCandidate(validateShadowFrozenCandidate(value)), snapshot);
}

function trainFoldModel(
  snapshots: readonly ShadowEvaluationSnapshot[],
  heldOutFold: number,
): FoldModel {
  const training = snapshots.filter(
    (snapshot) => shadowFoldForDomain(snapshot.domain) !== heldOutFold,
  );
  const heldOutDomains = snapshots.length - training.length;
  const model = trainMultiHeadModel(training);
  return Object.freeze({
    model,
    metadata: Object.freeze({
      fold: heldOutFold,
      trainingDomains: training.length,
      heldOutDomains,
      trainingIncrementalPairLift: model.trainingIncrementalPairLift,
      globalMeanIncrementalPairLift: model.globalMeanIncrementalPairLift,
      trainingRareSingletonLift: model.trainingRareSingletonLift,
      globalMeanRareSingletonLift: model.globalMeanRareSingletonLift,
      recurringNameHeads: model.recurringNames.length,
      pairDeficit: model.trainingObjectives.pairDeficit,
      nameDeficit: model.trainingObjectives.nameDeficit,
      featureTokenCount: model.tokens.size,
      smoothingPrior: SHADOW_CALIBRATION_SMOOTHING_PRIOR,
    }),
  });
}

function deploymentTokenEstimate(
  targetSum: number,
  domains: number,
  globalMean: number,
): number {
  return (
    targetSum
    + (SHADOW_CALIBRATION_SMOOTHING_PRIOR * globalMean)
  ) / (domains + SHADOW_CALIBRATION_SMOOTHING_PRIOR);
}

function predictWithModel(
  model: TrainedMultiHeadModel,
  snapshot: Pick<ShadowEvaluationSnapshot, "t1" | "t2" | "preBrowser">,
): ShadowTriggerPrediction {
  const featureTokens = shadowTriggerFeatureTokens(snapshot);
  const matched = featureTokens
    .map((token) => model.tokens.get(token))
    .filter((aggregate): aggregate is TokenAggregate => aggregate !== undefined);
  let pairSum = model.globalMeanIncrementalPairLift;
  let rareSum = model.globalMeanRareSingletonLift;
  for (const aggregate of matched) {
    pairSum += deploymentTokenEstimate(
      aggregate.pairTargetSum,
      aggregate.domains,
      model.globalMeanIncrementalPairLift,
    );
    rareSum += deploymentTokenEstimate(
      aggregate.rareTargetSum,
      aggregate.domains,
      model.globalMeanRareSingletonLift,
    );
  }
  const estimates = matched.length + 1;
  const recurringNames = model.recurringNames.map(
    ({ name, support }, head): ShadowRecurringNamePrediction => {
      const globalMean = support / model.trainingDomains;
      let sum = globalMean;
      for (const aggregate of matched) {
        sum += deploymentTokenEstimate(
          aggregate.recurringTargetSums.get(head) ?? 0,
          aggregate.domains,
          globalMean,
        );
      }
      return Object.freeze({
        name,
        probability: Math.min(1, Math.max(0, sum / estimates)),
      });
    },
  );
  return Object.freeze({
    pairLift: pairSum / estimates,
    rareNovelty: rareSum / estimates,
    recurringNames: Object.freeze(recurringNames),
    featureTokens: featureTokens.length,
  });
}

function scoreSnapshots(
  snapshots: readonly ShadowEvaluationSnapshot[],
): {
  readonly models: readonly FoldModel[];
  readonly scored: readonly ScoredSnapshot[];
} {
  const models = Array.from(
    { length: SHADOW_EVALUATION_FOLD_COUNT },
    (_, fold) => trainFoldModel(snapshots, fold),
  );
  const baselineNames = t2BaselineNames(snapshots);
  const scored = snapshots.map((snapshot): ScoredSnapshot => {
    const fold = shadowFoldForDomain(snapshot.domain);
    const foldModel = models[fold];
    if (foldModel === undefined) throw new TypeError("Missing calibration fold model");
    const prediction = predictWithModel(foldModel.model, snapshot);
    return Object.freeze({
      snapshot,
      prediction: Object.freeze({
        domain: snapshot.domain,
        fold,
        score: initialPredictionUtility(
          prediction,
          foldModel.model,
          baselineNames,
        ),
        pairLift: prediction.pairLift,
        rareNovelty: prediction.rareNovelty,
        recurringExpectedLift: prediction.recurringNames.reduce(
          (sum, { name, probability }) =>
            sum + (baselineNames.has(name) ? 0 : probability),
          0,
        ),
        recurringNames: prediction.recurringNames,
        featureTokens: prediction.featureTokens,
      }),
    });
  });
  return Object.freeze({
    models: Object.freeze(models),
    scored: Object.freeze(scored),
  });
}

function t2BaselineNames(
  snapshots: readonly Pick<ShadowEvaluationSnapshot, "t2">[],
): ReadonlySet<string> {
  const names = new Set<string>();
  for (const snapshot of snapshots) {
    for (const name of directNames(snapshot.t2)) names.add(name);
  }
  return names;
}

function predictionNovelty(
  prediction: Pick<InternalShadowPrediction, "rareNovelty" | "recurringNames">,
  baselineNames: ReadonlySet<string>,
  covered: ReadonlyMap<string, number> = new Map(),
): number {
  let novelty = prediction.rareNovelty;
  for (const { name, probability } of prediction.recurringNames) {
    if (baselineNames.has(name)) continue;
    novelty += probability * (1 - (covered.get(name) ?? 0));
  }
  return novelty;
}

function initialPredictionUtility(
  prediction: ShadowTriggerPrediction,
  model: TrainedMultiHeadModel,
  baselineNames: ReadonlySet<string>,
): number {
  const pair = model.trainingObjectives.pairDeficit === 0
    ? 0
    : prediction.pairLift / model.trainingObjectives.pairDeficit;
  const names = model.trainingObjectives.nameDeficit === 0
    ? 0
    : predictionNovelty(prediction, baselineNames)
      / model.trainingObjectives.nameDeficit;
  return pair + names;
}

function selectGreedyPredictions(
  scored: readonly ScoredSnapshot[],
  count: number,
  model: TrainedMultiHeadModel,
  baselineNames: ReadonlySet<string>,
): readonly ScoredSnapshot[] {
  const remaining = new Map(
    scored.map((item) => [item.snapshot.domain, item] as const),
  );
  const covered = new Map<string, number>();
  const selected: ScoredSnapshot[] = [];
  while (selected.length < count) {
    let best: ScoredSnapshot | undefined;
    let bestUtility = -1;
    for (const item of remaining.values()) {
      const pairContribution = item.prediction.pairLift
        / model.trainingObjectives.pairDeficit;
      const novelty = predictionNovelty(item.prediction, baselineNames, covered);
      const nameContribution = novelty / model.trainingObjectives.nameDeficit;
      const utility = pairContribution + nameContribution;
      const better = utility > bestUtility || (
        utility === bestUtility
        && best !== undefined
        && compareString(
          saltedHashHex(
            SHADOW_CALIBRATION_SALTS.scoreTieBreak,
            item.snapshot.domain,
          ),
          saltedHashHex(
            SHADOW_CALIBRATION_SALTS.scoreTieBreak,
            best.snapshot.domain,
          ),
        ) < 0
      );
      if (best === undefined || better) {
        best = item;
        bestUtility = utility;
      }
    }
    if (best === undefined) {
      throw new TypeError("Multi-objective trigger exhausted its cohort");
    }
    remaining.delete(best.snapshot.domain);
    for (const { name, probability } of best.prediction.recurringNames) {
      if (baselineNames.has(name)) continue;
      const previous = covered.get(name) ?? 0;
      covered.set(name, 1 - ((1 - previous) * (1 - probability)));
    }
    selected.push(Object.freeze({
      snapshot: best.snapshot,
      prediction: Object.freeze({ ...best.prediction, score: bestUtility }),
    }));
  }
  return Object.freeze(selected);
}

function largestRemainderQuotas(
  weights: readonly number[],
  total: number,
  capacities: readonly number[],
  label: string,
): readonly number[] {
  if (
    weights.length !== SHADOW_EVALUATION_FOLD_COUNT
    || capacities.length !== weights.length
    || !Number.isSafeInteger(total)
    || total < 0
  ) {
    throw new TypeError(`${label} quota inputs are invalid`);
  }
  const weightTotal = weights.reduce((sum, weight, fold) => {
    assertSafeCount(weight, `${label} fold ${fold} weight`);
    assertSafeCount(capacities[fold] ?? -1, `${label} fold ${fold} capacity`);
    return sum + weight;
  }, 0);
  if (!Number.isSafeInteger(weightTotal) || weightTotal === 0 || total > weightTotal) {
    throw new TypeError(`${label} quota distribution is impossible`);
  }

  const numerators = weights.map((weight) => weight * total);
  if (numerators.some((value) => !Number.isSafeInteger(value))) {
    throw new TypeError(`${label} quota arithmetic exceeded safe integers`);
  }
  const quotas = numerators.map((numerator, fold) => {
    const quota = Math.floor(numerator / weightTotal);
    if (quota > (capacities[fold] ?? -1)) {
      throw new TypeError(`${label} quota exceeds a fold capacity`);
    }
    return quota;
  });
  let remaining = total - quotas.reduce((sum, quota) => sum + quota, 0);
  const remainderOrder = [...weights.keys()].sort((left, right) =>
    (numerators[right]! % weightTotal) - (numerators[left]! % weightTotal)
    || left - right);

  while (remaining > 0) {
    let admitted = false;
    for (const fold of remainderOrder) {
      if ((quotas[fold] ?? 0) >= (capacities[fold] ?? -1)) continue;
      quotas[fold] = (quotas[fold] ?? 0) + 1;
      remaining -= 1;
      admitted = true;
      if (remaining === 0) break;
    }
    if (!admitted) {
      throw new TypeError(`${label} quota distribution is impossible`);
    }
  }
  return Object.freeze(quotas);
}

function foldQuotas(scored: readonly ScoredSnapshot[]): readonly ShadowFoldQuota[] {
  const foldSizes = Array.from(
    { length: SHADOW_EVALUATION_FOLD_COUNT },
    () => 0,
  );
  for (const item of scored) {
    const fold = item.prediction.fold;
    if (!Number.isSafeInteger(fold) || fold < 0 || fold >= foldSizes.length) {
      throw new TypeError("Calibration produced an invalid fold");
    }
    foldSizes[fold] = (foldSizes[fold] ?? 0) + 1;
  }
  if (
    foldSizes.reduce((sum, size) => sum + size, 0)
      !== SHADOW_EVALUATION_DOMAIN_COUNT
  ) {
    throw new TypeError("Calibration fold distribution is incomplete");
  }

  const routed = largestRemainderQuotas(
    foldSizes,
    SHADOW_TRIGGER_DOMAIN_CAP + SHADOW_CONTROL_DOMAIN_COUNT,
    foldSizes,
    "Routed-domain",
  );
  const controls = largestRemainderQuotas(
    foldSizes,
    SHADOW_CONTROL_DOMAIN_COUNT,
    routed,
    "Control",
  );
  const quotas = foldSizes.map((domains, fold): ShadowFoldQuota => {
    const routedQuota = routed[fold] ?? -1;
    const control = controls[fold] ?? -1;
    const trigger = routedQuota - control;
    if (
      routedQuota < 0
      || routedQuota > domains
      || control < 0
      || control > routedQuota
      || trigger < 0
      || trigger + control !== routedQuota
      || domains - trigger < control
    ) {
      throw new TypeError("Calibration fold quota distribution is impossible");
    }
    return Object.freeze({ fold, domains, routed: routedQuota, trigger, control });
  });
  if (
    quotas.reduce((sum, quota) => sum + quota.routed, 0)
      !== SHADOW_TRIGGER_DOMAIN_CAP + SHADOW_CONTROL_DOMAIN_COUNT
    || quotas.reduce((sum, quota) => sum + quota.trigger, 0)
      !== SHADOW_TRIGGER_DOMAIN_CAP
    || quotas.reduce((sum, quota) => sum + quota.control, 0)
      !== SHADOW_CONTROL_DOMAIN_COUNT
  ) {
    throw new TypeError("Calibration fold quotas do not fill the frozen 38+2 budget");
  }
  return Object.freeze(quotas);
}

function ratio(retained: number, total: number): number | null {
  return total === 0 ? null : retained / total;
}

function costMetric(selected: number, full: number): ShadowCostMetric {
  return Object.freeze({ selected, full, relative: ratio(selected, full) });
}

function addSafeCost(left: number, right: number, label: string): number {
  const result = left + right;
  if (!Number.isSafeInteger(result)) {
    throw new TypeError(`${label} aggregate exceeds the safe-integer boundary`);
  }
  return result;
}

function addCost(target: MutableCostTotals, snapshot: ShadowEvaluationSnapshot): void {
  target.browserPagesAttempted = addSafeCost(
    target.browserPagesAttempted,
    snapshot.fullCost.browserPagesAttempted,
    "Browser pages attempted",
  );
  target.browserPagesAdmitted = addSafeCost(
    target.browserPagesAdmitted,
    snapshot.fullCost.browserPagesAdmitted,
    "Browser pages admitted",
  );
  target.browserRequests = addSafeCost(
    target.browserRequests,
    snapshot.fullCost.browserRequests,
    "Browser requests",
  );
  target.browserTransferredBytes = addSafeCost(
    target.browserTransferredBytes,
    snapshot.fullCost.browserTransferredBytes,
    "Browser transferred bytes",
  );
  target.browserMs = addSafeCost(
    target.browserMs,
    snapshot.fullCost.browserMs,
    "Browser milliseconds",
  );
}

function costsForSelection(
  snapshots: readonly ShadowEvaluationSnapshot[],
  selected: ReadonlySet<string>,
): ShadowBrowserCostMetrics {
  const selection: MutableCostTotals = {
    browserPagesAttempted: 0,
    browserPagesAdmitted: 0,
    browserRequests: 0,
    browserTransferredBytes: 0,
    browserMs: 0,
  };
  const full: MutableCostTotals = {
    browserPagesAttempted: 0,
    browserPagesAdmitted: 0,
    browserRequests: 0,
    browserTransferredBytes: 0,
    browserMs: 0,
  };
  for (const snapshot of snapshots) {
    addCost(full, snapshot);
    if (selected.has(snapshot.domain)) addCost(selection, snapshot);
  }
  return Object.freeze({
    browserDomains: costMetric(selected.size, snapshots.length),
    browserPagesAttempted: costMetric(
      selection.browserPagesAttempted,
      full.browserPagesAttempted,
    ),
    browserPagesAdmitted: costMetric(
      selection.browserPagesAdmitted,
      full.browserPagesAdmitted,
    ),
    browserRequests: costMetric(selection.browserRequests, full.browserRequests),
    browserTransferredBytes: costMetric(
      selection.browserTransferredBytes,
      full.browserTransferredBytes,
    ),
    browserMs: costMetric(selection.browserMs, full.browserMs),
  });
}

function simulatedNames(
  snapshot: ShadowEvaluationSnapshot,
  selected: ReadonlySet<string>,
): ReadonlySet<string> {
  return new Set(
    selected.has(snapshot.domain)
      ? snapshot.full.directNames
      : directNames(snapshot.t2),
  );
}

function retentionForSelection(
  snapshots: readonly ShadowEvaluationSnapshot[],
  selected: ReadonlySet<string>,
): ShadowRetentionMetrics {
  const allFullNames = new Set<string>();
  const allSimulatedNames = new Set<string>();
  const fullTechnologyDomains = new Map<string, Set<string>>();
  const simulatedTechnologyDomains = new Map<string, Set<string>>();
  const extraPairs: ShadowExtraPair[] = [];
  let retainedPairs = 0;
  let fullPairs = 0;
  let domainRecallSum = 0;
  let eligibleDomains = 0;
  let emptyFullLabelDomains = 0;

  for (const snapshot of snapshots) {
    const full = new Set(snapshot.full.directNames);
    const simulated = simulatedNames(snapshot, selected);
    for (const name of full) {
      allFullNames.add(name);
      const domains = fullTechnologyDomains.get(name) ?? new Set<string>();
      domains.add(snapshot.domain);
      fullTechnologyDomains.set(name, domains);
    }
    for (const name of simulated) {
      allSimulatedNames.add(name);
      const domains = simulatedTechnologyDomains.get(name) ?? new Set<string>();
      domains.add(snapshot.domain);
      simulatedTechnologyDomains.set(name, domains);
      if (!full.has(name)) {
        extraPairs.push(Object.freeze({ domain: snapshot.domain, technology: name }));
      }
    }

    if (full.size === 0) {
      emptyFullLabelDomains += 1;
      continue;
    }
    let domainRetained = 0;
    for (const name of full) {
      fullPairs += 1;
      if (simulated.has(name)) {
        retainedPairs += 1;
        domainRetained += 1;
      }
    }
    domainRecallSum += domainRetained / full.size;
    eligibleDomains += 1;
  }

  let retainedNames = 0;
  for (const name of allFullNames) {
    if (allSimulatedNames.has(name)) retainedNames += 1;
  }
  const extraNames = [...allSimulatedNames]
    .filter((name) => !allFullNames.has(name))
    .sort(compareString);

  let technologyRecallSum = 0;
  for (const [name, fullDomains] of fullTechnologyDomains) {
    const simulatedDomains = simulatedTechnologyDomains.get(name);
    let retainedDomains = 0;
    if (simulatedDomains !== undefined) {
      for (const domain of fullDomains) {
        if (simulatedDomains.has(domain)) retainedDomains += 1;
      }
    }
    technologyRecallSum += retainedDomains / fullDomains.size;
  }

  extraPairs.sort((left, right) =>
    compareString(left.domain, right.domain)
    || compareString(left.technology, right.technology));
  return Object.freeze({
    canonicalDirectNames: Object.freeze({
      retained: retainedNames,
      total: allFullNames.size,
      ratio: ratio(retainedNames, allFullNames.size),
    }),
    domainTechnologyPairs: Object.freeze({
      retained: retainedPairs,
      total: fullPairs,
      ratio: ratio(retainedPairs, fullPairs),
    }),
    macroDomains: Object.freeze({
      eligible: eligibleDomains,
      meanRecall: eligibleDomains === 0 ? null : domainRecallSum / eligibleDomains,
    }),
    macroTechnologies: Object.freeze({
      eligible: fullTechnologyDomains.size,
      meanRecall: fullTechnologyDomains.size === 0
        ? null
        : technologyRecallSum / fullTechnologyDomains.size,
    }),
    emptyFullLabelDomains,
    extraDirectNames: Object.freeze(extraNames),
    extraDomainTechnologyPairs: Object.freeze(extraPairs),
  });
}

function metricsForSelection(
  snapshots: readonly ShadowEvaluationSnapshot[],
  domains: readonly string[],
): ShadowSelectionMetrics {
  const selected = new Set(domains);
  if (selected.size !== domains.length) {
    throw new TypeError("A calibrated selection contains duplicate domains");
  }
  return Object.freeze({
    routedDomains: selected.size,
    retention: retentionForSelection(snapshots, selected),
    costs: costsForSelection(snapshots, selected),
  });
}

function provisionalGuardrailVerdict(
  metrics: ShadowSelectionMetrics,
): ShadowProvisionalGuardrailVerdict {
  const nameActual = metrics.retention.canonicalDirectNames.ratio;
  const pairActual = metrics.retention.domainTechnologyPairs.ratio;
  const namePassed = nameActual !== null
    && nameActual >= SHADOW_PROVISIONAL_GUARDRAILS
      .canonicalDirectNameRetentionMinimum;
  const pairPassed = pairActual !== null
    && pairActual >= SHADOW_PROVISIONAL_GUARDRAILS
      .domainTechnologyPairRetentionMinimum;
  const routedPassed = metrics.routedDomains
    <= SHADOW_PROVISIONAL_GUARDRAILS.routedDomainMaximum;
  const costVerdict = (
    metric: ShadowCostMetric,
  ): ShadowCostGuardrailVerdict => Object.freeze({
    selected: metric.selected,
    full: metric.full,
    actual: metric.relative,
    maximum: SHADOW_REAL_BROWSER_COST_MAXIMUM,
    passed: BigInt(metric.selected) * 10n <= BigInt(metric.full) * 3n,
  });
  const browserPagesAttempted = costVerdict(metrics.costs.browserPagesAttempted);
  const browserPagesAdmitted = costVerdict(metrics.costs.browserPagesAdmitted);
  const browserRequests = costVerdict(metrics.costs.browserRequests);
  const browserTransferredBytes = costVerdict(
    metrics.costs.browserTransferredBytes,
  );
  const browserMs = costVerdict(metrics.costs.browserMs);
  const realBrowserCosts = Object.freeze({
    browserPagesAttempted,
    browserPagesAdmitted,
    browserRequests,
    browserTransferredBytes,
    browserMs,
    passed: browserPagesAttempted.passed
      && browserPagesAdmitted.passed
      && browserRequests.passed
      && browserTransferredBytes.passed
      && browserMs.passed,
  });
  return Object.freeze({
    scope: "provisional-shadow-challenge" as const,
    canonicalDirectNames: Object.freeze({
      actual: nameActual,
      minimum: SHADOW_PROVISIONAL_GUARDRAILS
        .canonicalDirectNameRetentionMinimum,
      passed: namePassed,
    }),
    domainTechnologyPairs: Object.freeze({
      actual: pairActual,
      minimum: SHADOW_PROVISIONAL_GUARDRAILS
        .domainTechnologyPairRetentionMinimum,
      passed: pairPassed,
    }),
    routedDomains: Object.freeze({
      actual: metrics.routedDomains,
      maximum: SHADOW_PROVISIONAL_GUARDRAILS.routedDomainMaximum,
      passed: routedPassed,
    }),
    realBrowserCosts,
    passed: namePassed && pairPassed && routedPassed && realBrowserCosts.passed,
  });
}

function deterministicHashSelection(
  snapshots: readonly ShadowEvaluationSnapshot[],
  salt: string,
  count: number,
): readonly string[] {
  return Object.freeze([...snapshots]
    .sort((left, right) =>
      compareString(
        saltedHashHex(salt, left.domain),
        saltedHashHex(salt, right.domain),
      ) || compareString(left.domain, right.domain))
    .slice(0, count)
    .map(({ domain }) => domain));
}

function greedySelection(
  snapshots: readonly ShadowEvaluationSnapshot[],
  count: number,
): {
  readonly domains: readonly string[];
  readonly steps: readonly ShadowGreedyStep[];
} {
  const remaining = new Map(snapshots.map((snapshot) => [snapshot.domain, snapshot]));
  const canonicalNames = new Set<string>();
  for (const snapshot of snapshots) {
    for (const name of snapshot.full.directNames) canonicalNames.add(name);
  }
  const simulatedCanonicalNameCounts = new Map<string, number>();
  for (const snapshot of snapshots) {
    for (const name of directNames(snapshot.t2)) {
      if (!canonicalNames.has(name)) continue;
      simulatedCanonicalNameCounts.set(
        name,
        (simulatedCanonicalNameCounts.get(name) ?? 0) + 1,
      );
    }
  }
  const steps: ShadowGreedyStep[] = [];

  for (let rank = 1; rank <= count; rank += 1) {
    let best: ShadowEvaluationSnapshot | undefined;
    let bestPairLift = -1;
    let bestNameLift = -1;
    for (const snapshot of remaining.values()) {
      const baseline = new Set(directNames(snapshot.t2));
      const full = new Set(snapshot.full.directNames);
      let pairLift = 0;
      let nameLift = 0;
      for (const name of full) {
        if (!baseline.has(name)) pairLift += 1;
        if (!baseline.has(name) && !simulatedCanonicalNameCounts.has(name)) {
          nameLift += 1;
        }
      }
      for (const name of baseline) {
        if (
          !full.has(name)
          && canonicalNames.has(name)
          && simulatedCanonicalNameCounts.get(name) === 1
        ) {
          nameLift -= 1;
        }
      }
      const isBetter = pairLift > bestPairLift
        || (pairLift === bestPairLift && nameLift > bestNameLift)
        || (
          pairLift === bestPairLift
          && nameLift === bestNameLift
          && best !== undefined
          && compareString(
              saltedHashHex(
                SHADOW_CALIBRATION_SALTS.greedyTieBreak,
                snapshot.domain,
              ),
              saltedHashHex(
                SHADOW_CALIBRATION_SALTS.greedyTieBreak,
                best.domain,
              ),
            ) < 0
        );
      if (best === undefined || isBetter) {
        best = snapshot;
        bestPairLift = pairLift;
        bestNameLift = nameLift;
      }
    }
    if (best === undefined) throw new TypeError("Greedy comparator exhausted cohort");
    remaining.delete(best.domain);
    for (const name of directNames(best.t2)) {
      if (!canonicalNames.has(name)) continue;
      const previous = simulatedCanonicalNameCounts.get(name);
      if (previous === undefined) {
        throw new TypeError("Greedy comparator canonical-name state is invalid");
      }
      if (previous === 1) simulatedCanonicalNameCounts.delete(name);
      else simulatedCanonicalNameCounts.set(name, previous - 1);
    }
    for (const name of best.full.directNames) {
      simulatedCanonicalNameCounts.set(
        name,
        (simulatedCanonicalNameCounts.get(name) ?? 0) + 1,
      );
    }
    steps.push(Object.freeze({
      rank,
      domain: best.domain,
      incrementalPairLift: bestPairLift,
      incrementalNameLift: bestNameLift,
    }));
  }
  return Object.freeze({
    domains: Object.freeze(steps.map(({ domain }) => domain)),
    steps: Object.freeze(steps),
  });
}

function publishedPrediction(prediction: InternalShadowPrediction): ShadowOofPrediction {
  return Object.freeze({
    domain: prediction.domain,
    fold: prediction.fold,
    score: prediction.score,
    pairLift: prediction.pairLift,
    rareNovelty: prediction.rareNovelty,
    recurringExpectedLift: prediction.recurringExpectedLift,
    featureTokens: prediction.featureTokens,
  });
}

function developmentCalibration(
  artifact: ShadowEvaluationArtifact,
): {
  readonly report: ShadowDevelopmentSourceReport;
  readonly snapshots: readonly ShadowEvaluationSnapshot[];
} {
  const snapshots = validateArtifact(artifact);
  const { models, scored } = scoreSnapshots(snapshots);
  const quotas = foldQuotas(scored);
  const baselineNames = t2BaselineNames(snapshots);
  const triggered: ScoredSnapshot[] = [];
  const controls: ScoredSnapshot[] = [];
  for (const quota of quotas) {
    const foldScored = scored
      .filter(({ prediction }) => prediction.fold === quota.fold);
    if (foldScored.length !== quota.domains) {
      throw new TypeError("Calibration fold membership does not match its quota");
    }
    const foldModel = models[quota.fold];
    if (foldModel === undefined) throw new TypeError("Missing calibration fold model");
    const foldTriggered = selectGreedyPredictions(
      foldScored,
      quota.trigger,
      foldModel.model,
      baselineNames,
    );
    const triggeredDomains = new Set(
      foldTriggered.map(({ snapshot }) => snapshot.domain),
    );
    const foldControls = foldScored
      .filter(({ snapshot }) => !triggeredDomains.has(snapshot.domain))
      .sort((left, right) =>
        compareString(
          saltedHashHex(SHADOW_CALIBRATION_SALTS.control, left.snapshot.domain),
          saltedHashHex(SHADOW_CALIBRATION_SALTS.control, right.snapshot.domain),
        ) || compareString(left.snapshot.domain, right.snapshot.domain))
      .slice(0, quota.control);
    if (
      foldTriggered.length !== quota.trigger
      || foldControls.length !== quota.control
    ) {
      throw new TypeError("Calibration cannot fill a fold-local routed quota");
    }
    triggered.push(...foldTriggered);
    controls.push(...foldControls);
  }

  const selected: ShadowSelectedDomain[] = [];
  for (const [index, item] of triggered.entries()) {
    selected.push(Object.freeze({
      rank: index + 1,
      domain: item.snapshot.domain,
      fold: item.prediction.fold,
      score: item.prediction.score,
      source: "trigger" as const,
    }));
  }
  for (const [index, item] of controls.entries()) {
    selected.push(Object.freeze({
      rank: triggered.length + index + 1,
      domain: item.snapshot.domain,
      fold: item.prediction.fold,
      score: item.prediction.score,
      source: "control" as const,
    }));
  }
  if (
    triggered.length !== SHADOW_TRIGGER_DOMAIN_CAP
    || controls.length !== SHADOW_CONTROL_DOMAIN_COUNT
    || selected.length !== SHADOW_TRIGGER_DOMAIN_CAP + SHADOW_CONTROL_DOMAIN_COUNT
  ) {
    throw new TypeError("Calibration could not fill the frozen 38+2 browser quota");
  }

  const deployableDomains = selected.map(({ domain }) => domain);
  const randomDomains = deterministicHashSelection(
    snapshots,
    SHADOW_CALIBRATION_SALTS.random,
    SHADOW_TRIGGER_DOMAIN_CAP + SHADOW_CONTROL_DOMAIN_COUNT,
  );
  const greedy = greedySelection(
    snapshots,
    SHADOW_TRIGGER_DOMAIN_CAP + SHADOW_CONTROL_DOMAIN_COUNT,
  );
  const deployableMetrics = metricsForSelection(snapshots, deployableDomains);
  const report: ShadowDevelopmentSourceReport = Object.freeze({
    mode: "development-source" as const,
    calibrationRevision: SHADOW_CALIBRATION_REVISION,
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    runId: snapshots[0]?.runId ?? "",
    evaluationProvenance: cloneProvenance(artifact.provenance),
    cohortDomains: SHADOW_EVALUATION_DOMAIN_COUNT,
    foldCount: SHADOW_EVALUATION_FOLD_COUNT,
    salts: SHADOW_CALIBRATION_SALTS,
    model: Object.freeze({
      kind: SHADOW_MODEL_KIND,
      targets: Object.freeze([
        "incremental-domain-technology-pairs",
        "recurring-canonical-name-presence",
        "rare-singleton-novelty",
      ] as const),
      smoothingPrior: SHADOW_CALIBRATION_SMOOTHING_PRIOR,
      folds: Object.freeze(models.map(({ metadata }) => metadata)),
    }),
    oofPredictions: Object.freeze(
      scored.map(({ prediction }) => publishedPrediction(prediction)),
    ),
    deployable: Object.freeze({
      name: "development-oof-trigger" as const,
      triggerDomainCount: triggered.length,
      controlDomainCount: controls.length,
      selected: Object.freeze(selected),
      metrics: deployableMetrics,
      provisionalGuardrails: provisionalGuardrailVerdict(deployableMetrics),
    }),
    deterministicRandom: Object.freeze({
      name: "deterministic-label-blind-random" as const,
      selectedDomains: randomDomains,
      metrics: metricsForSelection(snapshots, randomDomains),
    }),
    labelAwareGreedy: Object.freeze({
      name: "label-aware-greedy" as const,
      objective: "incremental-domain-technology-pairs-then-canonical-names" as const,
      selectedDomains: greedy.domains,
      steps: greedy.steps,
      metrics: metricsForSelection(snapshots, greedy.domains),
    }),
  });
  return Object.freeze({ report, snapshots });
}

export function calibrateShadowDevelopmentSource(
  artifact: ShadowEvaluationArtifact,
): ShadowDevelopmentSourceReport {
  return developmentCalibration(artifact).report;
}

export function calibrateShadowDevelopment(
  artifact: ShadowEvaluationArtifact,
  options: ShadowDevelopmentCalibrationOptions,
): ShadowDevelopmentCalibrationReport {
  const { report, snapshots } = developmentCalibration(artifact);
  const trainingArtifactDigest = normalizeSha256Digest(
    options.trainingArtifactDigest,
    "Training artifact digest",
  );
  const candidate = report.deployable.provisionalGuardrails.passed
    ? buildFrozenCandidate(trainMultiHeadModel(snapshots), artifact, {
      ...options,
      trainingArtifactDigest,
    })
    : null;
  return Object.freeze({
    ...report,
    mode: "development-oof" as const,
    trainingArtifactDigest,
    candidate,
    deploymentModel: candidate,
  });
}

export function evaluateFrozenShadowCandidate(
  artifact: ShadowEvaluationArtifact,
  candidateValue: unknown,
  options: ShadowFrozenHoldoutOptions,
): ShadowFrozenHoldoutReport {
  const snapshots = validateArtifact(artifact);
  const candidate = assertShadowFrozenCandidateCompatibility(candidateValue, {
    schemaVersion: artifact.schemaVersion,
    protocolRevision: artifact.protocolRevision,
    scannerVersion: artifact.provenance.scannerVersion,
    catalog: artifact.provenance.catalog,
    configDigest: artifact.provenance.configDigest,
  });
  const model = modelFromCandidate(candidate);
  const candidateDigest = digestShadowFrozenCandidate(candidate);
  if (
    normalizeSha256Digest(options.candidateDigest, "Pinned candidate digest")
      !== candidateDigest
  ) {
    throw new TypeError("Pinned candidate digest does not match candidate");
  }
  if (
    artifact.runId === candidate.trainingIdentity.runId
    || computeDomainSetDigest(snapshots.map(({ domain }) => domain))
      === candidate.trainingIdentity.domainSetDigest
  ) {
    throw new TypeError("Frozen holdout must use a distinct run and domain set");
  }
  const baselineNames = t2BaselineNames(snapshots);
  const scored = snapshots.map((snapshot): ScoredSnapshot => {
    const prediction = predictWithModel(model, snapshot);
    return Object.freeze({
      snapshot,
      prediction: Object.freeze({
        domain: snapshot.domain,
        fold: shadowFoldForDomain(snapshot.domain),
        score: initialPredictionUtility(prediction, model, baselineNames),
        pairLift: prediction.pairLift,
        rareNovelty: prediction.rareNovelty,
        recurringExpectedLift: prediction.recurringNames.reduce(
          (sum, { name, probability }) =>
            sum + (baselineNames.has(name) ? 0 : probability),
          0,
        ),
        recurringNames: prediction.recurringNames,
        featureTokens: prediction.featureTokens,
      }),
    });
  });
  const triggered = selectGreedyPredictions(
    scored,
    SHADOW_TRIGGER_DOMAIN_CAP,
    model,
    baselineNames,
  );
  const triggeredDomains = new Set(
    triggered.map(({ snapshot }) => snapshot.domain),
  );
  const controls = scored
    .filter(({ snapshot }) => !triggeredDomains.has(snapshot.domain))
    .sort((left, right) => compareString(
      saltedHashHex(SHADOW_CALIBRATION_SALTS.control, left.snapshot.domain),
      saltedHashHex(SHADOW_CALIBRATION_SALTS.control, right.snapshot.domain),
    ) || compareString(left.snapshot.domain, right.snapshot.domain))
    .slice(0, SHADOW_CONTROL_DOMAIN_COUNT);
  if (
    triggered.length !== SHADOW_TRIGGER_DOMAIN_CAP
    || controls.length !== SHADOW_CONTROL_DOMAIN_COUNT
  ) {
    throw new TypeError("Frozen trigger cannot fill the exact 38+2 quota");
  }
  const selected: ShadowSelectedDomain[] = [
    ...triggered.map((item, index) => Object.freeze({
      rank: index + 1,
      domain: item.snapshot.domain,
      fold: item.prediction.fold,
      score: item.prediction.score,
      source: "trigger" as const,
    })),
    ...controls.map((item, index) => Object.freeze({
      rank: SHADOW_TRIGGER_DOMAIN_CAP + index + 1,
      domain: item.snapshot.domain,
      fold: item.prediction.fold,
      score: item.prediction.score,
      source: "control" as const,
    })),
  ];
  const selectedDomains = selected.map(({ domain }) => domain);
  const metrics = metricsForSelection(snapshots, selectedDomains);
  return Object.freeze({
    mode: "frozen-holdout" as const,
    calibrationRevision: SHADOW_CALIBRATION_REVISION,
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    runId: artifact.runId,
    cohortDomains: SHADOW_EVALUATION_DOMAIN_COUNT,
    salts: SHADOW_CALIBRATION_SALTS,
    candidateDigest,
    trainingIdentity: candidate.trainingIdentity,
    evaluationProvenance: cloneProvenance(artifact.provenance),
    predictions: Object.freeze(
      scored.map(({ prediction }) => publishedPrediction(prediction)),
    ),
    deployable: Object.freeze({
      name: "frozen-holdout-trigger" as const,
      triggerDomainCount: triggered.length,
      controlDomainCount: controls.length,
      selected: Object.freeze(selected),
      metrics,
      provisionalGuardrails: provisionalGuardrailVerdict(metrics),
    }),
  });
}
