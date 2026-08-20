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
import type { CompiledFingerprintCatalog } from "./detect/catalog.ts";
import type { CatalogProvenance, Provenance } from "./model.ts";

export const SHADOW_CALIBRATION_REVISION = "2026-08-20.2";
export const SHADOW_PAIRED_EXPERIMENT_REVISION = "2026-08-20.3";
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
const SHADOW_PAIRED_CANDIDATE_KIND = "paired-shadow-trigger-v1" as const;
export const SHADOW_BASELINE_FEATURE_SET = "baseline-v2" as const;
export const SHADOW_CATEGORY_FEATURE_SET =
  "baseline-v2+t2-direct-category-id-v1" as const;
export const SHADOW_CATEGORY_FOLD_WIN_MINIMUM = 4;
export const SHADOW_PAIRED_COHORT_SALT =
  "website-technologies-scraper/shadow/2026-08-20.3/cohort-sample/v1";
export const SHADOW_CATEGORY_ID_MAXIMUM = 1_000_000;
export const SHADOW_CATEGORY_IDS_PER_TECHNOLOGY_MAXIMUM = 32;
export const SHADOW_CATEGORY_TECHNOLOGY_MAXIMUM = 10_000;
export const SHADOW_CATEGORY_ASSOCIATION_MAXIMUM = 320_000;
export const SHADOW_CATEGORY_UNIQUE_ID_MAXIMUM = 1_024;
export const SHADOW_MODEL_TOKEN_CAP = 20_000;
export const SHADOW_MODEL_RECURRING_NAME_CAP = 10_000;
export const SHADOW_MODEL_RECURRING_TARGET_CAP = 50_000;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const GIT_COMMIT = /^[0-9a-f]{40}$/u;
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

export type ShadowPairedFeatureSet =
  | typeof SHADOW_BASELINE_FEATURE_SET
  | typeof SHADOW_CATEGORY_FEATURE_SET;

export interface ShadowT2CategoryTechnology {
  readonly name: string;
  readonly categoryIds: readonly number[];
}

/**
 * Raw-free catalog projection used only to turn already-observed T2 direct
 * names into bounded numeric category tokens.
 */
export interface ShadowT2CategoryProjection {
  readonly catalog: CatalogProvenance;
  readonly technologies: readonly ShadowT2CategoryTechnology[];
}

export interface ShadowPairedPreregistration {
  readonly schemaVersion: 1;
  readonly experimentRevision: typeof SHADOW_PAIRED_EXPERIMENT_REVISION;
  readonly baselineImplementationCommit: string;
  readonly discoveryArtifactDigest: string;
  readonly discoveryDomainSetDigest: string;
  readonly discoveryScannerVersion: "0.1.5";
  readonly expectedDevelopmentScannerVersion: string;
  readonly expectedDevelopmentConfigDigest: string;
  readonly catalog: CatalogProvenance;
  readonly protocolRevision: typeof SHADOW_EVALUATION_PROTOCOL_REVISION;
  readonly categoryProjectionDigest: string;
  readonly categoryFeature: {
    readonly source: "t2.directNames";
    readonly mapping: "effective-catalog-category-ids";
    readonly token: "t2.directCategoryId=<decimal>";
    readonly aggregation: "sorted-unique-union";
    readonly missing: "reject";
    readonly forbiddenInputs: readonly [
      "t1",
      "inferred",
      "full",
      "count",
      "category-name",
      "category-group",
    ];
  };
  readonly cohortPolicy: {
    readonly developmentDomains: typeof SHADOW_EVALUATION_DOMAIN_COUNT;
    readonly holdoutDomains: typeof SHADOW_EVALUATION_DOMAIN_COUNT;
    readonly sourceIdentity: "delegated-to-immutable-manifest";
    readonly selection: "sha256-rank-without-replacement-v1";
    readonly salt: typeof SHADOW_PAIRED_COHORT_SALT;
    readonly developmentSelection: "first-200-after-d1-exclusion";
    readonly holdoutSelection: "next-200-after-d1-exclusion";
    readonly overlap: "zero-canonical-d1-d2-h1";
    readonly preScreen: "none";
    readonly replacement: "none-after-freeze";
  };
  readonly featureSets: readonly [
    typeof SHADOW_BASELINE_FEATURE_SET,
    typeof SHADOW_CATEGORY_FEATURE_SET,
  ];
  readonly foldCount: typeof SHADOW_EVALUATION_FOLD_COUNT;
  readonly triggerDomainCount: typeof SHADOW_TRIGGER_DOMAIN_CAP;
  readonly controlDomainCount: typeof SHADOW_CONTROL_DOMAIN_COUNT;
  readonly smoothingPrior: typeof SHADOW_CALIBRATION_SMOOTHING_PRIOR;
  readonly recurringNameMinimumSupport:
    typeof SHADOW_RECURRING_NAME_MINIMUM_SUPPORT;
  readonly salts: typeof SHADOW_CALIBRATION_SALTS;
  readonly guardrails: {
    readonly canonicalDirectNameRetentionMinimum: 0.95;
    readonly domainTechnologyPairRetentionMinimum: 0.8;
    readonly realBrowserCostMaximum: typeof SHADOW_REAL_BROWSER_COST_MAXIMUM;
  };
  readonly foldWin: {
    readonly minimumCategoryWins: typeof SHADOW_CATEGORY_FOLD_WIN_MINIMUM;
    readonly scope: "trigger-only";
    readonly pairLift: "sum-full-minus-t2";
    readonly novelNameCoverage:
      "selected-full-union-minus-global-t2-union";
    readonly rule: "componentwise-non-regression-with-one-strict";
    readonly requirePositiveTriggerQuotaEachFold: true;
    readonly globalT2Union: "same-cohort-union-shared-by-arms";
    readonly interpretation: "stability-heuristic-not-statistical-test";
  };
  readonly controlsIncludedInGlobalGuardrails: true;
  readonly decisionRule:
    "baseline-first-else-category-if-eligible-else-no-go";
}

interface ShadowPairedCohortManifestBase {
  readonly schemaVersion: 1;
  readonly experimentRevision: typeof SHADOW_PAIRED_EXPERIMENT_REVISION;
  readonly preregistrationDigest: string;
  readonly input: {
    readonly fileDigest: string;
    readonly domainSetDigest: string;
    readonly domains: typeof SHADOW_EVALUATION_DOMAIN_COUNT;
  };
  readonly expected: {
    readonly scannerVersion: string;
    readonly configDigest: string;
    readonly catalog: CatalogProvenance;
    readonly schemaVersion: 1;
    readonly protocolRevision: typeof SHADOW_EVALUATION_PROTOCOL_REVISION;
  };
  readonly source: {
    readonly name: string;
    readonly revision: string;
    readonly digest: string;
  };
  readonly sampling: {
    readonly revision: string;
    readonly salt: string;
  };
  readonly zeroOverlapWith: readonly {
    readonly label: string;
    readonly domainSetDigest: string;
    readonly domains: readonly string[];
  }[];
}

export interface ShadowPairedDevelopmentCohortManifest
  extends ShadowPairedCohortManifestBase {
  readonly role: "development";
  readonly sealedHoldoutManifestDigest: string;
}

export interface ShadowPairedHoldoutCohortManifest
  extends ShadowPairedCohortManifestBase {
  readonly role: "holdout";
}

export type ShadowPairedCohortManifest =
  | ShadowPairedDevelopmentCohortManifest
  | ShadowPairedHoldoutCohortManifest;

export interface ShadowPairedFrozenCandidate {
  readonly kind: typeof SHADOW_PAIRED_CANDIDATE_KIND;
  readonly experimentRevision: typeof SHADOW_PAIRED_EXPERIMENT_REVISION;
  readonly featureSet: ShadowPairedFeatureSet;
  readonly preregistrationDigest: string;
  readonly trainingCohort: {
    readonly manifestDigest: string;
    readonly sealedHoldoutManifestDigest: string;
    readonly source: ShadowPairedCohortManifest["source"];
    readonly sampling: ShadowPairedCohortManifest["sampling"];
  };
  readonly categoryProjectionDigest: string;
  readonly model: ShadowFrozenCandidate;
}

/** @deprecated Use ShadowFrozenCandidate. */
export type ShadowDeploymentModel = ShadowFrozenCandidate;

export interface ShadowDevelopmentCalibrationOptions {
  readonly trainingArtifactDigest: string;
  readonly expectedEvaluationScannerVersion: string;
  readonly expectedEvaluationConfigDigest: string;
}

export interface ShadowPairedDevelopmentOptions
  extends ShadowDevelopmentCalibrationOptions {
  readonly preregistrationDigest: string;
  readonly cohortManifestDigest: string;
  readonly sealedHoldoutManifestDigest: string;
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

export interface ShadowPairedDevelopmentSourceReport {
  readonly mode: "paired-development-source";
  readonly experimentRevision: typeof SHADOW_PAIRED_EXPERIMENT_REVISION;
  readonly preregistrationDigest: string;
  readonly cohortManifestDigest: string;
  readonly sealedHoldoutManifestDigest: string;
  readonly categoryProjectionDigest: string;
  readonly source: ShadowDevelopmentSourceReport;
}

export interface ShadowPairedDevelopmentSourceOptions {
  readonly preregistrationDigest: string;
  readonly cohortManifestDigest: string;
  readonly sealedHoldoutManifestDigest: string;
  readonly categoryProjectionDigest: string;
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

export interface ShadowFoldTriggerOutcome {
  readonly fold: number;
  readonly triggerDomainCount: number;
  readonly pairLift: number;
  readonly novelNameCoverage: number;
}

export interface ShadowPairedFoldComparison {
  readonly fold: number;
  readonly baseline: ShadowFoldTriggerOutcome;
  readonly category: ShadowFoldTriggerOutcome;
  readonly categoryWon: boolean;
}

export type ShadowPairedDecision =
  | Readonly<{
    selectedFeatureSet: typeof SHADOW_BASELINE_FEATURE_SET;
    reason: "baseline-passed-all-official-gates";
  }>
  | Readonly<{
    selectedFeatureSet: typeof SHADOW_CATEGORY_FEATURE_SET;
    reason: "category-passed-all-official-gates-and-fold-win-minimum";
  }>
  | Readonly<{
    selectedFeatureSet: null;
    reason: "no-arm-eligible";
  }>;

export interface ShadowPairedDevelopmentReport {
  readonly mode: "paired-development-oof";
  readonly experimentRevision: typeof SHADOW_PAIRED_EXPERIMENT_REVISION;
  readonly preregistrationDigest: string;
  readonly cohortManifestDigest: string;
  readonly sealedHoldoutManifestDigest: string;
  readonly categoryProjectionDigest: string;
  readonly trainingArtifactDigest: string;
  readonly baseline: ShadowDevelopmentSourceReport;
  readonly category: ShadowDevelopmentSourceReport;
  readonly foldComparisons: readonly ShadowPairedFoldComparison[];
  readonly categoryFoldWins: number;
  readonly decision: ShadowPairedDecision;
  readonly candidate: ShadowPairedFrozenCandidate | null;
}

export interface ShadowPairedFrozenHoldoutReport {
  readonly mode: "paired-frozen-holdout";
  readonly experimentRevision: typeof SHADOW_PAIRED_EXPERIMENT_REVISION;
  readonly featureSet: ShadowPairedFeatureSet;
  readonly preregistrationDigest: string;
  readonly cohortManifestDigest: string;
  readonly candidateDigest: string;
  readonly categoryProjectionDigest: string;
  readonly evaluation: ShadowFrozenHoldoutReport;
}

export type ShadowCalibrationReport =
  | ShadowDevelopmentSourceReport
  | ShadowDevelopmentCalibrationReport
  | ShadowPairedDevelopmentSourceReport;

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

export function validateShadowT2CategoryProjection(
  value: unknown,
): ShadowT2CategoryProjection {
  const projection = exactRecord(
    value,
    ["catalog", "technologies"],
    "T2 category projection",
  );
  const catalogRecord = exactRecord(
    projection.catalog,
    ["source", "revision", "digest"],
    "T2 category projection catalog",
  );
  const catalog = cloneCatalog({
    source: boundedString(
      catalogRecord.source,
      "T2 category projection catalog source",
      1_024,
    ),
    revision: boundedString(
      catalogRecord.revision,
      "T2 category projection catalog revision",
      1_024,
    ),
    digest: normalizeSha256Digest(
      boundedString(
        catalogRecord.digest,
        "T2 category projection catalog digest",
        128,
      ),
      "T2 category projection catalog digest",
    ),
  });
  if (
    !Array.isArray(projection.technologies)
    || projection.technologies.length === 0
    || projection.technologies.length > SHADOW_CATEGORY_TECHNOLOGY_MAXIMUM
  ) {
    throw new TypeError("T2 category projection technologies exceed their bound");
  }

  const names = new Set<string>();
  const uniqueCategoryIds = new Set<number>();
  let associations = 0;
  const technologies = projection.technologies.map((value, index) => {
    const technology = exactRecord(
      value,
      ["name", "categoryIds"],
      `T2 category projection technology ${index}`,
    );
    const name = boundedString(
      technology.name,
      `T2 category projection technology ${index} name`,
      4_096,
    );
    if (names.has(name)) {
      throw new TypeError("T2 category projection contains a duplicate technology");
    }
    names.add(name);
    if (
      !Array.isArray(technology.categoryIds)
      || technology.categoryIds.length === 0
      || technology.categoryIds.length
        > SHADOW_CATEGORY_IDS_PER_TECHNOLOGY_MAXIMUM
    ) {
      throw new TypeError("T2 category projection category IDs exceed their bound");
    }
    const categoryIds = [...new Set(technology.categoryIds.map((rawId) => {
      if (
        typeof rawId !== "number"
        || !Number.isSafeInteger(rawId)
        || rawId < 1
        || rawId > SHADOW_CATEGORY_ID_MAXIMUM
      ) {
        throw new TypeError("T2 category projection contains an invalid category ID");
      }
      return rawId;
    }))].sort((left, right) => left - right);
    associations += categoryIds.length;
    if (
      !Number.isSafeInteger(associations)
      || associations > SHADOW_CATEGORY_ASSOCIATION_MAXIMUM
    ) {
      throw new TypeError("T2 category projection associations exceed their bound");
    }
    for (const categoryId of categoryIds) uniqueCategoryIds.add(categoryId);
    if (uniqueCategoryIds.size > SHADOW_CATEGORY_UNIQUE_ID_MAXIMUM) {
      throw new TypeError("T2 category projection unique category IDs exceed their bound");
    }
    return Object.freeze({ name, categoryIds: Object.freeze(categoryIds) });
  }).sort((left, right) => compareString(left.name, right.name));

  return Object.freeze({
    catalog,
    technologies: Object.freeze(technologies),
  });
}

export function projectShadowT2Categories(
  catalog: CompiledFingerprintCatalog,
): ShadowT2CategoryProjection {
  return validateShadowT2CategoryProjection({
    catalog: {
      source: catalog.source,
      revision: catalog.revision,
      digest: catalog.digest,
    },
    technologies: catalog.technologies.map((technology) => ({
      name: technology.name,
      categoryIds: technology.categories.map(({ id }) => id),
    })),
  });
}

type ShadowFeatureInput = Pick<
  ShadowEvaluationSnapshot,
  "t1" | "t2" | "preBrowser"
>;
type ShadowFeatureTokenFunction = (
  snapshot: ShadowFeatureInput,
) => readonly string[];

function categoryProjectionIndex(
  projection: ShadowT2CategoryProjection,
): ReadonlyMap<string, readonly number[]> {
  return new Map(
    projection.technologies.map(({ name, categoryIds }) => [name, categoryIds]),
  );
}

function categoryFeatureTokenFunction(
  projection: ShadowT2CategoryProjection,
): ShadowFeatureTokenFunction {
  const categoryIdsByTechnology = categoryProjectionIndex(projection);
  return (snapshot): readonly string[] => {
    const tokens = new Set(shadowTriggerFeatureTokens(snapshot));
    for (const name of directNames(snapshot.t2)) {
      const categoryIds = categoryIdsByTechnology.get(name);
      if (categoryIds === undefined || categoryIds.length === 0) {
        throw new TypeError(
          "T2 direct technology is missing from the category projection",
        );
      }
      for (const categoryId of categoryIds) {
        tokens.add(`t2.directCategoryId=${categoryId}`);
      }
    }
    return Object.freeze([...tokens].sort(compareString));
  };
}

export function shadowCategoryTriggerFeatureTokens(
  snapshot: ShadowFeatureInput,
  projectionValue: unknown,
): readonly string[] {
  return categoryFeatureTokenFunction(
    validateShadowT2CategoryProjection(projectionValue),
  )(snapshot);
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

function canonicalCatalogProvenance(
  value: unknown,
  label: string,
): CatalogProvenance {
  const catalog = exactRecord(value, ["source", "revision", "digest"], label);
  return cloneCatalog({
    source: boundedString(catalog.source, `${label}.source`, 1_024),
    revision: boundedString(catalog.revision, `${label}.revision`, 1_024),
    digest: normalizeSha256Digest(
      boundedString(catalog.digest, `${label}.digest`, 128),
      `${label}.digest`,
    ),
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

export function validateShadowPairedPreregistration(
  value: unknown,
): ShadowPairedPreregistration {
  const preregistration = exactRecord(value, [
    "schemaVersion",
    "experimentRevision",
    "baselineImplementationCommit",
    "discoveryArtifactDigest",
    "discoveryDomainSetDigest",
    "discoveryScannerVersion",
    "expectedDevelopmentScannerVersion",
    "expectedDevelopmentConfigDigest",
    "catalog",
    "protocolRevision",
    "categoryProjectionDigest",
    "categoryFeature",
    "cohortPolicy",
    "featureSets",
    "foldCount",
    "triggerDomainCount",
    "controlDomainCount",
    "smoothingPrior",
    "recurringNameMinimumSupport",
    "salts",
    "guardrails",
    "foldWin",
    "controlsIncludedInGlobalGuardrails",
    "decisionRule",
  ], "Paired preregistration");
  if (
    preregistration.schemaVersion !== 1
    || preregistration.experimentRevision !== SHADOW_PAIRED_EXPERIMENT_REVISION
    || preregistration.discoveryScannerVersion !== "0.1.5"
    || preregistration.protocolRevision !== SHADOW_EVALUATION_PROTOCOL_REVISION
    || preregistration.foldCount !== SHADOW_EVALUATION_FOLD_COUNT
    || preregistration.triggerDomainCount !== SHADOW_TRIGGER_DOMAIN_CAP
    || preregistration.controlDomainCount !== SHADOW_CONTROL_DOMAIN_COUNT
    || preregistration.smoothingPrior !== SHADOW_CALIBRATION_SMOOTHING_PRIOR
    || preregistration.recurringNameMinimumSupport
      !== SHADOW_RECURRING_NAME_MINIMUM_SUPPORT
    || preregistration.controlsIncludedInGlobalGuardrails !== true
    || preregistration.decisionRule
      !== "baseline-first-else-category-if-eligible-else-no-go"
  ) {
    throw new TypeError("Paired preregistration constants do not match");
  }
  const baselineImplementationCommit = boundedString(
    preregistration.baselineImplementationCommit,
    "Paired preregistration baseline commit",
    40,
  );
  if (!GIT_COMMIT.test(baselineImplementationCommit)) {
    throw new TypeError("Paired preregistration baseline commit is invalid");
  }
  const discoveryArtifactDigest = normalizeSha256Digest(
    boundedString(
      preregistration.discoveryArtifactDigest,
      "Paired preregistration discovery artifact digest",
      128,
    ),
    "Paired preregistration discovery artifact digest",
  );
  const discoveryDomainSetDigest = normalizeSha256Digest(
    boundedString(
      preregistration.discoveryDomainSetDigest,
      "Paired preregistration discovery domain-set digest",
      128,
    ),
    "Paired preregistration discovery domain-set digest",
  );
  const expectedDevelopmentScannerVersion = boundedString(
    preregistration.expectedDevelopmentScannerVersion,
    "Paired preregistration development scanner version",
    128,
  );
  const expectedDevelopmentConfigDigest = normalizeSha256Digest(
    boundedString(
      preregistration.expectedDevelopmentConfigDigest,
      "Paired preregistration development config digest",
      128,
    ),
    "Paired preregistration development config digest",
  );
  const catalog = canonicalCatalogProvenance(
    preregistration.catalog,
    "Paired preregistration catalog",
  );
  const categoryProjectionDigest = normalizeSha256Digest(
    boundedString(
      preregistration.categoryProjectionDigest,
      "Paired preregistration category projection digest",
      128,
    ),
    "Paired preregistration category projection digest",
  );

  const categoryFeature = exactRecord(preregistration.categoryFeature, [
    "source",
    "mapping",
    "token",
    "aggregation",
    "missing",
    "forbiddenInputs",
  ], "Paired preregistration category feature");
  const forbiddenInputs = [
    "t1",
    "inferred",
    "full",
    "count",
    "category-name",
    "category-group",
  ] as const;
  if (
    categoryFeature.source !== "t2.directNames"
    || categoryFeature.mapping !== "effective-catalog-category-ids"
    || categoryFeature.token !== "t2.directCategoryId=<decimal>"
    || categoryFeature.aggregation !== "sorted-unique-union"
    || categoryFeature.missing !== "reject"
    || canonicalJson(categoryFeature.forbiddenInputs)
      !== canonicalJson(forbiddenInputs)
  ) {
    throw new TypeError("Paired preregistration category feature does not match");
  }

  const cohortPolicy = exactRecord(preregistration.cohortPolicy, [
    "developmentDomains",
    "holdoutDomains",
    "sourceIdentity",
    "selection",
    "salt",
    "developmentSelection",
    "holdoutSelection",
    "overlap",
    "preScreen",
    "replacement",
  ], "Paired preregistration cohort policy");
  if (
    cohortPolicy.developmentDomains !== SHADOW_EVALUATION_DOMAIN_COUNT
    || cohortPolicy.holdoutDomains !== SHADOW_EVALUATION_DOMAIN_COUNT
    || cohortPolicy.sourceIdentity !== "delegated-to-immutable-manifest"
    || cohortPolicy.selection !== "sha256-rank-without-replacement-v1"
    || cohortPolicy.salt !== SHADOW_PAIRED_COHORT_SALT
    || cohortPolicy.developmentSelection !== "first-200-after-d1-exclusion"
    || cohortPolicy.holdoutSelection !== "next-200-after-d1-exclusion"
    || cohortPolicy.overlap !== "zero-canonical-d1-d2-h1"
    || cohortPolicy.preScreen !== "none"
    || cohortPolicy.replacement !== "none-after-freeze"
  ) {
    throw new TypeError("Paired preregistration cohort policy does not match");
  }
  const featureSets = [
    SHADOW_BASELINE_FEATURE_SET,
    SHADOW_CATEGORY_FEATURE_SET,
  ] as const;
  if (canonicalJson(preregistration.featureSets) !== canonicalJson(featureSets)) {
    throw new TypeError("Paired preregistration feature sets do not match");
  }
  const salts = exactRecord(
    preregistration.salts,
    Object.keys(SHADOW_CALIBRATION_SALTS),
    "Paired preregistration salts",
  );
  if (canonicalJson(salts) !== canonicalJson(SHADOW_CALIBRATION_SALTS)) {
    throw new TypeError("Paired preregistration salts do not match");
  }
  const guardrails = exactRecord(preregistration.guardrails, [
    "canonicalDirectNameRetentionMinimum",
    "domainTechnologyPairRetentionMinimum",
    "realBrowserCostMaximum",
  ], "Paired preregistration guardrails");
  if (
    guardrails.canonicalDirectNameRetentionMinimum !== 0.95
    || guardrails.domainTechnologyPairRetentionMinimum !== 0.8
    || guardrails.realBrowserCostMaximum !== SHADOW_REAL_BROWSER_COST_MAXIMUM
  ) {
    throw new TypeError("Paired preregistration guardrails do not match");
  }
  const foldWin = exactRecord(preregistration.foldWin, [
    "minimumCategoryWins",
    "scope",
    "pairLift",
    "novelNameCoverage",
    "rule",
    "requirePositiveTriggerQuotaEachFold",
    "globalT2Union",
    "interpretation",
  ], "Paired preregistration fold-win rule");
  if (
    foldWin.minimumCategoryWins !== SHADOW_CATEGORY_FOLD_WIN_MINIMUM
    || foldWin.scope !== "trigger-only"
    || foldWin.pairLift !== "sum-full-minus-t2"
    || foldWin.novelNameCoverage
      !== "selected-full-union-minus-global-t2-union"
    || foldWin.rule !== "componentwise-non-regression-with-one-strict"
    || foldWin.requirePositiveTriggerQuotaEachFold !== true
    || foldWin.globalT2Union !== "same-cohort-union-shared-by-arms"
    || foldWin.interpretation !== "stability-heuristic-not-statistical-test"
  ) {
    throw new TypeError("Paired preregistration fold-win rule does not match");
  }

  return Object.freeze({
    schemaVersion: 1 as const,
    experimentRevision: SHADOW_PAIRED_EXPERIMENT_REVISION,
    baselineImplementationCommit,
    discoveryArtifactDigest,
    discoveryDomainSetDigest,
    discoveryScannerVersion: "0.1.5" as const,
    expectedDevelopmentScannerVersion,
    expectedDevelopmentConfigDigest,
    catalog,
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    categoryProjectionDigest,
    categoryFeature: Object.freeze({
      source: "t2.directNames" as const,
      mapping: "effective-catalog-category-ids" as const,
      token: "t2.directCategoryId=<decimal>" as const,
      aggregation: "sorted-unique-union" as const,
      missing: "reject" as const,
      forbiddenInputs: Object.freeze(forbiddenInputs),
    }),
    cohortPolicy: Object.freeze({
      developmentDomains: SHADOW_EVALUATION_DOMAIN_COUNT,
      holdoutDomains: SHADOW_EVALUATION_DOMAIN_COUNT,
      sourceIdentity: "delegated-to-immutable-manifest" as const,
      selection: "sha256-rank-without-replacement-v1" as const,
      salt: SHADOW_PAIRED_COHORT_SALT,
      developmentSelection: "first-200-after-d1-exclusion" as const,
      holdoutSelection: "next-200-after-d1-exclusion" as const,
      overlap: "zero-canonical-d1-d2-h1" as const,
      preScreen: "none" as const,
      replacement: "none-after-freeze" as const,
    }),
    featureSets: Object.freeze(featureSets),
    foldCount: SHADOW_EVALUATION_FOLD_COUNT,
    triggerDomainCount: SHADOW_TRIGGER_DOMAIN_CAP,
    controlDomainCount: SHADOW_CONTROL_DOMAIN_COUNT,
    smoothingPrior: SHADOW_CALIBRATION_SMOOTHING_PRIOR,
    recurringNameMinimumSupport: SHADOW_RECURRING_NAME_MINIMUM_SUPPORT,
    salts: SHADOW_CALIBRATION_SALTS,
    guardrails: Object.freeze({
      canonicalDirectNameRetentionMinimum: 0.95 as const,
      domainTechnologyPairRetentionMinimum: 0.8 as const,
      realBrowserCostMaximum: SHADOW_REAL_BROWSER_COST_MAXIMUM,
    }),
    foldWin: Object.freeze({
      minimumCategoryWins: SHADOW_CATEGORY_FOLD_WIN_MINIMUM,
      scope: "trigger-only" as const,
      pairLift: "sum-full-minus-t2" as const,
      novelNameCoverage:
        "selected-full-union-minus-global-t2-union" as const,
      rule: "componentwise-non-regression-with-one-strict" as const,
      requirePositiveTriggerQuotaEachFold: true as const,
      globalT2Union: "same-cohort-union-shared-by-arms" as const,
      interpretation: "stability-heuristic-not-statistical-test" as const,
    }),
    controlsIncludedInGlobalGuardrails: true as const,
    decisionRule:
      "baseline-first-else-category-if-eligible-else-no-go" as const,
  });
}

export function validateShadowPairedCohortManifest(
  value: unknown,
): ShadowPairedCohortManifest {
  const rawRole = typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>).role
    : undefined;
  const manifest = exactRecord(value, [
    "schemaVersion",
    "experimentRevision",
    "role",
    "preregistrationDigest",
    "input",
    "expected",
    "source",
    "sampling",
    "zeroOverlapWith",
    ...(rawRole === "development" ? ["sealedHoldoutManifestDigest"] : []),
  ], "Paired cohort manifest");
  if (
    manifest.schemaVersion !== 1
    || manifest.experimentRevision !== SHADOW_PAIRED_EXPERIMENT_REVISION
    || (manifest.role !== "development" && manifest.role !== "holdout")
  ) {
    throw new TypeError("Paired cohort manifest identity does not match");
  }
  const role = manifest.role;
  const sealedHoldoutManifestDigest = role === "development"
    ? normalizeSha256Digest(
      boundedString(
        manifest.sealedHoldoutManifestDigest,
        "Paired development sealed holdout manifest digest",
        128,
      ),
      "Paired development sealed holdout manifest digest",
    )
    : undefined;
  const preregistrationDigest = normalizeSha256Digest(
    boundedString(
      manifest.preregistrationDigest,
      "Paired cohort manifest preregistration digest",
      128,
    ),
    "Paired cohort manifest preregistration digest",
  );
  const input = exactRecord(
    manifest.input,
    ["fileDigest", "domainSetDigest", "domains"],
    "Paired cohort manifest input",
  );
  if (input.domains !== SHADOW_EVALUATION_DOMAIN_COUNT) {
    throw new TypeError("Paired cohort manifest requires exactly 200 domains");
  }
  const canonicalInput = Object.freeze({
    fileDigest: normalizeSha256Digest(
      boundedString(input.fileDigest, "Paired cohort input file digest", 128),
      "Paired cohort input file digest",
    ),
    domainSetDigest: normalizeSha256Digest(
      boundedString(
        input.domainSetDigest,
        "Paired cohort input domain-set digest",
        128,
      ),
      "Paired cohort input domain-set digest",
    ),
    domains: SHADOW_EVALUATION_DOMAIN_COUNT,
  });
  const expected = exactRecord(manifest.expected, [
    "scannerVersion",
    "configDigest",
    "catalog",
    "schemaVersion",
    "protocolRevision",
  ], "Paired cohort expected identity");
  if (
    expected.schemaVersion !== 1
    || expected.protocolRevision !== SHADOW_EVALUATION_PROTOCOL_REVISION
  ) {
    throw new TypeError("Paired cohort expected protocol does not match");
  }
  const canonicalExpected = Object.freeze({
    scannerVersion: boundedString(
      expected.scannerVersion,
      "Paired cohort expected scanner version",
      128,
    ),
    configDigest: normalizeSha256Digest(
      boundedString(
        expected.configDigest,
        "Paired cohort expected config digest",
        128,
      ),
      "Paired cohort expected config digest",
    ),
    catalog: canonicalCatalogProvenance(
      expected.catalog,
      "Paired cohort expected catalog",
    ),
    schemaVersion: 1 as const,
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
  });
  const source = exactRecord(
    manifest.source,
    ["name", "revision", "digest"],
    "Paired cohort source",
  );
  const canonicalSource = Object.freeze({
    name: boundedString(source.name, "Paired cohort source name", 1_024),
    revision: boundedString(source.revision, "Paired cohort source revision", 1_024),
    digest: normalizeSha256Digest(
      boundedString(source.digest, "Paired cohort source digest", 128),
      "Paired cohort source digest",
    ),
  });
  const sampling = exactRecord(
    manifest.sampling,
    ["revision", "salt"],
    "Paired cohort sampling",
  );
  if (
    sampling.revision !== "sha256-rank-without-replacement-v1"
    || sampling.salt !== SHADOW_PAIRED_COHORT_SALT
  ) {
    throw new TypeError("Paired cohort sampling does not match preregistration");
  }
  const canonicalSampling = Object.freeze({
    revision: "sha256-rank-without-replacement-v1" as const,
    salt: SHADOW_PAIRED_COHORT_SALT,
  });
  if (!Array.isArray(manifest.zeroOverlapWith)) {
    throw new TypeError("Paired cohort zero-overlap proof must be an array");
  }
  const requiredLabels = role === "development"
    ? ["D1"] as const
    : ["D1", "D2"] as const;
  if (manifest.zeroOverlapWith.length !== requiredLabels.length) {
    throw new TypeError("Paired cohort zero-overlap proof is incomplete");
  }
  const zeroOverlapWith = manifest.zeroOverlapWith.map((value, index) => {
    const proof = exactRecord(
      value,
      ["label", "domainSetDigest", "domains"],
      `Paired cohort zero-overlap proof ${index}`,
    );
    if (proof.label !== requiredLabels[index]) {
      throw new TypeError("Paired cohort zero-overlap labels do not match role");
    }
    if (
      !Array.isArray(proof.domains)
      || proof.domains.length !== SHADOW_EVALUATION_DOMAIN_COUNT
    ) {
      throw new TypeError("Paired cohort zero-overlap proof requires 200 domains");
    }
    const domains = proof.domains.map((domain, domainIndex) => boundedString(
      domain,
      `Paired cohort zero-overlap domain ${domainIndex}`,
      253,
    )).sort(compareString);
    const computedDigest = computeDomainSetDigest(domains);
    const pinnedDigest = normalizeSha256Digest(
      boundedString(
        proof.domainSetDigest,
        "Paired cohort zero-overlap domain-set digest",
        128,
      ),
      "Paired cohort zero-overlap domain-set digest",
    );
    if (computedDigest !== pinnedDigest) {
      throw new TypeError("Paired cohort zero-overlap digest does not match domains");
    }
    return Object.freeze({
      label: proof.label as "D1" | "D2",
      domainSetDigest: pinnedDigest,
      domains: Object.freeze(domains),
    });
  });
  const canonical = {
    schemaVersion: 1 as const,
    experimentRevision:
      SHADOW_PAIRED_EXPERIMENT_REVISION as typeof SHADOW_PAIRED_EXPERIMENT_REVISION,
    role,
    preregistrationDigest,
    input: canonicalInput,
    expected: canonicalExpected,
    source: canonicalSource,
    sampling: canonicalSampling,
    zeroOverlapWith: Object.freeze(zeroOverlapWith),
  };
  return role === "development"
    ? Object.freeze({
      ...canonical,
      role: "development" as const,
      sealedHoldoutManifestDigest: sealedHoldoutManifestDigest!,
    })
    : Object.freeze({ ...canonical, role: "holdout" as const });
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
  featureTokens: ShadowFeatureTokenFunction = shadowTriggerFeatureTokens,
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
    for (const token of featureTokens(snapshot)) {
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

export function validateShadowPairedFrozenCandidate(
  value: unknown,
): ShadowPairedFrozenCandidate {
  const candidate = exactRecord(value, [
    "kind",
    "experimentRevision",
    "featureSet",
    "preregistrationDigest",
    "trainingCohort",
    "categoryProjectionDigest",
    "model",
  ], "Paired frozen candidate");
  if (
    candidate.kind !== SHADOW_PAIRED_CANDIDATE_KIND
    || candidate.experimentRevision !== SHADOW_PAIRED_EXPERIMENT_REVISION
    || (
      candidate.featureSet !== SHADOW_BASELINE_FEATURE_SET
      && candidate.featureSet !== SHADOW_CATEGORY_FEATURE_SET
    )
  ) {
    throw new TypeError("Paired frozen candidate identity does not match");
  }
  const preregistrationDigest = normalizeSha256Digest(
    boundedString(
      candidate.preregistrationDigest,
      "Paired frozen candidate preregistration digest",
      128,
    ),
    "Paired frozen candidate preregistration digest",
  );
  const categoryProjectionDigest = normalizeSha256Digest(
    boundedString(
      candidate.categoryProjectionDigest,
      "Paired frozen candidate category projection digest",
      128,
    ),
    "Paired frozen candidate category projection digest",
  );
  const trainingCohort = exactRecord(candidate.trainingCohort, [
    "manifestDigest",
    "sealedHoldoutManifestDigest",
    "source",
    "sampling",
  ], "Paired frozen candidate training cohort");
  const manifestDigest = normalizeSha256Digest(
    boundedString(
      trainingCohort.manifestDigest,
      "Paired frozen candidate training manifest digest",
      128,
    ),
    "Paired frozen candidate training manifest digest",
  );
  const sealedHoldoutManifestDigest = normalizeSha256Digest(
    boundedString(
      trainingCohort.sealedHoldoutManifestDigest,
      "Paired frozen candidate sealed holdout manifest digest",
      128,
    ),
    "Paired frozen candidate sealed holdout manifest digest",
  );
  const source = exactRecord(
    trainingCohort.source,
    ["name", "revision", "digest"],
    "Paired frozen candidate training source",
  );
  const canonicalSource = Object.freeze({
    name: boundedString(
      source.name,
      "Paired frozen candidate training source name",
      1_024,
    ),
    revision: boundedString(
      source.revision,
      "Paired frozen candidate training source revision",
      1_024,
    ),
    digest: normalizeSha256Digest(
      boundedString(
        source.digest,
        "Paired frozen candidate training source digest",
        128,
      ),
      "Paired frozen candidate training source digest",
    ),
  });
  const sampling = exactRecord(
    trainingCohort.sampling,
    ["revision", "salt"],
    "Paired frozen candidate training sampling",
  );
  if (
    sampling.revision !== "sha256-rank-without-replacement-v1"
    || sampling.salt !== SHADOW_PAIRED_COHORT_SALT
  ) {
    throw new TypeError("Paired frozen candidate sampling does not match");
  }
  return Object.freeze({
    kind: SHADOW_PAIRED_CANDIDATE_KIND,
    experimentRevision: SHADOW_PAIRED_EXPERIMENT_REVISION,
    featureSet: candidate.featureSet,
    preregistrationDigest,
    trainingCohort: Object.freeze({
      manifestDigest,
      sealedHoldoutManifestDigest,
      source: canonicalSource,
      sampling: Object.freeze({
        revision: "sha256-rank-without-replacement-v1" as const,
        salt: SHADOW_PAIRED_COHORT_SALT,
      }),
    }),
    categoryProjectionDigest,
    model: validateShadowFrozenCandidate(candidate.model),
  });
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

export function canonicalizeShadowT2CategoryProjection(value: unknown): string {
  return canonicalJson(validateShadowT2CategoryProjection(value));
}

export function digestShadowT2CategoryProjection(value: unknown): string {
  return `sha256:${createHash("sha256")
    .update(canonicalizeShadowT2CategoryProjection(value), "utf8")
    .digest("hex")}`;
}

export function canonicalizeShadowPairedPreregistration(value: unknown): string {
  return `${canonicalJson(validateShadowPairedPreregistration(value))}\n`;
}

export function digestShadowPairedPreregistration(value: unknown): string {
  return `sha256:${createHash("sha256")
    .update(canonicalizeShadowPairedPreregistration(value), "utf8")
    .digest("hex")}`;
}

export function canonicalizeShadowPairedCohortManifest(value: unknown): string {
  return `${canonicalJson(validateShadowPairedCohortManifest(value))}\n`;
}

export function digestShadowPairedCohortManifest(value: unknown): string {
  return `sha256:${createHash("sha256")
    .update(canonicalizeShadowPairedCohortManifest(value), "utf8")
    .digest("hex")}`;
}

export function canonicalizeShadowFrozenCandidate(value: unknown): string {
  return canonicalJson(validateShadowFrozenCandidate(value));
}

export function digestShadowFrozenCandidate(value: unknown): string {
  return `sha256:${createHash("sha256")
    .update(canonicalizeShadowFrozenCandidate(value), "utf8")
    .digest("hex")}`;
}

export function canonicalizeShadowPairedFrozenCandidate(value: unknown): string {
  return `${canonicalJson(validateShadowPairedFrozenCandidate(value))}\n`;
}

export function digestShadowPairedFrozenCandidate(value: unknown): string {
  return `sha256:${createHash("sha256")
    .update(canonicalizeShadowPairedFrozenCandidate(value), "utf8")
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

export interface ShadowPairedFrozenHoldoutOptions
  extends ShadowFrozenHoldoutOptions {
  readonly preregistrationDigest: string;
  readonly cohortManifestDigest: string;
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
  featureTokens: ShadowFeatureTokenFunction = shadowTriggerFeatureTokens,
): FoldModel {
  const training = snapshots.filter(
    (snapshot) => shadowFoldForDomain(snapshot.domain) !== heldOutFold,
  );
  const heldOutDomains = snapshots.length - training.length;
  const model = trainMultiHeadModel(training, featureTokens);
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
  snapshot: ShadowFeatureInput,
  featureTokensForSnapshot: ShadowFeatureTokenFunction = shadowTriggerFeatureTokens,
): ShadowTriggerPrediction {
  const featureTokens = featureTokensForSnapshot(snapshot);
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
  featureTokens: ShadowFeatureTokenFunction = shadowTriggerFeatureTokens,
): {
  readonly models: readonly FoldModel[];
  readonly scored: readonly ScoredSnapshot[];
} {
  const models = Array.from(
    { length: SHADOW_EVALUATION_FOLD_COUNT },
    (_, fold) => trainFoldModel(snapshots, fold, featureTokens),
  );
  const baselineNames = t2BaselineNames(snapshots);
  const scored = snapshots.map((snapshot): ScoredSnapshot => {
    const fold = shadowFoldForDomain(snapshot.domain);
    const foldModel = models[fold];
    if (foldModel === undefined) throw new TypeError("Missing calibration fold model");
    const prediction = predictWithModel(foldModel.model, snapshot, featureTokens);
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
  featureTokens: ShadowFeatureTokenFunction = shadowTriggerFeatureTokens,
): {
  readonly report: ShadowDevelopmentSourceReport;
  readonly snapshots: readonly ShadowEvaluationSnapshot[];
} {
  const snapshots = validateArtifact(artifact);
  const { models, scored } = scoreSnapshots(snapshots, featureTokens);
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

export function validateShadowPairedDevelopmentSource(
  value: unknown,
  artifact: ShadowEvaluationArtifact,
): ShadowPairedDevelopmentSourceReport {
  const report = exactRecord(value, [
    "mode",
    "experimentRevision",
    "preregistrationDigest",
    "cohortManifestDigest",
    "sealedHoldoutManifestDigest",
    "categoryProjectionDigest",
    "source",
  ], "Paired development source");
  if (
    report.mode !== "paired-development-source"
    || report.experimentRevision !== SHADOW_PAIRED_EXPERIMENT_REVISION
  ) {
    throw new TypeError("Paired development source identity does not match");
  }
  const canonical = Object.freeze({
    mode: "paired-development-source" as const,
    experimentRevision: SHADOW_PAIRED_EXPERIMENT_REVISION,
    preregistrationDigest: normalizeSha256Digest(
      boundedString(
        report.preregistrationDigest,
        "Paired development source preregistration digest",
        128,
      ),
      "Paired development source preregistration digest",
    ),
    cohortManifestDigest: normalizeSha256Digest(
      boundedString(
        report.cohortManifestDigest,
        "Paired development source cohort manifest digest",
        128,
      ),
      "Paired development source cohort manifest digest",
    ),
    sealedHoldoutManifestDigest: normalizeSha256Digest(
      boundedString(
        report.sealedHoldoutManifestDigest,
        "Paired development source sealed holdout manifest digest",
        128,
      ),
      "Paired development source sealed holdout manifest digest",
    ),
    categoryProjectionDigest: normalizeSha256Digest(
      boundedString(
        report.categoryProjectionDigest,
        "Paired development source category projection digest",
        128,
      ),
      "Paired development source category projection digest",
    ),
    source: developmentCalibration(artifact).report,
  });
  if (canonicalJson(report.source) !== canonicalJson(canonical.source)) {
    throw new TypeError("Paired development source does not match its artifact");
  }
  return canonical;
}

export function createShadowPairedDevelopmentSource(
  artifact: ShadowEvaluationArtifact,
  options: ShadowPairedDevelopmentSourceOptions,
): ShadowPairedDevelopmentSourceReport {
  return validateShadowPairedDevelopmentSource({
    mode: "paired-development-source",
    experimentRevision: SHADOW_PAIRED_EXPERIMENT_REVISION,
    preregistrationDigest: options.preregistrationDigest,
    cohortManifestDigest: options.cohortManifestDigest,
    sealedHoldoutManifestDigest: options.sealedHoldoutManifestDigest,
    categoryProjectionDigest: options.categoryProjectionDigest,
    source: developmentCalibration(artifact).report,
  }, artifact);
}

export function canonicalizeShadowPairedDevelopmentSource(
  value: unknown,
  artifact: ShadowEvaluationArtifact,
): string {
  return `${canonicalJson(validateShadowPairedDevelopmentSource(value, artifact))}\n`;
}

function foldTriggerOutcome(
  report: ShadowDevelopmentSourceReport,
  snapshots: readonly ShadowEvaluationSnapshot[],
  fold: number,
  globalT2Names: ReadonlySet<string>,
): ShadowFoldTriggerOutcome {
  const selectedDomains = new Set(report.deployable.selected
    .filter((selected) => selected.source === "trigger" && selected.fold === fold)
    .map(({ domain }) => domain));
  if (selectedDomains.size === 0) {
    throw new TypeError("Every paired fold must have a positive trigger quota");
  }
  let pairLift = 0;
  const novelNames = new Set<string>();
  for (const snapshot of snapshots) {
    if (!selectedDomains.has(snapshot.domain)) continue;
    pairLift += incrementalPairLift(snapshot);
    for (const name of snapshot.full.directNames) {
      if (!globalT2Names.has(name)) novelNames.add(name);
    }
  }
  return Object.freeze({
    fold,
    triggerDomainCount: selectedDomains.size,
    pairLift,
    novelNameCoverage: novelNames.size,
  });
}

export function decideShadowPairedExperiment(
  baselinePassed: boolean,
  categoryPassed: boolean,
  categoryFoldWins: number,
): ShadowPairedDecision {
  if (
    typeof baselinePassed !== "boolean"
    || typeof categoryPassed !== "boolean"
    || !Number.isSafeInteger(categoryFoldWins)
    || categoryFoldWins < 0
    || categoryFoldWins > SHADOW_EVALUATION_FOLD_COUNT
  ) {
    throw new TypeError("Paired experiment decision inputs are invalid");
  }
  if (baselinePassed) {
    return Object.freeze({
      selectedFeatureSet: SHADOW_BASELINE_FEATURE_SET,
      reason: "baseline-passed-all-official-gates" as const,
    });
  }
  if (
    categoryPassed
    && categoryFoldWins >= SHADOW_CATEGORY_FOLD_WIN_MINIMUM
  ) {
    return Object.freeze({
      selectedFeatureSet: SHADOW_CATEGORY_FEATURE_SET,
      reason:
        "category-passed-all-official-gates-and-fold-win-minimum" as const,
    });
  }
  return Object.freeze({
    selectedFeatureSet: null,
    reason: "no-arm-eligible" as const,
  });
}

function sameCatalog(
  left: CatalogProvenance,
  right: CatalogProvenance,
): boolean {
  return left.source === right.source
    && left.revision === right.revision
    && left.digest === right.digest;
}

function assertPairedDevelopmentIdentity(
  artifact: ShadowEvaluationArtifact,
  snapshots: readonly ShadowEvaluationSnapshot[],
  projection: ShadowT2CategoryProjection,
  preregistration: ShadowPairedPreregistration,
  manifest: ShadowPairedCohortManifest,
  sealedHoldoutManifest: ShadowPairedCohortManifest,
  preregistrationDigest: string,
  manifestDigest: string,
  sealedHoldoutManifestDigest: string,
): void {
  if (manifest.role !== "development") {
    throw new TypeError("Paired development requires a development manifest");
  }
  if (
    manifest.preregistrationDigest !== preregistrationDigest
    || digestShadowPairedCohortManifest(manifest) !== manifestDigest
    || computeDomainSetDigest(snapshots.map(({ domain }) => domain))
      !== manifest.input.domainSetDigest
    || artifact.schemaVersion !== manifest.expected.schemaVersion
    || artifact.protocolRevision !== manifest.expected.protocolRevision
    || artifact.provenance.scannerVersion !== manifest.expected.scannerVersion
    || artifact.provenance.configDigest !== manifest.expected.configDigest
    || !sameCatalog(artifact.provenance.catalog, manifest.expected.catalog)
  ) {
    throw new TypeError("Paired development artifact does not match its manifest");
  }
  if (
    manifest.sealedHoldoutManifestDigest !== sealedHoldoutManifestDigest
    || sealedHoldoutManifest.role !== "holdout"
    || digestShadowPairedCohortManifest(sealedHoldoutManifest)
      !== sealedHoldoutManifestDigest
    || sealedHoldoutManifest.preregistrationDigest !== preregistrationDigest
    || sealedHoldoutManifest.source.name !== manifest.source.name
    || sealedHoldoutManifest.source.revision !== manifest.source.revision
    || sealedHoldoutManifest.source.digest !== manifest.source.digest
    || sealedHoldoutManifest.sampling.revision !== manifest.sampling.revision
    || sealedHoldoutManifest.sampling.salt !== manifest.sampling.salt
    || sealedHoldoutManifest.expected.scannerVersion
      !== manifest.expected.scannerVersion
    || sealedHoldoutManifest.expected.configDigest
      !== manifest.expected.configDigest
    || !sameCatalog(
      sealedHoldoutManifest.expected.catalog,
      manifest.expected.catalog,
    )
  ) {
    throw new TypeError("Development manifest does not match its sealed holdout");
  }
  if (
    preregistration.expectedDevelopmentScannerVersion
      !== manifest.expected.scannerVersion
    || preregistration.expectedDevelopmentConfigDigest
      !== manifest.expected.configDigest
    || !sameCatalog(preregistration.catalog, manifest.expected.catalog)
    || !sameCatalog(projection.catalog, preregistration.catalog)
    || digestShadowT2CategoryProjection(projection)
      !== preregistration.categoryProjectionDigest
  ) {
    throw new TypeError("Paired development identities do not match preregistration");
  }
  const d1 = manifest.zeroOverlapWith[0];
  const sealedD1 = sealedHoldoutManifest.zeroOverlapWith[0];
  const sealedD2 = sealedHoldoutManifest.zeroOverlapWith[1];
  const developmentDomainSetDigest = computeDomainSetDigest(
    snapshots.map(({ domain }) => domain),
  );
  if (
    d1?.label !== "D1"
    || d1.domainSetDigest !== preregistration.discoveryDomainSetDigest
    || sealedD1?.label !== "D1"
    || sealedD1.domainSetDigest !== preregistration.discoveryDomainSetDigest
    || sealedD2?.label !== "D2"
    || sealedD2.domainSetDigest !== developmentDomainSetDigest
    || sealedHoldoutManifest.input.domainSetDigest === developmentDomainSetDigest
    || sealedHoldoutManifest.input.domainSetDigest
      === preregistration.discoveryDomainSetDigest
  ) {
    throw new TypeError("Development manifests do not prove the frozen cohorts");
  }
  const currentDomains = new Set(snapshots.map(({ domain }) => domain));
  if (d1.domains.some((domain) => currentDomains.has(domain))) {
    throw new TypeError("Development cohort overlaps the discovery cohort");
  }
}

export function calibrateShadowPairedDevelopment(
  artifact: ShadowEvaluationArtifact,
  developmentSourceValue: unknown,
  projectionValue: unknown,
  preregistrationValue: unknown,
  manifestValue: unknown,
  sealedHoldoutManifestValue: unknown,
  options: ShadowPairedDevelopmentOptions,
): ShadowPairedDevelopmentReport {
  const snapshots = validateArtifact(artifact);
  const developmentSource = validateShadowPairedDevelopmentSource(
    developmentSourceValue,
    artifact,
  );
  const projection = validateShadowT2CategoryProjection(projectionValue);
  const preregistration = validateShadowPairedPreregistration(
    preregistrationValue,
  );
  const manifest = validateShadowPairedCohortManifest(manifestValue);
  const sealedHoldoutManifest = validateShadowPairedCohortManifest(
    sealedHoldoutManifestValue,
  );
  const preregistrationDigest = normalizeSha256Digest(
    options.preregistrationDigest,
    "Pinned preregistration digest",
  );
  const cohortManifestDigest = normalizeSha256Digest(
    options.cohortManifestDigest,
    "Pinned cohort manifest digest",
  );
  const sealedHoldoutManifestDigest = normalizeSha256Digest(
    options.sealedHoldoutManifestDigest,
    "Pinned sealed holdout manifest digest",
  );
  const computedPreregistrationDigest = digestShadowPairedPreregistration(
    preregistration,
  );
  if (preregistrationDigest !== computedPreregistrationDigest) {
    throw new TypeError("Pinned preregistration digest does not match preregistration");
  }
  assertPairedDevelopmentIdentity(
    artifact,
    snapshots,
    projection,
    preregistration,
    manifest,
    sealedHoldoutManifest,
    preregistrationDigest,
    cohortManifestDigest,
    sealedHoldoutManifestDigest,
  );
  const categoryProjectionDigest = digestShadowT2CategoryProjection(projection);
  if (
    developmentSource.preregistrationDigest !== preregistrationDigest
    || developmentSource.cohortManifestDigest !== cohortManifestDigest
    || developmentSource.sealedHoldoutManifestDigest
      !== sealedHoldoutManifestDigest
    || developmentSource.categoryProjectionDigest !== categoryProjectionDigest
  ) {
    throw new TypeError("Paired development source boundary does not match");
  }
  if (
    options.expectedEvaluationScannerVersion
      !== preregistration.expectedDevelopmentScannerVersion
    || options.expectedEvaluationConfigDigest
      !== preregistration.expectedDevelopmentConfigDigest
  ) {
    throw new TypeError(
      "Paired candidate evaluation identity must match preregistration",
    );
  }

  const categoryFeatureTokens = categoryFeatureTokenFunction(projection);
  // ponytail: the bound baseline and direct category run keep arm state isolated.
  const baseline = developmentSource.source;
  const category = developmentCalibration(artifact, categoryFeatureTokens).report;
  const globalT2Names = t2BaselineNames(snapshots);
  const foldComparisons = Object.freeze(Array.from(
    { length: SHADOW_EVALUATION_FOLD_COUNT },
    (_, fold): ShadowPairedFoldComparison => {
      const baselineOutcome = foldTriggerOutcome(
        baseline,
        snapshots,
        fold,
        globalT2Names,
      );
      const categoryOutcome = foldTriggerOutcome(
        category,
        snapshots,
        fold,
        globalT2Names,
      );
      const categoryWon = categoryOutcome.pairLift >= baselineOutcome.pairLift
        && categoryOutcome.novelNameCoverage
          >= baselineOutcome.novelNameCoverage
        && (
          categoryOutcome.pairLift > baselineOutcome.pairLift
          || categoryOutcome.novelNameCoverage
            > baselineOutcome.novelNameCoverage
        );
      return Object.freeze({
        fold,
        baseline: baselineOutcome,
        category: categoryOutcome,
        categoryWon,
      });
    },
  ));
  const categoryFoldWins = foldComparisons.filter(
    ({ categoryWon }) => categoryWon,
  ).length;
  const decision = decideShadowPairedExperiment(
    baseline.deployable.provisionalGuardrails.passed,
    category.deployable.provisionalGuardrails.passed,
    categoryFoldWins,
  );
  const trainingArtifactDigest = normalizeSha256Digest(
    options.trainingArtifactDigest,
    "Training artifact digest",
  );
  let candidate: ShadowPairedFrozenCandidate | null = null;
  if (decision.selectedFeatureSet !== null) {
    const selectedFeatureTokens = decision.selectedFeatureSet
      === SHADOW_CATEGORY_FEATURE_SET
      ? categoryFeatureTokens
      : shadowTriggerFeatureTokens;
    candidate = validateShadowPairedFrozenCandidate({
      kind: SHADOW_PAIRED_CANDIDATE_KIND,
      experimentRevision: SHADOW_PAIRED_EXPERIMENT_REVISION,
      featureSet: decision.selectedFeatureSet,
      preregistrationDigest,
      trainingCohort: {
        manifestDigest: cohortManifestDigest,
        sealedHoldoutManifestDigest,
        source: manifest.source,
        sampling: manifest.sampling,
      },
      categoryProjectionDigest,
      model: buildFrozenCandidate(
        trainMultiHeadModel(snapshots, selectedFeatureTokens),
        artifact,
        { ...options, trainingArtifactDigest },
      ),
    });
  }
  return Object.freeze({
    mode: "paired-development-oof" as const,
    experimentRevision: SHADOW_PAIRED_EXPERIMENT_REVISION,
    preregistrationDigest,
    cohortManifestDigest,
    sealedHoldoutManifestDigest,
    categoryProjectionDigest,
    trainingArtifactDigest,
    baseline,
    category,
    foldComparisons,
    categoryFoldWins,
    decision,
    candidate,
  });
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

function evaluateFrozenShadowCandidateWithFeatures(
  artifact: ShadowEvaluationArtifact,
  candidateValue: unknown,
  options: ShadowFrozenHoldoutOptions,
  featureTokens: ShadowFeatureTokenFunction,
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
    const prediction = predictWithModel(model, snapshot, featureTokens);
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

export function evaluateFrozenShadowCandidate(
  artifact: ShadowEvaluationArtifact,
  candidateValue: unknown,
  options: ShadowFrozenHoldoutOptions,
): ShadowFrozenHoldoutReport {
  return evaluateFrozenShadowCandidateWithFeatures(
    artifact,
    candidateValue,
    options,
    shadowTriggerFeatureTokens,
  );
}

export function evaluateFrozenShadowPairedCandidate(
  artifact: ShadowEvaluationArtifact,
  projectionValue: unknown,
  preregistrationValue: unknown,
  manifestValue: unknown,
  candidateValue: unknown,
  options: ShadowPairedFrozenHoldoutOptions,
): ShadowPairedFrozenHoldoutReport {
  const snapshots = validateArtifact(artifact);
  const projection = validateShadowT2CategoryProjection(projectionValue);
  const preregistration = validateShadowPairedPreregistration(
    preregistrationValue,
  );
  const manifest = validateShadowPairedCohortManifest(manifestValue);
  const candidate = validateShadowPairedFrozenCandidate(candidateValue);
  const preregistrationDigest = normalizeSha256Digest(
    options.preregistrationDigest,
    "Pinned preregistration digest",
  );
  const cohortManifestDigest = normalizeSha256Digest(
    options.cohortManifestDigest,
    "Pinned cohort manifest digest",
  );
  const candidateDigest = normalizeSha256Digest(
    options.candidateDigest,
    "Pinned paired candidate digest",
  );
  if (
    digestShadowPairedPreregistration(preregistration)
      !== preregistrationDigest
    || digestShadowPairedCohortManifest(manifest) !== cohortManifestDigest
    || digestShadowPairedFrozenCandidate(candidate) !== candidateDigest
    || candidate.preregistrationDigest !== preregistrationDigest
    || manifest.preregistrationDigest !== preregistrationDigest
    || candidate.trainingCohort.sealedHoldoutManifestDigest
      !== cohortManifestDigest
  ) {
    throw new TypeError("Pinned paired evaluation digest does not match");
  }
  if (
    manifest.role !== "holdout"
    || computeDomainSetDigest(snapshots.map(({ domain }) => domain))
      !== manifest.input.domainSetDigest
    || artifact.schemaVersion !== manifest.expected.schemaVersion
    || artifact.protocolRevision !== manifest.expected.protocolRevision
    || artifact.provenance.scannerVersion !== manifest.expected.scannerVersion
    || artifact.provenance.configDigest !== manifest.expected.configDigest
    || !sameCatalog(artifact.provenance.catalog, manifest.expected.catalog)
    || manifest.expected.scannerVersion
      !== preregistration.expectedDevelopmentScannerVersion
    || manifest.expected.configDigest
      !== preregistration.expectedDevelopmentConfigDigest
    || !sameCatalog(manifest.expected.catalog, preregistration.catalog)
    || !sameCatalog(projection.catalog, artifact.provenance.catalog)
    || candidate.categoryProjectionDigest
      !== preregistration.categoryProjectionDigest
    || digestShadowT2CategoryProjection(projection)
      !== candidate.categoryProjectionDigest
    || manifest.source.name !== candidate.trainingCohort.source.name
    || manifest.source.revision !== candidate.trainingCohort.source.revision
    || manifest.source.digest !== candidate.trainingCohort.source.digest
    || manifest.sampling.revision !== candidate.trainingCohort.sampling.revision
    || manifest.sampling.salt !== candidate.trainingCohort.sampling.salt
  ) {
    throw new TypeError("Paired holdout identities are incompatible");
  }
  const d1 = manifest.zeroOverlapWith[0];
  const d2 = manifest.zeroOverlapWith[1];
  if (
    d1?.label !== "D1"
    || d1.domainSetDigest !== preregistration.discoveryDomainSetDigest
    || d2?.label !== "D2"
    || d2.domainSetDigest !== candidate.model.trainingIdentity.domainSetDigest
  ) {
    throw new TypeError("Paired holdout zero-overlap proof does not match");
  }
  const currentDomains = new Set(snapshots.map(({ domain }) => domain));
  if (
    d1.domains.some((domain) => currentDomains.has(domain))
    || d2.domains.some((domain) => currentDomains.has(domain))
  ) {
    throw new TypeError("Paired holdout overlaps a prior cohort");
  }
  const featureTokens = candidate.featureSet === SHADOW_CATEGORY_FEATURE_SET
    ? categoryFeatureTokenFunction(projection)
    : shadowTriggerFeatureTokens;
  const evaluation = evaluateFrozenShadowCandidateWithFeatures(
    artifact,
    candidate.model,
    { candidateDigest: digestShadowFrozenCandidate(candidate.model) },
    featureTokens,
  );
  return Object.freeze({
    mode: "paired-frozen-holdout" as const,
    experimentRevision: SHADOW_PAIRED_EXPERIMENT_REVISION,
    featureSet: candidate.featureSet,
    preregistrationDigest,
    cohortManifestDigest,
    candidateDigest,
    categoryProjectionDigest: candidate.categoryProjectionDigest,
    evaluation,
  });
}
