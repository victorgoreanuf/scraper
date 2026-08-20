import { createHash } from "node:crypto";

import {
  SHADOW_CONTROL_DOMAIN_COUNT,
  SHADOW_EVALUATION_DOMAIN_COUNT,
  SHADOW_EVALUATION_FOLD_COUNT,
  SHADOW_EVALUATION_PROTOCOL_REVISION,
  SHADOW_TRIGGER_DOMAIN_CAP,
  type AvailableShadowDetectorView,
  type ShadowDetectorView,
  type ShadowEvaluationSnapshot,
  type ShadowPreBrowserFeatures,
} from "./evaluation.ts";

export const SHADOW_CALIBRATION_REVISION = "2026-08-20.1";
export const SHADOW_CALIBRATION_SMOOTHING_PRIOR = 4;
export const SHADOW_PROVISIONAL_GUARDRAILS = Object.freeze({
  canonicalDirectNameRetentionMinimum: 0.95,
  domainTechnologyPairRetentionMinimum: 0.8,
  routedDomainMaximum: 40,
});

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
  readonly featureTokenCount: number;
  readonly smoothingPrior: number;
}

export interface ShadowDeploymentToken {
  readonly token: string;
  readonly domains: number;
  readonly targetSum: number;
  readonly estimate: number;
}

export interface ShadowDeploymentModel {
  readonly kind: "smoothed-empirical-token-lift-v1";
  readonly calibrationRevision: typeof SHADOW_CALIBRATION_REVISION;
  readonly protocolRevision: typeof SHADOW_EVALUATION_PROTOCOL_REVISION;
  readonly target: "incremental-domain-technology-pairs";
  readonly trainingDomains: typeof SHADOW_EVALUATION_DOMAIN_COUNT;
  readonly trainingIncrementalPairLift: number;
  readonly globalMeanIncrementalPairLift: number;
  readonly smoothingPrior: typeof SHADOW_CALIBRATION_SMOOTHING_PRIOR;
  readonly tokens: readonly ShadowDeploymentToken[];
}

export interface ShadowOofPrediction {
  readonly domain: string;
  readonly fold: number;
  readonly score: number;
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
  readonly passed: boolean;
}

export interface ShadowDeployableEvaluation {
  readonly name: "deployable-oof-trigger";
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

export interface ShadowCalibrationReport {
  readonly calibrationRevision: typeof SHADOW_CALIBRATION_REVISION;
  readonly protocolRevision: typeof SHADOW_EVALUATION_PROTOCOL_REVISION;
  readonly runId: string;
  readonly cohortDomains: typeof SHADOW_EVALUATION_DOMAIN_COUNT;
  readonly foldCount: typeof SHADOW_EVALUATION_FOLD_COUNT;
  readonly salts: typeof SHADOW_CALIBRATION_SALTS;
  readonly model: {
    readonly kind: "smoothed-empirical-token-lift-v1";
    readonly target: "incremental-domain-technology-pairs";
    readonly smoothingPrior: typeof SHADOW_CALIBRATION_SMOOTHING_PRIOR;
    readonly folds: readonly ShadowFoldModelMetadata[];
  };
  readonly deploymentModel: ShadowDeploymentModel;
  readonly oofPredictions: readonly ShadowOofPrediction[];
  readonly deployable: ShadowDeployableEvaluation;
  readonly deterministicRandom: ShadowComparatorEvaluation;
  readonly labelAwareGreedy: ShadowGreedyEvaluation;
}

interface TokenAggregate {
  domains: number;
  targetSum: number;
}

interface FoldModel {
  readonly globalMean: number;
  readonly tokens: ReadonlyMap<string, TokenAggregate>;
  readonly metadata: ShadowFoldModelMetadata;
}

interface ScoredSnapshot {
  readonly snapshot: ShadowEvaluationSnapshot;
  readonly prediction: ShadowOofPrediction;
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

function incrementalPairLift(snapshot: ShadowEvaluationSnapshot): number {
  const baseline = new Set(directNames(snapshot.t2));
  let lift = 0;
  for (const name of snapshot.full.directNames) {
    if (!baseline.has(name)) lift += 1;
  }
  return lift;
}

function trainFoldModel(
  snapshots: readonly ShadowEvaluationSnapshot[],
  heldOutFold: number,
): FoldModel {
  const tokenAggregates = new Map<string, TokenAggregate>();
  let trainingDomains = 0;
  let targetSum = 0;
  let heldOutDomains = 0;

  for (const snapshot of snapshots) {
    if (shadowFoldForDomain(snapshot.domain) === heldOutFold) {
      heldOutDomains += 1;
      continue;
    }
    trainingDomains += 1;
    const target = incrementalPairLift(snapshot);
    targetSum += target;
    for (const token of shadowTriggerFeatureTokens(snapshot)) {
      const aggregate = tokenAggregates.get(token) ?? { domains: 0, targetSum: 0 };
      aggregate.domains += 1;
      aggregate.targetSum += target;
      tokenAggregates.set(token, aggregate);
    }
  }

  if (trainingDomains === 0) {
    throw new TypeError("A calibration fold has no training domains");
  }
  const globalMean = targetSum / trainingDomains;
  return Object.freeze({
    globalMean,
    tokens: tokenAggregates,
    metadata: Object.freeze({
      fold: heldOutFold,
      trainingDomains,
      heldOutDomains,
      trainingIncrementalPairLift: targetSum,
      globalMeanIncrementalPairLift: globalMean,
      featureTokenCount: tokenAggregates.size,
      smoothingPrior: SHADOW_CALIBRATION_SMOOTHING_PRIOR,
    }),
  });
}

function predict(model: FoldModel, tokens: readonly string[]): number {
  let sum = model.globalMean;
  let estimates = 1;
  for (const token of tokens) {
    const aggregate = model.tokens.get(token);
    if (aggregate === undefined) continue;
    sum += deploymentTokenEstimate(aggregate, model.globalMean);
    estimates += 1;
  }
  return sum / estimates;
}

function deploymentTokenEstimate(
  aggregate: TokenAggregate,
  globalMean: number,
): number {
  return (
    aggregate.targetSum
    + (SHADOW_CALIBRATION_SMOOTHING_PRIOR * globalMean)
  ) / (aggregate.domains + SHADOW_CALIBRATION_SMOOTHING_PRIOR);
}

function trainDeploymentModel(
  snapshots: readonly ShadowEvaluationSnapshot[],
): ShadowDeploymentModel {
  const aggregates = new Map<string, TokenAggregate>();
  let targetSum = 0;
  for (const snapshot of snapshots) {
    const target = incrementalPairLift(snapshot);
    targetSum += target;
    for (const token of shadowTriggerFeatureTokens(snapshot)) {
      const aggregate = aggregates.get(token) ?? { domains: 0, targetSum: 0 };
      aggregate.domains += 1;
      aggregate.targetSum += target;
      aggregates.set(token, aggregate);
    }
  }
  const globalMean = targetSum / snapshots.length;
  const tokens = Object.freeze([...aggregates.entries()]
    .sort(([left], [right]) => compareString(left, right))
    .map(([token, aggregate]): ShadowDeploymentToken => Object.freeze({
      token,
      domains: aggregate.domains,
      targetSum: aggregate.targetSum,
      estimate: deploymentTokenEstimate(aggregate, globalMean),
    })));
  return Object.freeze({
    kind: "smoothed-empirical-token-lift-v1" as const,
    calibrationRevision: SHADOW_CALIBRATION_REVISION,
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    target: "incremental-domain-technology-pairs" as const,
    trainingDomains: SHADOW_EVALUATION_DOMAIN_COUNT,
    trainingIncrementalPairLift: targetSum,
    globalMeanIncrementalPairLift: globalMean,
    smoothingPrior: SHADOW_CALIBRATION_SMOOTHING_PRIOR,
    tokens,
  });
}

export function scoreShadowSnapshot(
  model: ShadowDeploymentModel,
  snapshot: Pick<ShadowEvaluationSnapshot, "t1" | "t2" | "preBrowser">,
): number {
  if (
    model.kind !== "smoothed-empirical-token-lift-v1"
    || model.calibrationRevision !== SHADOW_CALIBRATION_REVISION
    || model.protocolRevision !== SHADOW_EVALUATION_PROTOCOL_REVISION
    || model.target !== "incremental-domain-technology-pairs"
    || model.trainingDomains !== SHADOW_EVALUATION_DOMAIN_COUNT
    || model.smoothingPrior !== SHADOW_CALIBRATION_SMOOTHING_PRIOR
    || !Number.isFinite(model.globalMeanIncrementalPairLift)
    || model.globalMeanIncrementalPairLift < 0
  ) {
    throw new TypeError("Deployment model does not match the frozen calibration");
  }

  const estimates = new Map<string, number>();
  let previous: string | undefined;
  for (const entry of model.tokens) {
    if (
      entry.token.length === 0
      || (previous !== undefined && compareString(previous, entry.token) >= 0)
      || !Number.isFinite(entry.estimate)
      || entry.estimate < 0
    ) {
      throw new TypeError("Deployment model tokens are invalid or unsorted");
    }
    previous = entry.token;
    estimates.set(entry.token, entry.estimate);
  }

  let sum = model.globalMeanIncrementalPairLift;
  let matchedEstimates = 1;
  for (const token of shadowTriggerFeatureTokens(snapshot)) {
    const estimate = estimates.get(token);
    if (estimate === undefined) continue;
    sum += estimate;
    matchedEstimates += 1;
  }
  return sum / matchedEstimates;
}

function scoreSnapshots(
  snapshots: readonly ShadowEvaluationSnapshot[],
): {
  readonly models: readonly ShadowFoldModelMetadata[];
  readonly scored: readonly ScoredSnapshot[];
} {
  const models = Array.from(
    { length: SHADOW_EVALUATION_FOLD_COUNT },
    (_, fold) => trainFoldModel(snapshots, fold),
  );
  const scored = snapshots.map((snapshot): ScoredSnapshot => {
    const fold = shadowFoldForDomain(snapshot.domain);
    const tokens = shadowTriggerFeatureTokens(snapshot);
    const model = models[fold];
    if (model === undefined) throw new TypeError("Missing calibration fold model");
    return Object.freeze({
      snapshot,
      prediction: Object.freeze({
        domain: snapshot.domain,
        fold,
        score: predict(model, tokens),
        featureTokens: tokens.length,
      }),
    });
  });
  return Object.freeze({
    models: Object.freeze(models.map(({ metadata }) => metadata)),
    scored: Object.freeze(scored),
  });
}

function compareOofRank(left: ScoredSnapshot, right: ScoredSnapshot): number {
  const scoreOrder = right.prediction.score - left.prediction.score;
  if (scoreOrder !== 0) return scoreOrder;
  return compareString(
    saltedHashHex(SHADOW_CALIBRATION_SALTS.scoreTieBreak, left.snapshot.domain),
    saltedHashHex(SHADOW_CALIBRATION_SALTS.scoreTieBreak, right.snapshot.domain),
  ) || compareString(left.snapshot.domain, right.snapshot.domain);
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

function addCost(target: MutableCostTotals, snapshot: ShadowEvaluationSnapshot): void {
  target.browserPagesAttempted += snapshot.fullCost.browserPagesAttempted;
  target.browserPagesAdmitted += snapshot.fullCost.browserPagesAdmitted;
  target.browserRequests += snapshot.fullCost.browserRequests;
  target.browserTransferredBytes += snapshot.fullCost.browserTransferredBytes;
  target.browserMs += snapshot.fullCost.browserMs;
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
    passed: namePassed && pairPassed && routedPassed,
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

export function calibrateShadowEvaluation(
  inputSnapshots: readonly ShadowEvaluationSnapshot[],
): ShadowCalibrationReport {
  const snapshots = validateSnapshots(inputSnapshots);
  const { models, scored } = scoreSnapshots(snapshots);
  const quotas = foldQuotas(scored);
  const triggered: ScoredSnapshot[] = [];
  const controls: ScoredSnapshot[] = [];
  for (const quota of quotas) {
    const ranked = scored
      .filter(({ prediction }) => prediction.fold === quota.fold)
      .sort(compareOofRank);
    if (ranked.length !== quota.domains) {
      throw new TypeError("Calibration fold membership does not match its quota");
    }
    const foldTriggered = ranked.slice(0, quota.trigger);
    const triggeredDomains = new Set(
      foldTriggered.map(({ snapshot }) => snapshot.domain),
    );
    const foldControls = ranked
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
  const deploymentModel = trainDeploymentModel(snapshots);
  const deployableMetrics = metricsForSelection(snapshots, deployableDomains);

  return Object.freeze({
    calibrationRevision: SHADOW_CALIBRATION_REVISION,
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    runId: snapshots[0]?.runId ?? "",
    cohortDomains: SHADOW_EVALUATION_DOMAIN_COUNT,
    foldCount: SHADOW_EVALUATION_FOLD_COUNT,
    salts: SHADOW_CALIBRATION_SALTS,
    model: Object.freeze({
      kind: "smoothed-empirical-token-lift-v1" as const,
      target: "incremental-domain-technology-pairs" as const,
      smoothingPrior: SHADOW_CALIBRATION_SMOOTHING_PRIOR,
      folds: models,
    }),
    deploymentModel,
    oofPredictions: Object.freeze(scored.map(({ prediction }) => prediction)),
    deployable: Object.freeze({
      name: "deployable-oof-trigger" as const,
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
}
