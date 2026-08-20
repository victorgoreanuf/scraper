import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  assertShadowFrozenCandidateCompatibility,
  calibrateShadowDevelopment,
  calibrateShadowDevelopmentSource,
  calibrateShadowPairedDevelopment,
  canonicalizeShadowPairedDevelopmentSource,
  canonicalizeShadowPairedCohortManifest,
  canonicalizeShadowPairedFrozenCandidate,
  canonicalizeShadowPairedPreregistration,
  canonicalizeShadowT2CategoryProjection,
  canonicalizeShadowFrozenCandidate,
  createShadowPairedDevelopmentSource,
  decideShadowPairedExperiment,
  digestShadowPairedCohortManifest,
  digestShadowPairedFrozenCandidate,
  digestShadowPairedPreregistration,
  digestShadowT2CategoryProjection,
  digestShadowFrozenCandidate,
  evaluateFrozenShadowCandidate,
  evaluateFrozenShadowPairedCandidate,
  predictShadowSnapshot,
  SHADOW_BASELINE_FEATURE_SET,
  SHADOW_CALIBRATION_SALTS,
  SHADOW_CATEGORY_FEATURE_SET,
  SHADOW_CATEGORY_FOLD_WIN_MINIMUM,
  SHADOW_CATEGORY_ID_MAXIMUM,
  SHADOW_CATEGORY_IDS_PER_TECHNOLOGY_MAXIMUM,
  SHADOW_MODEL_RECURRING_TARGET_CAP,
  SHADOW_MODEL_TOKEN_CAP,
  SHADOW_PAIRED_COHORT_SALT,
  SHADOW_PAIRED_EXPERIMENT_REVISION,
  shadowFoldForDomain,
  shadowCategoryTriggerFeatureTokens,
  validateShadowPairedCohortManifest,
  validateShadowPairedPreregistration,
  validateShadowT2CategoryProjection,
  validateShadowFrozenCandidate,
  type ShadowFrozenCandidate,
  type ShadowPairedCohortManifest,
  type ShadowPairedDevelopmentSourceReport,
  type ShadowPairedPreregistration,
  type ShadowT2CategoryProjection,
} from "../src/evaluation-calibration.ts";
import {
  SHADOW_EVALUATION_DOMAIN_COUNT,
  SHADOW_EVALUATION_PROTOCOL_REVISION,
  type ShadowDetectorView,
  type ShadowEvaluationArtifact,
  type ShadowEvaluationSnapshot,
  type ShadowFullCost,
} from "../src/evaluation.ts";
import { computeDomainSetDigest } from "../src/domain-set.ts";
import type { Provenance } from "../src/model.ts";

const TRAINING_RUN_ID = "123e4567-e89b-42d3-a456-426614174001";
const HOLDOUT_RUN_ID = "123e4567-e89b-42d3-a456-426614174002";
const TRAINING_ARTIFACT_DIGEST = `sha256:${"1".repeat(64)}`;
const TRAINING_CONFIG_DIGEST = `sha256:${"2".repeat(64)}`;
const EVALUATION_CONFIG_DIGEST = `sha256:${"3".repeat(64)}`;
const CATALOG_DIGEST = `sha256:${"4".repeat(64)}`;
const BASE_NAMES = Object.freeze(Array.from(
  { length: 20 },
  (_, index) => `Base-${String(index).padStart(2, "0")}`,
));
const detectionStats = Object.freeze({
  rawDirect: 2,
  gatedDirect: 0,
  suppressedDirect: 0,
  retainedDirect: 2,
});

function provenance(scannerVersion: string, configDigest: string): Provenance {
  return Object.freeze({
    scannerVersion,
    runtime: Object.freeze({
      node: "24.19.0",
      playwright: "1.62.1",
      chromiumRevision: "1234",
    }),
    catalog: Object.freeze({
      source: "example/catalog",
      revision: "revision-1",
      digest: CATALOG_DIGEST,
    }),
    configDigest,
  });
}

function available(directNames: readonly string[]): ShadowDetectorView {
  return Object.freeze({
    state: "available" as const,
    directNames: Object.freeze([...directNames].sort()),
    inferredNames: Object.freeze([]),
    detectionStats,
    completed: true,
    errors: Object.freeze([]),
  });
}

function directName(view: ShadowDetectorView): string {
  assert.equal(view.state, "available");
  assert.equal(view.directNames.length, 1);
  return view.directNames[0]!;
}

function domain(index: number): string {
  return `d${String(index).padStart(3, "0")}.example`;
}

function holdoutDomain(index: number): string {
  return `h${String(index).padStart(3, "0")}.example`;
}

function cost(value = 1): ShadowFullCost {
  return Object.freeze({
    browserPagesAttempted: value,
    browserPagesAdmitted: value,
    browserRequests: value,
    browserTransferredBytes: value,
    browserMs: value,
  });
}

function snapshot(
  index: number,
  runId: string,
  overrides: Partial<ShadowEvaluationSnapshot> = {},
): ShadowEvaluationSnapshot {
  const highLift = index < 50;
  return Object.freeze({
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    runId,
    domain: runId === HOLDOUT_RUN_ID ? holdoutDomain(index) : domain(index),
    t1: available(BASE_NAMES),
    t2: available(BASE_NAMES),
    preBrowser: Object.freeze({
      entryOutcome: "html" as const,
      entryStatusClass: "2xx" as const,
      entryHtmlBytes: highLift ? 8_000 : 1_000,
      entryTextCodePoints: 500,
      staticNavigationLinks: highLift ? 16 : 1,
      metadataEntries: 2,
      resourceEntries: 8,
      dnsRecords: 2,
      tlsIssuerPresent: true,
      t2Selected: true,
      t2Role: "detail" as const,
      t2Outcome: "html" as const,
      probesObserved: highLift ? 8 : 1,
      httpRequests: 4,
      staticTransferredBytes: highLift ? 16_000 : 2_000,
    }),
    full: Object.freeze({
      directNames: Object.freeze([
        ...BASE_NAMES,
        ...(highLift ? ["Recurring"] : []),
        ...(index === 0 ? ["Singleton"] : []),
      ].sort()),
      inferredNames: Object.freeze([]),
      status: "success" as const,
    }),
    fullCost: cost(),
    browserLimitHits: Object.freeze([]),
    ...overrides,
  });
}

function snapshots(runId: string): readonly ShadowEvaluationSnapshot[] {
  return Object.freeze(Array.from(
    { length: SHADOW_EVALUATION_DOMAIN_COUNT },
    (_, index) => snapshot(index, runId),
  ));
}

function artifact(
  runId: string,
  scannerVersion: string,
  configDigest: string,
  inputSnapshots: readonly ShadowEvaluationSnapshot[] = snapshots(runId),
): ShadowEvaluationArtifact {
  return Object.freeze({
    schemaVersion: 1 as const,
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    runId,
    inputDomains: SHADOW_EVALUATION_DOMAIN_COUNT,
    provenance: provenance(scannerVersion, configDigest),
    snapshots: inputSnapshots,
    browserLimitAggregates: Object.freeze([]),
  });
}

const developmentOptions = Object.freeze({
  trainingArtifactDigest: TRAINING_ARTIFACT_DIGEST,
  expectedEvaluationScannerVersion: "0.1.7",
  expectedEvaluationConfigDigest: EVALUATION_CONFIG_DIGEST,
});

const DISCOVERY_DOMAINS = Object.freeze(Array.from(
  { length: SHADOW_EVALUATION_DOMAIN_COUNT },
  (_, index) => `x${String(index).padStart(3, "0")}.example`,
));

function categoryProjection(
  names: readonly string[] = BASE_NAMES,
  categoryIds: (name: string, index: number) => readonly number[] = () => [1],
): ShadowT2CategoryProjection {
  return validateShadowT2CategoryProjection({
    catalog: provenance("0.1.8", TRAINING_CONFIG_DIGEST).catalog,
    technologies: names.map((name, index) => ({
      name,
      categoryIds: categoryIds(name, index),
    })),
  });
}

function pairedPreregistration(
  projection: ShadowT2CategoryProjection,
): ShadowPairedPreregistration {
  return validateShadowPairedPreregistration({
    schemaVersion: 1,
    experimentRevision: SHADOW_PAIRED_EXPERIMENT_REVISION,
    baselineImplementationCommit: "67890e61a16d74eb5bfade6d789f968fc2e1eee7",
    discoveryArtifactDigest: `sha256:${"5".repeat(64)}`,
    discoveryDomainSetDigest: computeDomainSetDigest(DISCOVERY_DOMAINS),
    discoveryScannerVersion: "0.1.5",
    expectedDevelopmentScannerVersion: "0.1.8",
    expectedDevelopmentConfigDigest: TRAINING_CONFIG_DIGEST,
    catalog: projection.catalog,
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    categoryProjectionDigest: digestShadowT2CategoryProjection(projection),
    categoryFeature: {
      source: "t2.directNames",
      mapping: "effective-catalog-category-ids",
      token: "t2.directCategoryId=<decimal>",
      aggregation: "sorted-unique-union",
      missing: "reject",
      forbiddenInputs: [
        "t1",
        "inferred",
        "full",
        "count",
        "category-name",
        "category-group",
      ],
    },
    cohortPolicy: {
      developmentDomains: 200,
      holdoutDomains: 200,
      sourceIdentity: "delegated-to-immutable-manifest",
      selection: "sha256-rank-without-replacement-v1",
      salt: SHADOW_PAIRED_COHORT_SALT,
      developmentSelection: "first-200-after-d1-exclusion",
      holdoutSelection: "next-200-after-d1-exclusion",
      overlap: "zero-canonical-d1-d2-h1",
      preScreen: "none",
      replacement: "none-after-freeze",
    },
    featureSets: [SHADOW_BASELINE_FEATURE_SET, SHADOW_CATEGORY_FEATURE_SET],
    foldCount: 5,
    triggerDomainCount: 38,
    controlDomainCount: 2,
    smoothingPrior: 4,
    recurringNameMinimumSupport: 2,
    salts: SHADOW_CALIBRATION_SALTS,
    guardrails: {
      canonicalDirectNameRetentionMinimum: 0.95,
      domainTechnologyPairRetentionMinimum: 0.8,
      realBrowserCostMaximum: 0.3,
    },
    foldWin: {
      minimumCategoryWins: SHADOW_CATEGORY_FOLD_WIN_MINIMUM,
      scope: "trigger-only",
      pairLift: "sum-full-minus-t2",
      novelNameCoverage: "selected-full-union-minus-global-t2-union",
      rule: "componentwise-non-regression-with-one-strict",
      requirePositiveTriggerQuotaEachFold: true,
      globalT2Union: "same-cohort-union-shared-by-arms",
      interpretation: "stability-heuristic-not-statistical-test",
    },
    controlsIncludedInGlobalGuardrails: true,
    decisionRule: "baseline-first-else-category-if-eligible-else-no-go",
  });
}

function developmentManifest(
  inputArtifact: ShadowEvaluationArtifact,
  preregistration: ShadowPairedPreregistration,
  sealedHoldoutManifestDigest: string,
): ShadowPairedCohortManifest {
  return validateShadowPairedCohortManifest({
    schemaVersion: 1,
    experimentRevision: SHADOW_PAIRED_EXPERIMENT_REVISION,
    role: "development",
    sealedHoldoutManifestDigest,
    preregistrationDigest: digestShadowPairedPreregistration(preregistration),
    input: {
      fileDigest: `sha256:${"6".repeat(64)}`,
      domainSetDigest: computeDomainSetDigest(
        inputArtifact.snapshots.map(({ domain: value }) => value),
      ),
      domains: SHADOW_EVALUATION_DOMAIN_COUNT,
    },
    expected: {
      scannerVersion: inputArtifact.provenance.scannerVersion,
      configDigest: inputArtifact.provenance.configDigest,
      catalog: inputArtifact.provenance.catalog,
      schemaVersion: 1,
      protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    },
    source: {
      name: "fixture-source",
      revision: "fixture-source-v1",
      digest: `sha256:${"7".repeat(64)}`,
    },
    sampling: {
      revision: "sha256-rank-without-replacement-v1",
      salt: SHADOW_PAIRED_COHORT_SALT,
    },
    zeroOverlapWith: [{
      label: "D1",
      domainSetDigest: computeDomainSetDigest(DISCOVERY_DOMAINS),
      domains: DISCOVERY_DOMAINS,
    }],
  });
}

function holdoutManifest(
  inputArtifact: ShadowEvaluationArtifact,
  preregistration: ShadowPairedPreregistration,
  developmentDomains: readonly string[],
): ShadowPairedCohortManifest {
  return validateShadowPairedCohortManifest({
    schemaVersion: 1,
    experimentRevision: SHADOW_PAIRED_EXPERIMENT_REVISION,
    role: "holdout",
    preregistrationDigest: digestShadowPairedPreregistration(preregistration),
    input: {
      fileDigest: `sha256:${"8".repeat(64)}`,
      domainSetDigest: computeDomainSetDigest(
        inputArtifact.snapshots.map(({ domain: value }) => value),
      ),
      domains: SHADOW_EVALUATION_DOMAIN_COUNT,
    },
    expected: {
      scannerVersion: inputArtifact.provenance.scannerVersion,
      configDigest: inputArtifact.provenance.configDigest,
      catalog: inputArtifact.provenance.catalog,
      schemaVersion: 1,
      protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    },
    source: {
      name: "fixture-source",
      revision: "fixture-source-v1",
      digest: `sha256:${"7".repeat(64)}`,
    },
    sampling: {
      revision: "sha256-rank-without-replacement-v1",
      salt: SHADOW_PAIRED_COHORT_SALT,
    },
    zeroOverlapWith: [
      {
        label: "D1",
        domainSetDigest: computeDomainSetDigest(DISCOVERY_DOMAINS),
        domains: DISCOVERY_DOMAINS,
      },
      {
        label: "D2",
        domainSetDigest: computeDomainSetDigest(developmentDomains),
        domains: developmentDomains,
      },
    ],
  });
}

function pairedDevelopmentOptions(
  preregistration: ShadowPairedPreregistration,
  manifest: ShadowPairedCohortManifest,
  sealedHoldoutManifest: ShadowPairedCohortManifest,
) {
  return Object.freeze({
    trainingArtifactDigest: TRAINING_ARTIFACT_DIGEST,
    expectedEvaluationScannerVersion:
      preregistration.expectedDevelopmentScannerVersion,
    expectedEvaluationConfigDigest:
      preregistration.expectedDevelopmentConfigDigest,
    preregistrationDigest: digestShadowPairedPreregistration(preregistration),
    cohortManifestDigest: digestShadowPairedCohortManifest(manifest),
    sealedHoldoutManifestDigest:
      digestShadowPairedCohortManifest(sealedHoldoutManifest),
  });
}

function pairedDevelopmentBoundary(
  inputArtifact: ShadowEvaluationArtifact,
  projection: ShadowT2CategoryProjection,
  preregistration: ShadowPairedPreregistration,
): {
  readonly source: ShadowPairedDevelopmentSourceReport;
  readonly manifest: ShadowPairedCohortManifest;
  readonly sealedHoldoutManifest: ShadowPairedCohortManifest;
  readonly options: ReturnType<typeof pairedDevelopmentOptions>;
} {
  const sealedSnapshots = inputArtifact.snapshots.map((item, index) => Object.freeze({
    ...item,
    runId: HOLDOUT_RUN_ID,
    domain: holdoutDomain(index),
  }));
  const sealedArtifact = artifact(
    HOLDOUT_RUN_ID,
    inputArtifact.provenance.scannerVersion,
    inputArtifact.provenance.configDigest,
    sealedSnapshots,
  );
  const sealedHoldoutManifest = holdoutManifest(
    sealedArtifact,
    preregistration,
    inputArtifact.snapshots.map(({ domain: value }) => value),
  );
  const manifest = developmentManifest(
    inputArtifact,
    preregistration,
    digestShadowPairedCohortManifest(sealedHoldoutManifest),
  );
  const options = pairedDevelopmentOptions(
    preregistration,
    manifest,
    sealedHoldoutManifest,
  );
  const source = createShadowPairedDevelopmentSource(inputArtifact, {
    preregistrationDigest: options.preregistrationDigest,
    cohortManifestDigest: options.cohortManifestDigest,
    sealedHoldoutManifestDigest: options.sealedHoldoutManifestDigest,
    categoryProjectionDigest: digestShadowT2CategoryProjection(projection),
  });
  return Object.freeze({ source, manifest, sealedHoldoutManifest, options });
}

function passingCandidate(): ShadowFrozenCandidate {
  const report = calibrateShadowDevelopment(
    artifact(TRAINING_RUN_ID, "0.1.5", TRAINING_CONFIG_DIGEST),
    developmentOptions,
  );
  assert.equal(report.deployable.provisionalGuardrails.passed, true);
  assert.ok(report.candidate);
  return report.candidate;
}

function featureSnapshot(
  index: number,
  runId: string,
  feature: "a" | "b",
  extraFullNames: readonly string[] = [],
): ShadowEvaluationSnapshot {
  const base = snapshot(index, runId);
  assert.ok(base.preBrowser);
  return snapshot(index, runId, {
    preBrowser: Object.freeze({
      ...base.preBrowser,
      entryHtmlBytes: feature === "a" ? 16_000 : 500,
      staticNavigationLinks: feature === "a" ? 32 : 0,
      probesObserved: feature === "a" ? 16 : 0,
      staticTransferredBytes: feature === "a" ? 32_000 : 1_000,
    }),
    full: Object.freeze({
      directNames: Object.freeze([...BASE_NAMES, ...extraFullNames].sort()),
      inferredNames: Object.freeze([]),
      status: "success" as const,
    }),
  });
}

function pairedFeatureSnapshot(
  index: number,
  categorySignal: "high" | "low",
): ShadowEvaluationSnapshot {
  const name = `Tech-${String(index).padStart(3, "0")}`;
  const base = snapshot(100, TRAINING_RUN_ID);
  return Object.freeze({
    ...base,
    runId: TRAINING_RUN_ID,
    domain: domain(index),
    t1: available([name]),
    t2: available([name]),
    full: Object.freeze({
      directNames: Object.freeze([
        name,
        ...(categorySignal === "high"
          ? Array.from({ length: 10 }, (_, lift) =>
            `Lift-${String(lift).padStart(2, "0")}`)
          : []),
      ].sort()),
      inferredNames: Object.freeze([]),
      status: "success" as const,
    }),
  });
}

test("development OOF selection is blind to held-out labels, costs, and telemetry", () => {
  const original = artifact(TRAINING_RUN_ID, "0.1.5", TRAINING_CONFIG_DIGEST);
  const targetFold = 3;
  const changedSnapshots = original.snapshots.map((item, index) => {
    if (shadowFoldForDomain(item.domain) !== targetFold) return item;
    return snapshot(index, TRAINING_RUN_ID, {
      full: Object.freeze({
        directNames: Object.freeze([`Changed-${String(index).padStart(3, "0")}`]),
        inferredNames: Object.freeze(["Changed-inferred"]),
        status: "failed" as const,
      }),
      fullCost: cost(10_000 + index),
      browserLimitHits: Object.freeze([Object.freeze({
        pageId: "p1" as const,
        category: "inspection.domAccess" as const,
        domSelectorOrdinal: index,
      })]),
    });
  });
  const baseline = calibrateShadowDevelopmentSource(original);
  const changed = calibrateShadowDevelopmentSource(artifact(
    TRAINING_RUN_ID,
    "0.1.5",
    TRAINING_CONFIG_DIGEST,
    changedSnapshots,
  ));
  assert.deepEqual(
    changed.oofPredictions.filter(({ fold }) => fold === targetFold),
    baseline.oofPredictions.filter(({ fold }) => fold === targetFold),
  );
  assert.deepEqual(
    changed.deployable.selected.filter(({ fold }) => fold === targetFold),
    baseline.deployable.selected.filter(({ fold }) => fold === targetFold),
  );
  assert.equal(baseline.deployable.triggerDomainCount, 38);
  assert.equal(baseline.deployable.controlDomainCount, 2);
});

test("development source report is byte-stable and omits per-name prediction vectors", () => {
  const forwardArtifact = artifact(
    TRAINING_RUN_ID,
    "0.1.5",
    TRAINING_CONFIG_DIGEST,
  );
  const reverseArtifact = artifact(
    TRAINING_RUN_ID,
    "0.1.5",
    TRAINING_CONFIG_DIGEST,
    [...forwardArtifact.snapshots].reverse(),
  );
  const forward = calibrateShadowDevelopmentSource(forwardArtifact);
  const reverse = calibrateShadowDevelopmentSource(reverseArtifact);
  assert.equal(forward.mode, "development-source");
  assert.equal(JSON.stringify(forward), JSON.stringify(reverse));
  assert.equal(forward.deployable.selected.length, 40);
  assert.ok(forward.oofPredictions.every((prediction) =>
    !Object.hasOwn(prediction, "recurringNames")));
});

test("candidate uses pair, recurring-name, and rare-singleton heads", () => {
  const report = calibrateShadowDevelopment(
    artifact(TRAINING_RUN_ID, "0.1.5", TRAINING_CONFIG_DIGEST),
    developmentOptions,
  );
  assert.ok(report.candidate);
  assert.equal(report.candidate.trainingIncrementalPairLift, 51);
  assert.equal(report.candidate.trainingRareSingletonLift, 1);
  assert.deepEqual(report.candidate.recurringNames, [
    { name: "Recurring", support: 50 },
  ]);
  assert.equal(report.candidate.trainingIdentity.provenance.scannerVersion, "0.1.5");
  assert.equal(report.candidate.evaluationCompatibility.scannerVersion, "0.1.7");
  assert.equal(
    report.candidate.trainingIdentity.provenance.configDigest,
    TRAINING_CONFIG_DIGEST,
  );
  assert.equal(
    report.candidate.evaluationCompatibility.configDigest,
    EVALUATION_CONFIG_DIGEST,
  );
  const high = predictShadowSnapshot(report.candidate, snapshot(1, HOLDOUT_RUN_ID));
  const low = predictShadowSnapshot(report.candidate, snapshot(100, HOLDOUT_RUN_ID));
  assert.ok(high.pairLift > low.pairLift);
  assert.ok(high.recurringNames[0]!.probability > low.recurringNames[0]!.probability);
});

test("support two becomes recurring while support one stays rare and held-out-only", () => {
  const byFold = new Map<number, number[]>();
  for (let index = 0; index < SHADOW_EVALUATION_DOMAIN_COUNT; index += 1) {
    const fold = shadowFoldForDomain(domain(index));
    const indices = byFold.get(fold) ?? [];
    indices.push(index);
    byFold.set(fold, indices);
  }
  const target = [...byFold.entries()].find(([, indices]) => indices.length >= 2);
  assert.ok(target);
  const [targetFold, targetIndices] = target;
  const first = targetIndices[0]!;
  const second = targetIndices[1]!;
  const singleton = Array.from(
    { length: SHADOW_EVALUATION_DOMAIN_COUNT },
    (_, index) => index,
  ).find((index) => index !== first && index !== second)!;
  const input = Array.from(
    { length: SHADOW_EVALUATION_DOMAIN_COUNT },
    (_, index) => featureSnapshot(
      index,
      TRAINING_RUN_ID,
      index === first || index === second || index === singleton ? "a" : "b",
      index === first || index === second
        ? ["Two-support"]
        : index === singleton
          ? ["One-support"]
          : [],
    ),
  );
  const source = calibrateShadowDevelopmentSource(artifact(
    TRAINING_RUN_ID,
    "0.1.5",
    TRAINING_CONFIG_DIGEST,
    input,
  ));
  assert.equal(source.model.folds[targetFold]!.recurringNameHeads, 0);
  assert.ok(source.model.folds.some((fold) =>
    fold.fold !== targetFold && fold.recurringNameHeads === 1));
  assert.ok(source.model.folds.some(({ trainingRareSingletonLift }) =>
    trainingRareSingletonLift === 1));

  const development = calibrateShadowDevelopment(
    artifact(TRAINING_RUN_ID, "0.1.5", TRAINING_CONFIG_DIGEST, input),
    developmentOptions,
  );
  assert.ok(development.candidate);
  assert.deepEqual(development.candidate.recurringNames, [
    { name: "Two-support", support: 2 },
  ]);
  assert.equal(development.candidate.trainingRareSingletonLift, 1);
});

test("diminishing recurring credit promotes a distinct predicted name", () => {
  const training = Array.from(
    { length: SHADOW_EVALUATION_DOMAIN_COUNT },
    (_, index) => featureSnapshot(
      index,
      TRAINING_RUN_ID,
      index < 100 ? "a" : "b",
      [index < 100 ? "Name-A" : "Name-B"],
    ),
  );
  const development = calibrateShadowDevelopment(
    artifact(TRAINING_RUN_ID, "0.1.5", TRAINING_CONFIG_DIGEST, training),
    developmentOptions,
  );
  assert.ok(development.candidate);
  assert.deepEqual(
    development.candidate.recurringNames.map(({ name }) => name),
    ["Name-A", "Name-B"],
  );
  const holdout = Array.from(
    { length: SHADOW_EVALUATION_DOMAIN_COUNT },
    (_, index) => featureSnapshot(
      index,
      HOLDOUT_RUN_ID,
      index === 0 ? "b" : "a",
    ),
  );
  const result = evaluateFrozenShadowCandidate(
    artifact(
      HOLDOUT_RUN_ID,
      "0.1.7",
      EVALUATION_CONFIG_DIGEST,
      holdout,
    ),
    development.candidate,
    { candidateDigest: digestShadowFrozenCandidate(development.candidate) },
  );
  const firstTwo = result.deployable.selected
    .filter(({ source }) => source === "trigger")
    .slice(0, 2)
    .map(({ domain: selectedDomain }) =>
      selectedDomain === holdoutDomain(0) ? "b" : "a");
  assert.deepEqual(new Set(firstTwo), new Set(["a", "b"]));
});

test("an allowlisted pre-browser mutation can change a frozen prediction", () => {
  const candidate = passingCandidate();
  const high = snapshot(1, HOLDOUT_RUN_ID);
  const lowPrefix = snapshot(100, HOLDOUT_RUN_ID).preBrowser;
  assert.ok(lowPrefix);
  const low = snapshot(1, HOLDOUT_RUN_ID, {
    preBrowser: lowPrefix,
    full: Object.freeze({
      directNames: Object.freeze(["Label-only"]),
      inferredNames: Object.freeze([]),
      status: "failed" as const,
    }),
    fullCost: cost(99_999),
  });
  const highPrediction = predictShadowSnapshot(candidate, high);
  const lowPrediction = predictShadowSnapshot(candidate, low);
  assert.notEqual(highPrediction.pairLift, lowPrediction.pairLift);
});

test("a failed OOF GO/NO-GO cannot produce a frozen candidate", () => {
  const unique = snapshots(TRAINING_RUN_ID).map((_, index) => snapshot(
    index,
    TRAINING_RUN_ID,
    {
      full: Object.freeze({
        directNames: Object.freeze([
          ...BASE_NAMES,
          `Unique-${String(index).padStart(3, "0")}`,
        ]),
        inferredNames: Object.freeze([]),
        status: "success" as const,
      }),
    },
  ));
  const report = calibrateShadowDevelopment(
    artifact(TRAINING_RUN_ID, "0.1.5", TRAINING_CONFIG_DIGEST, unique),
    developmentOptions,
  );
  assert.equal(report.deployable.provisionalGuardrails.passed, false);
  assert.equal(report.candidate, null);
  assert.equal(report.deploymentModel, null);
});

test("all five real browser costs compare exact 30 percent including controls", () => {
  const baseArtifact = artifact(TRAINING_RUN_ID, "0.1.5", TRAINING_CONFIG_DIGEST);
  const baseReport = calibrateShadowDevelopmentSource(baseArtifact);
  const selected = new Set(baseReport.deployable.selected.map(({ domain: value }) => value));
  const nonSelected = baseArtifact.snapshots
    .filter(({ domain: value }) => !selected.has(value))
    .map(({ domain: value }) => value);
  const nonSelectedRank = new Map(nonSelected.map((value, index) => [value, index]));
  const exactSnapshots = baseArtifact.snapshots.map((item, index) => snapshot(
    index,
    TRAINING_RUN_ID,
    {
      fullCost: cost(selected.has(item.domain)
        ? 3
        : (nonSelectedRank.get(item.domain) ?? 160) < 120 ? 2 : 1),
    },
  ));
  const exact = calibrateShadowDevelopmentSource(artifact(
    TRAINING_RUN_ID,
    "0.1.5",
    TRAINING_CONFIG_DIGEST,
    exactSnapshots,
  ));
  const exactCosts = exact.deployable.provisionalGuardrails.realBrowserCosts;
  for (const metric of [
    exactCosts.browserPagesAttempted,
    exactCosts.browserPagesAdmitted,
    exactCosts.browserRequests,
    exactCosts.browserTransferredBytes,
    exactCosts.browserMs,
  ]) {
    assert.equal(metric.selected, 120);
    assert.equal(metric.full, 400);
    assert.equal(metric.passed, true);
  }
  assert.equal(exactCosts.passed, true);
  assert.equal(
    exact.deployable.selected.filter(({ source }) => source === "control").length,
    2,
  );

  const selectedFirst = exact.deployable.selected[0]!.domain;
  const nonSelectedLast = nonSelected.at(-1)!;
  const overSnapshots = exactSnapshots.map((item, index) => snapshot(
    index,
    TRAINING_RUN_ID,
    {
      fullCost: item.domain === selectedFirst
        ? cost(4)
        : item.domain === nonSelectedLast
          ? cost(0)
          : item.fullCost,
    },
  ));
  const over = calibrateShadowDevelopment(
    artifact(TRAINING_RUN_ID, "0.1.5", TRAINING_CONFIG_DIGEST, overSnapshots),
    developmentOptions,
  );
  const overCosts = over.deployable.provisionalGuardrails.realBrowserCosts;
  assert.equal(overCosts.browserMs.selected, 121);
  assert.equal(overCosts.browserMs.full, 400);
  assert.equal(overCosts.passed, false);
  assert.equal(over.candidate, null);
});

test("zero selected and full browser costs pass with a null ratio", () => {
  const zeroCostSnapshots = snapshots(TRAINING_RUN_ID).map((_, index) => snapshot(
    index,
    TRAINING_RUN_ID,
    { fullCost: cost(0) },
  ));
  const report = calibrateShadowDevelopmentSource(artifact(
    TRAINING_RUN_ID,
    "0.1.5",
    TRAINING_CONFIG_DIGEST,
    zeroCostSnapshots,
  ));
  const costs = report.deployable.provisionalGuardrails.realBrowserCosts;
  for (const metric of [
    costs.browserPagesAttempted,
    costs.browserPagesAdmitted,
    costs.browserRequests,
    costs.browserTransferredBytes,
    costs.browserMs,
  ]) {
    assert.equal(metric.selected, 0);
    assert.equal(metric.full, 0);
    assert.equal(metric.actual, null);
    assert.equal(metric.passed, true);
  }
  assert.equal(costs.passed, true);
});

test("browser cost aggregation fails before safe-integer precision is lost", () => {
  const baseArtifact = artifact(TRAINING_RUN_ID, "0.1.5", TRAINING_CONFIG_DIGEST);
  const selected = new Set(
    calibrateShadowDevelopmentSource(baseArtifact).deployable.selected
      .map(({ domain: value }) => value),
  );
  const unit = 700_000_000_000_000;
  let firstSelected = true;
  const unsafeAggregate = baseArtifact.snapshots.map((item, index) => {
    let value = selected.has(item.domain) ? 12 * unit : 7 * unit;
    if (selected.has(item.domain) && firstSelected) {
      value += 1;
      firstSelected = false;
    }
    assert.equal(Number.isSafeInteger(value), true);
    return snapshot(index, TRAINING_RUN_ID, { fullCost: cost(value) });
  });
  assert.throws(
    () => calibrateShadowDevelopmentSource(artifact(
      TRAINING_RUN_ID,
      "0.1.5",
      TRAINING_CONFIG_DIGEST,
      unsafeAggregate,
    )),
    /safe-integer boundary/u,
  );
});

test("frozen holdout never retrains or selects from labels, costs, or telemetry", () => {
  const candidate = passingCandidate();
  const cleanArtifact = artifact(
    HOLDOUT_RUN_ID,
    "0.1.7",
    EVALUATION_CONFIG_DIGEST,
  );
  const candidateDigest = digestShadowFrozenCandidate(candidate);
  const baseline = evaluateFrozenShadowCandidate(
    cleanArtifact,
    candidate,
    { candidateDigest },
  );
  const changedSnapshots = cleanArtifact.snapshots.map((_, index) => snapshot(
    index,
    HOLDOUT_RUN_ID,
    {
      full: Object.freeze({
        directNames: Object.freeze([`Changed-${String(index).padStart(3, "0")}`]),
        inferredNames: Object.freeze(["Changed-inferred"]),
        status: "failed" as const,
      }),
      fullCost: cost(50_000 + index),
      browserLimitHits: Object.freeze([Object.freeze({
        pageId: "p2" as const,
        category: "inspection.domMatches" as const,
        domSelectorOrdinal: null,
      })]),
    },
  ));
  const changed = evaluateFrozenShadowCandidate(
    artifact(
      HOLDOUT_RUN_ID,
      "0.1.7",
      EVALUATION_CONFIG_DIGEST,
      changedSnapshots,
    ),
    candidate,
    { candidateDigest },
  );
  assert.equal(baseline.mode, "frozen-holdout");
  assert.deepEqual(changed.predictions, baseline.predictions);
  assert.deepEqual(changed.deployable.selected, baseline.deployable.selected);
  assert.deepEqual(changed.trainingIdentity, candidate.trainingIdentity);
  assert.equal(changed.deployable.triggerDomainCount, 38);
  assert.equal(changed.deployable.controlDomainCount, 2);
  assert.notDeepEqual(changed.deployable.metrics, baseline.deployable.metrics);

  const sameDomainSet = cleanArtifact.snapshots.map((item, index) => Object.freeze({
    ...item,
    domain: domain(index),
  }));
  assert.throws(
    () => evaluateFrozenShadowCandidate(
      artifact(
        HOLDOUT_RUN_ID,
        "0.1.7",
        EVALUATION_CONFIG_DIGEST,
        sameDomainSet,
      ),
      candidate,
      { candidateDigest },
    ),
    /distinct run and domain set/u,
  );
  assert.throws(
    () => evaluateFrozenShadowCandidate(
      artifact(
        TRAINING_RUN_ID,
        "0.1.7",
        EVALUATION_CONFIG_DIGEST,
        cleanArtifact.snapshots.map((item) => Object.freeze({
          ...item,
          runId: TRAINING_RUN_ID,
        })),
      ),
      candidate,
      { candidateDigest },
    ),
    /distinct run and domain set/u,
  );
});

test("candidate digest, compatibility, and structural bounds fail closed", () => {
  const candidate = passingCandidate();
  const digest = digestShadowFrozenCandidate(candidate);
  const raw = JSON.parse(JSON.stringify(candidate)) as Record<string, unknown>;
  const reversed = Object.fromEntries(Object.entries(raw).reverse());
  assert.equal(digestShadowFrozenCandidate(reversed), digest);
  assert.equal(
    canonicalizeShadowFrozenCandidate(reversed),
    canonicalizeShadowFrozenCandidate(candidate),
  );
  const catalog = provenance("0.1.7", EVALUATION_CONFIG_DIGEST).catalog;
  assert.doesNotThrow(() => assertShadowFrozenCandidateCompatibility(candidate, {
    schemaVersion: 1,
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    scannerVersion: "0.1.7",
    catalog,
    configDigest: EVALUATION_CONFIG_DIGEST,
  }));
  assert.throws(
    () => assertShadowFrozenCandidateCompatibility(candidate, {
      schemaVersion: 1,
      protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
      scannerVersion: "0.1.8",
      catalog,
      configDigest: EVALUATION_CONFIG_DIGEST,
    }),
    /incompatible/u,
  );
  assert.throws(
    () => evaluateFrozenShadowCandidate(
      artifact(HOLDOUT_RUN_ID, "0.1.7", EVALUATION_CONFIG_DIGEST),
      candidate,
      { candidateDigest: `sha256:${"f".repeat(64)}` },
    ),
    /digest does not match/u,
  );
  assert.throws(
    () => calibrateShadowDevelopment(
      artifact(TRAINING_RUN_ID, "0.1.5", TRAINING_CONFIG_DIGEST),
      { ...developmentOptions, trainingArtifactDigest: "1".repeat(64) },
    ),
    /SHA-256 digest/u,
  );

  const firstToken = candidate.tokens[0]!;
  assert.throws(
    () => validateShadowFrozenCandidate({
      ...candidate,
      tokens: Array.from(
        { length: SHADOW_MODEL_TOKEN_CAP + 1 },
        (_, index) => ({ ...firstToken, token: `token-${String(index).padStart(6, "0")}` }),
      ),
    }),
    /tokens exceed/u,
  );
  assert.throws(
    () => validateShadowFrozenCandidate({
      ...candidate,
      tokens: [{
        ...firstToken,
        recurringTargetSums: Array.from(
          { length: SHADOW_MODEL_RECURRING_TARGET_CAP + 1 },
          () => ({ head: 0, targetSum: 1 }),
        ),
      }],
    }),
    /recurring targets exceed/u,
  );
  assert.throws(
    () => validateShadowFrozenCandidate({
      ...candidate,
      tokens: [{ ...firstToken, pairTargetSum: Number.MAX_SAFE_INTEGER }],
    }),
    /exceed training totals/u,
  );
  assert.throws(
    () => validateShadowFrozenCandidate({
      ...candidate,
      recurringNames: candidate.recurringNames.map((head) => ({
        ...head,
        support: head.support + 1,
      })),
    }),
    /breadth targets exceed pair lift/u,
  );
  assert.throws(
    () => validateShadowFrozenCandidate({
      ...candidate,
      trainingIdentity: { ...candidate.trainingIdentity, runId: "not-a-run-id" },
    }),
    /runId is invalid/u,
  );
});

test("calibration salts and folds remain frozen", () => {
  assert.deepEqual(SHADOW_CALIBRATION_SALTS, {
    fold: "website-technologies-scraper/shadow/2026-08-20.1/fold/v1",
    scoreTieBreak:
      "website-technologies-scraper/shadow/2026-08-20.1/score-tie/v1",
    control: "website-technologies-scraper/shadow/2026-08-20.1/control/v1",
    random: "website-technologies-scraper/shadow/2026-08-20.1/random/v1",
    greedyTieBreak:
      "website-technologies-scraper/shadow/2026-08-20.1/greedy-tie/v1",
  });
  assert.deepEqual(
    ["alpha.example", "beta.example", "gamma.example", "delta.example"]
      .map(shadowFoldForDomain),
    [1, 0, 0, 0],
  );
});

test("category feature maps only T2 direct names to a sorted unique ID union", () => {
  const projection = categoryProjection(
    [BASE_NAMES[0]!, BASE_NAMES[1]!],
    (_, index) => index === 0 ? [3, 2, 2] : [2, 1],
  );
  const input = snapshot(0, TRAINING_RUN_ID, {
    t1: available(["T1-only"]),
    t2: available([BASE_NAMES[0]!, BASE_NAMES[1]!]),
    full: Object.freeze({
      directNames: Object.freeze(["Full-only"]),
      inferredNames: Object.freeze(["Inferred-only"]),
      status: "success" as const,
    }),
  });
  const categoryTokens = shadowCategoryTriggerFeatureTokens(input, projection)
    .filter((token) => token.startsWith("t2.directCategoryId="));
  assert.deepEqual(categoryTokens, [
    "t2.directCategoryId=1",
    "t2.directCategoryId=2",
    "t2.directCategoryId=3",
  ]);
  assert.equal(categoryTokens.some((token) => token.includes("count")), false);

  const changedT1 = snapshot(0, TRAINING_RUN_ID, {
    t1: available(["Different-T1"]),
    t2: input.t2,
    full: Object.freeze({
      directNames: Object.freeze(["Different-full"]),
      inferredNames: Object.freeze(["Different-inferred"]),
      status: "failed" as const,
    }),
  });
  assert.deepEqual(
    shadowCategoryTriggerFeatureTokens(changedT1, projection)
      .filter((token) => token.startsWith("t2.directCategoryId=")),
    categoryTokens,
  );
  assert.throws(
    () => shadowCategoryTriggerFeatureTokens(
      snapshot(0, TRAINING_RUN_ID, { t2: available(["Missing"]) }),
      projection,
    ),
    /missing from the category projection/u,
  );

  const reversed = {
    catalog: projection.catalog,
    technologies: [...projection.technologies].reverse().map((technology) => ({
      ...technology,
      categoryIds: [...technology.categoryIds].reverse(),
    })),
  };
  assert.equal(
    canonicalizeShadowT2CategoryProjection(reversed),
    canonicalizeShadowT2CategoryProjection(projection),
  );
  assert.equal(
    digestShadowT2CategoryProjection(reversed),
    digestShadowT2CategoryProjection(projection),
  );
});

test("category projection rejects missing categories and numeric bounds", () => {
  const catalog = provenance("0.1.8", TRAINING_CONFIG_DIGEST).catalog;
  assert.throws(
    () => validateShadowT2CategoryProjection({
      catalog,
      technologies: [{ name: "Missing-category", categoryIds: [] }],
    }),
    /category IDs exceed/u,
  );
  assert.throws(
    () => validateShadowT2CategoryProjection({
      catalog,
      technologies: [{
        name: "Out-of-range",
        categoryIds: [SHADOW_CATEGORY_ID_MAXIMUM + 1],
      }],
    }),
    /invalid category ID/u,
  );
  assert.throws(
    () => validateShadowT2CategoryProjection({
      catalog,
      technologies: [{
        name: "Too-many",
        categoryIds: Array.from(
          { length: SHADOW_CATEGORY_IDS_PER_TECHNOLOGY_MAXIMUM + 1 },
          (_, index) => index + 1,
        ),
      }],
    }),
    /category IDs exceed/u,
  );
});

test("paired preregistration and manifest are canonical, bounded, and newline framed", () => {
  const projection = categoryProjection();
  const preregistration = pairedPreregistration(projection);
  const inputArtifact = artifact(
    TRAINING_RUN_ID,
    "0.1.8",
    TRAINING_CONFIG_DIGEST,
  );
  const boundary = pairedDevelopmentBoundary(
    inputArtifact,
    projection,
    preregistration,
  );
  const manifest = boundary.manifest;
  assert.equal(manifest.role, "development");
  if (manifest.role !== "development") throw new Error("expected development manifest");
  assert.equal(
    manifest.sealedHoldoutManifestDigest,
    digestShadowPairedCohortManifest(boundary.sealedHoldoutManifest),
  );
  assert.equal(boundary.sealedHoldoutManifest.role, "holdout");
  assert.throws(
    () => validateShadowPairedCohortManifest(Object.fromEntries(
      Object.entries(manifest)
        .filter(([key]) => key !== "sealedHoldoutManifestDigest"),
    )),
    /exact frozen shape/u,
  );
  assert.throws(
    () => validateShadowPairedCohortManifest({
      ...boundary.sealedHoldoutManifest,
      sealedHoldoutManifestDigest: digestShadowPairedCohortManifest(
        boundary.sealedHoldoutManifest,
      ),
    }),
    /exact frozen shape/u,
  );
  assert.equal(canonicalizeShadowPairedPreregistration(preregistration).endsWith("\n"), true);
  assert.equal(canonicalizeShadowPairedCohortManifest(manifest).endsWith("\n"), true);
  assert.equal(
    canonicalizeShadowPairedDevelopmentSource(boundary.source, inputArtifact)
      .endsWith("\n"),
    true,
  );
  assert.equal(
    canonicalizeShadowPairedPreregistration(
      Object.fromEntries(Object.entries(preregistration).reverse()),
    ),
    canonicalizeShadowPairedPreregistration(preregistration),
  );
  assert.equal(
    digestShadowPairedCohortManifest(
      Object.fromEntries(Object.entries(manifest).reverse()),
    ),
    digestShadowPairedCohortManifest(manifest),
  );
  assert.throws(
    () => validateShadowPairedCohortManifest({
      ...manifest,
      zeroOverlapWith: [{
        ...manifest.zeroOverlapWith[0],
        domainSetDigest: `sha256:${"f".repeat(64)}`,
      }],
    }),
    /digest does not match domains/u,
  );
  assert.throws(
    () => validateShadowPairedPreregistration({
      ...preregistration,
      foldWin: { ...preregistration.foldWin, minimumCategoryWins: 3 },
    }),
    /fold-win rule does not match/u,
  );
});

test("repository paired preregistration bytes match the frozen public digest", async () => {
  const bytes = await readFile(new URL(
    "../shadow-category-ablation.v1.json",
    import.meta.url,
  ));
  assert.equal(bytes.at(-1), 0x0a);
  assert.equal(bytes.includes(0x0d), false);
  const text = bytes.toString("utf8");
  const preregistration = validateShadowPairedPreregistration(JSON.parse(text));
  assert.equal(text, canonicalizeShadowPairedPreregistration(preregistration));
  assert.equal(
    digestShadowPairedPreregistration(preregistration),
    "sha256:bf924836872efc40ee30b92ae51eb456d08ce3172b19de25b401be422107f849",
  );
});

test("paired decision is baseline-first and requires at least four fold wins", () => {
  assert.deepEqual(decideShadowPairedExperiment(true, true, 5), {
    selectedFeatureSet: SHADOW_BASELINE_FEATURE_SET,
    reason: "baseline-passed-all-official-gates",
  });
  assert.deepEqual(decideShadowPairedExperiment(false, true, 3), {
    selectedFeatureSet: null,
    reason: "no-arm-eligible",
  });
  assert.deepEqual(decideShadowPairedExperiment(false, true, 4), {
    selectedFeatureSet: SHADOW_CATEGORY_FEATURE_SET,
    reason: "category-passed-all-official-gates-and-fold-win-minimum",
  });
  assert.deepEqual(decideShadowPairedExperiment(false, false, 5), {
    selectedFeatureSet: null,
    reason: "no-arm-eligible",
  });
  assert.throws(
    () => decideShadowPairedExperiment(false, true, 6),
    /decision inputs are invalid/u,
  );
});

test("paired calibration preserves baseline bytes and selects a four-fold category winner", () => {
  const inputSnapshots = Object.freeze(Array.from(
    { length: SHADOW_EVALUATION_DOMAIN_COUNT },
    (_, index) => pairedFeatureSnapshot(index, index < 50 ? "high" : "low"),
  ));
  const inputArtifact = artifact(
    TRAINING_RUN_ID,
    "0.1.8",
    TRAINING_CONFIG_DIGEST,
    inputSnapshots,
  );
  const names = inputSnapshots.map(({ t2 }) => directName(t2));
  const projection = categoryProjection(
    names,
    (_, index) => [index < 50 ? 1 : 2],
  );
  const preregistration = pairedPreregistration(projection);
  const boundary = pairedDevelopmentBoundary(
    inputArtifact,
    projection,
    preregistration,
  );
  const result = calibrateShadowPairedDevelopment(
    inputArtifact,
    boundary.source,
    projection,
    preregistration,
    boundary.manifest,
    boundary.sealedHoldoutManifest,
    boundary.options,
  );
  const replacementHoldout = validateShadowPairedCohortManifest({
    ...boundary.sealedHoldoutManifest,
    input: {
      ...boundary.sealedHoldoutManifest.input,
      fileDigest: `sha256:${"9".repeat(64)}`,
    },
  });
  assert.throws(
    () => calibrateShadowPairedDevelopment(
      inputArtifact,
      boundary.source,
      projection,
      preregistration,
      boundary.manifest,
      replacementHoldout,
      boundary.options,
    ),
    /sealed holdout/u,
  );
  assert.equal(
    JSON.stringify(result.baseline),
    JSON.stringify(calibrateShadowDevelopmentSource(inputArtifact)),
  );
  assert.equal(result.baseline.deployable.provisionalGuardrails.passed, false);
  assert.equal(result.category.deployable.provisionalGuardrails.passed, true);
  assert.ok(result.categoryFoldWins >= SHADOW_CATEGORY_FOLD_WIN_MINIMUM);
  assert.ok(result.foldComparisons.every((comparison) =>
    comparison.baseline.triggerDomainCount > 0
    && comparison.category.triggerDomainCount > 0));
  assert.equal(
    result.foldComparisons.reduce(
      (sum, comparison) => sum + comparison.baseline.triggerDomainCount,
      0,
    ),
    38,
  );
  assert.equal(result.category.deployable.selected.length, 40);
  assert.equal(
    result.category.deployable.selected.filter(({ source }) => source === "control")
      .length,
    2,
  );
  assert.equal(result.decision.selectedFeatureSet, SHADOW_CATEGORY_FEATURE_SET);
  assert.ok(result.candidate);
  assert.equal(result.candidate.featureSet, SHADOW_CATEGORY_FEATURE_SET);
  assert.equal(result.candidate.preregistrationDigest, result.preregistrationDigest);
  assert.equal(
    result.candidate.trainingCohort.manifestDigest,
    result.cohortManifestDigest,
  );
  assert.equal(
    result.candidate.trainingCohort.sealedHoldoutManifestDigest,
    result.sealedHoldoutManifestDigest,
  );
  assert.equal(canonicalizeShadowPairedFrozenCandidate(result.candidate).endsWith("\n"), true);
  assert.equal(
    digestShadowPairedFrozenCandidate(
      Object.fromEntries(Object.entries(result.candidate).reverse()),
    ),
    digestShadowPairedFrozenCandidate(result.candidate),
  );
});

test("paired category arm remains label-blind inside each held-out fold", () => {
  const inputSnapshots = Object.freeze(Array.from(
    { length: SHADOW_EVALUATION_DOMAIN_COUNT },
    (_, index) => pairedFeatureSnapshot(index, index < 50 ? "high" : "low"),
  ));
  const originalArtifact = artifact(
    TRAINING_RUN_ID,
    "0.1.8",
    TRAINING_CONFIG_DIGEST,
    inputSnapshots,
  );
  const projection = categoryProjection(
    inputSnapshots.map(({ t2 }) => directName(t2)),
    (_, index) => [index < 50 ? 1 : 2],
  );
  const preregistration = pairedPreregistration(projection);
  const boundary = pairedDevelopmentBoundary(
    originalArtifact,
    projection,
    preregistration,
  );
  const targetFold = 2;
  const changedSnapshots = inputSnapshots.map((item, index) =>
    shadowFoldForDomain(item.domain) !== targetFold
      ? item
      : Object.freeze({
        ...item,
        full: Object.freeze({
          directNames: Object.freeze([`Changed-${String(index).padStart(3, "0")}`]),
          inferredNames: Object.freeze(["Changed-inferred"]),
          status: "failed" as const,
        }),
        fullCost: cost(10_000 + index),
        browserLimitHits: Object.freeze([]),
      }));
  const baseline = calibrateShadowPairedDevelopment(
    originalArtifact,
    boundary.source,
    projection,
    preregistration,
    boundary.manifest,
    boundary.sealedHoldoutManifest,
    boundary.options,
  );
  const changedArtifact = artifact(
    TRAINING_RUN_ID,
    "0.1.8",
    TRAINING_CONFIG_DIGEST,
    changedSnapshots,
  );
  const changedSource = createShadowPairedDevelopmentSource(changedArtifact, {
    preregistrationDigest: boundary.options.preregistrationDigest,
    cohortManifestDigest: boundary.options.cohortManifestDigest,
    sealedHoldoutManifestDigest:
      boundary.options.sealedHoldoutManifestDigest,
    categoryProjectionDigest: digestShadowT2CategoryProjection(projection),
  });
  assert.throws(
    () => calibrateShadowPairedDevelopment(
      changedArtifact,
      boundary.source,
      projection,
      preregistration,
      boundary.manifest,
      boundary.sealedHoldoutManifest,
      boundary.options,
    ),
    /source does not match its artifact/u,
  );
  const changed = calibrateShadowPairedDevelopment(
    changedArtifact,
    changedSource,
    projection,
    preregistration,
    boundary.manifest,
    boundary.sealedHoldoutManifest,
    boundary.options,
  );
  for (const arm of ["baseline", "category"] as const) {
    assert.deepEqual(
      changed[arm].oofPredictions.filter(({ fold }) => fold === targetFold),
      baseline[arm].oofPredictions.filter(({ fold }) => fold === targetFold),
    );
    assert.deepEqual(
      changed[arm].deployable.selected.filter(({ fold }) => fold === targetFold),
      baseline[arm].deployable.selected.filter(({ fold }) => fold === targetFold),
    );
  }
});

test("paired frozen holdout uses the frozen arm and remains label-blind", () => {
  const developmentSnapshots = Object.freeze(Array.from(
    { length: SHADOW_EVALUATION_DOMAIN_COUNT },
    (_, index) => pairedFeatureSnapshot(index, index < 50 ? "high" : "low"),
  ));
  const developmentArtifact = artifact(
    TRAINING_RUN_ID,
    "0.1.8",
    TRAINING_CONFIG_DIGEST,
    developmentSnapshots,
  );
  const projection = categoryProjection(
    developmentSnapshots.map(({ t2 }) => directName(t2)),
    (_, index) => [index < 50 ? 1 : 2],
  );
  const preregistration = pairedPreregistration(projection);
  const boundary = pairedDevelopmentBoundary(
    developmentArtifact,
    projection,
    preregistration,
  );
  const development = calibrateShadowPairedDevelopment(
    developmentArtifact,
    boundary.source,
    projection,
    preregistration,
    boundary.manifest,
    boundary.sealedHoldoutManifest,
    boundary.options,
  );
  assert.ok(development.candidate);

  const holdoutSnapshots = Object.freeze(developmentSnapshots.map((item, index) =>
    Object.freeze({
      ...item,
      runId: HOLDOUT_RUN_ID,
      domain: holdoutDomain(index),
    })));
  const holdoutArtifact = artifact(
    HOLDOUT_RUN_ID,
    "0.1.8",
    TRAINING_CONFIG_DIGEST,
    holdoutSnapshots,
  );
  const h1Manifest = boundary.sealedHoldoutManifest;
  const candidateDigest = digestShadowPairedFrozenCandidate(
    development.candidate,
  );
  const options = {
    candidateDigest,
    preregistrationDigest: digestShadowPairedPreregistration(preregistration),
    cohortManifestDigest: digestShadowPairedCohortManifest(h1Manifest),
  };
  const baseline = evaluateFrozenShadowPairedCandidate(
    holdoutArtifact,
    projection,
    preregistration,
    h1Manifest,
    development.candidate,
    options,
  );
  const changedSnapshots = holdoutSnapshots.map((item, index) => Object.freeze({
    ...item,
    full: Object.freeze({
      directNames: Object.freeze([`Changed-${String(index).padStart(3, "0")}`]),
      inferredNames: Object.freeze(["Changed-inferred"]),
      status: "failed" as const,
    }),
    fullCost: cost(50_000 + index),
    browserLimitHits: Object.freeze([]),
  }));
  const changed = evaluateFrozenShadowPairedCandidate(
    artifact(
      HOLDOUT_RUN_ID,
      "0.1.8",
      TRAINING_CONFIG_DIGEST,
      changedSnapshots,
    ),
    projection,
    preregistration,
    h1Manifest,
    development.candidate,
    options,
  );
  assert.equal(baseline.candidateDigest, candidateDigest);
  assert.equal(
    development.candidate.trainingCohort.sealedHoldoutManifestDigest,
    options.cohortManifestDigest,
  );
  assert.equal(baseline.featureSet, SHADOW_CATEGORY_FEATURE_SET);
  assert.deepEqual(changed.evaluation.predictions, baseline.evaluation.predictions);
  assert.deepEqual(
    changed.evaluation.deployable.selected,
    baseline.evaluation.deployable.selected,
  );
  assert.notDeepEqual(
    changed.evaluation.deployable.metrics,
    baseline.evaluation.deployable.metrics,
  );
  const missingProjection = categoryProjection(
    developmentSnapshots.slice(1).map(({ t2 }) => directName(t2)),
    (_, index) => [index < 49 ? 1 : 2],
  );
  assert.throws(
    () => evaluateFrozenShadowPairedCandidate(
      holdoutArtifact,
      missingProjection,
      preregistration,
      h1Manifest,
      development.candidate,
      options,
    ),
    /incompatible/u,
  );
});

test("paired calibration returns NO-GO when neither arm is eligible", () => {
  const inputSnapshots = Object.freeze(Array.from(
    { length: SHADOW_EVALUATION_DOMAIN_COUNT },
    (_, index) => pairedFeatureSnapshot(index, index < 50 ? "high" : "low"),
  ));
  const inputArtifact = artifact(
    TRAINING_RUN_ID,
    "0.1.8",
    TRAINING_CONFIG_DIGEST,
    inputSnapshots,
  );
  const projection = categoryProjection(
    inputSnapshots.map(({ t2 }) => directName(t2)),
    () => [1],
  );
  const preregistration = pairedPreregistration(projection);
  const boundary = pairedDevelopmentBoundary(
    inputArtifact,
    projection,
    preregistration,
  );
  const result = calibrateShadowPairedDevelopment(
    inputArtifact,
    boundary.source,
    projection,
    preregistration,
    boundary.manifest,
    boundary.sealedHoldoutManifest,
    boundary.options,
  );
  assert.equal(result.baseline.deployable.provisionalGuardrails.passed, false);
  assert.equal(result.categoryFoldWins, 0);
  assert.deepEqual(result.decision, {
    selectedFeatureSet: null,
    reason: "no-arm-eligible",
  });
  assert.equal(result.candidate, null);
});
