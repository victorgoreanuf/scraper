import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  link,
  lstat,
  mkdtemp,
  readFile,
  realpath,
  readdir,
  rm,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  SHADOW_BASELINE_FEATURE_SET,
  SHADOW_CALIBRATION_SALTS,
  SHADOW_CATEGORY_FEATURE_SET,
  SHADOW_CATEGORY_FOLD_WIN_MINIMUM,
  SHADOW_PAIRED_COHORT_SALT,
  SHADOW_PAIRED_EXPERIMENT_REVISION,
  calibrateShadowDevelopmentSource,
  createShadowPairedDevelopmentSource,
  canonicalizeShadowPairedCohortManifest,
  canonicalizeShadowPairedFrozenCandidate,
  canonicalizeShadowPairedPreregistration,
  canonicalizeShadowFrozenCandidate,
  digestShadowPairedCohortManifest,
  digestShadowPairedFrozenCandidate,
  digestShadowPairedPreregistration,
  digestShadowT2CategoryProjection,
  digestShadowFrozenCandidate,
  SHADOW_MODEL_RECURRING_TARGET_CAP,
  SHADOW_MODEL_TOKEN_CAP,
  type ShadowDevelopmentCalibrationReport,
  type ShadowDevelopmentSourceReport,
  type ShadowFrozenCandidate,
  type ShadowPairedCohortManifest,
  type ShadowPairedDevelopmentReport,
  type ShadowPairedFrozenCandidate,
  type ShadowPairedPreregistration,
  type ShadowT2CategoryProjection,
} from "../src/evaluation-calibration.ts";
import type { CompiledFingerprintCatalog } from "../src/detect/catalog.ts";
import { computeDomainSetDigest } from "../src/domain-set.ts";
import {
  createShadowEvaluationAccumulator,
  SHADOW_EVALUATION_DOMAIN_COUNT,
  SHADOW_EVALUATION_IDENTITY_VALUE_CAP,
  SHADOW_EVALUATION_PROTOCOL_REVISION,
  type ShadowEvaluationArtifact,
  type ShadowEvaluationSnapshot,
} from "../src/evaluation.ts";
import {
  EvaluationWriterError,
  calibratePinnedShadowPairedDevelopment,
  preflightShadowCandidateOutput,
  preflightShadowEvaluationOutput,
  preflightShadowPairedReportOutput,
  readPinnedShadowCandidate,
  readPinnedShadowFrozenCandidate,
  readPinnedShadowDevelopmentArtifact,
  readPinnedShadowInputFile,
  readPinnedShadowPairedCohortManifest,
  readPinnedShadowPairedFrozenCandidate,
  readPinnedShadowPairedPreregistration,
  SHADOW_EVALUATION_ARTIFACT_BYTES,
  writeShadowFrozenCandidateArtifact,
  writeShadowEvaluationArtifact,
  writeShadowPairedDevelopmentReport,
  writeShadowPairedFrozenCandidateArtifact,
} from "../src/output/evaluation-writer.ts";
import type { Provenance } from "../src/model.ts";

const RUN_ID = "12345678-1234-4123-8123-123456789abc";
const TRAINING_RUN_ID = "87654321-4321-4321-8321-cba987654321";
const DISCOVERY_DOMAINS = Object.freeze(Array.from(
  { length: SHADOW_EVALUATION_DOMAIN_COUNT },
  (_, index) => `training-${String(index).padStart(3, "0")}.vendor.com`,
));
const TRAINING_DOMAIN_SET_DIGEST = computeDomainSetDigest(DISCOVERY_DOMAINS);

const provenance: Provenance = Object.freeze({
  scannerVersion: "0.1.5",
  runtime: Object.freeze({
    node: "24.19.0",
    playwright: "1.62.1",
    chromiumRevision: "1234",
  }),
  catalog: Object.freeze({
    source: "fixture-catalog",
    revision: "fixture-v1",
    digest: `sha256:${"a".repeat(64)}`,
  }),
  configDigest: `sha256:${"b".repeat(64)}`,
});

function snapshot(index: number): ShadowEvaluationSnapshot {
  const detectorView = Object.freeze({
    state: "available" as const,
    directNames: Object.freeze([]),
    inferredNames: Object.freeze([]),
    detectionStats: Object.freeze({
      rawDirect: 0,
      gatedDirect: 0,
      suppressedDirect: 0,
      retainedDirect: 0,
    }),
    completed: true,
    errors: Object.freeze([]),
  });
  return Object.freeze({
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    runId: RUN_ID,
    domain: `domain-${String(index).padStart(3, "0")}.vendor.com`,
    t1: detectorView,
    t2: detectorView,
    preBrowser: Object.freeze({
      entryOutcome: "failed" as const,
      entryStatusClass: null,
      entryHtmlBytes: 0,
      entryTextCodePoints: 0,
      staticNavigationLinks: 0,
      metadataEntries: 0,
      resourceEntries: 0,
      dnsRecords: 0,
      tlsIssuerPresent: false,
      t2Selected: false,
      t2Role: null,
      t2Outcome: "not-selected" as const,
      probesObserved: 0,
      httpRequests: 0,
      staticTransferredBytes: 0,
    }),
    full: Object.freeze({
      directNames: Object.freeze([]),
      inferredNames: Object.freeze([]),
      status: "failed" as const,
    }),
    fullCost: Object.freeze({
      browserPagesAttempted: 0,
      browserPagesAdmitted: 0,
      browserRequests: 0,
      browserTransferredBytes: 0,
      browserMs: 0,
    }),
    browserLimitHits: Object.freeze([]),
  });
}

function evaluationArtifact(): ShadowEvaluationArtifact {
  const accumulator = createShadowEvaluationAccumulator({ runId: RUN_ID, provenance });
  for (let index = 0; index < SHADOW_EVALUATION_DOMAIN_COUNT; index += 1) {
    accumulator.add(snapshot(index));
  }
  return accumulator.build(SHADOW_EVALUATION_DOMAIN_COUNT);
}

function passingPairedArtifact(): ShadowEvaluationArtifact {
  const accumulator = createShadowEvaluationAccumulator({ runId: RUN_ID, provenance });
  for (let index = 0; index < SHADOW_EVALUATION_DOMAIN_COUNT; index += 1) {
    const base = snapshot(index);
    const detectorView = Object.freeze({
      state: "available" as const,
      directNames: Object.freeze(["Fixture Technology"]),
      inferredNames: Object.freeze([]),
      detectionStats: Object.freeze({
        rawDirect: 1,
        gatedDirect: 0,
        suppressedDirect: 0,
        retainedDirect: 1,
      }),
      completed: true,
      errors: Object.freeze([]),
    });
    accumulator.add(Object.freeze({
      ...base,
      t1: detectorView,
      t2: detectorView,
      full: Object.freeze({
        directNames: Object.freeze(["Fixture Technology"]),
        inferredNames: Object.freeze([]),
        status: "success" as const,
      }),
      fullCost: Object.freeze({
        browserPagesAttempted: 1,
        browserPagesAdmitted: 1,
        browserRequests: 1,
        browserTransferredBytes: 1_000,
        browserMs: 10,
      }),
    }));
  }
  return accumulator.build(SHADOW_EVALUATION_DOMAIN_COUNT);
}

function identityCapArtifact(): ShadowEvaluationArtifact {
  const identitiesPerSnapshot =
    SHADOW_EVALUATION_IDENTITY_VALUE_CAP / SHADOW_EVALUATION_DOMAIN_COUNT;
  assert.equal(Number.isSafeInteger(identitiesPerSnapshot), true);
  const directNameCount = identitiesPerSnapshot - 1;
  const accumulator = createShadowEvaluationAccumulator({ runId: RUN_ID, provenance });
  for (let index = 0; index < SHADOW_EVALUATION_DOMAIN_COUNT; index += 1) {
    const base = snapshot(index);
    const directNames = Object.freeze(Array.from(
      { length: directNameCount },
      (_, nameIndex) =>
        `t2-${String(index).padStart(3, "0")}-${String(nameIndex).padStart(3, "0")}`,
    ));
    accumulator.add(Object.freeze({
      ...base,
      t2: Object.freeze({
        state: "available" as const,
        directNames,
        inferredNames: Object.freeze([]),
        detectionStats: Object.freeze({
          rawDirect: directNameCount,
          gatedDirect: 0,
          suppressedDirect: 0,
          retainedDirect: directNameCount,
        }),
        completed: true,
        errors: Object.freeze([]),
      }),
      full: Object.freeze({
        directNames: Object.freeze([]),
        inferredNames: Object.freeze([]),
        status: "success" as const,
      }),
    }));
  }
  return accumulator.build(SHADOW_EVALUATION_DOMAIN_COUNT);
}

const artifact = evaluationArtifact();
const publishedArtifact = Object.freeze({
  ...artifact,
  calibration: calibrateShadowDevelopmentSource(artifact),
});

function digest(bytes: string | Buffer): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

const pairedProjection: ShadowT2CategoryProjection = Object.freeze({
  catalog: provenance.catalog,
  technologies: Object.freeze([
    Object.freeze({ name: "Fixture Technology", categoryIds: Object.freeze([7]) }),
  ]),
});

const pairedCatalog = {
  source: provenance.catalog.source,
  revision: provenance.catalog.revision,
  digest: provenance.catalog.digest,
  technologies: [{
    name: "Fixture Technology",
    categories: [{ id: 7 }],
  }],
} as unknown as CompiledFingerprintCatalog;

function pairedPreregistration(): ShadowPairedPreregistration {
  return Object.freeze({
    schemaVersion: 1 as const,
    experimentRevision: SHADOW_PAIRED_EXPERIMENT_REVISION,
    baselineImplementationCommit: "67890e61a16d74eb5bfade6d789f968fc2e1eee7",
    discoveryArtifactDigest: `sha256:${"1".repeat(64)}`,
    discoveryDomainSetDigest: TRAINING_DOMAIN_SET_DIGEST,
    discoveryScannerVersion: "0.1.5" as const,
    expectedDevelopmentScannerVersion: provenance.scannerVersion,
    expectedDevelopmentConfigDigest: provenance.configDigest,
    catalog: provenance.catalog,
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    categoryProjectionDigest: digestShadowT2CategoryProjection(pairedProjection),
    categoryFeature: Object.freeze({
      source: "t2.directNames" as const,
      mapping: "effective-catalog-category-ids" as const,
      token: "t2.directCategoryId=<decimal>" as const,
      aggregation: "sorted-unique-union" as const,
      missing: "reject" as const,
      forbiddenInputs: Object.freeze([
        "t1",
        "inferred",
        "full",
        "count",
        "category-name",
        "category-group",
      ] as const),
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
    featureSets: Object.freeze([
      SHADOW_BASELINE_FEATURE_SET,
      SHADOW_CATEGORY_FEATURE_SET,
    ] as const),
    foldCount: 5 as const,
    triggerDomainCount: 38 as const,
    controlDomainCount: 2 as const,
    smoothingPrior: 4 as const,
    recurringNameMinimumSupport: 2 as const,
    salts: SHADOW_CALIBRATION_SALTS,
    guardrails: Object.freeze({
      canonicalDirectNameRetentionMinimum: 0.95 as const,
      domainTechnologyPairRetentionMinimum: 0.8 as const,
      realBrowserCostMaximum: 0.3 as const,
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

function pairedManifest(
  role: ShadowPairedCohortManifest["role"],
  preregistrationDigest: string,
  cohortDomains: readonly string[],
  d2Domains: readonly string[] = [],
  fileDigest = `sha256:${"2".repeat(64)}`,
  sealedHoldoutManifestDigest = `sha256:${"5".repeat(64)}`,
): ShadowPairedCohortManifest {
  const zeroOverlapWith = role === "development"
    ? [Object.freeze({
        label: "D1",
        domainSetDigest: TRAINING_DOMAIN_SET_DIGEST,
        domains: DISCOVERY_DOMAINS,
      })]
    : [
        Object.freeze({
          label: "D1",
          domainSetDigest: TRAINING_DOMAIN_SET_DIGEST,
          domains: DISCOVERY_DOMAINS,
        }),
        Object.freeze({
          label: "D2",
          domainSetDigest: computeDomainSetDigest(d2Domains),
          domains: Object.freeze([...d2Domains]),
        }),
      ];
  const base = Object.freeze({
    schemaVersion: 1 as const,
    experimentRevision: SHADOW_PAIRED_EXPERIMENT_REVISION,
    preregistrationDigest,
    input: Object.freeze({
      fileDigest,
      domainSetDigest: computeDomainSetDigest(cohortDomains),
      domains: SHADOW_EVALUATION_DOMAIN_COUNT,
    }),
    expected: Object.freeze({
      scannerVersion: provenance.scannerVersion,
      configDigest: provenance.configDigest,
      catalog: provenance.catalog,
      schemaVersion: 1 as const,
      protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    }),
    source: Object.freeze({
      name: "CrUX",
      revision: "202607",
      digest: `sha256:${"3".repeat(64)}`,
    }),
    sampling: Object.freeze({
      revision: "sha256-rank-without-replacement-v1" as const,
      salt: SHADOW_PAIRED_COHORT_SALT,
    }),
    zeroOverlapWith: Object.freeze(zeroOverlapWith),
  });
  return role === "development"
    ? Object.freeze({
        ...base,
        role: "development" as const,
        sealedHoldoutManifestDigest,
      })
    : Object.freeze({ ...base, role: "holdout" as const });
}

function pairedCandidate(
  preregistration: ShadowPairedPreregistration,
  manifest: ShadowPairedCohortManifest,
  model: ShadowFrozenCandidate = frozenCandidate(),
): ShadowPairedFrozenCandidate {
  return Object.freeze({
    kind: "paired-shadow-trigger-v1" as const,
    experimentRevision: SHADOW_PAIRED_EXPERIMENT_REVISION,
    featureSet: SHADOW_BASELINE_FEATURE_SET,
    preregistrationDigest: digestShadowPairedPreregistration(preregistration),
    trainingCohort: Object.freeze({
      manifestDigest: digestShadowPairedCohortManifest(manifest),
      sealedHoldoutManifestDigest: manifest.role === "development"
        ? manifest.sealedHoldoutManifestDigest
        : `sha256:${"5".repeat(64)}`,
      source: manifest.source,
      sampling: manifest.sampling,
    }),
    categoryProjectionDigest: preregistration.categoryProjectionDigest,
    model,
  });
}

function frozenCandidate(
  tokens: ShadowFrozenCandidate["tokens"] = Object.freeze([]),
): ShadowFrozenCandidate {
  return Object.freeze({
    kind: "bounded-multiobjective-trigger-v2" as const,
    calibrationRevision: "2026-08-20.2" as const,
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    trainingDomains: SHADOW_EVALUATION_DOMAIN_COUNT,
    objectives: Object.freeze({
      canonicalDirectNameRetentionMinimum: 0.95 as const,
      domainTechnologyPairRetentionMinimum: 0.8 as const,
    }),
    recurringNameMinimumSupport: 2 as const,
    trainingIncrementalPairLift: 6,
    trainingRareSingletonLift: 0,
    globalMeanIncrementalPairLift: 6 / SHADOW_EVALUATION_DOMAIN_COUNT,
    globalMeanRareSingletonLift: 0,
    smoothingPrior: 4 as const,
    trainingIdentity: Object.freeze({
      artifactDigest: `sha256:${"c".repeat(64)}`,
      domainSetDigest: TRAINING_DOMAIN_SET_DIGEST,
      schemaVersion: 1 as const,
      protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
      runId: TRAINING_RUN_ID,
      provenance,
    }),
    evaluationCompatibility: Object.freeze({
      schemaVersion: 1 as const,
      protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
      scannerVersion: provenance.scannerVersion,
      catalog: provenance.catalog,
      configDigest: provenance.configDigest,
    }),
    trainingObjectives: Object.freeze({
      fullPairs: 6,
      baselineRetainedPairs: 0,
      pairDeficit: 5,
      fullCanonicalNames: 3,
      baselineRetainedNames: 0,
      nameDeficit: 3,
    }),
    recurringNames: Object.freeze([
      Object.freeze({ name: "Recurring A", support: 2 }),
      Object.freeze({ name: "Recurring B", support: 2 }),
      Object.freeze({ name: "Recurring C", support: 2 }),
    ]),
    tokens,
  });
}

function developmentReport(
  candidate: ShadowFrozenCandidate | null,
  passed: boolean,
): ShadowDevelopmentCalibrationReport {
  const cost = { passed };
  return {
    candidate,
    deployable: {
      provisionalGuardrails: {
        passed,
        canonicalDirectNames: { passed },
        domainTechnologyPairs: { passed },
        routedDomains: { passed },
        realBrowserCosts: {
          passed,
          browserPagesAttempted: cost,
          browserPagesAdmitted: cost,
          browserRequests: cost,
          browserTransferredBytes: cost,
          browserMs: cost,
        },
      },
    },
  } as unknown as ShadowDevelopmentCalibrationReport;
}

async function expectEvaluationError(
  promise: Promise<unknown>,
  code: EvaluationWriterError["code"],
): Promise<void> {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof EvaluationWriterError);
    assert.equal(error.code, code);
    return true;
  });
}

test("derives the canonical sidecar name and publishes compact JSON atomically", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-evaluation-writer-"));
  t.after(() => rm(directory, { recursive: true, force: true }));

  const prepared = await preflightShadowEvaluationOutput({
    resultPath: join(directory, "cohort.jsonl"),
  });
  assert.equal(
    prepared.evaluationPath,
    join(prepared.parentPath, "cohort.evaluation.json"),
  );

  await writeShadowEvaluationArtifact(prepared, artifact);
  const bytes = await readFile(prepared.evaluationPath);
  assert.equal(bytes.toString("utf8"), `${JSON.stringify(publishedArtifact)}\n`);
  assert.equal((await lstat(prepared.evaluationPath)).mode & 0o777, 0o600);
  assert.deepEqual(
    (await readdir(directory)).sort(),
    ["cohort.evaluation.json"],
  );

  const appended = await preflightShadowEvaluationOutput({
    resultPath: join(directory, "cohort.data"),
  });
  assert.equal(
    appended.evaluationPath,
    join(appended.parentPath, "cohort.data.evaluation.json"),
  );
});

test("reads a canonical development sidecar only through its exact pinned digest", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-evaluation-source-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const sourcePath = join(directory, "development.evaluation.json");
  const wire = `${JSON.stringify(publishedArtifact)}\n`;
  await writeFile(sourcePath, wire, { encoding: "utf8", mode: 0o600 });

  const loaded = await readPinnedShadowDevelopmentArtifact(
    sourcePath,
    digest(wire),
  );
  assert.deepEqual(loaded.artifact, artifact);
  assert.equal(loaded.sourcePath, await realpath(sourcePath));
  assert.equal(loaded.digest, digest(wire));

  await expectEvaluationError(
    readPinnedShadowDevelopmentArtifact(
      sourcePath,
      `sha256:${"0".repeat(64)}`,
    ),
    "EVALUATION_DIGEST_MISMATCH",
  );

  const symlinkPath = join(directory, "development-link.json");
  await symlink(sourcePath, symlinkPath);
  await expectEvaluationError(
    readPinnedShadowDevelopmentArtifact(symlinkPath, digest(wire)),
    "EVALUATION_SOURCE_INVALID",
  );

  const invalidUtf8Path = join(directory, "invalid-utf8.json");
  const invalidUtf8 = Buffer.from([0xc3, 0x28]);
  await writeFile(invalidUtf8Path, invalidUtf8, { mode: 0o600 });
  await expectEvaluationError(
    readPinnedShadowDevelopmentArtifact(invalidUtf8Path, digest(invalidUtf8)),
    "EVALUATION_SOURCE_INVALID",
  );

  const hardlinkPath = join(directory, "development-hardlink.json");
  await link(sourcePath, hardlinkPath);
  await expectEvaluationError(
    readPinnedShadowDevelopmentArtifact(hardlinkPath, digest(wire)),
    "EVALUATION_SOURCE_INVALID",
  );
});

test("keeps historical legacy development calibration opaque", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-legacy-source-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const sourcePath = join(directory, "legacy.evaluation.json");
  const historical = Object.freeze({
    ...artifact,
    calibration: Object.freeze({
      mode: "development-source",
      calibrationRevision: "historical-v0.1.5",
      legacyMetric: 17,
    }),
  });
  const wire = `${JSON.stringify(historical)}\n`;
  await writeFile(sourcePath, wire, { encoding: "utf8", mode: 0o600 });

  const loaded = await readPinnedShadowDevelopmentArtifact(
    sourcePath,
    digest(wire),
  );
  assert.deepEqual(loaded.artifact, artifact);
  assert.equal(loaded.pairedDevelopmentSource, null);
  assert.equal(loaded.digest, digest(wire));
});

test("reads every paired source only as canonical digest-pinned bytes", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-paired-sources-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const preregistration = pairedPreregistration();
  const preregistrationWire = canonicalizeShadowPairedPreregistration(
    preregistration,
  );
  assert.equal(preregistrationWire.endsWith("\n"), true);
  const preregistrationPath = join(directory, "paired.preregistration.json");
  await writeFile(preregistrationPath, preregistrationWire, { mode: 0o600 });
  const loadedPreregistration = await readPinnedShadowPairedPreregistration(
    preregistrationPath,
    digestShadowPairedPreregistration(preregistration),
  );
  assert.deepEqual(loadedPreregistration.preregistration, preregistration);

  const cohortDomains = artifact.snapshots.map(({ domain }) => domain);
  const manifest = pairedManifest(
    "development",
    loadedPreregistration.digest,
    cohortDomains,
  );
  const manifestWire = canonicalizeShadowPairedCohortManifest(manifest);
  assert.equal(manifestWire.endsWith("\n"), true);
  const manifestPath = join(directory, "paired.manifest.json");
  await writeFile(manifestPath, manifestWire, { mode: 0o600 });
  const loadedManifest = await readPinnedShadowPairedCohortManifest(
    manifestPath,
    digestShadowPairedCohortManifest(manifest),
  );
  assert.deepEqual(loadedManifest.manifest, manifest);

  const candidate = pairedCandidate(preregistration, manifest);
  const candidateWire = canonicalizeShadowPairedFrozenCandidate(candidate);
  assert.equal(candidateWire.endsWith("\n"), true);
  const candidatePath = join(directory, "paired.candidate.json");
  await writeFile(candidatePath, candidateWire, { mode: 0o600 });
  const loadedCandidate = await readPinnedShadowPairedFrozenCandidate(
    candidatePath,
    digestShadowPairedFrozenCandidate(candidate),
  );
  assert.deepEqual(loadedCandidate.candidate, candidate);
  assert.equal(
    (await readPinnedShadowCandidate(candidatePath, loadedCandidate.digest)).kind,
    "paired",
  );

  const legacy = frozenCandidate();
  const legacyWire = canonicalizeShadowFrozenCandidate(legacy);
  assert.equal(legacyWire.endsWith("\n"), false);
  const legacyPath = join(directory, "legacy.candidate.json");
  await writeFile(legacyPath, legacyWire, { mode: 0o600 });
  assert.equal(
    (await readPinnedShadowCandidate(
      legacyPath,
      digestShadowFrozenCandidate(legacy),
    )).kind,
    "legacy",
  );

  const inputPath = join(directory, "cohort.parquet");
  const inputBytes = Buffer.from("bounded-cohort-input", "utf8");
  await writeFile(inputPath, inputBytes, { mode: 0o600 });
  const loadedInput = await readPinnedShadowInputFile(
    inputPath,
    digest(inputBytes),
  );
  assert.equal(loadedInput.sourcePath, await realpath(inputPath));
  await expectEvaluationError(
    readPinnedShadowInputFile(inputPath, `sha256:${"0".repeat(64)}`),
    "EVALUATION_DIGEST_MISMATCH",
  );
  const oversizedInputPath = join(directory, "oversized.parquet");
  await writeFile(oversizedInputPath, "", { mode: 0o600 });
  await truncate(
    oversizedInputPath,
    SHADOW_EVALUATION_ARTIFACT_BYTES + 1,
  );
  await expectEvaluationError(
    readPinnedShadowInputFile(
      oversizedInputPath,
      `sha256:${"0".repeat(64)}`,
    ),
    "EVALUATION_SOURCE_INVALID",
  );
});

test("runs the paired development evaluator only from pinned frozen inputs", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-paired-offline-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const developmentArtifact = passingPairedArtifact();
  const preregistration = pairedPreregistration();
  const preregistrationPath = join(directory, "paired.preregistration.json");
  await writeFile(
    preregistrationPath,
    canonicalizeShadowPairedPreregistration(preregistration),
    { mode: 0o600 },
  );
  const preregistrationDigest = digestShadowPairedPreregistration(
    preregistration,
  );
  const developmentDomains = developmentArtifact.snapshots.map(
    ({ domain }) => domain,
  );
  const holdoutDomains = Array.from(
    { length: SHADOW_EVALUATION_DOMAIN_COUNT },
    (_, index) => `holdout-${String(index).padStart(3, "0")}.vendor.com`,
  );
  const sealedHoldoutManifest = pairedManifest(
    "holdout",
    preregistrationDigest,
    holdoutDomains,
    developmentDomains,
  );
  const sealedHoldoutManifestDigest = digestShadowPairedCohortManifest(
    sealedHoldoutManifest,
  );
  const manifest = pairedManifest(
    "development",
    preregistrationDigest,
    developmentDomains,
    [],
    `sha256:${"2".repeat(64)}`,
    sealedHoldoutManifestDigest,
  );
  const manifestDigest = digestShadowPairedCohortManifest(manifest);
  const developmentPublished = Object.freeze({
    ...developmentArtifact,
    calibration: createShadowPairedDevelopmentSource(developmentArtifact, {
      preregistrationDigest,
      cohortManifestDigest: manifestDigest,
      sealedHoldoutManifestDigest,
      categoryProjectionDigest: preregistration.categoryProjectionDigest,
    }),
  });
  const sidecarPath = join(directory, "development.evaluation.json");
  const sidecarWire = `${JSON.stringify(developmentPublished)}\n`;
  await writeFile(sidecarPath, sidecarWire, { mode: 0o600 });
  const manifestPath = join(directory, "development.manifest.json");
  await writeFile(
    manifestPath,
    canonicalizeShadowPairedCohortManifest(manifest),
    { mode: 0o600 },
  );
  const sealedHoldoutManifestPath = join(directory, "holdout.manifest.json");
  await writeFile(
    sealedHoldoutManifestPath,
    canonicalizeShadowPairedCohortManifest(sealedHoldoutManifest),
    { mode: 0o600 },
  );

  const loaded = await calibratePinnedShadowPairedDevelopment({
    developmentArtifactPath: sidecarPath,
    developmentArtifactDigest: digest(sidecarWire),
    preregistrationPath,
    preregistrationDigest,
    cohortManifestPath: manifestPath,
    cohortManifestDigest: manifestDigest,
    sealedHoldoutManifestPath,
    sealedHoldoutManifestDigest,
    catalog: pairedCatalog,
  });
  assert.equal(loaded.report.mode, "paired-development-oof");
  assert.equal(loaded.report.trainingArtifactDigest, digest(sidecarWire));
  assert.equal(loaded.report.preregistrationDigest, preregistrationDigest);
  assert.equal(
    loaded.report.sealedHoldoutManifestDigest,
    sealedHoldoutManifestDigest,
  );
  assert.deepEqual(loaded.projection, pairedProjection);
  assert.notEqual(loaded.report.candidate, null);

  const swappedHoldoutManifest = pairedManifest(
    "holdout",
    preregistrationDigest,
    holdoutDomains.map((domain) => `swapped-${domain}`),
    developmentDomains,
  );
  const swappedHoldoutPath = join(directory, "swapped-holdout.manifest.json");
  await writeFile(
    swappedHoldoutPath,
    canonicalizeShadowPairedCohortManifest(swappedHoldoutManifest),
    { mode: 0o600 },
  );
  await expectEvaluationError(
    calibratePinnedShadowPairedDevelopment({
      developmentArtifactPath: sidecarPath,
      developmentArtifactDigest: digest(sidecarWire),
      preregistrationPath,
      preregistrationDigest,
      cohortManifestPath: manifestPath,
      cohortManifestDigest: manifestDigest,
      sealedHoldoutManifestPath: swappedHoldoutPath,
      sealedHoldoutManifestDigest: digestShadowPairedCohortManifest(
        swappedHoldoutManifest,
      ),
      catalog: pairedCatalog,
    }),
    "EVALUATION_INVALID_ARTIFACT",
  );

  const reportOutput = await preflightShadowPairedReportOutput({
    reportPath: join(directory, "paired.report.json"),
    sourcePaths: loaded.sourcePaths,
  });
  await writeShadowPairedDevelopmentReport(reportOutput, loaded.report);
  const reportWire = await readFile(reportOutput.reportPath, "utf8");
  assert.equal(reportWire.endsWith("\n"), true);
  assert.equal((await lstat(reportOutput.reportPath)).mode & 0o777, 0o600);

  const candidateOutput = await preflightShadowCandidateOutput({
    candidatePath: join(directory, "paired.candidate.json"),
    sourcePaths: loaded.sourcePaths,
  });
  const candidateDigest = await writeShadowPairedFrozenCandidateArtifact(
    candidateOutput,
    loaded.report,
  );
  assert.equal(
    candidateDigest,
    digestShadowPairedFrozenCandidate(loaded.report.candidate),
  );
  assert.equal(
    await readFile(candidateOutput.candidatePath, "utf8"),
    canonicalizeShadowPairedFrozenCandidate(loaded.report.candidate),
  );
});

test("preflight rejects collisions and every existing target shape", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-evaluation-preflight-"));
  t.after(() => rm(directory, { recursive: true, force: true }));

  const collisionResult = join(directory, "collision.jsonl");
  const collisionTarget = join(directory, "collision.evaluation.json");
  await expectEvaluationError(
    preflightShadowEvaluationOutput({
      resultPath: collisionResult,
      reservedPaths: [collisionTarget],
    }),
    "EVALUATION_PATH_COLLISION",
  );

  const existingResult = join(directory, "existing.jsonl");
  const existingTarget = join(directory, "existing.evaluation.json");
  await writeFile(existingTarget, "existing", { mode: 0o600 });
  await expectEvaluationError(
    preflightShadowEvaluationOutput({ resultPath: existingResult }),
    "EVALUATION_EXISTS",
  );

  const source = join(directory, "source");
  await writeFile(source, "source", { mode: 0o600 });
  const symlinkTarget = join(directory, "symlink.evaluation.json");
  await symlink(source, symlinkTarget);
  await expectEvaluationError(
    preflightShadowEvaluationOutput({
      resultPath: join(directory, "symlink.jsonl"),
    }),
    "EVALUATION_INVALID_TARGET",
  );

  const hardlinkTarget = join(directory, "hardlink.evaluation.json");
  await link(source, hardlinkTarget);
  await expectEvaluationError(
    preflightShadowEvaluationOutput({
      resultPath: join(directory, "hardlink.jsonl"),
    }),
    "EVALUATION_INVALID_TARGET",
  );
  assert.equal(await readFile(source, "utf8"), "source");
});

test("preflights a standalone candidate target as create-only and collision-free", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-candidate-preflight-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const candidatePath = join(directory, "trigger.candidate.json");

  const prepared = await preflightShadowCandidateOutput({ candidatePath });
  assert.equal(
    prepared.candidatePath,
    join(await realpath(directory), "trigger.candidate.json"),
  );

  await expectEvaluationError(
    preflightShadowCandidateOutput({
      candidatePath,
      sourcePaths: [candidatePath],
    }),
    "EVALUATION_PATH_COLLISION",
  );

  await writeFile(candidatePath, "existing", { mode: 0o600 });
  await expectEvaluationError(
    preflightShadowCandidateOutput({ candidatePath }),
    "EVALUATION_EXISTS",
  );
});

test("publishes and reloads only a canonical GO candidate with its exact digest", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-candidate-write-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const prepared = await preflightShadowCandidateOutput({
    candidatePath: join(directory, "trigger.candidate.json"),
  });
  const candidate = frozenCandidate();

  const candidateDigest = await writeShadowFrozenCandidateArtifact(
    prepared,
    developmentReport(candidate, true),
  );
  const wire = await readFile(prepared.candidatePath, "utf8");
  assert.equal(wire, canonicalizeShadowFrozenCandidate(candidate));
  assert.equal(candidateDigest, digestShadowFrozenCandidate(candidate));
  assert.equal(digest(wire), candidateDigest);
  assert.equal((await lstat(prepared.candidatePath)).mode & 0o777, 0o600);

  const loaded = await readPinnedShadowFrozenCandidate(
    prepared.candidatePath,
    candidateDigest,
  );
  assert.deepEqual(loaded.candidate, candidate);
  assert.equal(loaded.digest, candidateDigest);

  const nonCanonicalPath = join(directory, "non-canonical.candidate.json");
  const nonCanonicalWire = `${wire}\n`;
  await writeFile(nonCanonicalPath, nonCanonicalWire, { mode: 0o600 });
  await expectEvaluationError(
    readPinnedShadowFrozenCandidate(
      nonCanonicalPath,
      digest(nonCanonicalWire),
    ),
    "EVALUATION_SOURCE_INVALID",
  );
});

test("refuses candidate publication after a development NO-GO", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-candidate-no-go-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const prepared = await preflightShadowCandidateOutput({
    candidatePath: join(directory, "rejected.candidate.json"),
  });

  await expectEvaluationError(
    writeShadowFrozenCandidateArtifact(
      prepared,
      developmentReport(null, false),
    ),
    "EVALUATION_CANDIDATE_REJECTED",
  );
  await assert.rejects(lstat(prepared.candidatePath), { code: "ENOENT" });
  const inconsistentPrepared = await preflightShadowCandidateOutput({
    candidatePath: join(directory, "cost-rejected.candidate.json"),
  });
  const inconsistent = developmentReport(frozenCandidate(), true);
  const rejectedCost = {
    ...inconsistent,
    deployable: {
      ...inconsistent.deployable,
      provisionalGuardrails: {
        ...inconsistent.deployable.provisionalGuardrails,
        realBrowserCosts: {
          ...inconsistent.deployable.provisionalGuardrails.realBrowserCosts,
          browserMs: {
            ...inconsistent.deployable.provisionalGuardrails.realBrowserCosts.browserMs,
            passed: false,
          },
        },
      },
    },
  } as ShadowDevelopmentCalibrationReport;
  await expectEvaluationError(
    writeShadowFrozenCandidateArtifact(inconsistentPrepared, rejectedCost),
    "EVALUATION_CANDIDATE_REJECTED",
  );
  await assert.rejects(lstat(inconsistentPrepared.candidatePath), {
    code: "ENOENT",
  });
  assert.deepEqual(await readdir(directory), []);
});

test("rejects paired candidate reports not produced by the pinned evaluator", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-paired-candidate-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const preregistration = pairedPreregistration();
  const manifest = pairedManifest(
    "development",
    digestShadowPairedPreregistration(preregistration),
    artifact.snapshots.map(({ domain }) => domain),
  );
  const candidate = pairedCandidate(preregistration, manifest);
  const passingArm = developmentReport(
    frozenCandidate(),
    true,
  ) as unknown as ShadowDevelopmentSourceReport;
  const report: ShadowPairedDevelopmentReport = Object.freeze({
    mode: "paired-development-oof" as const,
    experimentRevision: SHADOW_PAIRED_EXPERIMENT_REVISION,
    preregistrationDigest: candidate.preregistrationDigest,
    cohortManifestDigest: candidate.trainingCohort.manifestDigest,
    sealedHoldoutManifestDigest:
      candidate.trainingCohort.sealedHoldoutManifestDigest,
    categoryProjectionDigest: candidate.categoryProjectionDigest,
    trainingArtifactDigest: `sha256:${"4".repeat(64)}`,
    baseline: passingArm,
    category: passingArm,
    foldComparisons: Object.freeze([]),
    categoryFoldWins: 0,
    decision: Object.freeze({
      selectedFeatureSet: SHADOW_BASELINE_FEATURE_SET,
      reason: "baseline-passed-all-official-gates" as const,
    }),
    candidate,
  });
  const prepared = await preflightShadowCandidateOutput({
    candidatePath: join(directory, "paired.candidate.json"),
  });
  await expectEvaluationError(
    writeShadowPairedFrozenCandidateArtifact(prepared, report),
    "EVALUATION_INVALID_ARTIFACT",
  );
  await assert.rejects(lstat(prepared.candidatePath), { code: "ENOENT" });
});

test("frozen holdout membership is independent of full labels and browser costs", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-holdout-label-blind-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const candidate = frozenCandidate();
  const candidateDigest = digestShadowFrozenCandidate(candidate);
  const mutated = Object.freeze({
    ...artifact,
    snapshots: Object.freeze(artifact.snapshots.map((value, index) => Object.freeze({
      ...value,
      full: Object.freeze({
        directNames: Object.freeze([`Browser label ${String(index).padStart(3, "0")}`]),
        inferredNames: Object.freeze([]),
        status: "success" as const,
      }),
      fullCost: Object.freeze({
        browserPagesAttempted: index + 1,
        browserPagesAdmitted: index,
        browserRequests: (index + 1) * 10,
        browserTransferredBytes: (index + 1) * 1_000,
        browserMs: (index + 1) * 100,
      }),
    }))),
  });
  const selectedSets: string[][] = [];
  for (const [name, value] of [
    ["original", artifact],
    ["mutated", mutated],
  ] as const) {
    const prepared = await preflightShadowEvaluationOutput({
      resultPath: join(directory, `${name}.jsonl`),
    });
    await writeShadowEvaluationArtifact(prepared, value, {
      frozenCandidate: candidate,
      candidateDigest,
    });
    const published = JSON.parse(await readFile(
      prepared.evaluationPath,
      "utf8",
    )) as {
      readonly calibration: {
        readonly mode: string;
        readonly deployable: {
          readonly selected: readonly { readonly domain: string }[];
        };
      };
    };
    assert.equal(published.calibration.mode, "frozen-holdout");
    selectedSets.push(published.calibration.deployable.selected.map(
      ({ domain }) => domain,
    ));
  }
  assert.deepEqual(selectedSets[0], selectedSets[1]);
});

test("publishes the maximum bounded candidate and rejects one extra token atomically", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-candidate-cap-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const targetsPerToken = Math.floor(
    SHADOW_MODEL_RECURRING_TARGET_CAP / SHADOW_MODEL_TOKEN_CAP,
  );
  const tokensWithExtraTarget = SHADOW_MODEL_RECURRING_TARGET_CAP
    - (targetsPerToken * SHADOW_MODEL_TOKEN_CAP);
  const tokens = Object.freeze(Array.from(
    { length: SHADOW_MODEL_TOKEN_CAP },
    (_, index) => {
      const targetCount = targetsPerToken
        + (index < tokensWithExtraTarget ? 1 : 0);
      return Object.freeze({
        token: `feature-${String(index).padStart(5, "0")}`,
        domains: 1,
        pairTargetSum: targetCount,
        rareTargetSum: 0,
        recurringTargetSums: Object.freeze(Array.from(
          { length: targetCount },
          (__, head) => Object.freeze({ head, targetSum: 1 }),
        )),
      });
    },
  ));
  assert.equal(
    tokens.reduce((sum, token) => sum + token.recurringTargetSums.length, 0),
    SHADOW_MODEL_RECURRING_TARGET_CAP,
  );
  const candidate = frozenCandidate(tokens);
  const accepted = await preflightShadowCandidateOutput({
    candidatePath: join(directory, "accepted.candidate.json"),
  });
  await writeShadowFrozenCandidateArtifact(
    accepted,
    developmentReport(candidate, true),
  );
  assert.equal((await lstat(accepted.candidatePath)).isFile(), true);

  const overflow = await preflightShadowCandidateOutput({
    candidatePath: join(directory, "overflow.candidate.json"),
  });
  const extraToken = Object.freeze({
    token: "feature-99999",
    domains: 1,
    pairTargetSum: 0,
    rareTargetSum: 0,
    recurringTargetSums: Object.freeze([]),
  });
  await expectEvaluationError(
    writeShadowFrozenCandidateArtifact(
      overflow,
      developmentReport(
        frozenCandidate(Object.freeze([...tokens, extraToken])),
        true,
      ),
    ),
    "EVALUATION_INVALID_ARTIFACT",
  );
  await assert.rejects(lstat(overflow.candidatePath), { code: "ENOENT" });
  assert.deepEqual(
    (await readdir(directory)).sort(),
    ["accepted.candidate.json"],
  );
});

test("publication is no-clobber and leaves no temporary file on failure", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-evaluation-race-"));
  t.after(() => rm(directory, { recursive: true, force: true }));

  const prepared = await preflightShadowEvaluationOutput({
    resultPath: join(directory, "cohort.jsonl"),
  });
  await writeFile(prepared.evaluationPath, "late collision", { mode: 0o600 });

  await expectEvaluationError(
    writeShadowEvaluationArtifact(prepared, artifact),
    "EVALUATION_EXISTS",
  );
  assert.equal(await readFile(prepared.evaluationPath, "utf8"), "late collision");
  assert.deepEqual(
    (await readdir(directory)).sort(),
    ["cohort.evaluation.json"],
  );
});

test("serialization failure leaves the preflight target absent", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-evaluation-invalid-"));
  t.after(() => rm(directory, { recursive: true, force: true }));

  const prepared = await preflightShadowEvaluationOutput({
    resultPath: join(directory, "cohort.jsonl"),
  });
  const cyclic: { self?: unknown } = {};
  cyclic.self = cyclic;
  await expectEvaluationError(
    writeShadowEvaluationArtifact(
      prepared,
      cyclic as unknown as ShadowEvaluationArtifact,
    ),
    "EVALUATION_INVALID_ARTIFACT",
  );
  await assert.rejects(lstat(prepared.evaluationPath), { code: "ENOENT" });
  assert.deepEqual(await readdir(directory), []);
});

test("rejects non-canonical nested fields before creating a temporary file", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-evaluation-context-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const prepared = await preflightShadowEvaluationOutput({
    resultPath: join(directory, "cohort.jsonl"),
  });
  const contaminated = Object.freeze({
    ...artifact,
    snapshots: Object.freeze([
      Object.freeze({
        ...artifact.snapshots[0]!,
        preBrowser: Object.freeze({
          ...artifact.snapshots[0]!.preBrowser!,
          rawHtml: "SUPER_SECRET_RAW_HTML",
        }),
      }),
      ...artifact.snapshots.slice(1),
    ]),
  });

  await expectEvaluationError(
    writeShadowEvaluationArtifact(
      prepared,
      contaminated as ShadowEvaluationArtifact,
    ),
    "EVALUATION_INVALID_ARTIFACT",
  );
  await assert.rejects(lstat(prepared.evaluationPath), { code: "ENOENT" });
  assert.deepEqual(await readdir(directory), []);
});

test("rejects the structural byte budget before JSON serialization", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-evaluation-limit-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const prepared = await preflightShadowEvaluationOutput({
    resultPath: join(directory, "cohort.jsonl"),
  });
  const oversized = Object.freeze({
    ...artifact,
    provenance: Object.freeze({
      ...artifact.provenance,
      catalog: Object.freeze({
        ...artifact.provenance.catalog,
        source: "x".repeat(
          Math.floor(SHADOW_EVALUATION_ARTIFACT_BYTES / 6) + 1,
        ),
      }),
    }),
  });

  await expectEvaluationError(
    writeShadowEvaluationArtifact(prepared, oversized),
    "EVALUATION_ARTIFACT_LIMIT",
  );
  await assert.rejects(lstat(prepared.evaluationPath), { code: "ENOENT" });
  assert.deepEqual(await readdir(directory), []);
});

test("publishes the worst-shaped identity-cap cohort and rejects cap overflow atomically", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-evaluation-identities-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const capped = identityCapArtifact();
  const accepted = await preflightShadowEvaluationOutput({
    resultPath: join(directory, "accepted.jsonl"),
  });

  await writeShadowEvaluationArtifact(accepted, capped);
  const published = JSON.parse(await readFile(accepted.evaluationPath, "utf8")) as {
    readonly snapshots: readonly unknown[];
    readonly calibration: {
      readonly mode: string;
      readonly model: {
        readonly folds: readonly { readonly featureTokenCount: number }[];
      };
    };
  };
  assert.equal(published.snapshots.length, SHADOW_EVALUATION_DOMAIN_COUNT);
  assert.equal(published.calibration.mode, "development-source");
  assert.equal(published.calibration.model.folds.length, 5);
  assert.ok(published.calibration.model.folds.every(
    ({ featureTokenCount }) => featureTokenCount > 0,
  ));

  const overflow = await preflightShadowEvaluationOutput({
    resultPath: join(directory, "overflow.jsonl"),
  });
  const first = capped.snapshots[0]!;
  if (first.t2.state !== "available") throw new Error("invalid fixture");
  const overflowNames = Object.freeze([...first.t2.directNames, "zz-over-cap"]);
  const oversized = Object.freeze({
    ...capped,
    snapshots: Object.freeze([
      Object.freeze({
        ...first,
        t2: Object.freeze({
          ...first.t2,
          directNames: overflowNames,
          detectionStats: Object.freeze({
            ...first.t2.detectionStats,
            rawDirect: first.t2.detectionStats.rawDirect + 1,
            retainedDirect: first.t2.detectionStats.retainedDirect + 1,
          }),
        }),
      }),
      ...capped.snapshots.slice(1),
    ]),
  });

  await expectEvaluationError(
    writeShadowEvaluationArtifact(overflow, oversized),
    "EVALUATION_INVALID_ARTIFACT",
  );
  await assert.rejects(lstat(overflow.evaluationPath), { code: "ENOENT" });
  assert.deepEqual(
    (await readdir(directory)).sort(),
    ["accepted.evaluation.json"],
  );
});
