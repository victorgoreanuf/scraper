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
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  calibrateShadowDevelopmentSource,
  canonicalizeShadowFrozenCandidate,
  digestShadowFrozenCandidate,
  SHADOW_MODEL_RECURRING_TARGET_CAP,
  SHADOW_MODEL_TOKEN_CAP,
  type ShadowDevelopmentCalibrationReport,
  type ShadowFrozenCandidate,
} from "../src/evaluation-calibration.ts";
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
  preflightShadowCandidateOutput,
  preflightShadowEvaluationOutput,
  readPinnedShadowFrozenCandidate,
  readPinnedShadowDevelopmentArtifact,
  SHADOW_EVALUATION_ARTIFACT_BYTES,
  writeShadowFrozenCandidateArtifact,
  writeShadowEvaluationArtifact,
} from "../src/output/evaluation-writer.ts";
import type { Provenance } from "../src/model.ts";

const RUN_ID = "12345678-1234-4123-8123-123456789abc";
const TRAINING_RUN_ID = "87654321-4321-4321-8321-cba987654321";
const TRAINING_DOMAIN_SET_DIGEST = computeDomainSetDigest(Array.from(
  { length: SHADOW_EVALUATION_DOMAIN_COUNT },
  (_, index) => `training-${String(index).padStart(3, "0")}.vendor.com`,
));

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
