import assert from "node:assert/strict";
import {
  link,
  lstat,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { calibrateShadowEvaluation } from "../src/evaluation-calibration.ts";
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
  preflightShadowEvaluationOutput,
  SHADOW_EVALUATION_ARTIFACT_BYTES,
  writeShadowEvaluationArtifact,
} from "../src/output/evaluation-writer.ts";
import type { Provenance } from "../src/model.ts";

const RUN_ID = "12345678-1234-4123-8123-123456789abc";

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
  calibration: calibrateShadowEvaluation(artifact.snapshots),
});

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
      readonly deploymentModel: { readonly tokens: readonly unknown[] };
    };
  };
  assert.equal(published.snapshots.length, SHADOW_EVALUATION_DOMAIN_COUNT);
  assert.ok(published.calibration.deploymentModel.tokens.length >= 19_600);

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
