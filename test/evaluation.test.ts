import assert from "node:assert/strict";
import test from "node:test";

import {
  createShadowEvaluationAccumulator,
  SHADOW_EVALUATION_DOMAIN_COUNT,
  SHADOW_EVALUATION_IDENTITY_VALUE_CAP,
  SHADOW_EVALUATION_PROTOCOL_REVISION,
  shadowDetectorView,
  type ShadowEvaluationSnapshot,
} from "../src/evaluation.ts";
import type { DetectHttpResult } from "../src/detect/engine.ts";
import type {
  DetectionStats,
  Provenance,
  ScanError,
  Technology,
} from "../src/model.ts";

const RUN_ID = "123e4567-e89b-42d3-a456-426614174000";
const detectionStats: DetectionStats = Object.freeze({
  rawDirect: 2,
  gatedDirect: 0,
  suppressedDirect: 0,
  retainedDirect: 2,
});
const provenance: Provenance = Object.freeze({
  scannerVersion: "0.1.5",
  runtime: Object.freeze({
    node: "24.19.0",
    playwright: "1.62.1",
    chromiumRevision: "1234",
  }),
  catalog: Object.freeze({
    source: "fixture/catalog",
    revision: "fixture-revision",
    digest: `sha256:${"a".repeat(64)}`,
  }),
  configDigest: `sha256:${"b".repeat(64)}`,
});

function technology(name: string, type: "direct" | "inferred"): Technology {
  return Object.freeze({
    name,
    categories: Object.freeze([]),
    version: null,
    confidence: 100,
    type,
    pageIds: Object.freeze([]),
    evidence: Object.freeze([]),
    inferredFrom: Object.freeze([]),
  });
}

function scanError(retryable: boolean): ScanError {
  return Object.freeze({
    stage: "detect",
    code: "REGEX_RULE_TIMEOUT",
    pageId: null,
    retryable,
    message: "not persisted in shadow telemetry",
    ruleId: "not-persisted",
    signal: "html",
    limit: "not-persisted",
    catalogRevision: "not-persisted",
  });
}

function snapshot(index: number): ShadowEvaluationSnapshot {
  const domain = `d${String(index).padStart(3, "0")}.vendor.com`;
  return Object.freeze({
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    runId: RUN_ID,
    domain,
    t1: Object.freeze({
      state: "available" as const,
      directNames: Object.freeze(["Alpha"]),
      inferredNames: Object.freeze([]),
      detectionStats,
      completed: true,
      errors: Object.freeze([]),
    }),
    t2: Object.freeze({
      state: "available" as const,
      directNames: Object.freeze(["Alpha", "Beta"]),
      inferredNames: Object.freeze([]),
      detectionStats,
      completed: true,
      errors: Object.freeze([]),
    }),
    preBrowser: Object.freeze({
      entryOutcome: "html" as const,
      entryStatusClass: "2xx" as const,
      entryHtmlBytes: 100,
      entryTextCodePoints: 20,
      staticNavigationLinks: 2,
      metadataEntries: 1,
      resourceEntries: 3,
      dnsRecords: 2,
      tlsIssuerPresent: true,
      t2Selected: true,
      t2Role: "detail" as const,
      t2Outcome: "html" as const,
      probesObserved: 1,
      httpRequests: 4,
      staticTransferredBytes: 1_024,
    }),
    full: Object.freeze({
      directNames: Object.freeze(["Alpha", "Beta", "Gamma"]),
      inferredNames: Object.freeze([]),
      status: "partial" as const,
    }),
    fullCost: Object.freeze({
      browserPagesAttempted: 2,
      browserPagesAdmitted: 2,
      browserRequests: 10,
      browserTransferredBytes: 2_048,
      browserMs: 25,
    }),
    browserLimitHits: index < 2
      ? Object.freeze([
          Object.freeze({
            pageId: "p1" as const,
            category: "inspection.domMatches" as const,
            domSelectorOrdinal: 7,
          }),
        ])
      : Object.freeze([]),
  });
}

function identityHeavySnapshot(
  index: number,
  directNameCount: number,
): ShadowEvaluationSnapshot {
  const base = snapshot(index);
  const directNames = Object.freeze(Array.from(
    { length: directNameCount },
    (_, nameIndex) =>
      `t2-${String(index).padStart(3, "0")}-${String(nameIndex).padStart(3, "0")}`,
  ));
  return Object.freeze({
    ...base,
    t1: Object.freeze({
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
    }),
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
    browserLimitHits: Object.freeze([]),
  });
}

test("shadow detector views retain only sorted identities and controlled errors", () => {
  const result: DetectHttpResult = Object.freeze({
    technologies: Object.freeze([
      technology("Zulu", "direct"),
      technology("Alpha", "inferred"),
      technology("Beta", "direct"),
      technology("Beta", "direct"),
    ]),
    detectionStats,
    errors: Object.freeze([
      scanError(true),
      scanError(false),
      scanError(true),
    ]),
    signalAdmitted: true,
    completed: false,
  });

  assert.deepEqual(shadowDetectorView(result), {
    state: "available",
    directNames: ["Beta", "Zulu"],
    inferredNames: ["Alpha"],
    detectionStats,
    completed: false,
    errors: [
      {
        stage: "detect",
        code: "REGEX_RULE_TIMEOUT",
        retryable: false,
        count: 1,
      },
      {
        stage: "detect",
        code: "REGEX_RULE_TIMEOUT",
        retryable: true,
        count: 2,
      },
    ],
  });
  assert.equal(JSON.stringify(shadowDetectorView(result)).includes("not-persisted"), false);
});

test("shadow accumulator is completion-order independent and aggregates limit hits", () => {
  const forward = createShadowEvaluationAccumulator({ runId: RUN_ID, provenance });
  const reverse = createShadowEvaluationAccumulator({ runId: RUN_ID, provenance });
  const snapshots = Array.from(
    { length: SHADOW_EVALUATION_DOMAIN_COUNT },
    (_, index) => snapshot(index),
  );
  for (const item of snapshots) forward.add(item);
  for (const item of [...snapshots].reverse()) reverse.add(item);

  const forwardArtifact = forward.build(SHADOW_EVALUATION_DOMAIN_COUNT);
  const reverseArtifact = reverse.build(SHADOW_EVALUATION_DOMAIN_COUNT);
  assert.equal(JSON.stringify(forwardArtifact), JSON.stringify(reverseArtifact));
  assert.deepEqual(forwardArtifact.browserLimitAggregates, [
    {
      category: "inspection.domMatches",
      domSelectorOrdinal: 7,
      affectedDomains: 2,
      affectedPages: 2,
      hits: 2,
    },
  ]);
  assert.equal(forwardArtifact.snapshots[0]?.domain, "d000.vendor.com");
  assert.equal(forwardArtifact.snapshots[199]?.domain, "d199.vendor.com");
});

test("shadow accumulator enforces the cohort, run identity, and duplicate keys", () => {
  const accumulator = createShadowEvaluationAccumulator({ runId: RUN_ID, provenance });
  const first = snapshot(0);
  accumulator.add(first);
  assert.throws(() => accumulator.add(first), /duplicate domain/u);
  assert.throws(() => accumulator.build(1), /exact 200-domain cohort/u);

  const mismatched = {
    ...snapshot(1),
    runId: "223e4567-e89b-42d3-a456-426614174000",
  };
  assert.throws(
    () => accumulator.add(mismatched),
    /runId does not match/u,
  );
});

test("shadow identity cap is cumulative and a rejected addition is atomic", () => {
  const identitiesPerAtCapSnapshot =
    SHADOW_EVALUATION_IDENTITY_VALUE_CAP / SHADOW_EVALUATION_DOMAIN_COUNT;
  assert.equal(Number.isSafeInteger(identitiesPerAtCapSnapshot), true);
  const directNamesPerAtCapSnapshot = identitiesPerAtCapSnapshot - 1;
  assert.equal(directNamesPerAtCapSnapshot, 49);

  const accumulator = createShadowEvaluationAccumulator({ runId: RUN_ID, provenance });
  for (let index = 0; index < SHADOW_EVALUATION_DOMAIN_COUNT - 1; index += 1) {
    accumulator.add(identityHeavySnapshot(index, directNamesPerAtCapSnapshot));
  }

  assert.throws(
    () => accumulator.add(identityHeavySnapshot(
      SHADOW_EVALUATION_DOMAIN_COUNT - 1,
      directNamesPerAtCapSnapshot + 1,
    )),
    /identity value cap/u,
  );
  assert.equal(accumulator.size, SHADOW_EVALUATION_DOMAIN_COUNT - 1);

  accumulator.add(identityHeavySnapshot(
    SHADOW_EVALUATION_DOMAIN_COUNT - 1,
    directNamesPerAtCapSnapshot,
  ));
  const artifact = accumulator.build(SHADOW_EVALUATION_DOMAIN_COUNT);
  assert.equal(artifact.snapshots.length, SHADOW_EVALUATION_DOMAIN_COUNT);
  assert.equal(
    artifact.snapshots.reduce((total, item) =>
      total
      + 1
      + (item.t1.state === "available"
        ? item.t1.directNames.length
          + item.t1.inferredNames.length
          + item.t1.errors.length
        : 1)
      + (item.t2.state === "available"
        ? item.t2.directNames.length
          + item.t2.inferredNames.length
          + item.t2.errors.length
        : 1)
      + item.full.directNames.length
      + item.full.inferredNames.length
      + item.browserLimitHits.length,
    0),
    SHADOW_EVALUATION_IDENTITY_VALUE_CAP,
  );
});

test("shadow accumulator allowlists fields before persistence", () => {
  const accumulator = createShadowEvaluationAccumulator({
    runId: RUN_ID,
    provenance: {
      ...provenance,
      rawCatalog: "SUPER_SECRET_RAW_CATALOG",
    } as Provenance & { readonly rawCatalog: string },
  });
  for (let index = 0; index < SHADOW_EVALUATION_DOMAIN_COUNT; index += 1) {
    const base = snapshot(index);
    if (base.t1.state !== "available") throw new Error("invalid fixture");
    const item = {
      ...base,
      rawHtml: "SUPER_SECRET_RAW_HTML",
      t1: {
        ...base.t1,
        errors: [{
          stage: "detect",
          code: "REGEX_RULE_TIMEOUT",
          retryable: true,
          count: 1,
          rawToken: "SUPER_SECRET_RAW_TOKEN",
        } as unknown as (typeof base.t1.errors)[number]],
      },
      preBrowser: {
        ...base.preBrowser!,
        rawText: "SUPER_SECRET_RAW_TEXT",
      },
    } as ShadowEvaluationSnapshot & { readonly rawHtml: string };
    accumulator.add(item);
  }
  const artifact = accumulator.build(SHADOW_EVALUATION_DOMAIN_COUNT);
  const serialized = JSON.stringify(artifact);
  assert.equal(serialized.includes("SUPER_SECRET_RAW_HTML"), false);
  assert.equal(serialized.includes("SUPER_SECRET_RAW_TEXT"), false);
  assert.equal(serialized.includes("SUPER_SECRET_RAW_CATALOG"), false);
  assert.equal(serialized.includes("SUPER_SECRET_RAW_TOKEN"), false);
  assert.equal("rawHtml" in (artifact.snapshots[0] as object), false);
  assert.equal("rawText" in (artifact.snapshots[0]!.preBrowser as object), false);
  assert.equal("rawCatalog" in (artifact.provenance as object), false);
});
