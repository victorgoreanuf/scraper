import assert from "node:assert/strict";
import test from "node:test";

import {
  calibrateShadowEvaluation,
  SHADOW_CALIBRATION_SALTS,
  scoreShadowSnapshot,
  shadowFoldForDomain,
  shadowTriggerFeatureTokens,
} from "../src/evaluation-calibration.ts";
import {
  SHADOW_EVALUATION_DOMAIN_COUNT,
  SHADOW_EVALUATION_PROTOCOL_REVISION,
  type ShadowDetectorView,
  type ShadowEvaluationSnapshot,
} from "../src/evaluation.ts";

const RUN_ID = "123e4567-e89b-42d3-a456-426614174001";
const detectionStats = Object.freeze({
  rawDirect: 2,
  gatedDirect: 0,
  suppressedDirect: 0,
  retainedDirect: 2,
});

function available(directNames: readonly string[]): ShadowDetectorView {
  return Object.freeze({
    state: "available" as const,
    directNames: Object.freeze([...directNames]),
    inferredNames: Object.freeze([]),
    detectionStats,
    completed: true,
    errors: Object.freeze([]),
  });
}

function unavailable(
  reason: "prefix-unavailable" | "detector-unavailable",
): ShadowDetectorView {
  return Object.freeze({ state: "unavailable" as const, reason });
}

function domain(index: number): string {
  return `d${String(index).padStart(3, "0")}.example`;
}

function snapshot(
  index: number,
  overrides: Partial<ShadowEvaluationSnapshot> = {},
): ShadowEvaluationSnapshot {
  return Object.freeze({
    protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
    runId: RUN_ID,
    domain: domain(index),
    t1: available(Object.freeze(["Base"])),
    t2: available(Object.freeze(["Base", "Extra"])),
    preBrowser: Object.freeze({
      entryOutcome: "html" as const,
      entryStatusClass: "2xx" as const,
      entryHtmlBytes: 1_000,
      entryTextCodePoints: 500,
      staticNavigationLinks: 4,
      metadataEntries: 2,
      resourceEntries: 8,
      dnsRecords: 2,
      tlsIssuerPresent: true,
      t2Selected: true,
      t2Role: "detail" as const,
      t2Outcome: "html" as const,
      probesObserved: 1,
      httpRequests: 4,
      staticTransferredBytes: 2_000,
    }),
    full: Object.freeze({
      directNames: Object.freeze(["Base", `Unique-${String(index).padStart(3, "0")}`]),
      inferredNames: Object.freeze([]),
      status: "success" as const,
    }),
    fullCost: Object.freeze({
      browserPagesAttempted: 2,
      browserPagesAdmitted: 1,
      browserRequests: 10,
      browserTransferredBytes: 1_000,
      browserMs: 50,
    }),
    browserLimitHits: Object.freeze([]),
    ...overrides,
  });
}

function cohort(): readonly ShadowEvaluationSnapshot[] {
  return Object.freeze(Array.from(
    { length: SHADOW_EVALUATION_DOMAIN_COUNT },
    (_, index) => snapshot(index),
  ));
}

function predictionScore(
  snapshots: readonly ShadowEvaluationSnapshot[],
  selectedDomain: string,
): number {
  const prediction = calibrateShadowEvaluation(snapshots).oofPredictions
    .find(({ domain: candidate }) => candidate === selectedDomain);
  assert.ok(prediction);
  return prediction.score;
}

test("out-of-fold score does not use the held-out domain's full label or cost", () => {
  const original = cohort();
  const heldOutIndex = 17;
  const heldOut = original[heldOutIndex];
  assert.ok(heldOut);
  const changedHeldOut = snapshot(heldOutIndex, {
    full: Object.freeze({
      directNames: Object.freeze([
        "Base",
        "Changed-A",
        "Changed-B",
        "Changed-C",
      ]),
      inferredNames: Object.freeze(["Changed-Inferred"]),
      status: "failed",
    }),
    fullCost: Object.freeze({
      browserPagesAttempted: 99,
      browserPagesAdmitted: 88,
      browserRequests: 777,
      browserTransferredBytes: 999_999,
      browserMs: 55_555,
    }),
    browserLimitHits: Object.freeze([
      Object.freeze({
        pageId: "p1" as const,
        category: "inspection.domMatches" as const,
        domSelectorOrdinal: 9,
      }),
    ]),
  });
  const changed = [...original];
  changed[heldOutIndex] = changedHeldOut;

  assert.equal(
    predictionScore(original, heldOut.domain),
    predictionScore(changed, heldOut.domain),
  );
  assert.deepEqual(
    shadowTriggerFeatureTokens(heldOut),
    shadowTriggerFeatureTokens(changedHeldOut),
  );
  assert.equal(
    shadowFoldForDomain(heldOut.domain),
    shadowFoldForDomain(changedHeldOut.domain),
  );
});

test("fold-local routed selection is invariant to every label and cost in its fold", () => {
  const original = cohort();
  const targetFold = 3;
  const baseline = calibrateShadowEvaluation(original);
  const changed = original.map((item, index): ShadowEvaluationSnapshot => {
    if (shadowFoldForDomain(item.domain) !== targetFold) return item;
    return snapshot(index, {
      full: Object.freeze({
        directNames: Object.freeze([
          "Base",
          `Changed direct A ${String(index).padStart(3, "0")}`,
          `Changed direct B ${String(index).padStart(3, "0")}`,
        ].sort()),
        inferredNames: Object.freeze([
          `Changed inferred ${String(index).padStart(3, "0")}`,
        ]),
        status: "failed",
      }),
      fullCost: Object.freeze({
        browserPagesAttempted: 100 + index,
        browserPagesAdmitted: 80 + index,
        browserRequests: 1_000 + index,
        browserTransferredBytes: 1_000_000 + index,
        browserMs: 50_000 + index,
      }),
      browserLimitHits: Object.freeze([
        Object.freeze({
          pageId: "p1" as const,
          category: "inspection.domAccess" as const,
          domSelectorOrdinal: index,
        }),
      ]),
    });
  });
  const recalibrated = calibrateShadowEvaluation(changed);
  const selectedInFold = (report: typeof baseline) => report.deployable.selected
    .filter(({ fold }) => fold === targetFold);

  assert.deepEqual(selectedInFold(recalibrated), selectedInFold(baseline));
  assert.equal(baseline.deployable.triggerDomainCount, 38);
  assert.equal(baseline.deployable.controlDomainCount, 2);
  assert.equal(baseline.deployable.selected.length, 40);
  assert.ok(recalibrated.oofPredictions.some((prediction) => {
    if (prediction.fold === targetFold) return false;
    const previous = baseline.oofPredictions.find(
      ({ domain: candidate }) => candidate === prediction.domain,
    );
    return previous !== undefined && previous.score !== prediction.score;
  }));
});

test("calibration is byte-stable when snapshot completion order reverses", () => {
  const forward = calibrateShadowEvaluation(cohort());
  const reverse = calibrateShadowEvaluation([...cohort()].reverse());
  assert.equal(JSON.stringify(forward), JSON.stringify(reverse));
  assert.deepEqual(
    forward.model.folds.map(({ heldOutDomains }) => heldOutDomains)
      .reduce((sum, value) => sum + value, 0),
    SHADOW_EVALUATION_DOMAIN_COUNT,
  );
});

test("deployable selection fills 38 trigger and exactly 2 control places", () => {
  const report = calibrateShadowEvaluation(cohort());
  assert.equal(report.deployable.triggerDomainCount, 38);
  assert.equal(report.deployable.controlDomainCount, 2);
  assert.equal(report.deployable.selected.length, 40);
  assert.equal(
    new Set(report.deployable.selected.map(({ domain }) => domain)).size,
    40,
  );
  assert.equal(
    report.deployable.selected.filter(({ source }) => source === "trigger").length,
    38,
  );
  assert.equal(
    report.deployable.selected.filter(({ source }) => source === "control").length,
    2,
  );
  assert.equal(report.deterministicRandom.selectedDomains.length, 40);
  assert.equal(report.labelAwareGreedy.selectedDomains.length, 40);
  assert.equal(report.labelAwareGreedy.name, "label-aware-greedy");
  assert.deepEqual(
    Array.from({ length: 5 }, (_, fold) => ({
      fold,
      trigger: report.deployable.selected.filter(
        (item) => item.fold === fold && item.source === "trigger",
      ).length,
      control: report.deployable.selected.filter(
        (item) => item.fold === fold && item.source === "control",
      ).length,
    })),
    [
      { fold: 0, trigger: 7, control: 0 },
      { fold: 1, trigger: 8, control: 0 },
      { fold: 2, trigger: 7, control: 0 },
      { fold: 3, trigger: 8, control: 1 },
      { fold: 4, trigger: 8, control: 1 },
    ],
  );
});

test("greedy canonical-name lift follows exact T2-to-full replacement", () => {
  const snapshots = Array.from(
    { length: SHADOW_EVALUATION_DOMAIN_COUNT },
    (_, index): ShadowEvaluationSnapshot => snapshot(index, {
      t1: available(Object.freeze(["Base"])),
      t2: available(Object.freeze(["Base"])),
      full: Object.freeze({
        directNames: Object.freeze(["Base"]),
        inferredNames: Object.freeze([]),
        status: "success" as const,
      }),
    }),
  );
  snapshots[42] = snapshot(42, {
    t1: available(Object.freeze(["Cross-domain"])),
    t2: available(Object.freeze(["Cross-domain"])),
    full: Object.freeze({
      directNames: Object.freeze(["Lossy replacement"]),
      inferredNames: Object.freeze([]),
      status: "success" as const,
    }),
  });
  snapshots[1] = snapshot(1, {
    t1: available(Object.freeze([])),
    t2: available(Object.freeze([])),
    full: Object.freeze({
      directNames: Object.freeze(["Cross-domain"]),
      inferredNames: Object.freeze([]),
      status: "success" as const,
    }),
  });
  snapshots[199] = snapshot(199, {
    t1: available(Object.freeze([])),
    t2: available(Object.freeze([])),
    full: Object.freeze({
      directNames: Object.freeze(["Pure gain"]),
      inferredNames: Object.freeze([]),
      status: "success" as const,
    }),
  });

  const steps = calibrateShadowEvaluation(snapshots).labelAwareGreedy.steps;
  assert.deepEqual(
    steps.slice(0, 3).map(({ domain, incrementalPairLift, incrementalNameLift }) =>
      ({ domain, incrementalPairLift, incrementalNameLift })),
    [
      {
        domain: domain(199),
        incrementalPairLift: 1,
        incrementalNameLift: 1,
      },
      {
        domain: domain(42),
        incrementalPairLift: 1,
        incrementalNameLift: 0,
      },
      {
        domain: domain(1),
        incrementalPairLift: 1,
        incrementalNameLift: 1,
      },
    ],
  );
});

test("known fixture reports intersections, macro recall, extras, and actual costs", () => {
  const report = calibrateShadowEvaluation(cohort());
  const metrics = report.deployable.metrics;

  assert.deepEqual(metrics.retention.canonicalDirectNames, {
    retained: 41,
    total: 201,
    ratio: 41 / 201,
  });
  assert.deepEqual(metrics.retention.domainTechnologyPairs, {
    retained: 240,
    total: 400,
    ratio: 0.6,
  });
  assert.deepEqual(metrics.retention.macroDomains, {
    eligible: 200,
    meanRecall: 0.6,
  });
  assert.deepEqual(metrics.retention.macroTechnologies, {
    eligible: 201,
    meanRecall: 41 / 201,
  });
  assert.equal(metrics.retention.emptyFullLabelDomains, 0);
  assert.deepEqual(metrics.retention.extraDirectNames, ["Extra"]);
  assert.equal(metrics.retention.extraDomainTechnologyPairs.length, 160);

  assert.deepEqual(metrics.costs.browserDomains, {
    selected: 40,
    full: 200,
    relative: 0.2,
  });
  assert.deepEqual(metrics.costs.browserPagesAttempted, {
    selected: 80,
    full: 400,
    relative: 0.2,
  });
  assert.deepEqual(metrics.costs.browserPagesAdmitted, {
    selected: 40,
    full: 200,
    relative: 0.2,
  });
  assert.deepEqual(metrics.costs.browserRequests, {
    selected: 400,
    full: 2_000,
    relative: 0.2,
  });
  assert.deepEqual(metrics.costs.browserTransferredBytes, {
    selected: 40_000,
    full: 200_000,
    relative: 0.2,
  });
  assert.deepEqual(metrics.costs.browserMs, {
    selected: 2_000,
    full: 10_000,
    relative: 0.2,
  });
  assert.deepEqual(report.deployable.provisionalGuardrails, {
    scope: "provisional-shadow-challenge",
    canonicalDirectNames: {
      actual: 41 / 201,
      minimum: 0.95,
      passed: false,
    },
    domainTechnologyPairs: {
      actual: 0.6,
      minimum: 0.8,
      passed: false,
    },
    routedDomains: { actual: 40, maximum: 40, passed: true },
    passed: false,
  });
});

test("full-cohort deployment model is sorted and reproduces its score", () => {
  const snapshots = cohort();
  const report = calibrateShadowEvaluation(snapshots);
  const target = snapshots[23];
  assert.ok(target);
  const featureTokens = new Set(shadowTriggerFeatureTokens(target));
  const matching = report.deploymentModel.tokens
    .filter(({ token }) => featureTokens.has(token));
  const expected = (
    report.deploymentModel.globalMeanIncrementalPairLift
    + matching.reduce((sum, { estimate }) => sum + estimate, 0)
  ) / (matching.length + 1);

  assert.equal(scoreShadowSnapshot(report.deploymentModel, target), expected);
  assert.equal(report.deploymentModel.trainingDomains, 200);
  assert.equal(report.deploymentModel.trainingIncrementalPairLift, 200);
  assert.deepEqual(
    report.deploymentModel.tokens.map(({ token }) => token),
    [...report.deploymentModel.tokens.map(({ token }) => token)].sort(),
  );
  assert.ok(report.deploymentModel.tokens.every(({ domains, targetSum, estimate }) =>
    domains > 0 && targetSum >= 0 && estimate >= 0));
});

test("detector-unavailable shadow captures invalidate calibration", () => {
  const snapshots = Array.from(
    { length: SHADOW_EVALUATION_DOMAIN_COUNT },
    (_, index): ShadowEvaluationSnapshot => snapshot(index, {
      t1: unavailable("detector-unavailable"),
      t2: unavailable("detector-unavailable"),
      full: Object.freeze({
        directNames: Object.freeze(["Only"]),
        inferredNames: Object.freeze([]),
        status: "failed",
      }),
      fullCost: Object.freeze({
        browserPagesAttempted: 0,
        browserPagesAdmitted: 0,
        browserRequests: 0,
        browserTransferredBytes: 0,
        browserMs: 0,
      }),
    }),
  );
  assert.throws(
    () => calibrateShadowEvaluation(snapshots),
    /complete T1 and T2 shadow captures/u,
  );
});

test("calibration validates exact cohort identity, protocol, and prefix states", () => {
  const valid = cohort();
  assert.throws(
    () => calibrateShadowEvaluation(valid.slice(1)),
    /exact 200-domain cohort/u,
  );

  const duplicate = [...valid];
  duplicate[1] = duplicate[0] as ShadowEvaluationSnapshot;
  assert.throws(
    () => calibrateShadowEvaluation(duplicate),
    /duplicate domain/u,
  );

  const wrongProtocol = [...valid];
  wrongProtocol[0] = {
    ...snapshot(0),
    protocolRevision: "wrong",
  } as unknown as ShadowEvaluationSnapshot;
  assert.throws(
    () => calibrateShadowEvaluation(wrongProtocol),
    /protocol revision/u,
  );

  const invalidUnavailable = [...valid];
  invalidUnavailable[0] = snapshot(0, {
    t1: unavailable("prefix-unavailable"),
    t2: unavailable("prefix-unavailable"),
  });
  assert.throws(
    () => calibrateShadowEvaluation(invalidUnavailable),
    /requires null preBrowser/u,
  );

  const unavailableCohort = Array.from(
    { length: SHADOW_EVALUATION_DOMAIN_COUNT },
    (_, index) => snapshot(index, {
      t1: unavailable("prefix-unavailable"),
      t2: unavailable("prefix-unavailable"),
      preBrowser: null,
    }),
  );
  assert.throws(
    () => calibrateShadowEvaluation(unavailableCohort),
    /complete T1 and T2 shadow captures/u,
  );
});

test("calibration salts and hash folds are frozen", () => {
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
