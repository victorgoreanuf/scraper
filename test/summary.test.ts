import assert from "node:assert/strict";
import { test } from "node:test";

import {
  computeConfigDigest,
  createDefaultScanConfig,
  parseScanConfig,
} from "../src/config.ts";
import type {
  DomainResult,
  Evidence,
  Provenance,
  ScanError,
  Technology,
} from "../src/model.ts";
import {
  createRunSummaryAccumulator,
  type RunSummary,
} from "../src/output/summary.ts";

const RUN_ID = "37937a78-f39d-49ed-a51d-6d398ae45a20";
const RULE_ID = `sha256:${"1".repeat(64)}`;
const config = createDefaultScanConfig(
  "WebsiteTechScraper/0.1.0 (https://contact.website-tech-scraper.dev/crawler)",
);
const provenance: Provenance = Object.freeze({
  scannerVersion: "0.1.0",
  runtime: Object.freeze({
    node: "24.19.0",
    playwright: "1.62.1",
    chromiumRevision: "chromium-123456",
  }),
  catalog: Object.freeze({
    source: "enthec/webappanalyzer",
    revision: "5e7c47b1d441ded0bd476b252261e87634349f96",
    digest: `sha256:${"b".repeat(64)}`,
  }),
  configDigest: computeConfigDigest(config),
});

function evidence(overrides: Partial<Evidence> = {}): Evidence {
  return {
    collector: "http",
    source: "header",
    pageId: "p1",
    key: "server",
    match: { kind: "presence", value: null, truncated: false },
    ruleId: RULE_ID,
    pattern: null,
    confidence: 50,
    version: null,
    ...overrides,
  };
}

function direct(
  name: string,
  technologyEvidence: readonly Evidence[],
): Technology {
  return {
    name,
    categories: [],
    version: null,
    confidence: 50,
    type: "direct",
    pageIds: ["p1", "p2", "p3"].filter((pageId) =>
      technologyEvidence.some((item) => item.pageId === pageId)
    ) as Technology["pageIds"],
    evidence: technologyEvidence,
    inferredFrom: [],
  };
}

function inferred(name: string, parent: string): Technology {
  return {
    name,
    categories: [],
    version: null,
    confidence: 50,
    type: "inferred",
    pageIds: [],
    evidence: [],
    inferredFrom: [{
      technology: parent,
      ruleId: RULE_ID,
      confidence: 50,
      version: null,
    }],
  };
}

function scanError(
  stage: ScanError["stage"],
  code: ScanError["code"],
): ScanError {
  return {
    stage,
    code,
    pageId: null,
    retryable: false,
    message: `${stage}/${code}`,
    ruleId: null,
    signal: null,
    limit: null,
    catalogRevision: null,
  };
}

function makeResult(
  domain: string,
  overrides: Partial<DomainResult> = {},
): DomainResult {
  return {
    schemaVersion: 1,
    runId: RUN_ID,
    domain,
    scannedAt: "2026-08-18T00:00:00.000Z",
    status: "success",
    finalUrl: `https://${domain}/`,
    scanMode: "full",
    pages: [{
      id: "p1",
      role: "entry",
      url: `https://${domain}/`,
      httpStatus: 200,
      collectors: ["http", "browser"],
    }],
    technologies: [],
    detectionStats: {
      rawDirect: 0,
      gatedDirect: 0,
      suppressedDirect: 0,
      retainedDirect: 0,
    },
    errors: [],
    timings: {
      totalMs: 0,
      targetMs: 0,
      robotsMs: 0,
      httpMs: 0,
      dnsMs: 0,
      tlsMs: 0,
      browserMs: 0,
      detectMs: 0,
    },
    usage: {
      httpRequests: 1,
      browserRequests: 1,
      retries: 0,
      pagesVisited: 1,
      probesIssued: 0,
      scriptBodiesInspected: 0,
      staticTransferredBytes: 0,
      browserTransferredBytes: 0,
    },
    provenance,
    ...overrides,
  };
}

function runResults(): readonly DomainResult[] {
  const first = makeResult("alpha.example", {
    technologies: [
      direct("HttpOnly", [evidence()]),
      direct("BrowserProbe", [
        evidence({
          collector: "browser",
          source: "dom",
          key: "html[data-app]",
        }),
        evidence({ source: "probe", pageId: null, key: "/version" }),
      ]),
      inferred("InferredShared", "HttpOnly"),
    ],
    detectionStats: {
      rawDirect: 4,
      gatedDirect: 1,
      suppressedDirect: 1,
      retainedDirect: 2,
    },
    timings: {
      totalMs: 10,
      targetMs: 1,
      robotsMs: 1,
      httpMs: 2,
      dnsMs: 1,
      tlsMs: 1,
      browserMs: 2,
      detectMs: 2,
    },
    usage: {
      httpRequests: 2,
      browserRequests: 3,
      retries: 0,
      pagesVisited: 1,
      probesIssued: 1,
      scriptBodiesInspected: 1,
      staticTransferredBytes: 100,
      browserTransferredBytes: 200,
    },
  });
  const second = makeResult("beta.example", {
    status: "partial",
    pages: [
      {
        id: "p1",
        role: "entry",
        url: "https://beta.example/",
        httpStatus: 200,
        collectors: ["http", "browser"],
      },
      {
        id: "p2",
        role: "detail",
        url: "https://beta.example/product",
        httpStatus: 200,
        collectors: ["http", "browser"],
      },
    ],
    technologies: [
      direct("Shared", [evidence({
        collector: "browser",
        source: "script_content",
        pageId: "p2",
        key: "https://beta.example/app.js",
      })]),
      inferred("InferredShared", "Shared"),
    ],
    detectionStats: {
      rawDirect: 2,
      gatedDirect: 0,
      suppressedDirect: 1,
      retainedDirect: 1,
    },
    errors: [
      scanError("http", "HTTP_LIMIT_EXCEEDED"),
      scanError("detect", "REGEX_DOMAIN_BUDGET_EXCEEDED"),
    ],
    timings: {
      totalMs: 30,
      targetMs: 1,
      robotsMs: 1,
      httpMs: 5,
      dnsMs: 1,
      tlsMs: 1,
      browserMs: 10,
      detectMs: 5,
    },
    usage: {
      httpRequests: 4,
      browserRequests: 5,
      retries: 1,
      pagesVisited: 2,
      probesIssued: 0,
      scriptBodiesInspected: 2,
      staticTransferredBytes: 300,
      browserTransferredBytes: 400,
    },
  });
  const third = makeResult("gamma.example", {
    status: "failed",
    finalUrl: null,
    pages: [],
    errors: [
      scanError("http", "HTTP_LIMIT_EXCEEDED"),
      scanError("detect", "REGEX_EXECUTION_LIMIT"),
    ],
    timings: {
      totalMs: 20,
      targetMs: null,
      robotsMs: null,
      httpMs: 10,
      dnsMs: null,
      tlsMs: null,
      browserMs: null,
      detectMs: 10,
    },
    usage: {
      httpRequests: 1,
      browserRequests: 0,
      retries: 0,
      pagesVisited: 0,
      probesIssued: 0,
      scriptBodiesInspected: 0,
      staticTransferredBytes: 0,
      browserTransferredBytes: 0,
    },
  });
  return [first, second, third];
}

function summarize(results: readonly DomainResult[]): RunSummary {
  const accumulator = createRunSummaryAccumulator({
    runId: RUN_ID,
    config,
    provenance,
  });
  for (const result of results) {
    accumulator.add(result);
  }
  return accumulator.build(5);
}

function configWithRows(rows: number) {
  const value = structuredClone(config) as unknown as {
    limits: { parquet: { rows: number } };
  };
  value.limits.parquet.rows = rows;
  return parseScanConfig(value);
}

function reverseKeyOrder(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(reverseKeyOrder);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).reverse().map(([key, nested]) => [
        key,
        reverseKeyOrder(nested),
      ]),
    );
  }
  return value;
}

test("aggregates persisted counters and overlapping evidence attribution", () => {
  const summary = summarize(runResults());

  assert.equal(summary.schemaVersion, 1);
  assert.equal(summary.runId, RUN_ID);
  assert.equal(summary.scanMode, "full");
  assert.equal(summary.inputDomains, 5);
  assert.equal(summary.processedDomains, 3);
  assert.deepEqual(summary.statusCounts, { success: 1, partial: 1, failed: 1 });
  assert.deepEqual(summary.technologies, {
    direct: 3,
    inferred: 2,
    total: 5,
    unique: 4,
  });
  assert.deepEqual(summary.detectionStats, {
    rawDirect: 6,
    gatedDirect: 1,
    suppressedDirect: 2,
    retainedDirect: 3,
  });
  assert.deepEqual(summary.durationMs, {
    average: 20,
    p50: 20,
    p95: 30,
    p99: 30,
  });
  assert.deepEqual(summary.usage, {
    httpRequests: 7,
    browserRequests: 8,
    retries: 1,
    pagesVisited: 3,
    probesIssued: 1,
    scriptBodiesInspected: 3,
    staticTransferredBytes: 400,
    browserTransferredBytes: 600,
  });
  assert.deepEqual(summary.evidenceAttribution, {
    directWithOnlyHttpEvidence: 1,
    directWithBrowserEvidence: 2,
    directWithProbeEvidence: 1,
    directWithInternalPageEvidence: 1,
    directWithScriptContentEvidence: 1,
  });
  assert.equal(summary.hardLimitHits, 4);
  assert.deepEqual(summary.errors, [
    { stage: "http", code: "HTTP_LIMIT_EXCEEDED", count: 2 },
    {
      stage: "detect",
      code: "REGEX_DOMAIN_BUDGET_EXCEEDED",
      count: 1,
    },
    { stage: "detect", code: "REGEX_EXECUTION_LIMIT", count: 1 },
  ]);
});

test("is independent of result completion order", () => {
  const results = runResults();
  const forward = summarize(results);
  const reverse = summarize([...results].reverse());

  assert.deepEqual(reverse, forward);
  assert.equal(JSON.stringify(reverse), JSON.stringify(forward));
});

test("uses nearest-rank percentiles, three-decimal averages, and zeroes", () => {
  const accumulator = createRunSummaryAccumulator({
    runId: RUN_ID,
    config,
    provenance,
  });
  [1, 2, 4].forEach((totalMs, index) => accumulator.add(makeResult(
    `duration-${index}.example`,
    { timings: { ...makeResult("fixture.example").timings, totalMs } },
  )));

  assert.deepEqual(accumulator.build(3).durationMs, {
    average: 2.333,
    p50: 2,
    p95: 4,
    p99: 4,
  });

  const empty = createRunSummaryAccumulator({
    runId: RUN_ID,
    config,
    provenance,
  }).build(0);
  assert.equal(empty.processedDomains, 0);
  assert.deepEqual(empty.durationMs, { average: 0, p50: 0, p95: 0, p99: 0 });
  assert.deepEqual(empty.errors, []);
});

test("rejects mismatched contexts and duplicate domains without double counting", () => {
  assert.throws(
    () => createRunSummaryAccumulator({
      runId: RUN_ID,
      config,
      provenance: { ...provenance, configDigest: `sha256:${"c".repeat(64)}` },
    }),
    /provenance does not match/u,
  );

  const accumulator = createRunSummaryAccumulator({
    runId: RUN_ID,
    config,
    provenance,
  });
  const result = runResults()[0]!;
  assert.throws(
    () => accumulator.add({ ...result, runId: "b5091a50-10e1-4da4-b435-9653acaa02ed" }),
    /does not match/u,
  );
  assert.throws(
    () => accumulator.add({
      ...result,
      provenance: {
        ...provenance,
        runtime: { ...provenance.runtime, chromiumRevision: "other" },
      },
    }),
    /does not match/u,
  );

  accumulator.add(result);
  assert.throws(() => accumulator.add(result), /already summarized/u);
  assert.equal(accumulator.build(1).processedDomains, 1);
  assert.equal(accumulator.build(1).technologies.total, 3);
  assert.throws(() => accumulator.build(0), /lower than processedDomains/u);
  assert.throws(() => accumulator.build(-1), /non-negative safe integer/u);
  assert.throws(() => accumulator.build(1.5), /non-negative safe integer/u);
});

test("returns closed deeply frozen snapshots without retaining caller objects", () => {
  const accumulator = createRunSummaryAccumulator({
    runId: RUN_ID,
    config,
    provenance,
  });
  for (const result of runResults()) {
    accumulator.add(result);
  }
  const summary = accumulator.build(3);

  assert.ok(Object.isFrozen(accumulator));
  assert.ok(Object.isFrozen(summary));
  assert.ok(Object.isFrozen(summary.statusCounts));
  assert.ok(Object.isFrozen(summary.technologies));
  assert.ok(Object.isFrozen(summary.detectionStats));
  assert.ok(Object.isFrozen(summary.durationMs));
  assert.ok(Object.isFrozen(summary.usage));
  assert.ok(Object.isFrozen(summary.evidenceAttribution));
  assert.ok(Object.isFrozen(summary.errors));
  assert.ok(Object.isFrozen(summary.errors[0]));
  assert.ok(Object.isFrozen(summary.provenance));
  assert.ok(Object.isFrozen(summary.provenance.runtime));
  assert.ok(Object.isFrozen(summary.config));
  assert.ok(Object.isFrozen(summary.config.targetPolicy.candidateOrder));
  assert.notEqual(summary.provenance, provenance);
  assert.notEqual(summary.config, config);
  assert.throws(() => {
    (summary.statusCounts as { success: number }).success = 99;
  }, TypeError);
});

test("enforces the configured input row limit in add and build", () => {
  const limitedConfig = configWithRows(1);
  const limitedProvenance = {
    ...provenance,
    configDigest: computeConfigDigest(limitedConfig),
  };
  const accumulator = createRunSummaryAccumulator({
    runId: RUN_ID,
    config: limitedConfig,
    provenance: limitedProvenance,
  });
  accumulator.add(makeResult("one.example", { provenance: limitedProvenance }));

  assert.throws(
    () => accumulator.add(makeResult("two.example", { provenance: limitedProvenance })),
    /input row limit/u,
  );
  assert.equal(accumulator.build(1).processedDomains, 1);
  assert.throws(() => accumulator.build(2), /input row limit/u);
});

test("requires a canonical UUID v4 run id", () => {
  for (const runId of [
    "not-a-uuid",
    RUN_ID.toUpperCase(),
    "37937a78-f39d-19ed-a51d-6d398ae45a20",
  ]) {
    assert.throws(
      () => createRunSummaryAccumulator({ runId, config, provenance }),
      /canonical UUID v4/u,
    );
  }
});

test("serializes byte-identically across context insertion orders", () => {
  const reorderedConfig = parseScanConfig(reverseKeyOrder(config));
  const reorderedProvenance = {
    configDigest: provenance.configDigest,
    catalog: {
      digest: provenance.catalog.digest,
      revision: provenance.catalog.revision,
      source: provenance.catalog.source,
    },
    runtime: {
      chromiumRevision: provenance.runtime.chromiumRevision,
      playwright: provenance.runtime.playwright,
      node: provenance.runtime.node,
    },
    scannerVersion: provenance.scannerVersion,
  } satisfies Provenance;
  const canonical = createRunSummaryAccumulator({
    runId: RUN_ID,
    config,
    provenance,
  }).build(0);
  const reordered = createRunSummaryAccumulator({
    runId: RUN_ID,
    config: reorderedConfig,
    provenance: reorderedProvenance,
  }).build(0);

  assert.equal(JSON.stringify(reordered), JSON.stringify(canonical));
});

test("rejects unsafe aggregate overflow atomically", () => {
  const accumulator = createRunSummaryAccumulator({
    runId: RUN_ID,
    config,
    provenance,
  });
  accumulator.add(makeResult("maximum.example", {
    usage: {
      ...makeResult("fixture.example").usage,
      staticTransferredBytes: Number.MAX_SAFE_INTEGER,
    },
  }));
  const before = accumulator.build(1);

  assert.throws(
    () => accumulator.add(makeResult("overflow.example", {
      usage: {
        ...makeResult("fixture.example").usage,
        staticTransferredBytes: 1,
      },
    })),
    /safe integer/u,
  );
  assert.deepEqual(accumulator.build(1), before);

  accumulator.add(makeResult("overflow.example", {
    usage: {
      ...makeResult("fixture.example").usage,
      staticTransferredBytes: 0,
    },
  }));
  assert.equal(accumulator.build(2).processedDomains, 2);
});
