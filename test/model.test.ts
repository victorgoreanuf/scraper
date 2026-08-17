import assert from "node:assert/strict";
import { test } from "node:test";

import {
  computeConfigDigest,
  createDefaultScanConfig,
  parseScanConfig,
} from "../src/config.ts";
import {
  DomainResultValidationError,
  sanitizeUrl,
  validateDomainResult,
  type DomainResult,
  type Evidence,
  type ScanError,
  type Technology,
} from "../src/model.ts";

const ruleOne = `sha256:${"1".repeat(64)}`;
const ruleTwo = `sha256:${"2".repeat(64)}`;
const scanConfig = createDefaultScanConfig(
  "WebsiteTechScraper/0.1.0 (https://contact.website-tech-scraper.dev/crawler)",
);
const configDigest = computeConfigDigest(scanConfig);

function makeEvidence(overrides: Partial<Evidence> = {}): Evidence {
  return {
    collector: "http",
    source: "script_url",
    pageId: "p1",
    key: "src",
    match: {
      kind: "value",
      value: "https://cdn.vendor.tld/example-1.2.0.js",
      truncated: false,
    },
    ruleId: ruleOne,
    pattern: "example-([0-9.]+)\\.js",
    confidence: 50,
    version: "1.2.0",
    ...overrides,
  };
}

function makeDirectTechnology(
  overrides: Partial<Technology> = {},
): Technology {
  return {
    name: "Example",
    categories: [{ id: 6, name: "JavaScript frameworks" }],
    version: "1.2.0",
    confidence: 50,
    type: "direct",
    pageIds: ["p1"],
    evidence: [makeEvidence()],
    inferredFrom: [],
    ...overrides,
  };
}

function makeResult(overrides: Partial<DomainResult> = {}): DomainResult {
  return {
    schemaVersion: 1,
    runId: "37937a78-f39d-49ed-a51d-6d398ae45a20",
    domain: "shop.vendor.tld",
    scannedAt: "2026-08-17T00:00:00.000Z",
    status: "success",
    finalUrl: "https://shop.vendor.tld/",
    scanMode: "full",
    pages: [
      {
        id: "p1",
        role: "entry",
        url: "https://shop.vendor.tld/",
        httpStatus: 200,
        collectors: ["http", "browser"],
      },
    ],
    technologies: [makeDirectTechnology()],
    errors: [],
    timings: {
      totalMs: 912,
      targetMs: 42,
      robotsMs: 21,
      httpMs: 124,
      dnsMs: 8,
      tlsMs: 17,
      browserMs: 731,
      detectMs: 18,
    },
    usage: {
      httpRequests: 3,
      browserRequests: 24,
      retries: 0,
      pagesVisited: 1,
      probesIssued: 0,
      scriptBodiesInspected: 4,
      staticTransferredBytes: 18_320,
      browserTransferredBytes: 130_000,
    },
    provenance: {
      scannerVersion: "0.1.0",
      runtime: {
        node: "24.19.0",
        playwright: "1.62.1",
        chromiumRevision: "chromium-123456",
      },
      catalog: {
        source: "enthec/webappanalyzer",
        revision: "5e7c47b1d441ded0bd476b252261e87634349f96",
        digest: `sha256:${"b".repeat(64)}`,
      },
      configDigest,
    },
    ...overrides,
  };
}

function expectSemanticFailure(
  result: unknown,
  expectedIssue: RegExp,
  signalAdmitted = true,
): void {
  assert.throws(
    () =>
      validateDomainResult(result, {
        scanConfig,
        expectedConfigDigest: configDigest,
        signalAdmitted,
      }),
    (error: unknown) => {
      assert.ok(error instanceof DomainResultValidationError);
      assert.match(error.message, expectedIssue);
      return true;
    },
  );
}

test("accepts a schema-valid and semantically consistent result", () => {
  const result = makeResult();

  assert.equal(
    validateDomainResult(result, {
      scanConfig,
      expectedConfigDigest: configDigest,
      signalAdmitted: true,
    }),
    result,
  );
});

test("sanitizes URLs deterministically", () => {
  assert.equal(
    sanitizeUrl(
      "https://user:password@Example.COM/api/token/0123456789abcdef?key=secret#part",
    ),
    "https://example.com/%5Bredacted%5D/%5Bredacted%5D/%5Bredacted%5D?key=%5Bredacted%5D",
  );
  assert.equal(
    sanitizeUrl("https://example.com/products/widget?variant=%5Bredacted%5D"),
    "https://example.com/products/widget?variant=%5Bredacted%5D",
  );
  assert.equal(
    sanitizeUrl("https://example.com/monkey"),
    "https://example.com/monkey",
  );

  const expandingQuery = `https://vendor.tld/?${Array.from(
    { length: 150 },
    () => "a=x",
  ).join("&")}`;

  assert.ok(expandingQuery.length < 2_048);
  assert.throws(
    () => sanitizeUrl(expandingQuery),
    /Sanitized URL exceeds the configured code-unit limit/,
  );
});

test("rejects wire-shape and canonical scalar violations", () => {
  const missing = structuredClone(makeResult()) as unknown as Record<
    string,
    unknown
  >;
  delete missing.usage;
  expectSemanticFailure(missing, /wire schema/);

  expectSemanticFailure(
    makeResult({ scannedAt: "2026-02-30T00:00:00.000Z" }),
    /real canonical UTC timestamp/,
  );
  expectSemanticFailure(
    makeResult({ finalUrl: "https://shop.vendor.tld/?session=secret" }),
    /canonical sanitized URL/,
  );
  expectSemanticFailure(
    makeResult({ domain: `shop.${String.fromCharCode(0xd800)}.tld` }),
    /wire schema|unpaired surrogate/,
  );
  expectSemanticFailure(
    makeResult({ domain: "shop.invalid" }),
    /canonical validated input hostname/,
  );
  expectSemanticFailure(
    makeResult({
      finalUrl: "http://127.0.0.1/",
      pages: [
        {
          ...makeResult().pages[0]!,
          url: "http://127.0.0.1/",
        },
      ],
    }),
    /canonical sanitized URL/,
  );
  expectSemanticFailure(
    makeResult({
      finalUrl: "https://vendor.tld:444/",
      pages: [
        {
          ...makeResult().pages[0]!,
          url: "https://vendor.tld:444/",
        },
      ],
    }),
    /canonical sanitized URL/,
  );

  const publicIpResult = makeResult({
    finalUrl: "https://8.8.8.8/",
    pages: [
      {
        ...makeResult().pages[0]!,
        url: "https://8.8.8.8/",
      },
    ],
  });

  assert.doesNotThrow(() =>
    validateDomainResult(publicIpResult, {
      scanConfig,
      expectedConfigDigest: configDigest,
      signalAdmitted: true,
    })
  );
  expectSemanticFailure(
    makeResult({
      provenance: {
        ...makeResult().provenance,
        configDigest: `sha256:${"c".repeat(64)}`,
      },
    }),
    /does not match the validated configuration/,
  );

  const differentConfigValue = structuredClone(scanConfig) as unknown as {
    limits: { evidence: { matchCodePoints: number } };
  };
  differentConfigValue.limits.evidence.matchCodePoints = 255;
  const differentConfig = parseScanConfig(differentConfigValue);

  assert.throws(
    () =>
      validateDomainResult(makeResult(), {
        scanConfig: differentConfig,
        expectedConfigDigest: configDigest,
        signalAdmitted: true,
      }),
    /context digest does not match scanConfig/,
  );
});

test("rejects inconsistent pages and page references", () => {
  expectSemanticFailure(
    makeResult({ usage: { ...makeResult().usage, pagesVisited: 0 } }),
    /pagesVisited/,
  );
  expectSemanticFailure(
    makeResult({
      pages: [
        {
          ...makeResult().pages[0]!,
          url: "https://other.vendor.tld/",
        },
      ],
    }),
    /does not match.*finalUrl/,
  );
  expectSemanticFailure(
    makeResult({
      technologies: [
        makeDirectTechnology({
          evidence: [makeEvidence({ pageId: "p2" })],
          pageIds: ["p2"],
        }),
      ],
    }),
    /missing page/,
  );
});

test("enforces technology order, evidence identity, confidence, and version", () => {
  const another = makeDirectTechnology({
    name: "Another",
    version: null,
    pageIds: [],
    evidence: [
      makeEvidence({
        pageId: null,
        source: "header",
        key: "server",
        match: { kind: "value", value: "nginx", truncated: false },
        pattern: "nginx",
        version: null,
      }),
    ],
  });
  expectSemanticFailure(
    makeResult({ technologies: [makeDirectTechnology(), another] }),
    /not in canonical order/,
  );

  expectSemanticFailure(
    makeResult({
      technologies: [
        makeDirectTechnology({
          confidence: 90,
        }),
      ],
    }),
    /confidence does not match/,
  );

  expectSemanticFailure(
    makeResult({
      technologies: [
        makeDirectTechnology({
          version: "9.9.9",
        }),
      ],
    }),
    /version does not match/,
  );

  const duplicateEvidence = makeEvidence({ confidence: 51 });
  expectSemanticFailure(
    makeResult({
      technologies: [
        makeDirectTechnology({
          confidence: 51,
          evidence: [makeEvidence(), duplicateEvidence],
        }),
      ],
    }),
    /duplicate/,
  );
});

test("validates inferred provenance and rejects cycles", () => {
  const inferred: Technology = {
    name: "Platform",
    categories: [],
    version: null,
    confidence: 40,
    type: "inferred",
    pageIds: [],
    evidence: [],
    inferredFrom: [
      {
        technology: "Example",
        ruleId: ruleTwo,
        confidence: 40,
        version: null,
      },
    ],
  };
  const valid = makeResult({
    technologies: [makeDirectTechnology(), inferred],
  });
  assert.doesNotThrow(() =>
    validateDomainResult(valid, {
      scanConfig,
      expectedConfigDigest: configDigest,
      signalAdmitted: true,
    })
  );

  expectSemanticFailure(
    makeResult({
      technologies: [
        makeDirectTechnology(),
        { ...inferred, inferredFrom: [{ ...inferred.inferredFrom[0]!, technology: "Missing" }] },
      ],
    }),
    /missing technology/,
  );

  const alpha: Technology = {
    ...inferred,
    name: "Alpha",
    inferredFrom: [{ ...inferred.inferredFrom[0]!, technology: "Beta" }],
  };
  const beta: Technology = {
    ...inferred,
    name: "Beta",
    inferredFrom: [{ ...inferred.inferredFrom[0]!, technology: "Alpha" }],
  };
  expectSemanticFailure(
    makeResult({ technologies: [alpha, beta] }),
    /cyclic or rootless/,
  );
});

test("requires registered ordered errors and checks signal-aware status", () => {
  const error: ScanError = {
    stage: "http",
    code: "UNSUPPORTED_CONTENT_TYPE",
    pageId: null,
    retryable: false,
    message: "The selected target did not return HTML.",
    ruleId: null,
    signal: null,
    limit: null,
    catalogRevision: null,
  };
  const partial = makeResult({
    status: "partial",
    errors: [error],
  });

  expectSemanticFailure(partial, /no signal was admitted/, false);
  assert.doesNotThrow(() =>
    validateDomainResult(partial, {
      scanConfig,
      expectedConfigDigest: configDigest,
      signalAdmitted: true,
    })
  );

  const unregistered = structuredClone(partial) as unknown as {
    errors: Array<{ code: string }>;
  };
  unregistered.errors[0]!.code = "NOT_REGISTERED";
  expectSemanticFailure(unregistered, /not registered/, true);

  expectSemanticFailure(
    {
      ...partial,
      errors: [{ ...error, stage: "dns", code: "BROWSER_TIMEOUT" }],
    },
    /incompatible with its stage/,
  );

  expectSemanticFailure(
    {
      ...partial,
      errors: [
        {
          ...error,
          message: "Failed https://user:password@example.com/private.",
        },
      ],
    },
    /unsanitized data/,
  );

  assert.throws(
    () =>
      validateDomainResult(partial, {
        scanConfig,
        expectedConfigDigest: configDigest,
      } as Parameters<typeof validateDomainResult>[1]),
    /must declare signalAdmitted/,
  );
});

test("requires success to represent a completed full scan", () => {
  const emptySuccess = makeResult({
    finalUrl: null,
    pages: [],
    technologies: [],
    timings: {
      totalMs: 1,
      targetMs: null,
      robotsMs: null,
      httpMs: null,
      dnsMs: null,
      tlsMs: null,
      browserMs: null,
      detectMs: null,
    },
    usage: {
      httpRequests: 0,
      browserRequests: 0,
      retries: 0,
      pagesVisited: 0,
      probesIssued: 0,
      scriptBodiesInspected: 0,
      staticTransferredBytes: 0,
      browserTransferredBytes: 0,
    },
  });

  expectSemanticFailure(emptySuccess, /success requires a collected entry page/, false);

  expectSemanticFailure(
    makeResult({
      pages: [
        {
          ...makeResult().pages[0]!,
          collectors: ["http"],
        },
      ],
    }),
    /success requires full HTTP\/browser page collection/,
  );

  expectSemanticFailure(
    makeResult({
      usage: {
        ...makeResult().usage,
        httpRequests: 0,
        browserRequests: 0,
        staticTransferredBytes: 0,
        browserTransferredBytes: 0,
      },
    }),
    /httpRequests is lower than collected HTTP pages/,
  );
});

test("publishes only canonical public hostname and DNS evidence", () => {
  const directWith = (evidence: Evidence): Technology =>
    makeDirectTechnology({
      version: null,
      pageIds: evidence.pageId === null ? [] : [evidence.pageId],
      evidence: [evidence],
    });
  const dnsEvidence = makeEvidence({
    collector: "dns",
    source: "dns_record",
    pageId: null,
    key: "A",
    match: { kind: "value", value: "10.0.0.1", truncated: false },
    pattern: "10\\.0\\.0\\.1",
    version: null,
  });

  expectSemanticFailure(
    makeResult({ technologies: [directWith(dnsEvidence)] }),
    /canonical public IPv4/,
  );

  const hostnameEvidence = makeEvidence({
    collector: "browser",
    source: "network_hostname",
    pageId: "p1",
    key: "host",
    match: { kind: "value", value: "127.0.0.1", truncated: false },
    pattern: "127\\.0\\.0\\.1",
    version: null,
  });

  expectSemanticFailure(
    makeResult({ technologies: [directWith(hostnameEvidence)] }),
    /canonical public hostname/,
  );

  const cnameEvidence = {
    ...dnsEvidence,
    key: "CNAME",
    match: {
      kind: "value",
      value: "alice@example.invalid",
      truncated: false,
    },
    pattern: "alice@.+",
  } as const satisfies Evidence;

  expectSemanticFailure(
    makeResult({ technologies: [directWith(cnameEvidence)] }),
    /canonical public DNS hostname/,
  );

  const safeHeader = makeEvidence({
    collector: "http",
    source: "header",
    pageId: null,
    key: "server",
    match: { kind: "value", value: "Monkey", truncated: false },
    pattern: "Monkey",
    version: null,
  });

  assert.doesNotThrow(() =>
    validateDomainResult(
      makeResult({ technologies: [directWith(safeHeader)] }),
      { scanConfig, expectedConfigDigest: configDigest, signalAdmitted: true },
    )
  );
});

test("requires timings and counters to agree with emitted work", () => {
  expectSemanticFailure(
    makeResult({ usage: { ...makeResult().usage, retries: 4 } }),
    /retries is inconsistent/,
  );
  expectSemanticFailure(
    makeResult({
      usage: { ...makeResult().usage, httpRequests: 1, retries: 1 },
    }),
    /retries is inconsistent/,
  );
  expectSemanticFailure(
    makeResult({
      usage: {
        ...makeResult().usage,
        browserRequests: 0,
        browserTransferredBytes: 1,
      },
    }),
    /browserTransferredBytes requires/,
  );

  const noRetryConfigValue = structuredClone(scanConfig) as unknown as {
    limits: { http: { transientRetriesPerRequest: number } };
  };
  noRetryConfigValue.limits.http.transientRetriesPerRequest = 0;
  const noRetryConfig = parseScanConfig(noRetryConfigValue);
  const noRetryDigest = computeConfigDigest(noRetryConfig);
  const retryResult = makeResult({
    usage: { ...makeResult().usage, httpRequests: 2, retries: 1 },
    provenance: { ...makeResult().provenance, configDigest: noRetryDigest },
  });

  assert.throws(
    () =>
      validateDomainResult(retryResult, {
        scanConfig: noRetryConfig,
        expectedConfigDigest: noRetryDigest,
        signalAdmitted: true,
      }),
    /retries is inconsistent/,
  );
});

test("enforces safe lower limits from the validated scan configuration", () => {
  const mutableConfig = structuredClone(scanConfig) as unknown as {
    limits: { evidence: { matchCodePoints: number } };
  };
  mutableConfig.limits.evidence.matchCodePoints = 4;
  const lowerConfig = parseScanConfig(mutableConfig);
  const lowerDigest = computeConfigDigest(lowerConfig);
  const evidence = makeEvidence({
    source: "header",
    key: "server",
    match: { kind: "value", value: "nginx", truncated: false },
    pattern: "nginx",
    version: null,
  });
  const result = makeResult({
    technologies: [
      makeDirectTechnology({
        version: null,
        evidence: [evidence],
      }),
    ],
    provenance: {
      ...makeResult().provenance,
      configDigest: lowerDigest,
    },
  });

  assert.throws(
    () =>
      validateDomainResult(result, {
        scanConfig: lowerConfig,
        expectedConfigDigest: lowerDigest,
        signalAdmitted: true,
      }),
    /configured code-point limit/,
  );

  const versionConfigValue = structuredClone(scanConfig) as unknown as {
    limits: { evidence: { versionCodeUnits: number } };
  };
  versionConfigValue.limits.evidence.versionCodeUnits = 3;
  const versionConfig = parseScanConfig(versionConfigValue);
  const versionDigest = computeConfigDigest(versionConfig);
  const parent = makeDirectTechnology({
    version: null,
    evidence: [makeEvidence({ version: null })],
  });
  const inferred: Technology = {
    name: "Platform",
    categories: [],
    version: null,
    confidence: 40,
    type: "inferred",
    pageIds: [],
    evidence: [],
    inferredFrom: [
      {
        technology: "Example",
        ruleId: ruleOne,
        confidence: 40,
        version: "1.2.3",
      },
      {
        technology: "Example",
        ruleId: ruleTwo,
        confidence: 40,
        version: "2.3.4",
      },
    ],
  };
  const inferredResult = makeResult({
    technologies: [parent, inferred],
    provenance: { ...makeResult().provenance, configDigest: versionDigest },
  });

  assert.throws(
    () =>
      validateDomainResult(inferredResult, {
        scanConfig: versionConfig,
        expectedConfigDigest: versionDigest,
        signalAdmitted: true,
      }),
    /inferredFrom.*version exceeds/,
  );
});
