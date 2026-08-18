import assert from "node:assert/strict";
import { test } from "node:test";

import {
  computeConfigDigest,
  createDefaultScanConfig,
  parseScanConfig,
} from "../src/config.ts";
import {
  DomainResultValidationError,
  createEvidenceValueMatch,
  sanitizeEvidenceKey,
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
  const opaqueKey = "A".repeat(24);
  const oversizedKey = `${"x-".repeat(32)}x`;
  const sanitizedQuery = sanitizeUrl(
    `https://example.com/products/widget?variant=1&${opaqueKey}=2&secret-hunter2=3&${oversizedKey}=4&variant=5`,
  );
  assert.equal(
    sanitizedQuery,
    "https://example.com/products/widget?variant=%5Bredacted%5D&%5Bredacted%5D=%5Bredacted%5D&%5Bredacted%5D=%5Bredacted%5D&%5Bredacted%5D=%5Bredacted%5D&variant=%5Bredacted%5D",
  );
  assert.deepEqual(
    [...new URL(sanitizedQuery).searchParams.keys()],
    ["variant", "[redacted]", "[redacted]", "[redacted]", "variant"],
  );
  assert.equal(sanitizeUrl(sanitizedQuery), sanitizedQuery);
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

test("publishes whole safe DNS values and only the matched TLS issuer fragment", () => {
  const dnsMatch = (
    key: string,
    observedValue: string,
    matchedValue: string,
  ) => createEvidenceValueMatch({
    source: "dns_record",
    key,
    observedValue,
    matchedValue,
    scanConfig,
  });
  const safeDnsRecords = [
    ["A", "93.184.216.34", "184.216"],
    ["AAAA", "2606:2800:220:1:248:1893:25c8:1946", "248:1893"],
    ["CNAME", "edge.vendor.tld", "edge.vendor"],
    ["MX", "mail.vendor.tld", "mail.vendor"],
    ["NS", "ns1.vendor.tld", "ns1"],
    ["PTR", "ptr.vendor.tld", "ptr.vendor"],
    ["SRV", "service.vendor.tld", "service.vendor"],
  ] as const;

  for (const [key, observedValue, matchedValue] of safeDnsRecords) {
    assert.deepEqual(dnsMatch(key, observedValue, matchedValue), {
      kind: "value",
      value: observedValue,
      truncated: false,
    });
  }

  for (const [key, value] of [
    ["TXT", "google-site-verification=fixture-secret"],
    ["CAA", "letsencrypt.org"],
    ["SOA", "ns1.vendor.tld hostmaster.vendor.tld 1 2 3 4 5"],
  ] as const) {
    assert.deepEqual(dnsMatch(key, value, "vendor"), {
      kind: "redacted",
      value: null,
      truncated: false,
    });
  }

  assert.deepEqual(dnsMatch("A", "10.0.0.1", "10.0"), {
    kind: "redacted",
    value: null,
    truncated: false,
  });
  assert.deepEqual(dnsMatch("CNAME", "alice@example.invalid", "example"), {
    kind: "redacted",
    value: null,
    truncated: false,
  });

  const lowerConfigValue = structuredClone(scanConfig) as unknown as {
    limits: { evidence: { matchCodePoints: number } };
  };
  lowerConfigValue.limits.evidence.matchCodePoints = 4;
  const lowerConfig = parseScanConfig(lowerConfigValue);
  assert.deepEqual(createEvidenceValueMatch({
    source: "dns_record",
    key: "A",
    observedValue: "93.184.216.34",
    matchedValue: "93.184",
    scanConfig: lowerConfig,
  }), {
    kind: "redacted",
    value: null,
    truncated: false,
  });

  assert.deepEqual(createEvidenceValueMatch({
    source: "tls_issuer",
    key: null,
    observedValue: "C=US, O=Fixture, CN=Alpha Root CA 2026",
    matchedValue: "Alpha Root CA",
    scanConfig,
  }), {
    kind: "value",
    value: "Alpha Root CA",
    truncated: false,
  });
});

test("accepts sanitized query names through semantic URL validation", () => {
  const finalUrl = sanitizeUrl(
    `https://shop.vendor.tld/?variant=1&${"A".repeat(24)}=2&secret-hunter2=3`,
  );
  const baseline = makeResult();
  const result = makeResult({
    finalUrl,
    pages: [{ ...baseline.pages[0]!, url: finalUrl }],
  });

  assert.equal(
    validateDomainResult(result, {
      scanConfig,
      expectedConfigDigest: configDigest,
      signalAdmitted: true,
    }),
    result,
  );
});

test("sanitizes evidence locator keys and rejects unsafe published keys", () => {
  const drupalSession = `SESS${"0123456789abcdef".repeat(2)}`;

  assert.equal(sanitizeEvidenceKey("cookie", drupalSession, scanConfig), null);
  assert.equal(sanitizeEvidenceKey("cookie", "CFID", scanConfig), "CFID");
  assert.equal(sanitizeEvidenceKey("cookie", "CFTOKEN", scanConfig), "CFTOKEN");
  assert.equal(
    sanitizeEvidenceKey("header", `x-${"A".repeat(24)}`, scanConfig),
    null,
  );
  assert.equal(sanitizeEvidenceKey("meta", "secret-hunter2", scanConfig), null);

  const unsafeCookie = makeEvidence({
    source: "cookie",
    key: drupalSession,
    match: { kind: "presence", value: null, truncated: false },
    pattern: null,
    version: null,
  });
  expectSemanticFailure(
    makeResult({
      technologies: [makeDirectTechnology({
        version: null,
        evidence: [unsafeCookie],
      })],
    }),
    /key exposes a sensitive or opaque locator/,
  );

  const unsafeHeader = makeEvidence({
    source: "header",
    key: `x-${"A".repeat(24)}`,
    match: { kind: "redacted", value: null, truncated: false },
    version: null,
  });
  expectSemanticFailure(
    makeResult({
      technologies: [makeDirectTechnology({
        version: null,
        evidence: [unsafeHeader],
      })],
    }),
    /key exposes a sensitive or opaque locator/,
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

test("rejects zero-confidence technologies and accepts zero-confidence evidence", () => {
  expectSemanticFailure(
    makeResult({
      technologies: [
        makeDirectTechnology({
          confidence: 0,
          evidence: [makeEvidence({ confidence: 0 })],
        }),
      ],
    }),
    /wire schema/,
  );

  const inferred: Technology = {
    name: "Platform",
    categories: [],
    version: null,
    confidence: 0,
    type: "inferred",
    pageIds: [],
    evidence: [],
    inferredFrom: [
      {
        technology: "Example",
        ruleId: ruleTwo,
        confidence: 0,
        version: null,
      },
    ],
  };
  expectSemanticFailure(
    makeResult({ technologies: [makeDirectTechnology(), inferred] }),
    /wire schema/,
  );

  const withCompanionEvidence = makeResult({
    technologies: [makeDirectTechnology({
      evidence: [
        makeEvidence(),
        makeEvidence({
          ruleId: ruleTwo,
          confidence: 0,
          version: null,
        }),
      ],
    })],
  });
  assert.equal(
    validateDomainResult(withCompanionEvidence, {
      scanConfig,
      expectedConfigDigest: configDigest,
      signalAdmitted: true,
    }),
    withCompanionEvidence,
  );
});

test("allows one cookie-locator rule to prove multiple observed cookie names", () => {
  const cookieEvidence = (key: string): Evidence => makeEvidence({
    source: "cookie",
    key,
    match: { kind: "presence", value: null, truncated: false },
    pattern: null,
    confidence: 60,
    version: null,
  });
  const result = makeResult({
    technologies: [makeDirectTechnology({
      version: null,
      confidence: 60,
      evidence: [cookieEvidence("CFID"), cookieEvidence("CFTOKEN")],
    })],
  });

  assert.equal(
    validateDomainResult(result, {
      scanConfig,
      expectedConfigDigest: configDigest,
      signalAdmitted: true,
    }),
    result,
  );

  const headerEvidence = (key: string): Evidence => makeEvidence({
    source: "header",
    key,
    match: { kind: "presence", value: null, truncated: false },
    pattern: null,
    confidence: 60,
    version: null,
  });
  expectSemanticFailure(
    makeResult({
      technologies: [makeDirectTechnology({
        version: null,
        confidence: 60,
        evidence: [headerEvidence("server"), headerEvidence("x-powered-by")],
      })],
    }),
    /immutable rule metadata/,
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

test("validates deep inference provenance without recursive stack growth", () => {
  const count = 4_600;
  const nameAt = (index: number): string => `T${String(index).padStart(4, "0")}`;
  const technologies: Technology[] = [makeDirectTechnology({
    name: nameAt(0),
    version: null,
    confidence: 50,
    evidence: [makeEvidence({ version: null })],
  })];

  for (let index = 1; index < count; index += 1) {
    technologies.push({
      name: nameAt(index),
      categories: [],
      version: null,
      confidence: 50,
      type: "inferred",
      pageIds: [],
      evidence: [],
      inferredFrom: [{
        technology: nameAt(index - 1),
        ruleId: ruleTwo,
        confidence: 50,
        version: null,
      }],
    });
  }

  const result = makeResult({ technologies });
  assert.equal(
    validateDomainResult(result, {
      scanConfig,
      expectedConfigDigest: configDigest,
      signalAdmitted: true,
    }),
    result,
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

  const tlsLimitError: ScanError = {
    ...error,
    stage: "tls",
    code: "TLS_LIMIT_EXCEEDED",
    retryable: false,
    message: "TLS certificate observations exceeded a safety limit.",
  };
  assert.doesNotThrow(() =>
    validateDomainResult(makeResult({
      status: "partial",
      errors: [tlsLimitError],
    }), {
      scanConfig,
      expectedConfigDigest: configDigest,
      signalAdmitted: true,
    })
  );
  expectSemanticFailure(
    makeResult({
      status: "partial",
      errors: [{ ...tlsLimitError, stage: "dns" }],
    }),
    /incompatible with its stage/,
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

  const networkUrlEvidence = makeEvidence({
    collector: "browser",
    source: "network_url",
    pageId: "p1",
    key: null,
    match: {
      kind: "value",
      value: "https://api.vendor.tld/umbraco/api/?access_token=secret",
      truncated: false,
    },
    pattern: "/umbraco/api/",
    version: null,
  });

  expectSemanticFailure(
    makeResult({ technologies: [directWith(networkUrlEvidence)] }),
    /canonical sanitized URL/,
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

  const credentialHeader = makeEvidence({
    collector: "http",
    source: "header",
    pageId: null,
    key: "x-aspnet-version",
    match: {
      kind: "value",
      value: "EasyEngine Basic dXNlcjpwYXNz",
      truncated: false,
    },
    pattern: "(.+)",
    version: null,
  });
  expectSemanticFailure(
    makeResult({ technologies: [directWith(credentialHeader)] }),
    /sensitive header or token/,
  );

  const shortAuthHeader = makeEvidence({
    collector: "http",
    source: "header",
    pageId: null,
    key: "x-auth",
    match: { kind: "value", value: "hunter2", truncated: false },
    pattern: "(.+)",
    version: "hunter2",
  });
  expectSemanticFailure(
    makeResult({
      technologies: [makeDirectTechnology({
        version: "hunter2",
        pageIds: [],
        evidence: [shortAuthHeader],
      })],
    }),
    /sensitive header or token/,
  );

  const credentialMeta = makeEvidence({
    collector: "http",
    source: "meta",
    pageId: "p1",
    key: "generator",
    match: {
      kind: "value",
      value: "MediaWiki Bearer hunter2",
      truncated: false,
    },
    pattern: "(.+)",
    version: null,
  });
  expectSemanticFailure(
    makeResult({ technologies: [directWith(credentialMeta)] }),
    /sensitive metadata token/,
  );

  const tokenVersionEvidence = makeEvidence({
    collector: "http",
    source: "header",
    pageId: null,
    key: "server",
    match: { kind: "value", value: "Monkey", truncated: false },
    pattern: "Monkey",
    version: "token-secret",
  });
  expectSemanticFailure(
    makeResult({
      technologies: [makeDirectTechnology({
        version: "token-secret",
        pageIds: [],
        evidence: [tokenVersionEvidence],
      })],
    }),
    /version may expose a token/,
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
