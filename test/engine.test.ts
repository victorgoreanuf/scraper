import assert from "node:assert/strict";
import { test } from "node:test";

import {
  computeConfigDigest,
  createDefaultScanConfig,
  parseScanConfig,
  type ScanConfig,
} from "../src/config.ts";
import {
  detectHttp,
} from "../src/detect/engine.ts";
import type {
  CompiledFingerprintCatalog,
  CompiledFingerprintRule,
  CompiledImplication,
  CompiledTechnologyDefinition,
} from "../src/detect/catalog.ts";
import type {
  DetectorCandidate,
  DetectorMatchResult,
  DetectorPool,
  WorkerMatch,
} from "../src/detect/pool.ts";
import {
  validateDomainResult,
  type BrowserPageObservations,
  type Category,
  type DomainResult,
  type HttpEntryResult,
  type HttpPageObservations,
  type HttpPageResult,
  type HttpResponseObservations,
  type InfrastructureObservations,
  type ScanError,
} from "../src/model.ts";

type JsonRecord = Record<string, unknown>;

const userAgent =
  "WebsiteTechScraper/0.1.0 (https://contact.website-tech-scraper.dev/crawler)";
const defaultConfig = createDefaultScanConfig(userAgent);
const defaultCategory = { id: 1, name: "Test category" } as const;

function setConfigValue(
  value: JsonRecord,
  path: readonly string[],
  replacement: unknown,
): void {
  let current = value;

  for (const key of path.slice(0, -1)) {
    const next = current[key];
    assert.equal(typeof next, "object");
    assert.notEqual(next, null);
    assert.equal(Array.isArray(next), false);
    current = next as JsonRecord;
  }

  const key = path.at(-1);
  assert.notEqual(key, undefined);
  current[key as string] = replacement;
}

function configWith(
  replacements: ReadonlyArray<readonly [readonly string[], unknown]>,
): ScanConfig {
  const value = structuredClone(defaultConfig) as unknown as JsonRecord;

  for (const [path, replacement] of replacements) {
    setConfigValue(value, path, replacement);
  }

  return parseScanConfig(value);
}

function hashId(index: number): string {
  return `sha256:${index.toString(16).padStart(64, "0")}`;
}

function rule(
  index: number,
  technology: string,
  overrides: Partial<CompiledFingerprintRule> = {},
): CompiledFingerprintRule {
  return {
    ruleId: hashId(index),
    namespace: "test/engine:rule-v1",
    technology,
    source: "header",
    locator: "server",
    locatorPattern: null,
    original: "fixture",
    pattern: "fixture",
    matchMode: "regex",
    confidence: 100,
    versionTemplate: null,
    ...overrides,
  };
}

function implication(
  index: number,
  technology: string,
  confidence = 100,
  version: string | null = null,
): CompiledImplication {
  return {
    technology,
    ruleId: hashId(index),
    confidence,
    version,
  };
}

function technology(
  name: string,
  overrides: Partial<CompiledTechnologyDefinition> = {},
): CompiledTechnologyDefinition {
  const categories = [...(overrides.categories ?? [defaultCategory])].sort(
    (left, right) =>
      left.id - right.id
      || (left.name < right.name ? -1 : left.name > right.name ? 1 : 0),
  );
  return {
    name,
    requires: [],
    requiresCategory: [],
    implies: [],
    excludes: [],
    ...overrides,
    categories,
  };
}

function catalog(
  technologies: readonly CompiledTechnologyDefinition[],
  rules: readonly CompiledFingerprintRule[],
  categories: readonly Category[] = [defaultCategory],
): CompiledFingerprintCatalog {
  return {
    source: "test/engine",
    revision: "fixture-v1",
    digest: `sha256:${"a".repeat(64)}`,
    categories,
    technologies,
    rules,
    indexes: [],
    inspectionPlan: {
      dom: [],
      javascript: [],
      probePaths: [],
      dnsRecordTypes: [],
      tlsIssuer: false,
    },
    declarationCount: rules.length,
    relationshipCount: technologies.reduce(
      (total, item) =>
        total
        + item.requires.length
        + item.requiresCategory.length
        + item.implies.length
        + item.excludes.length,
      0,
    ),
    regexSourceCount: rules.filter((item) => item.pattern !== null).length,
    regexSourceCodeUnits: rules.reduce(
      (total, item) => total + (item.pattern?.length ?? 0),
      0,
    ),
  };
}

function response(
  overrides: Partial<HttpResponseObservations> = {},
): HttpResponseObservations {
  return {
    finalNetworkUrl: "https://shop.vendor.tld/",
    statusCode: 200,
    redirects: [],
    headers: [],
    cookies: [],
    cookiesTruncated: false,
    tlsIssuer: null,
    tlsHandshakeMs: null,
    ...overrides,
  };
}

function htmlEntry(
  pageOverrides: Partial<HttpPageObservations> = {},
  resultOverrides: {
    readonly robots?: HttpEntryResult["robots"];
    readonly errors?: readonly ScanError[];
  } = {},
): HttpEntryResult {
  return {
    kind: "html",
    page: {
      pageId: "p1",
      response: response(),
      html: "<html><body>Fixture</body></html>",
      text: "Fixture",
      textTruncated: false,
      metadata: [],
      metadataTruncated: false,
      resources: [],
      navigationLinks: [],
      urlsTruncated: false,
      collectionState: "complete",
      ...pageOverrides,
    },
    robots: resultOverrides.robots ?? [],
    errors: resultOverrides.errors ?? [],
  };
}

function emptyMatchResult(
  overrides: Partial<DetectorMatchResult> = {},
): DetectorMatchResult {
  return {
    matches: [],
    errors: [],
    completed: true,
    executions: 0,
    ...overrides,
  };
}

function fakePool(
  fingerprintCatalog: CompiledFingerprintCatalog,
  match: (
    candidates: readonly DetectorCandidate[],
    signal?: AbortSignal,
  ) => DetectorMatchResult | Promise<DetectorMatchResult>,
): DetectorPool {
  return {
    catalog: fingerprintCatalog,
    match: async (candidates, signal) => await match(candidates, signal),
    isAvailable: () => true,
    close: async () => {},
  };
}

function candidateOrdinal(
  candidates: readonly DetectorCandidate[],
  predicate: (candidate: DetectorCandidate) => boolean,
): number {
  const ordinal = candidates.findIndex(predicate);
  assert.notEqual(ordinal, -1, "Expected detector candidate was not emitted");
  return ordinal;
}

function workerMatch(
  candidates: readonly DetectorCandidate[],
  ruleOrdinal: number,
  predicate: (candidate: DetectorCandidate) => boolean,
  options: {
    readonly index?: number;
    readonly length?: number;
    readonly version?: string | null;
  } = {},
): WorkerMatch {
  const ordinal = candidateOrdinal(candidates, predicate);
  const candidate = candidates[ordinal];
  assert.notEqual(candidate, undefined);

  return {
    ruleOrdinal,
    candidateOrdinal: ordinal,
    index: options.index ?? 0,
    length: options.length ?? candidate!.value.length,
    version: options.version ?? null,
  };
}

function directRulePool(
  fingerprintCatalog: CompiledFingerprintCatalog,
  ruleToCandidate: (
    rule: CompiledFingerprintRule,
    candidate: DetectorCandidate,
  ) => boolean = (item, candidate) =>
    item.source === candidate.source
    && (item.locator === null || item.locator === candidate.key),
): DetectorPool {
  return fakePool(fingerprintCatalog, (candidates) => emptyMatchResult({
    matches: fingerprintCatalog.rules.flatMap((item, ruleOrdinal) => {
      const candidate = candidates.find(
        (value) => ruleToCandidate(item, value),
      );
      if (candidate === undefined) {
        return [];
      }
      return [workerMatch(
        candidates,
        ruleOrdinal,
        (value) => value === candidate,
      )];
    }),
  }));
}

function indexedHeaderPool(
  fingerprintCatalog: CompiledFingerprintCatalog,
): DetectorPool {
  return fakePool(fingerprintCatalog, (candidates) => {
    const candidateByKey = new Map(
      candidates.map((candidate, index) => [candidate.key, { candidate, index }]),
    );
    const matches: WorkerMatch[] = [];
    fingerprintCatalog.rules.forEach((item, ruleOrdinal) => {
      const entry = candidateByKey.get(item.locator);
      if (entry !== undefined) {
        matches.push({
          ruleOrdinal,
          candidateOrdinal: entry.index,
          index: 0,
          length: entry.candidate.value.length,
          version: null,
        });
      }
    });
    return emptyMatchResult({ matches });
  });
}

test("returns zero detection statistics without detector candidates", async () => {
  const fingerprintCatalog = catalog([], []);
  let poolCalled = false;
  const result = await detectHttp({
    kind: "failed",
    response: null,
    robots: [],
    errors: [{
      stage: "http",
      code: "HTTP_REQUEST_FAILED",
      pageId: null,
      retryable: true,
      message: "The static request failed.",
      ruleId: null,
      signal: null,
      limit: null,
      catalogRevision: null,
    }],
  }, {
    catalog: fingerprintCatalog,
    pool: fakePool(fingerprintCatalog, () => {
      poolCalled = true;
      return emptyMatchResult();
    }),
    config: defaultConfig,
  });

  assert.equal(poolCalled, false);
  assert.deepEqual(result.detectionStats, {
    rawDirect: 0,
    gatedDirect: 0,
    suppressedDirect: 0,
    retainedDirect: 0,
  });
  assert.equal(result.signalAdmitted, false);
  assert.equal(result.completed, true);
});

test("maps, normalizes, deduplicates, and ranks only supported HTTP candidates", async () => {
  const fingerprintCatalog = catalog([], []);
  let observed: readonly DetectorCandidate[] = [];
  const pool = fakePool(fingerprintCatalog, (candidates) => {
    observed = candidates;
    return emptyMatchResult();
  });
  const input = htmlEntry({
    response: response({
      finalNetworkUrl: "https://shop.vendor.tld/final",
      redirects: [
        {
          fromUrl: "https://shop.vendor.tld/",
          statusCode: 301,
          toUrl: "https://shop.vendor.tld/final",
        },
      ],
      headers: [
        { name: "Server", value: "Fixture/1" },
        { name: "server", value: "Fixture/1" },
      ],
      cookies: [
        { name: "session", value: "private" },
        { name: "session", value: "private" },
      ],
    }),
    html: "<html>Fixture</html>",
    text: "Fixture text",
    metadata: [
      { key: "Generator", value: "Fixture 1" },
      { key: "generator", value: "Fixture 1" },
    ],
    resources: [
      { kind: "stylesheet", url: "https://cdn.vendor.tld/site.css" },
      { kind: "script", url: "https://cdn.vendor.tld/app.js" },
      { kind: "script", url: "https://cdn.vendor.tld/app.js" },
      { kind: "image", url: "https://cdn.vendor.tld/logo.png" },
    ],
  }, {
    robots: [{
      ownerOrigin: "https://shop.vendor.tld",
      fetchedUrl: "https://shop.vendor.tld/robots.txt",
      text: "User-agent: *\nDisallow: /private",
    }],
  });

  const result = await detectHttp(input, {
    catalog: fingerprintCatalog,
    pool,
    config: defaultConfig,
  });

  assert.equal(result.signalAdmitted, true);
  assert.equal(result.completed, true);
  assert.deepEqual(result.technologies, []);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(
    observed.map(({ source, key, value }) => ({ source, key, value })),
    [
      { source: "url", key: null, value: "https://shop.vendor.tld/" },
      { source: "url", key: null, value: "https://shop.vendor.tld/final" },
      { source: "header", key: "server", value: "Fixture/1" },
      { source: "cookie", key: "session", value: "private" },
      { source: "html", key: null, value: "<html>Fixture</html>" },
      { source: "text", key: null, value: "Fixture text" },
      { source: "meta", key: "generator", value: "Fixture 1" },
      { source: "script_url", key: "src", value: "https://cdn.vendor.tld/app.js" },
      {
        source: "robots",
        key: null,
        value: "User-agent: *\nDisallow: /private",
      },
    ],
  );
  assert.equal(new Set(observed.map((item) => item.id)).size, observed.length);
  assert.deepEqual(
    observed.map((item) => item.id),
    [...observed.map((item) => item.id)].sort(),
  );
});

test("maps p2 and p3 HTTP variants with stable page-linked candidates", async () => {
  const fingerprintCatalog = catalog(
    [technology("P2 technology"), technology("P3 technology")],
    [
      rule(100, "P2 technology", {
        source: "meta",
        locator: "generator",
        pattern: "Fixture Generator",
      }),
      rule(101, "P3 technology", {
        locator: "server",
        pattern: "Fixture failure",
      }),
    ],
  );
  const p2Base = htmlEntry({
    response: response({
      finalNetworkUrl: "https://shop.vendor.tld/products/fixture",
      headers: [{ name: "X-Powered-By", value: "Fixture HTML" }],
      cookies: [{ name: "framework", value: "fixture-cookie" }],
    }),
    html: "<html>Product fixture</html>",
    text: "Product fixture",
    metadata: [{ key: "Generator", value: "Fixture Generator" }],
    resources: [{ kind: "script", url: "https://shop.vendor.tld/p2.js" }],
  });
  assert.equal(p2Base.kind, "html");
  const p2: HttpPageResult = {
    kind: "html",
    page: { ...p2Base.page, pageId: "p2" },
    robots: [],
    errors: [],
  };
  const p3NonHtml: HttpPageResult = {
    kind: "non-html",
    pageId: "p3",
    requestedUrl: "https://shop.vendor.tld/feed",
    response: response({
      finalNetworkUrl: "https://shop.vendor.tld/feed.xml",
      headers: [{ name: "Content-Type", value: "application/xml" }],
    }),
    robots: [],
    errors: [],
  };
  const p3Failed: HttpPageResult = {
    kind: "failed",
    pageId: "p3",
    requestedUrl: "https://shop.vendor.tld/broken-request",
    response: response({
      finalNetworkUrl: "https://shop.vendor.tld/broken",
      statusCode: 503,
      headers: [{ name: "Server", value: "Fixture failure" }],
    }),
    robots: [],
    errors: [{
      stage: "http",
      code: "HTTP_REQUEST_FAILED",
      pageId: "p3",
      retryable: true,
      message: "The static request failed.",
      ruleId: null,
      signal: null,
      limit: null,
      catalogRevision: null,
    }],
  };
  const skipped: HttpPageResult = {
    kind: "skipped",
    pageId: "p2",
    requestedUrl: "https://shop.vendor.tld/private",
    robots: [],
    errors: [],
  };
  type PageLinkedCandidate = DetectorCandidate & {
    readonly pageId: HttpPageObservations["pageId"] | null;
  };
  const run = async (
    httpPages: readonly HttpPageResult[],
  ) => {
    let observed: readonly PageLinkedCandidate[] = [];
    const result = await detectHttp(htmlEntry(), {
      catalog: fingerprintCatalog,
      pool: fakePool(fingerprintCatalog, (candidates) => {
        observed = candidates as readonly PageLinkedCandidate[];
        return emptyMatchResult({
          matches: [
            workerMatch(candidates, 0, (candidate) =>
              candidate.source === "meta"
              && candidate.key === "generator"
              && candidate.value === "Fixture Generator"),
            workerMatch(candidates, 1, (candidate) =>
              candidate.source === "header"
              && candidate.key === "server"
              && candidate.value === "Fixture failure"),
          ],
        });
      }),
      config: defaultConfig,
      httpPages,
    });
    assert.equal(result.completed, true);
    return { observed, result };
  };

  const pages = [skipped, p3Failed, p3NonHtml, p2] as const;
  const first = await run(pages);
  const reversed = await run([...pages].reverse());
  const observed = first.observed;
  assert.deepEqual(reversed.observed, observed);
  assert.deepEqual(reversed.result, first.result);
  assert.deepEqual(
    first.result.technologies.map((item) => [item.name, item.evidence[0]?.pageId]),
    [["P2 technology", "p2"], ["P3 technology", "p3"]],
  );
  assert.deepEqual(
    observed
      .filter((candidate) => candidate.pageId === "p2" || candidate.pageId === "p3")
      .map(({ source, pageId, key, value }) => [source, pageId, key, value]),
    [
      ["url", "p2", null, "https://shop.vendor.tld/products/fixture"],
      ["url", "p3", null, "https://shop.vendor.tld/broken"],
      ["url", "p3", null, "https://shop.vendor.tld/feed.xml"],
      ["header", "p2", "x-powered-by", "Fixture HTML"],
      ["header", "p3", "content-type", "application/xml"],
      ["header", "p3", "server", "Fixture failure"],
      ["cookie", "p2", "framework", "fixture-cookie"],
      ["html", "p2", null, "<html>Product fixture</html>"],
      ["text", "p2", null, "Product fixture"],
      ["meta", "p2", "generator", "Fixture Generator"],
      ["script_url", "p2", "src", "https://shop.vendor.tld/p2.js"],
    ],
  );
  assert.equal(
    observed.some((candidate) => candidate.value.includes("/private")),
    false,
  );
  assert.equal(
    observed.some((candidate) => candidate.value.includes("broken-request")),
    false,
  );
});

test("marks the T2 observation prefix without changing full candidate identities", async () => {
  const fingerprintCatalog = catalog([], []);
  const page = (
    pageId: "p2" | "p3",
    finalNetworkUrl: string,
    marker: string,
  ): HttpPageResult => {
    const base = htmlEntry({
      response: response({
        finalNetworkUrl,
        headers: [{ name: "X-Tier-Marker", value: marker }],
      }),
      html: `<html>${marker}</html>`,
      text: marker,
    });
    assert.equal(base.kind, "html");
    return {
      kind: "html",
      page: { ...base.page, pageId },
      robots: [],
      errors: [],
    };
  };
  const preferred = page(
    "p2",
    "https://shop.vendor.tld/preferred",
    "t2-signal",
  );
  const remappedPreferred = page(
    "p3",
    "https://shop.vendor.tld/preferred",
    "t2-signal",
  );
  const remainder = page(
    "p2",
    "https://shop.vendor.tld/remainder",
    "full-only-signal",
  );
  const run = async (withPriority: boolean): Promise<readonly DetectorCandidate[]> => {
    let observed: readonly DetectorCandidate[] = [];
    await detectHttp(htmlEntry(), {
      catalog: fingerprintCatalog,
      pool: fakePool(fingerprintCatalog, (candidates) => {
        observed = candidates;
        return emptyMatchResult();
      }),
      config: defaultConfig,
      httpPages: [remainder, remappedPreferred],
      ...(withPriority
        ? { priorityObservations: { httpPages: [preferred] } }
        : {}),
    });
    return observed;
  };

  const baseline = await run(false);
  const prioritized = await run(true);
  const withoutPriority = (candidate: DetectorCandidate): unknown => {
    const { priority: _priority, ...identity } = candidate;
    return identity;
  };
  assert.deepEqual(
    prioritized.map(withoutPriority),
    baseline.map(withoutPriority),
  );
  const fullOnly = prioritized.find((candidate) =>
    candidate.source === "header" && candidate.value === "full-only-signal");
  const retainedT2 = prioritized.find((candidate) =>
    candidate.source === "header" && candidate.value === "t2-signal");
  assert.equal(fullOnly?.priority, false);
  assert.equal(retainedT2?.priority, true);
  assert.equal((fullOnly?.id ?? "") < (retainedT2?.id ?? ""), true);
});

test("orders infrastructure candidates and publishes bounded DNS and TLS evidence", async () => {
  const rules = [
    rule(1, "Infrastructure service", {
      source: "dns_record",
      locator: "A",
      pattern: "184\\.216",
    }),
    rule(2, "Infrastructure service", {
      source: "dns_record",
      locator: "CNAME",
      pattern: "edge\\.vendor",
    }),
    rule(3, "Infrastructure service", {
      source: "dns_record",
      locator: "TXT",
      pattern: "verification=fixture",
    }),
    rule(4, "Infrastructure service", {
      source: "tls_issuer",
      locator: null,
      pattern: "Alpha Root CA",
      matchMode: "literal",
    }),
  ];
  const fingerprintCatalog = catalog(
    [technology("Infrastructure service")],
    rules,
  );
  const infrastructure = {
    dnsRecords: [
      { type: "TXT", value: "verification=fixture-secret" },
      { type: "CNAME", value: "edge.vendor.tld" },
      { type: "A", value: "93.184.216.34" },
      { type: "A", value: "93.184.216.34" },
    ],
    tlsIssuer: "C=US, O=Fixture, CN=Alpha Root CA 2026",
  } as const satisfies InfrastructureObservations;
  const failedInput: HttpEntryResult = {
    kind: "failed",
    response: null,
    robots: [],
    errors: [{
      stage: "http",
      code: "HTTP_REQUEST_FAILED",
      pageId: null,
      retryable: true,
      message: "The static request failed.",
      ruleId: null,
      signal: null,
      limit: null,
      catalogRevision: null,
    }],
  };
  let observed: readonly DetectorCandidate[] = [];
  const result = await detectHttp(failedInput, {
    catalog: fingerprintCatalog,
    pool: fakePool(fingerprintCatalog, (candidates) => {
      observed = candidates;
      return emptyMatchResult({
        matches: [
          workerMatch(candidates, 0, (candidate) => candidate.key === "A", {
            index: "93.184.216.34".indexOf("184.216"),
            length: "184.216".length,
          }),
          workerMatch(
            candidates,
            1,
            (candidate) => candidate.key === "CNAME",
            { length: "edge.vendor".length },
          ),
          workerMatch(candidates, 2, (candidate) => candidate.key === "TXT", {
            length: "verification=fixture".length,
          }),
          workerMatch(
            candidates,
            3,
            (candidate) => candidate.source === "tls_issuer",
            {
              index: infrastructure.tlsIssuer.indexOf("Alpha Root CA"),
              length: "Alpha Root CA".length,
            },
          ),
        ],
      });
    }),
    config: defaultConfig,
    infrastructure,
  });
  type InfrastructureCandidate = DetectorCandidate & {
    readonly collector: "dns" | "tls";
    readonly pageId: null;
  };
  const infrastructureCandidates = observed.filter(
    (candidate) => candidate.source === "dns_record"
      || candidate.source === "tls_issuer",
  ) as unknown as readonly InfrastructureCandidate[];

  assert.deepEqual(
    infrastructureCandidates.map(
      ({ collector, source, pageId, key, value }) => ({
        collector,
        source,
        pageId,
        key,
        value,
      }),
    ),
    [
      {
        collector: "dns",
        source: "dns_record",
        pageId: null,
        key: "A",
        value: "93.184.216.34",
      },
      {
        collector: "dns",
        source: "dns_record",
        pageId: null,
        key: "CNAME",
        value: "edge.vendor.tld",
      },
      {
        collector: "dns",
        source: "dns_record",
        pageId: null,
        key: "TXT",
        value: "verification=fixture-secret",
      },
      {
        collector: "tls",
        source: "tls_issuer",
        pageId: null,
        key: null,
        value: infrastructure.tlsIssuer,
      },
    ],
  );
  assert.deepEqual(
    infrastructureCandidates.map((candidate) => candidate.id),
    ["c00000000", "c00000001", "c00000002", "c00000003"],
  );
  assert.equal(result.signalAdmitted, true);
  assert.equal(result.completed, true);
  assert.deepEqual(result.errors, []);

  const detected = result.technologies[0];
  assert.equal(detected?.name, "Infrastructure service");
  const evidenceByKey = new Map(
    detected?.evidence.map((evidence) => [evidence.key, evidence]),
  );
  assert.deepEqual(evidenceByKey.get("A")?.match, {
    kind: "value",
    value: "93.184.216.34",
    truncated: false,
  });
  assert.deepEqual(evidenceByKey.get("CNAME")?.match, {
    kind: "value",
    value: "edge.vendor.tld",
    truncated: false,
  });
  assert.deepEqual(evidenceByKey.get("TXT")?.match, {
    kind: "redacted",
    value: null,
    truncated: false,
  });
  assert.deepEqual(evidenceByKey.get(null)?.match, {
    kind: "value",
    value: "Alpha Root CA",
    truncated: false,
  });
  assert.deepEqual(
    detected?.evidence.map((evidence) => [
      evidence.collector,
      evidence.pageId,
      evidence.key,
    ]),
    [
      ["dns", null, "A"],
      ["dns", null, "CNAME"],
      ["dns", null, "TXT"],
      ["tls", null, null],
    ],
  );

  const configDigest = computeConfigDigest(defaultConfig);
  const domainResult: DomainResult = {
    schemaVersion: 1,
    runId: "37937a78-f39d-49ed-a51d-6d398ae45a20",
    domain: "shop.vendor.tld",
    scannedAt: "2026-08-17T00:00:00.000Z",
    status: "partial",
    finalUrl: null,
    scanMode: "full",
    pages: [],
    technologies: result.technologies,
    detectionStats: result.detectionStats,
    errors: failedInput.errors,
    timings: {
      totalMs: 1,
      targetMs: 0,
      robotsMs: null,
      httpMs: 0,
      dnsMs: 0,
      tlsMs: 0,
      browserMs: null,
      detectMs: 0,
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
    provenance: {
      scannerVersion: "0.1.0",
      runtime: {
        node: "24.19.0",
        playwright: "1.62.1",
        chromiumRevision: "chromium-fixture",
      },
      catalog: {
        source: fingerprintCatalog.source,
        revision: fingerprintCatalog.revision,
        digest: fingerprintCatalog.digest,
      },
      configDigest,
    },
  };

  assert.equal(validateDomainResult(domainResult, {
    scanConfig: defaultConfig,
    expectedConfigDigest: configDigest,
    signalAdmitted: result.signalAdmitted,
  }), domainResult);
});

test("maps catalog probes by path and redacts literal bodies", async () => {
  const magentoPath = "/magento_version";
  const typo3Path = "/typo3/sysext/core/Resources/Public/Images/typo3_orange.svg";
  const rules = [
    rule(1, "Magento", {
      source: "probe",
      locator: magentoPath,
      pattern: "magento",
      matchMode: "literal",
    }),
    rule(2, "TYPO3 CMS", {
      source: "probe",
      locator: typo3Path,
      pattern: null,
      matchMode: "presence",
    }),
  ];
  const fingerprintCatalog = catalog(
    [technology("Magento"), technology("TYPO3 CMS")],
    rules,
  );
  let observed: readonly DetectorCandidate[] = [];
  const input = htmlEntry();
  const result = await detectHttp(input, {
    catalog: fingerprintCatalog,
    config: defaultConfig,
    probes: [
      { path: typo3Path, body: "" },
      { path: magentoPath, body: "release=MAGENTO 2" },
      { path: magentoPath, body: "release=MAGENTO 2" },
    ],
    pool: fakePool(fingerprintCatalog, (candidates) => {
      observed = candidates;
      const magento = candidateOrdinal(
        candidates,
        (candidate) => candidate.source === "probe"
          && candidate.key === magentoPath,
      );
      const typo3 = candidateOrdinal(
        candidates,
        (candidate) => candidate.source === "probe"
          && candidate.key === typo3Path,
      );
      return emptyMatchResult({
        matches: [
          {
            ruleOrdinal: 0,
            candidateOrdinal: magento,
            index: "release=".length,
            length: "MAGENTO".length,
            version: null,
          },
          {
            ruleOrdinal: 1,
            candidateOrdinal: typo3,
            index: 0,
            length: 0,
            version: null,
          },
        ],
      });
    }),
  });

  assert.deepEqual(
    observed
      .filter((candidate) => candidate.source === "probe")
      .map(({ kind, key, value }) => [kind, key, value]),
    [
      ["value", magentoPath, "release=MAGENTO 2"],
      ["value", typo3Path, ""],
    ],
  );
  assert.equal(result.signalAdmitted, true);
  assert.deepEqual(
    result.technologies.map((item) => ({
      name: item.name,
      pageIds: item.pageIds,
      evidence: item.evidence.map((evidence) => ({
        collector: evidence.collector,
        source: evidence.source,
        pageId: evidence.pageId,
        key: evidence.key,
        pattern: evidence.pattern,
        match: evidence.match,
      })),
    })),
    [
      {
        name: "Magento",
        pageIds: [],
        evidence: [{
          collector: "http",
          source: "probe",
          pageId: null,
          key: magentoPath,
          pattern: "magento",
          match: { kind: "redacted", value: null, truncated: false },
        }],
      },
      {
        name: "TYPO3 CMS",
        pageIds: [],
        evidence: [{
          collector: "http",
          source: "probe",
          pageId: null,
          key: typo3Path,
          pattern: null,
          match: { kind: "presence", value: null, truncated: false },
        }],
      },
    ],
  );
});

test("merges browser observations once and preserves every evidence page", async () => {
  const domLocator = JSON.stringify(["#app", "exists", null]);
  const rules = [
    rule(1, "Rendered stack", {
      source: "dom",
      locator: domLocator,
      pattern: null,
      matchMode: "presence",
      confidence: 25,
    }),
    rule(2, "Rendered stack", {
      source: "javascript",
      locator: "App.version",
      pattern: "1\\.2\\.3",
      confidence: 25,
      versionTemplate: "\\1",
    }),
    rule(3, "Rendered stack", {
      source: "script_url",
      locator: null,
      pattern: "shared\\.js",
      confidence: 20,
    }),
    rule(4, "Rendered API", {
      source: "network_url",
      locator: null,
      pattern: "/umbraco/api/",
      confidence: 35,
    }),
  ];
  const fingerprintCatalog = catalog(
    [technology("Rendered API"), technology("Rendered stack")],
    rules,
  );
  const sharedScriptUrl = "https://cdn.vendor.tld/shared.js";
  const browserPages: readonly BrowserPageObservations[] = [{
    pageId: "p2",
    finalUrl: "https://shop.vendor.tld/detail",
    dom: [{ pageId: "p2", locator: domLocator, fact: { kind: "presence" } }],
    javascript: [{
      pageId: "p2",
      path: "App.version",
      fact: { kind: "value", value: "1.2.3" },
    }],
    cookies: [{ name: "safe-cookie", value: "value" }],
    networkHostnames: ["cdn.vendor.tld"],
    scriptUrls: ["https://cdn.vendor.tld/dynamic.js"],
    scriptBodies: [{
      pageId: "p2",
      url: "https://cdn.vendor.tld/dynamic.js",
      content: "webpack runtime",
    }],
    navigationLinks: ["https://shop.vendor.tld/listing"],
    networkUrls: ["https://api.vendor.tld/umbraco/api/status"],
    truncated: false,
  }, {
    pageId: "p3",
    finalUrl: "https://shop.vendor.tld/listing",
    dom: [],
    javascript: [],
    cookies: [],
    networkUrls: [],
    networkHostnames: [],
    scriptUrls: [sharedScriptUrl],
    scriptBodies: [],
    navigationLinks: [],
    truncated: false,
  }];
  let observed: readonly DetectorCandidate[] = [];
  const pool = fakePool(fingerprintCatalog, (candidates) => {
    observed = candidates;
    const domOrdinal = candidateOrdinal(
      candidates,
      (candidate) => candidate.source === "dom" && candidate.key === domLocator,
    );
    const javascriptOrdinal = candidateOrdinal(
      candidates,
      (candidate) => candidate.source === "javascript"
        && candidate.key === "App.version",
    );
    const sharedOrdinals = candidates
      .map((candidate, index) => ({ candidate, index }))
      .filter(({ candidate }) =>
        candidate.source === "script_url" && candidate.value === sharedScriptUrl)
      .map(({ index }) => index);
    const networkUrlOrdinal = candidateOrdinal(
      candidates,
      (candidate) => candidate.source === "network_url",
    );
    assert.equal(candidates[domOrdinal]?.kind, "presence");
    assert.equal(candidates[domOrdinal]?.value, "");
    assert.equal(candidates[javascriptOrdinal]?.kind, "value");
    assert.equal(sharedOrdinals.length, 2);
    return emptyMatchResult({
      matches: [
        {
          ruleOrdinal: 0,
          candidateOrdinal: domOrdinal,
          index: 0,
          length: 0,
          version: null,
        },
        {
          ruleOrdinal: 1,
          candidateOrdinal: javascriptOrdinal,
          index: 0,
          length: 5,
          version: "1.2.3",
        },
        ...sharedOrdinals.map((candidateOrdinal) => ({
          ruleOrdinal: 2,
          candidateOrdinal,
          index: sharedScriptUrl.indexOf("shared.js"),
          length: "shared.js".length,
          version: null,
        })),
        {
          ruleOrdinal: 3,
          candidateOrdinal: networkUrlOrdinal,
          index: candidates[networkUrlOrdinal]!.value.indexOf("/umbraco/api/"),
          length: "/umbraco/api/".length,
          version: null,
        },
      ],
    });
  });
  const result = await detectHttp(htmlEntry({
    resources: [{ kind: "script", url: sharedScriptUrl }],
  }), {
    catalog: fingerprintCatalog,
    pool,
    config: defaultConfig,
    browserPages,
  });
  const byName = new Map(result.technologies.map((item) => [item.name, item]));
  const rendered = byName.get("Rendered stack");
  const renderedApi = byName.get("Rendered API");

  assert.equal(rendered?.name, "Rendered stack");
  assert.equal(rendered?.confidence, 70);
  assert.equal(rendered?.version, null);
  assert.deepEqual(rendered?.pageIds, ["p1", "p2", "p3"]);
  assert.deepEqual(renderedApi?.pageIds, ["p2"]);
  assert.deepEqual(renderedApi?.evidence[0], {
    collector: "browser",
    source: "network_url",
    pageId: "p2",
    key: null,
    match: {
      kind: "value",
      value: "https://api.vendor.tld/umbraco/api/status",
      truncated: false,
    },
    ruleId: hashId(4),
    pattern: "/umbraco/api/",
    confidence: 35,
    version: null,
  });
  assert.deepEqual(
    rendered?.evidence.map((item) => [item.collector, item.pageId, item.source]),
    [
      ["http", "p1", "script_url"],
      ["browser", "p3", "script_url"],
      ["browser", "p2", "dom"],
      ["browser", "p2", "javascript"],
    ],
  );
  assert.equal(
    observed.some((candidate) => candidate.source === "script_content"),
    true,
  );
  assert.equal(
    observed.some((candidate) => candidate.source === "network_url"),
    true,
  );
  assert.equal(
    observed.some((candidate) => candidate.source === "network_hostname"),
    true,
  );
  assert.deepEqual(
    [...new Set(observed.map((candidate) =>
      (candidate as DetectorCandidate & { readonly collector: string }).collector))],
    ["http", "browser"],
  );
  assert.equal(result.completed, true);
  assert.deepEqual(result.errors, []);

  const configDigest = computeConfigDigest(defaultConfig);
  const domainResult: DomainResult = {
    schemaVersion: 1,
    runId: "37937a78-f39d-49ed-a51d-6d398ae45a20",
    domain: "shop.vendor.tld",
    scannedAt: "2026-08-17T00:00:00.000Z",
    status: "success",
    finalUrl: "https://shop.vendor.tld/",
    scanMode: "full",
    pages: [{
      id: "p1",
      role: "entry",
      url: "https://shop.vendor.tld/",
      httpStatus: 200,
      collectors: ["http", "browser"],
    }, {
      id: "p2",
      role: "detail",
      url: "https://shop.vendor.tld/detail",
      httpStatus: 200,
      collectors: ["http", "browser"],
    }, {
      id: "p3",
      role: "listing",
      url: "https://shop.vendor.tld/listing",
      httpStatus: 200,
      collectors: ["http", "browser"],
    }],
    technologies: result.technologies,
    detectionStats: result.detectionStats,
    errors: [],
    timings: {
      totalMs: 1,
      targetMs: 0,
      robotsMs: 0,
      httpMs: 0,
      dnsMs: 0,
      tlsMs: 0,
      browserMs: 0,
      detectMs: 0,
    },
    usage: {
      httpRequests: 3,
      browserRequests: 3,
      retries: 0,
      pagesVisited: 3,
      probesIssued: 0,
      scriptBodiesInspected: 1,
      staticTransferredBytes: 1,
      browserTransferredBytes: 1,
    },
    provenance: {
      scannerVersion: "0.1.0",
      runtime: {
        node: "24.19.0",
        playwright: "1.62.1",
        chromiumRevision: "chromium-fixture",
      },
      catalog: {
        source: fingerprintCatalog.source,
        revision: fingerprintCatalog.revision,
        digest: fingerprintCatalog.digest,
      },
      configDigest,
    },
  };
  assert.equal(validateDomainResult(domainResult, {
    scanConfig: defaultConfig,
    expectedConfigDigest: configDigest,
    signalAdmitted: result.signalAdmitted,
  }), domainResult);
});

test("links HTML evidence to p1 and non-HTML and robots evidence to no page", async () => {
  const rules = [
    rule(1, "Page header"),
    rule(2, "Robots", {
      source: "robots",
      locator: null,
      pattern: "Disallow",
    }),
  ];
  const fingerprintCatalog = catalog(
    [technology("Page header"), technology("Robots")],
    rules,
  );
  const pool = directRulePool(fingerprintCatalog);
  const robots = [{
    ownerOrigin: "https://shop.vendor.tld",
    fetchedUrl: "https://shop.vendor.tld/robots.txt",
    text: "Disallow: /private",
  }] as const;
  const html = await detectHttp(htmlEntry({
    response: response({ headers: [{ name: "server", value: "fixture" }] }),
  }, { robots }), {
    catalog: fingerprintCatalog,
    pool,
    config: defaultConfig,
  });
  const nonHtml: HttpEntryResult = {
    kind: "non-html",
    response: response({ headers: [{ name: "server", value: "fixture" }] }),
    robots,
    errors: [],
  };
  const nonHtmlResult = await detectHttp(nonHtml, {
    catalog: fingerprintCatalog,
    pool,
    config: defaultConfig,
  });

  assert.deepEqual(
    html.technologies.map((item) => [item.name, item.evidence[0]?.pageId]),
    [["Page header", "p1"], ["Robots", null]],
  );
  assert.deepEqual(
    nonHtmlResult.technologies.map((item) => [item.name, item.evidence[0]?.pageId]),
    [["Page header", null], ["Robots", null]],
  );
});

test("publishes safe exact matches and redacts sensitive or raw HTTP values", async () => {
  const rules = [
    rule(1, "Script", {
      source: "script_url",
      locator: null,
      pattern: "app-([0-9.]+)\\.js",
      confidence: 30,
      versionTemplate: "\\1",
    }),
    rule(2, "Server", { pattern: "nginx", confidence: 40 }),
    rule(3, "Authorization", {
      locator: "authorization",
      pattern: "Bearer",
    }),
    rule(4, "Cookie", {
      source: "cookie",
      locator: "session",
      locatorPattern: "^(?:session)$",
      pattern: "secret",
      versionTemplate: "\\1",
    }),
    rule(5, "HTML", {
      source: "html",
      locator: null,
      pattern: "private-value",
    }),
    rule(6, "Generator", {
      source: "meta",
      locator: "generator",
      pattern: "Fixture",
    }),
    rule(7, "Unsafe meta", {
      source: "meta",
      locator: "description",
      pattern: "private",
    }),
    rule(8, "Query version", {
      source: "script_url",
      locator: null,
      pattern:
        "^https://cdn\\.vendor\\.tld/query\\.js(?=\\?access_token=([A-Za-z0-9]+))",
      versionTemplate: "\\1",
    }),
    rule(9, "Sensitive path version", {
      source: "script_url",
      locator: null,
      pattern: "(hunter2)",
      versionTemplate: "\\1",
    }),
  ];
  const fingerprintCatalog = catalog(
    rules.map((item) => technology(item.technology)),
    rules,
  );
  const pool = fakePool(fingerprintCatalog, (candidates) => emptyMatchResult({
    matches: [
      workerMatch(
        candidates,
        0,
        (item) => item.source === "script_url" && item.value.includes("app-1.2.0.js"),
        {
          index: candidates.find(
            (item) => item.source === "script_url"
              && item.value.includes("app-1.2.0.js"),
          )?.value.indexOf("app-1.2.0.js") ?? -1,
          length: "app-1.2.0.js".length,
          version: "1.2.0",
        },
      ),
      workerMatch(candidates, 1, (item) => item.key === "server", {
        length: 5,
        version: "1.25.0",
      }),
      workerMatch(candidates, 2, (item) => item.key === "authorization", {
        length: 6,
      }),
      workerMatch(candidates, 3, (item) => item.source === "cookie", {
        length: 6,
        version: "9.9.9",
      }),
      workerMatch(candidates, 4, (item) => item.source === "html", {
        index: 6,
        length: 13,
      }),
      workerMatch(candidates, 5, (item) => item.key === "generator", {
        length: 7,
      }),
      workerMatch(candidates, 6, (item) => item.key === "description", {
        length: 7,
      }),
      workerMatch(
        candidates,
        7,
        (item) => item.source === "script_url" && item.value.includes("query.js"),
        {
          index: 0,
          length: "https://cdn.vendor.tld/query.js".length,
          version: "hunter2",
        },
      ),
      workerMatch(
        candidates,
        8,
        (item) => item.source === "script_url" && item.value.includes("/token/"),
        {
          index: candidates.find(
            (item) => item.source === "script_url" && item.value.includes("/token/"),
          )?.value.indexOf("hunter2") ?? -1,
          length: "hunter2".length,
          version: "hunter2",
        },
      ),
    ],
  }));
  const input = htmlEntry({
    response: response({
      headers: [
        { name: "server", value: "nginx/1.25.0" },
        { name: "authorization", value: "Bearer private-token" },
      ],
      cookies: [{ name: "session", value: "secret" }],
    }),
    html: "<body>private-value</body>",
    metadata: [
      { key: "generator", value: "Fixture CMS" },
      { key: "description", value: "private description" },
    ],
    resources: [
      {
        kind: "script",
        url: "https://cdn.vendor.tld/app-1.2.0.js",
      },
      {
        kind: "script",
        url: "https://cdn.vendor.tld/query.js?access_token=hunter2",
      },
      {
        kind: "script",
        url: "https://cdn.vendor.tld/token/hunter2",
      },
    ],
  });

  const result = await detectHttp(input, {
    catalog: fingerprintCatalog,
    pool,
    config: defaultConfig,
  });
  const byName = new Map(result.technologies.map((item) => [item.name, item]));

  assert.deepEqual(byName.get("Script")?.evidence[0]?.match, {
    kind: "value",
    value: "https://cdn.vendor.tld/app-1.2.0.js",
    truncated: false,
  });
  assert.equal(byName.get("Script")?.version, "1.2.0");
  assert.deepEqual(byName.get("Query version")?.evidence[0]?.match, {
    kind: "value",
    value: "https://cdn.vendor.tld/query.js?%5Bredacted%5D=%5Bredacted%5D",
    truncated: false,
  });
  assert.equal(byName.get("Query version")?.version, null);
  assert.deepEqual(byName.get("Sensitive path version")?.evidence[0]?.match, {
    kind: "value",
    value: "https://cdn.vendor.tld/%5Bredacted%5D/%5Bredacted%5D",
    truncated: false,
  });
  assert.equal(byName.get("Sensitive path version")?.version, null);
  assert.deepEqual(byName.get("Server")?.evidence[0]?.match, {
    kind: "value",
    value: "nginx",
    truncated: false,
  });
  assert.equal(byName.get("Server")?.version, "1.25.0");
  assert.equal(byName.get("Generator")?.evidence[0]?.match.value, "Fixture");

  for (const name of ["Authorization", "Cookie", "HTML", "Unsafe meta"]) {
    assert.deepEqual(byName.get(name)?.evidence[0]?.match, {
      kind: "redacted",
      value: null,
      truncated: false,
    });
    assert.equal(byName.get(name)?.version, null);
    assert.equal(byName.get(name)?.evidence[0]?.version, null);
  }
});

test("redacts credential schemes and token-like derived versions", async () => {
  const rules = [
    rule(1, "Broad header", {
      locator: "x-aspnet-version",
      pattern: "(.+)",
      versionTemplate: "\\1",
    }),
    rule(2, "URL token", {
      source: "script_url",
      locator: null,
      pattern: "(token-secret)",
      versionTemplate: "\\1",
    }),
    rule(3, "Broad meta", {
      source: "meta",
      locator: "generator",
      pattern: "(.+)",
      versionTemplate: "\\1",
    }),
    rule(4, "Auth header", {
      locator: "x-auth",
      pattern: "(.+)",
      versionTemplate: "\\1",
    }),
  ];
  const fingerprintCatalog = catalog(
    [
      technology("Broad header"),
      technology("Broad meta"),
      technology("Auth header"),
      technology("URL token"),
    ],
    rules,
  );
  const pool = fakePool(fingerprintCatalog, (candidates) => emptyMatchResult({
    matches: [
      workerMatch(
        candidates,
        0,
        (candidate) => candidate.key === "x-aspnet-version",
        {
          length: "EasyEngine Basic dXNlcjpwYXNz".length,
          version: "dXNlcjpwYXNz",
        },
      ),
      workerMatch(
        candidates,
        1,
        (candidate) => candidate.source === "script_url",
        {
          index: candidates.find(
            (candidate) => candidate.source === "script_url",
          )?.value.indexOf("token-secret") ?? -1,
          length: "token-secret".length,
          version: "token-secret",
        },
      ),
      workerMatch(
        candidates,
        2,
        (candidate) => candidate.key === "generator",
        {
          length: "MediaWiki Bearer hunter2".length,
          version: "hunter2",
        },
      ),
      workerMatch(
        candidates,
        3,
        (candidate) => candidate.key === "x-auth",
        { length: "hunter2".length, version: "hunter2" },
      ),
    ],
  }));
  const result = await detectHttp(htmlEntry({
    response: response({
      headers: [
        {
          name: "x-aspnet-version",
          value: "EasyEngine Basic dXNlcjpwYXNz",
        },
        { name: "x-auth", value: "hunter2" },
      ],
    }),
    metadata: [{ key: "generator", value: "MediaWiki Bearer hunter2" }],
    resources: [{
      kind: "script",
      url: "https://cdn.vendor.tld/token-secret.js",
    }],
  }), {
    catalog: fingerprintCatalog,
    pool,
    config: defaultConfig,
  });
  const byName = new Map(result.technologies.map((item) => [item.name, item]));

  assert.equal(byName.get("Broad header")?.evidence[0]?.match.kind, "redacted");
  assert.equal(byName.get("Broad header")?.version, null);
  assert.equal(byName.get("Broad meta")?.evidence[0]?.match.kind, "redacted");
  assert.equal(byName.get("Broad meta")?.version, null);
  assert.equal(byName.get("Auth header")?.evidence[0]?.match.kind, "redacted");
  assert.equal(byName.get("Auth header")?.version, null);
  assert.equal(byName.get("URL token")?.evidence[0]?.match.kind, "value");
  assert.equal(byName.get("URL token")?.version, null);
});

test("forces presence evidence and versions to the presence contract", async () => {
  const rules = [rule(1, "Presence", {
    pattern: null,
    matchMode: "presence",
    confidence: 45,
    versionTemplate: "\\1",
  })];
  const fingerprintCatalog = catalog([technology("Presence")], rules);
  const pool = fakePool(fingerprintCatalog, (candidates) => emptyMatchResult({
    matches: [workerMatch(
      candidates,
      0,
      (item) => item.key === "server",
      { length: 0, version: "9.9.9" },
    )],
  }));
  const result = await detectHttp(htmlEntry({
    response: response({ headers: [{ name: "server", value: "anything" }] }),
  }), {
    catalog: fingerprintCatalog,
    pool,
    config: defaultConfig,
  });
  const item = result.technologies[0];

  assert.deepEqual(item?.evidence[0], {
    collector: "http",
    source: "header",
    pageId: "p1",
    key: "server",
    match: { kind: "presence", value: null, truncated: false },
    ruleId: hashId(1),
    pattern: null,
    confidence: 45,
    version: null,
  });
  assert.equal(item?.version, null);
});

test("counts confidence and version support once per unique rule", async () => {
  const rules = [
    rule(1, "Versioned", {
      source: "script_url",
      locator: null,
      confidence: 40,
      versionTemplate: "\\1",
    }),
    rule(2, "Versioned", {
      source: "script_url",
      locator: null,
      confidence: 30,
      versionTemplate: "\\1",
    }),
    rule(3, "Versioned", {
      source: "script_url",
      locator: null,
      confidence: 30,
      versionTemplate: "\\1",
    }),
  ];
  const fingerprintCatalog = catalog([technology("Versioned")], rules);
  const pool = fakePool(fingerprintCatalog, (candidates) => {
    const first = candidateOrdinal(
      candidates,
      (item) => item.value.includes("first.js"),
    );
    const second = candidateOrdinal(
      candidates,
      (item) => item.value.includes("second.js"),
    );
    return emptyMatchResult({
      matches: [
        { ruleOrdinal: 0, candidateOrdinal: first, index: 0, length: 5, version: "1.0" },
        { ruleOrdinal: 0, candidateOrdinal: second, index: 0, length: 5, version: "1.0" },
        { ruleOrdinal: 0, candidateOrdinal: first, index: 0, length: 5, version: "1.0" },
        { ruleOrdinal: 1, candidateOrdinal: first, index: 0, length: 5, version: "2.0" },
        { ruleOrdinal: 2, candidateOrdinal: second, index: 0, length: 5, version: "1.0" },
      ],
    });
  });
  const result = await detectHttp(htmlEntry({
    resources: [
      { kind: "script", url: "https://cdn.vendor.tld/second.js" },
      { kind: "script", url: "https://cdn.vendor.tld/first.js" },
    ],
  }), {
    catalog: fingerprintCatalog,
    pool,
    config: defaultConfig,
  });
  const item = result.technologies[0];

  assert.equal(item?.confidence, 100);
  assert.equal(item?.version, "1.0");
  assert.equal(item?.evidence.length, 4);

  const tiedRules = [
    rule(4, "Tie", { confidence: 50, versionTemplate: "\\1" }),
    rule(5, "Tie", { confidence: 50, versionTemplate: "\\1" }),
  ];
  const tiedCatalog = catalog([technology("Tie")], tiedRules);
  const tiedResult = await detectHttp(htmlEntry({
    response: response({ headers: [{ name: "server", value: "fixture" }] }),
  }), {
    catalog: tiedCatalog,
    pool: fakePool(tiedCatalog, (candidates) => emptyMatchResult({
      matches: [
        workerMatch(candidates, 0, (candidate) => candidate.key === "server", {
          version: "1.0",
        }),
        workerMatch(candidates, 1, (candidate) => candidate.key === "server", {
          version: "2.0",
        }),
      ],
    })),
    config: defaultConfig,
  });

  assert.equal(tiedResult.technologies[0]?.version, null);
});

test("uses zero-confidence matches only as companions to positive evidence", async () => {
  const technologies = [
    technology("Companion"),
    technology("Gated by zero", { requires: ["Zero only"] }),
    technology("Zero inferred"),
    technology("Zero only", {
      implies: [implication(101, "Zero inferred")],
      excludes: ["Companion"],
    }),
  ];
  const rules = [
    rule(1, "Companion", { locator: "x-companion", confidence: 60 }),
    rule(2, "Companion", {
      locator: "x-companion-version",
      confidence: 0,
      versionTemplate: "\\1",
    }),
    rule(3, "Zero only", { locator: "x-zero", confidence: 0 }),
    rule(4, "Gated by zero", { locator: "x-gated", confidence: 100 }),
  ];
  const fingerprintCatalog = catalog(technologies, rules);
  const result = await detectHttp(htmlEntry({
    response: response({ headers: [
      { name: "x-companion", value: "fixture" },
      { name: "x-companion-version", value: "9.1" },
      { name: "x-zero", value: "fixture" },
      { name: "x-gated", value: "fixture" },
    ] }),
  }), {
    catalog: fingerprintCatalog,
    pool: fakePool(fingerprintCatalog, (candidates) => emptyMatchResult({
      matches: [
        workerMatch(candidates, 0, (item) => item.key === "x-companion"),
        workerMatch(
          candidates,
          1,
          (item) => item.key === "x-companion-version",
          { version: "9.1" },
        ),
        workerMatch(candidates, 2, (item) => item.key === "x-zero"),
        workerMatch(candidates, 3, (item) => item.key === "x-gated"),
      ],
    })),
    config: defaultConfig,
  });
  const companion = result.technologies[0];

  assert.deepEqual(result.technologies.map((item) => item.name), ["Companion"]);
  assert.equal(companion?.confidence, 60);
  assert.equal(companion?.version, "9.1");
  assert.deepEqual(
    companion?.evidence.map((item) => item.confidence),
    [60, 0],
  );
});

test("keeps multiple cookie keys for one locator rule without double confidence", async () => {
  const rules = [rule(1, "Adobe ColdFusion", {
    source: "cookie",
    locator: "CFID|CFTOKEN",
    locatorPattern: "^(?:CFID|CFTOKEN)$",
    pattern: null,
    matchMode: "presence",
    confidence: 55,
  })];
  const fingerprintCatalog = catalog([technology("Adobe ColdFusion")], rules);
  const result = await detectHttp(htmlEntry({
    response: response({
      cookies: [
        { name: "CFTOKEN", value: "private-token" },
        { name: "CFID", value: "private-id" },
      ],
    }),
  }), {
    catalog: fingerprintCatalog,
    pool: fakePool(fingerprintCatalog, (candidates) => emptyMatchResult({
      matches: ["CFID", "CFTOKEN"].map((key) => workerMatch(
        candidates,
        0,
        (candidate) => candidate.source === "cookie" && candidate.key === key,
        { length: 0 },
      )),
    })),
    config: defaultConfig,
  });
  const detected = result.technologies[0];

  assert.equal(detected?.confidence, 55);
  assert.deepEqual(
    detected?.evidence.map((item) => [item.ruleId, item.key]),
    [[hashId(1), "CFID"], [hashId(1), "CFTOKEN"]],
  );
});

test("matches a Drupal-like session cookie without publishing its token key", async () => {
  const sessionName = `SESS${"a".repeat(32)}`;
  const rules = [rule(1, "Drupal", {
    source: "cookie",
    locator: "SESS[a-f0-9]{32}",
    locatorPattern: "^(?:SESS[a-f0-9]{32})$",
    pattern: null,
    matchMode: "presence",
  })];
  const fingerprintCatalog = catalog([technology("Drupal")], rules);
  let matchedCandidateKey: string | null = null;
  const result = await detectHttp(htmlEntry({
    response: response({ cookies: [{ name: sessionName, value: "private" }] }),
  }), {
    catalog: fingerprintCatalog,
    pool: fakePool(fingerprintCatalog, (candidates) => {
      const candidate = candidates.find((item) => item.source === "cookie");
      matchedCandidateKey = candidate?.key ?? null;
      return emptyMatchResult({
        matches: [workerMatch(
          candidates,
          0,
          (item) => item.source === "cookie" && item.key === sessionName,
          { length: 0 },
        )],
      });
    }),
    config: defaultConfig,
  });

  assert.equal(matchedCandidateKey, sessionName);
  assert.equal(result.technologies[0]?.evidence[0]?.key, null);
  assert.deepEqual(result.technologies[0]?.evidence[0]?.match, {
    kind: "presence",
    value: null,
    truncated: false,
  });
});

test("resolves technology and category gates with implications to a fixed point", async () => {
  const categories = [
    defaultCategory,
    { id: 2, name: "Unlock category" },
    { id: 3, name: "Self category" },
  ];
  const technologies = [
    technology("Category gate", { requiresCategory: [2] }),
    technology("Implied parent"),
    technology("Root", {
      implies: [implication(101, "Implied parent", 80)],
    }),
    technology("Self gate", {
      categories: [categories[2]!],
      requiresCategory: [3],
    }),
    technology("Technology gate", {
      categories: [categories[1]!],
      requires: ["Implied parent"],
    }),
  ];
  const rules = [
    rule(1, "Root", { locator: "x-root", confidence: 90 }),
    rule(2, "Technology gate", { locator: "x-tech", confidence: 70 }),
    rule(3, "Category gate", { locator: "x-category", confidence: 60 }),
    rule(4, "Self gate", { locator: "x-self", confidence: 100 }),
  ];
  const fingerprintCatalog = catalog(technologies, rules, categories);
  const result = await detectHttp(htmlEntry({
    response: response({
      headers: [
        { name: "x-self", value: "fixture" },
        { name: "x-category", value: "fixture" },
        { name: "x-tech", value: "fixture" },
        { name: "x-root", value: "fixture" },
      ],
    }),
  }), {
    catalog: fingerprintCatalog,
    pool: directRulePool(fingerprintCatalog),
    config: defaultConfig,
  });

  assert.deepEqual(result.technologies.map((item) => item.name), [
    "Category gate",
    "Implied parent",
    "Root",
    "Technology gate",
  ]);
  assert.equal(
    result.technologies.find((item) => item.name === "Implied parent")?.type,
    "inferred",
  );
  assert.equal(
    result.technologies.find((item) => item.name === "Technology gate")?.type,
    "direct",
  );
  assert.equal(result.technologies.some((item) => item.name === "Self gate"), false);
  assert.deepEqual(result.detectionStats, {
    rawDirect: 4,
    gatedDirect: 1,
    suppressedDirect: 0,
    retainedDirect: 3,
  });
});

test("uses widest implication paths, then minimum depth, with all winning parents", async () => {
  const technologies = [
    technology("Mid one", {
      implies: [
        implication(201, "Strong target", 100, "3.0"),
        implication(202, "Parent target", 100, "1.0"),
      ],
    }),
    technology("Mid two", {
      implies: [implication(203, "Parent target", 100, "2.0")],
    }),
    technology("Parent target"),
    technology("Root one", {
      implies: [
        implication(204, "Mid one", 70),
        implication(205, "Mid two", 70),
      ],
    }),
    technology("Root short", {
      implies: [
        implication(206, "Strong target", 60),
        implication(207, "Short target", 100),
      ],
    }),
    technology("Root tie", {
      implies: [implication(208, "Short target", 70)],
    }),
    technology("Short target"),
    technology("Strong target"),
  ];
  const rules = [
    rule(1, "Root one", { locator: "x-one", confidence: 80 }),
    rule(2, "Root short", { locator: "x-short", confidence: 60 }),
    rule(3, "Root tie", { locator: "x-tie", confidence: 70 }),
  ];
  const fingerprintCatalog = catalog(technologies, rules);
  const result = await detectHttp(htmlEntry({
    response: response({ headers: [
      { name: "x-tie", value: "fixture" },
      { name: "x-short", value: "fixture" },
      { name: "x-one", value: "fixture" },
    ] }),
  }), {
    catalog: fingerprintCatalog,
    pool: directRulePool(fingerprintCatalog),
    config: defaultConfig,
  });
  const byName = new Map(result.technologies.map((item) => [item.name, item]));

  assert.equal(byName.get("Strong target")?.confidence, 70);
  assert.deepEqual(
    byName.get("Strong target")?.inferredFrom.map((item) => item.technology),
    ["Mid one"],
  );
  assert.equal(byName.get("Short target")?.confidence, 70);
  assert.deepEqual(
    byName.get("Short target")?.inferredFrom.map((item) => item.technology),
    ["Root tie"],
  );
  assert.equal(byName.get("Parent target")?.confidence, 70);
  assert.deepEqual(
    byName.get("Parent target")?.inferredFrom.map((item) => item.technology),
    ["Mid one", "Mid two"],
  );
  assert.equal(byName.get("Parent target")?.version, null);
});

test("collects 5k equal winning parents without repeated provenance sorting", async () => {
  const count = 5_000;
  const target = "Fan-in target";
  const names = Array.from(
    { length: count },
    (_, index) => `Fan-in ${index.toString().padStart(5, "0")}`,
  );
  const technologies = [
    ...names.map((name, index) => technology(name, {
      implies: [implication(index + 200_000, target)],
    })),
    technology(target),
  ];
  const rules = names.map((name, index) => rule(index + 80_000, name, {
    locator: `x-fan-in-${index.toString().padStart(5, "0")}`,
  }));
  const fingerprintCatalog = catalog(technologies, rules);
  const startedAt = performance.now();
  const result = await detectHttp(htmlEntry({
    response: response({
      headers: rules.map((item) => ({ name: item.locator!, value: "fixture" })),
    }),
  }), {
    catalog: fingerprintCatalog,
    pool: indexedHeaderPool(fingerprintCatalog),
    config: defaultConfig,
  });
  const elapsedMs = performance.now() - startedAt;

  assert.deepEqual(result.technologies, []);
  assert.equal(result.completed, false);
  assert.equal(
    result.errors.some((item) => item.code === "RESULT_LIMIT_EXCEEDED"),
    true,
  );
  assert.ok(elapsedMs < 8_000, `5k implication parents took ${elapsedMs}ms`);
});

test("keeps exclusion direction in chains and prevents suppressed nodes from acting", async () => {
  const technologies = [
    technology("A", { excludes: ["B"] }),
    technology("B", { excludes: ["C"] }),
    technology("C"),
  ];
  const rules = [
    rule(1, "A", { locator: "x-a", confidence: 10 }),
    rule(2, "B", { locator: "x-b", confidence: 100 }),
    rule(3, "C", { locator: "x-c", confidence: 100 }),
  ];
  const fingerprintCatalog = catalog(technologies, rules);
  const result = await detectHttp(htmlEntry({
    response: response({ headers: [
      { name: "x-c", value: "fixture" },
      { name: "x-b", value: "fixture" },
      { name: "x-a", value: "fixture" },
    ] }),
  }), {
    catalog: fingerprintCatalog,
    pool: directRulePool(fingerprintCatalog),
    config: defaultConfig,
  });

  assert.deepEqual(result.technologies.map((item) => item.name), ["A", "C"]);
  assert.deepEqual(result.detectionStats, {
    rawDirect: 3,
    gatedDirect: 0,
    suppressedDirect: 1,
    retainedDirect: 2,
  });
});

test("breaks exclusion cycles only after external edges and uses the SCC rank", async () => {
  const technologies = [
    technology("Direct", { excludes: ["Inferred"] }),
    technology("External", { excludes: ["X"] }),
    technology("Inferred", { excludes: ["Direct"] }),
    technology("Lex A", { excludes: ["Lex B"] }),
    technology("Lex B", { excludes: ["Lex A"] }),
    technology("Root", {
      implies: [implication(301, "Inferred", 100)],
    }),
    technology("X", { excludes: ["Y"] }),
    technology("Y", { excludes: ["X"] }),
  ];
  const rules = [
    rule(1, "Direct", { locator: "x-direct", confidence: 1 }),
    rule(2, "External", { locator: "x-external", confidence: 50 }),
    rule(3, "Lex A", { locator: "x-lex-a", confidence: 50 }),
    rule(4, "Lex B", { locator: "x-lex-b", confidence: 50 }),
    rule(5, "Root", { locator: "x-root", confidence: 100 }),
    rule(6, "X", { locator: "x-x", confidence: 100 }),
    rule(7, "Y", { locator: "x-y", confidence: 1 }),
  ];
  const fingerprintCatalog = catalog(technologies, rules);
  const result = await detectHttp(htmlEntry({
    response: response({ headers: rules.map((item) => ({
      name: item.locator!,
      value: "fixture",
    })) }),
  }), {
    catalog: fingerprintCatalog,
    pool: directRulePool(fingerprintCatalog),
    config: defaultConfig,
  });

  assert.deepEqual(result.technologies.map((item) => item.name), [
    "Direct",
    "External",
    "Lex A",
    "Root",
    "Y",
  ]);
});

test("resolves an exclusion cycle deeper than the JavaScript call stack", async () => {
  const count = 5_000;
  const names = Array.from(
    { length: count },
    (_, index) => `Cycle ${index.toString().padStart(5, "0")}`,
  );
  const technologies = names.map((name, index) => technology(name, {
    excludes: [names[(index + 1) % count]!],
  }));
  const rules = names.map((name, index) => rule(index + 1_000, name, {
    locator: `x-cycle-${index.toString().padStart(5, "0")}`,
    confidence: 50,
  }));
  const fingerprintCatalog = catalog(technologies, rules);
  const result = await detectHttp(htmlEntry({
    response: response({
      headers: rules.map((item) => ({ name: item.locator!, value: "fixture" })),
    }),
  }), {
    catalog: fingerprintCatalog,
    pool: indexedHeaderPool(fingerprintCatalog),
    config: defaultConfig,
  });

  assert.equal(result.completed, true);
  assert.deepEqual(result.technologies.map((item) => item.name), [names[0]]);
});

test("walks a 5k-pair SCC condensation chain without rerunning Tarjan", async () => {
  const pairCount = 5_000;
  const pairNames = Array.from({ length: pairCount }, (_, index) => {
    const prefix = `SCC pair ${index.toString().padStart(5, "0")}`;
    return { a: `${prefix} A`, b: `${prefix} B` };
  });
  const technologies = pairNames.flatMap((names, index) => [
    technology(names.a, { excludes: [names.b] }),
    technology(names.b, {
      excludes: [
        names.a,
        ...(index + 1 < pairCount ? [pairNames[index + 1]!.a] : []),
      ],
    }),
  ]);
  const rules = technologies.map((item, index) => rule(index + 300_000, item.name, {
    locator: `x-scc-chain-${index.toString().padStart(5, "0")}`,
  }));
  const fingerprintCatalog = catalog(technologies, rules);
  const startedAt = performance.now();
  const result = await detectHttp(htmlEntry({
    response: response({
      headers: rules.map((item) => ({ name: item.locator!, value: "fixture" })),
    }),
  }), {
    catalog: fingerprintCatalog,
    pool: indexedHeaderPool(fingerprintCatalog),
    config: defaultConfig,
  });
  const elapsedMs = performance.now() - startedAt;

  assert.equal(result.completed, true);
  assert.deepEqual(
    result.technologies.map((item) => item.name),
    pairNames.map((names) => names.a),
  );
  assert.ok(elapsedMs < 8_000, `5k SCC pairs took ${elapsedMs}ms`);
});

test("recomposes only partially suppressed SCCs in a 4.8k-triad chain", async () => {
  const triadCount = 4_800;
  const triads = Array.from({ length: triadCount }, (_, index) => {
    const prefix = `SCC triad ${index.toString().padStart(5, "0")}`;
    return { a: `${prefix} A`, b: `${prefix} B`, c: `${prefix} C` };
  });
  const technologies = triads.flatMap((names, index) => [
    technology(names.a, {
      excludes: [
        names.b,
        names.c,
        ...(index + 1 < triadCount ? [triads[index + 1]!.b] : []),
      ],
    }),
    technology(names.b, { excludes: [names.a, names.c] }),
    technology(names.c, { excludes: [names.a, names.b] }),
  ]);
  const rules = technologies.map((item, index) => rule(index + 500_000, item.name, {
    locator: `x-scc-triad-${index.toString().padStart(5, "0")}`,
  }));
  const fingerprintCatalog = catalog(technologies, rules);
  const startedAt = performance.now();
  const result = await detectHttp(htmlEntry({
    response: response({
      headers: rules.map((item) => ({ name: item.locator!, value: "fixture" })),
    }),
  }), {
    catalog: fingerprintCatalog,
    pool: indexedHeaderPool(fingerprintCatalog),
    config: defaultConfig,
  });
  const elapsedMs = performance.now() - startedAt;

  assert.equal(result.completed, true);
  assert.deepEqual(
    result.technologies.map((item) => item.name),
    triads.map((names) => names.a),
  );
  assert.ok(elapsedMs < 8_000, `4.8k SCC triads took ${elapsedMs}ms`);
});

test("handles the configured 20k direct-technology cap without quadratic queue sorting", async () => {
  const count = defaultConfig.limits.output.technologiesPerDomain;
  const names = Array.from(
    { length: count },
    (_, index) => `Direct ${index.toString().padStart(5, "0")}`,
  );
  const technologies = names.map((name, index) => technology(name, {
    implies: index + 1 < count
      ? [implication(index + 100_000, names[index + 1]!)]
      : [],
  }));
  const rules = names.map((name, index) => rule(index + 10_000, name, {
    locator: `x-direct-${index.toString().padStart(5, "0")}`,
  }));
  const fingerprintCatalog = catalog(technologies, rules);
  const startedAt = performance.now();
  const result = await detectHttp(htmlEntry({
    response: response({
      headers: rules.map((item) => ({ name: item.locator!, value: "fixture" })),
    }),
  }), {
    catalog: fingerprintCatalog,
    pool: indexedHeaderPool(fingerprintCatalog),
    config: defaultConfig,
  });
  const elapsedMs = performance.now() - startedAt;

  assert.equal(result.completed, true);
  assert.equal(result.technologies.length, count);
  assert.ok(elapsedMs < 8_000, `20k direct detections took ${elapsedMs}ms`);
});

test("admits a 20k requires chain without rescanning every gated detection", async () => {
  const count = defaultConfig.limits.output.technologiesPerDomain;
  const names = Array.from(
    { length: count },
    (_, index) => `Gate ${index.toString().padStart(5, "0")}`,
  );
  const technologies = names.map((name, index) => technology(name, {
    requires: index === 0 ? [] : [names[index - 1]!],
  }));
  const rules = names.map((name, index) => rule(index + 30_000, name, {
    locator: `x-gate-${index.toString().padStart(5, "0")}`,
  }));
  const fingerprintCatalog = catalog(technologies, rules);
  const startedAt = performance.now();
  const result = await detectHttp(htmlEntry({
    response: response({
      headers: rules.map((item) => ({ name: item.locator!, value: "fixture" })),
    }),
  }), {
    catalog: fingerprintCatalog,
    pool: indexedHeaderPool(fingerprintCatalog),
    config: defaultConfig,
  });
  const elapsedMs = performance.now() - startedAt;

  assert.equal(result.completed, true);
  assert.equal(result.technologies.length, count);
  assert.ok(elapsedMs < 8_000, `20k gated detections took ${elapsedMs}ms`);
});

test("consumes a shared-category gate watcher list only once", async () => {
  const count = defaultConfig.limits.output.technologiesPerDomain;
  const names = Array.from(
    { length: count },
    (_, index) => `Category gate ${index.toString().padStart(5, "0")}`,
  );
  const technologies = names.map((name, index) => technology(name, {
    requiresCategory: index === 0 ? [] : [defaultCategory.id],
  }));
  const rules = names.map((name, index) => rule(index + 100_000, name, {
    locator: `x-category-gate-${index.toString().padStart(5, "0")}`,
  }));
  const fingerprintCatalog = catalog(technologies, rules);
  const startedAt = performance.now();
  const result = await detectHttp(htmlEntry({
    response: response({
      headers: rules.map((item) => ({ name: item.locator!, value: "fixture" })),
    }),
  }), {
    catalog: fingerprintCatalog,
    pool: indexedHeaderPool(fingerprintCatalog),
    config: defaultConfig,
  });
  const elapsedMs = performance.now() - startedAt;

  assert.equal(result.completed, true);
  assert.equal(result.technologies.length, count);
  assert.ok(elapsedMs < 8_000, `20k category gates took ${elapsedMs}ms`);
});

test("resolves a 20k unilateral exclusion chain with incremental indegrees", async () => {
  const count = defaultConfig.limits.output.technologiesPerDomain;
  const names = Array.from(
    { length: count },
    (_, index) => `Exclude ${index.toString().padStart(5, "0")}`,
  );
  const technologies = names.map((name, index) => technology(name, {
    excludes: index + 1 < count ? [names[index + 1]!] : [],
  }));
  const rules = names.map((name, index) => rule(index + 50_000, name, {
    locator: `x-exclude-${index.toString().padStart(5, "0")}`,
  }));
  const fingerprintCatalog = catalog(technologies, rules);
  const startedAt = performance.now();
  const result = await detectHttp(htmlEntry({
    response: response({
      headers: rules.map((item) => ({ name: item.locator!, value: "fixture" })),
    }),
  }), {
    catalog: fingerprintCatalog,
    pool: indexedHeaderPool(fingerprintCatalog),
    config: defaultConfig,
  });
  const elapsedMs = performance.now() - startedAt;

  assert.equal(result.completed, true);
  assert.deepEqual(
    result.technologies.map((item) => item.name),
    names.filter((_, index) => index % 2 === 0),
  );
  assert.ok(elapsedMs < 8_000, `20k exclusions took ${elapsedMs}ms`);
});

test("discards an oversized materialization and reports every output limit", async () => {
  const technologies = [technology("Alpha"), technology("Beta")];
  const rules = [
    rule(1, "Alpha", { locator: "x-alpha" }),
    rule(2, "Alpha", { locator: "x-alpha-two" }),
    rule(3, "Beta", { locator: "x-beta" }),
  ];
  const fingerprintCatalog = catalog(technologies, rules);
  const input = htmlEntry({
    response: response({ headers: [
      { name: "x-beta", value: "fixture" },
      { name: "x-alpha-two", value: "fixture" },
      { name: "x-alpha", value: "fixture" },
    ] }),
  });
  const technologyLimited = configWith([
    [["limits", "output", "technologiesPerDomain"], 1],
  ]);
  const technologyResult = await detectHttp(input, {
    catalog: fingerprintCatalog,
    pool: directRulePool(fingerprintCatalog),
    config: technologyLimited,
  });

  assert.deepEqual(technologyResult.technologies, []);
  assert.equal(technologyResult.completed, false);
  assert.deepEqual(
    [...new Set(technologyResult.errors.map((item) => item.code))],
    ["RESULT_LIMIT_EXCEEDED"],
  );
  assert.deepEqual(technologyResult.detectionStats, {
    rawDirect: 2,
    gatedDirect: 0,
    suppressedDirect: 0,
    retainedDirect: 2,
  });

  const evidenceLimited = configWith([
    [["limits", "output", "evidencePerTechnology"], 1],
    [["limits", "output", "evidencePerDomain"], 1],
  ]);
  const evidenceResult = await detectHttp(input, {
    catalog: fingerprintCatalog,
    pool: directRulePool(fingerprintCatalog),
    config: evidenceLimited,
  });
  assert.deepEqual(evidenceResult.technologies, []);
  assert.equal(evidenceResult.completed, false);
  assert.equal(
    evidenceResult.errors.some((item) => item.code === "RESULT_LIMIT_EXCEEDED"),
    true,
  );

  const inferenceCatalog = catalog([
    technology("Inferred"),
    technology("Root one", {
      implies: [implication(401, "Inferred")],
    }),
    technology("Root two", {
      implies: [implication(402, "Inferred")],
    }),
  ], [
    rule(4, "Root one", { locator: "x-root-one" }),
    rule(5, "Root two", { locator: "x-root-two" }),
  ]);
  const inferenceLimited = configWith([
    [["limits", "output", "inferencesPerTechnology"], 1],
    [["limits", "output", "inferencesPerDomain"], 1],
  ]);
  const inferenceResult = await detectHttp(htmlEntry({
    response: response({ headers: [
      { name: "x-root-two", value: "fixture" },
      { name: "x-root-one", value: "fixture" },
    ] }),
  }), {
    catalog: inferenceCatalog,
    pool: directRulePool(inferenceCatalog),
    config: inferenceLimited,
  });

  assert.deepEqual(inferenceResult.technologies, []);
  assert.equal(inferenceResult.completed, false);
  assert.equal(
    inferenceResult.errors.some((item) => item.code === "RESULT_LIMIT_EXCEEDED"),
    true,
  );
});

test("resolves exclusions from all evidence before terminal evidence limits", async () => {
  const technologies = [
    technology("A", { excludes: ["B"] }),
    technology("B", { excludes: ["A"] }),
  ];
  const rules = [
    rule(1, "A", { locator: "x-a-low", confidence: 1 }),
    rule(2, "A", { locator: "x-a-high", confidence: 99 }),
    rule(3, "B", { locator: "x-b", confidence: 50 }),
  ];
  const fingerprintCatalog = catalog(technologies, rules);
  const input = htmlEntry({
    response: response({ headers: [
      { name: "x-a-low", value: "fixture" },
      { name: "x-a-high", value: "fixture" },
      { name: "x-b", value: "fixture" },
    ] }),
  });
  const complete = await detectHttp(input, {
    catalog: fingerprintCatalog,
    pool: directRulePool(fingerprintCatalog),
    config: defaultConfig,
  });
  const limited = await detectHttp(input, {
    catalog: fingerprintCatalog,
    pool: directRulePool(fingerprintCatalog),
    config: configWith([
      [["limits", "output", "evidencePerTechnology"], 1],
    ]),
  });

  assert.deepEqual(
    complete.technologies.map((item) => [item.name, item.confidence]),
    [["A", 100]],
  );
  assert.deepEqual(limited.technologies, []);
  assert.equal(limited.completed, false);
  assert.equal(
    limited.errors.some((item) => item.code === "RESULT_LIMIT_EXCEEDED"),
    true,
  );
});

test("sorts worker results, categories, evidence, and technologies deterministically", async () => {
  const categories = [
    { id: 2, name: "Second" },
    { id: 1, name: "First" },
  ];
  const technologies = [
    technology("Zulu", { categories }),
    technology("Alpha", { categories }),
  ];
  const rules = [
    rule(1, "Zulu", { locator: "x-zulu" }),
    rule(2, "Alpha", { locator: "x-alpha" }),
    rule(3, "Alpha", { source: "meta", locator: "generator" }),
  ];
  const fingerprintCatalog = catalog(technologies, rules, categories);
  const input = htmlEntry({
    response: response({ headers: [
      { name: "x-zulu", value: "fixture" },
      { name: "x-alpha", value: "fixture" },
    ] }),
    metadata: [{ key: "generator", value: "fixture" }],
  });
  const run = async (reverse: boolean) => await detectHttp(input, {
    catalog: fingerprintCatalog,
    pool: fakePool(fingerprintCatalog, (candidates) => {
      const matches = [
        workerMatch(candidates, 0, (item) => item.key === "x-zulu"),
        workerMatch(candidates, 1, (item) => item.key === "x-alpha"),
        workerMatch(candidates, 2, (item) => item.key === "generator"),
      ];
      return emptyMatchResult({ matches: reverse ? matches.reverse() : matches });
    }),
    config: defaultConfig,
  });
  const first = await run(false);
  const second = await run(true);

  assert.deepEqual(second, first);
  assert.deepEqual(first.technologies.map((item) => item.name), ["Alpha", "Zulu"]);
  assert.deepEqual(first.technologies[0]?.categories, [
    { id: 1, name: "First" },
    { id: 2, name: "Second" },
  ]);
  assert.deepEqual(
    first.technologies[0]?.evidence.map((item) => [item.source, item.key]),
    [["header", "x-alpha"], ["meta", "generator"]],
  );
});

test("produces technology data accepted by the v1 schema and semantic validator", async () => {
  const rules = [rule(1, "Fixture", {
    pattern: "Fixture/([0-9.]+)",
    confidence: 65,
    versionTemplate: "\\1",
  })];
  const fingerprintCatalog = catalog([technology("Fixture")], rules);
  const result = await detectHttp(htmlEntry({
    response: response({ headers: [{ name: "server", value: "Fixture/1.2.0" }] }),
  }), {
    catalog: fingerprintCatalog,
    pool: fakePool(fingerprintCatalog, (candidates) => emptyMatchResult({
      matches: [workerMatch(
        candidates,
        0,
        (item) => item.key === "server",
        { length: 13, version: "1.2.0" },
      )],
    })),
    config: defaultConfig,
  });
  const configDigest = computeConfigDigest(defaultConfig);
  const domainResult: DomainResult = {
    schemaVersion: 1,
    runId: "37937a78-f39d-49ed-a51d-6d398ae45a20",
    domain: "shop.vendor.tld",
    scannedAt: "2026-08-17T00:00:00.000Z",
    status: "success",
    finalUrl: "https://shop.vendor.tld/",
    scanMode: "full",
    pages: [{
      id: "p1",
      role: "entry",
      url: "https://shop.vendor.tld/",
      httpStatus: 200,
      collectors: ["http", "browser"],
    }],
    technologies: result.technologies,
    detectionStats: result.detectionStats,
    errors: [],
    timings: {
      totalMs: 1,
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
      staticTransferredBytes: 1,
      browserTransferredBytes: 1,
    },
    provenance: {
      scannerVersion: "0.1.0",
      runtime: {
        node: "24.19.0",
        playwright: "1.62.1",
        chromiumRevision: "chromium-fixture",
      },
      catalog: {
        source: fingerprintCatalog.source,
        revision: fingerprintCatalog.revision,
        digest: fingerprintCatalog.digest,
      },
      configDigest,
    },
  };

  assert.equal(result.signalAdmitted, true);
  assert.equal(result.completed, true);
  assert.equal(
    validateDomainResult(domainResult, {
      scanConfig: defaultConfig,
      expectedConfigDigest: configDigest,
      signalAdmitted: result.signalAdmitted,
    }),
    domainResult,
  );
});
