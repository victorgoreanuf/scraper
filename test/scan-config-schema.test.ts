import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { validateHeaderValue } from "node:http";
import { test } from "node:test";

import { Ajv2020, type AnySchemaObject } from "ajv/dist/2020.js";

type JsonRecord = Record<string, unknown>;

const schema = JSON.parse(
  readFileSync(
    new URL("../schemas/scan-config.v1.schema.json", import.meta.url),
    "utf8",
  ),
) as AnySchemaObject;

const ajv = new Ajv2020({
  allErrors: true,
  coerceTypes: false,
  removeAdditional: false,
  strict: true,
  useDefaults: false,
  validateFormats: false,
});
const validate = ajv.compile(schema);

const canonicalConfig: JsonRecord = {
  schemaVersion: 1,
  scanMode: "full",
  userAgent:
    "WebsiteTechScraper/0.1.0 (https://contact.website-tech-scraper.dev/crawler)",
  inputPolicy: {
    format: "parquet",
    selectedColumn: "root_domain",
    allowedCodecs: ["UNCOMPRESSED", "SNAPPY"],
  },
  policyVersions: {
    parquet: 1,
    hostname: 1,
    address: 1,
    target: 1,
    robots: 1,
    pageSelection: 1,
    sanitizer: 1,
    evidence: 1,
    relationships: 1,
    detector: 1,
    browserEgress: 1,
    infrastructure: 1,
    output: 1,
  },
  registryPins: {
    specialUseDomainsReviewedOn: "2026-08-17",
    ianaIpv4UpdatedOn: "2025-10-09",
    ianaIpv6UpdatedOn: "2025-10-09",
    addressOverlayVersion: 1,
  },
  targetPolicy: {
    candidateOrder: [
      "https://{domain}/",
      "https://www.{domain}/",
      "http://{domain}/",
      "http://www.{domain}/",
    ],
    portsByScheme: {
      http: 80,
      https: 443,
    },
    topLevelMethod: "GET",
  },
  limits: {
    concurrency: {
      globalHttp: 20,
      perOriginHttp: 2,
      fullScans: 3,
    },
    timeMs: {
      activeDomain: 60_000,
      httpRequest: 10_000,
      browserPage: 15_000,
      browserSettle: 2_000,
      retryAfterCap: 2_000,
      robotsCache: 86_400_000,
      dnsLookup: 10_000,
    },
    parquet: {
      rows: 1_000_000,
      rowsPerRowGroup: 65_536,
      metadataBytes: 16_777_216,
      selectedChunkCompressedBytes: 33_554_432,
      selectedChunkUncompressedBytes: 33_554_432,
    },
    target: {
      candidates: 4,
      redirectsPerChain: 5,
    },
    hostname: {
      inputCodeUnits: 2_048,
    },
    url: {
      codeUnits: 2_048,
    },
    http: {
      transactionsPerDomain: 40,
      transientRetriesPerRequest: 1,
      headerFields: 100,
      headerBytes: 65_536,
      htmlCompressedBytesPerPage: 2_097_152,
      htmlDecompressedBytesPerPage: 4_194_304,
      staticDecompressedBytesPerDomain: 33_554_432,
      probeCompressedBytes: 262_144,
      probeDecompressedBytes: 524_288,
    },
    pages: {
      topLevelPerDomain: 3,
      catalogProbesPerDomain: 5,
      extractedUrlsPerPage: 5_000,
      metadataPerPage: 5_000,
      visibleTextBytesPerPage: 524_288,
    },
    scripts: {
      urlCandidatesPerDomain: 80,
      bodiesPerDomain: 20,
      bodyBytes: 2_097_152,
      totalBodyBytesPerDomain: 16_777_216,
    },
    browser: {
      contextsPerDomain: 1,
      activePagesPerContext: 1,
      networkHostnamesPerDomain: 200,
      requestsPerPage: 150,
      requestsPerDomain: 300,
      transferBytesPerPage: 15_728_640,
      transferBytesPerDomain: 31_457_280,
    },
    cookies: {
      perDomain: 100,
      nameCodeUnits: 256,
      valueBytes: 4_096,
      totalBytesPerDomain: 65_536,
    },
    dns: {
      recordsPerType: 32,
      recordsPerDomain: 128,
      txtItemBytes: 4_096,
      textBytesPerDomain: 65_536,
    },
    tls: {
      issuerBytes: 4_096,
    },
    robots: {
      bodyBytes: 524_288,
      redirects: 5,
      lines: 5_000,
      rules: 500,
      ruleCodeUnits: 512,
      matchingStatesPerUrl: 1_000_000,
    },
    inspection: {
      domSelectors: 5_000,
      domSelectorCodeUnits: 1_024,
      domMatchesPerSelector: 20,
      javascriptPaths: 10_000,
      javascriptPathCodeUnits: 512,
      returnedValueBytes: 8_192,
      returnedValuesBytesPerPage: 2_097_152,
    },
    detector: {
      workers: 2,
      catalogFiles: 64,
      catalogFileBytes: 1_048_576,
      catalogBytes: 16_777_216,
      catalogJsonDepth: 64,
      technologiesPerCatalog: 20_000,
      technologyNameCodePoints: 256,
      categoryNameCodePoints: 128,
      categoriesPerTechnology: 32,
      categoriesPerCatalog: 1_024,
      relationshipEdgesPerCatalog: 100_000,
      patternsPerCatalog: 20_000,
      patternSourceCodeUnits: 2_048,
      totalPatternSourceCodeUnits: 1_000_000,
      compileWatchdogMs: 5_000,
      workerOldHeapBytes: 134_217_728,
      workerYoungHeapBytes: 33_554_432,
      workerStackBytes: 4_194_304,
      ruleWatchdogMs: 50,
      watchdogPollMs: 10,
      activeMsPerDomain: 2_000,
      timeoutsPerDomain: 3,
      checkpointRules: 128,
      executionsPerDomain: 500_000,
    },
    evidence: {
      matchCodePoints: 256,
      safePathSegmentCodeUnits: 64,
      hexTokenMinCodeUnits: 16,
      base64UrlTokenMinCodeUnits: 24,
      versionCodeUnits: 64,
    },
    output: {
      jsonlRecordBytes: 16_777_216,
      technologiesPerDomain: 20_000,
      errorsPerDomain: 128,
      evidencePerTechnology: 256,
      evidencePerDomain: 20_000,
      inferencesPerTechnology: 256,
      inferencesPerDomain: 20_000,
    },
  },
  security: {
    network: {
      allowUrlCredentials: false,
      allowIpInput: false,
      requirePublicAddresses: true,
      rejectMixedAddressAnswers: true,
      validateConnectedAddress: true,
      revalidateRedirects: true,
      connectOnlySelectedAddress: true,
      verifyTls: true,
    },
    robots: {
      productToken: "WebsiteTechScraper",
      failurePolicy: "fail-closed",
      protectedTransportRequired: true,
    },
    browser: {
      allowedMethods: ["GET", "HEAD", "OPTIONS"],
      persistentContexts: false,
      sandbox: true,
      bypassCsp: false,
      serviceWorkers: "block",
      downloads: "deny",
      permissions: [],
      proxyRequired: true,
      proxyBypass: false,
      startupCanaryRequired: true,
      quic: false,
      nonProxiedWebRtc: false,
      webSockets: "block",
      mutableMethods: "block",
      popups: "block",
      crossOriginMainFrames: "block",
      interactions: "deny",
      abortedResourceTypes: ["image", "font", "media"],
    },
    evidence: {
      persistRawObservations: false,
      persistRequestHeaders: false,
      persistCookieValues: false,
      hashCookieValues: false,
      persistResponseBodies: false,
      redactUnknownValues: true,
      redactQueryValues: true,
      redactSensitivePathSegments: true,
      redactSensitiveResponseHeaders: true,
      stripUrlUserInfo: true,
      stripUrlFragments: true,
      emitVersionsFromRedactedSources: false,
      includeErrorStackTraces: false,
    },
  },
};

function cloneConfig(): JsonRecord {
  return structuredClone(canonicalConfig);
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function setAtPath(root: JsonRecord, path: readonly string[], value: unknown): void {
  assert.ok(path.length > 0);

  let current = root;

  for (const segment of path.slice(0, -1)) {
    const next = current[segment];

    assert.ok(isRecord(next), `Expected object at ${segment}`);
    current = next;
  }

  const finalSegment = path.at(-1);

  assert.ok(finalSegment);
  current[finalSegment] = value;
}

function deleteAtPath(root: JsonRecord, path: readonly string[]): void {
  assert.ok(path.length > 0);

  let current = root;

  for (const segment of path.slice(0, -1)) {
    const next = current[segment];

    assert.ok(isRecord(next), `Expected object at ${segment}`);
    current = next;
  }

  const finalSegment = path.at(-1);

  assert.ok(finalSegment);
  delete current[finalSegment];
}

function assertValid(candidate: unknown): void {
  assert.equal(validate(candidate), true, JSON.stringify(validate.errors));
}

function assertInvalid(candidate: unknown): void {
  assert.equal(validate(candidate), false, "Expected configuration to be invalid");
}

function auditSchemaNode(node: unknown, path: string): void {
  assert.ok(isRecord(node), `${path} must be a schema object`);
  assert.equal(Object.hasOwn(node, "default"), false, `${path} must not use default`);
  assert.equal(Object.hasOwn(node, "format"), false, `${path} must not use format`);

  if (Object.hasOwn(node, "$ref")) {
    assert.equal(typeof node.$ref, "string", `${path}.$ref must be a string`);
    assert.match(node.$ref as string, /^#\//, `${path}.$ref must be local`);
  }

  if (node.type === "integer") {
    const hasConst = Object.hasOwn(node, "const");
    const hasBounds =
      Number.isSafeInteger(node.minimum) && Number.isSafeInteger(node.maximum);

    assert.ok(hasConst || hasBounds, `${path} integer must be fixed or bounded`);
  }

  if (node.type !== "object") {
    return;
  }

  assert.equal(
    node.additionalProperties,
    false,
    `${path} must reject additional properties`,
  );
  assert.ok(isRecord(node.properties), `${path}.properties must be an object`);
  assert.ok(Array.isArray(node.required), `${path}.required must be an array`);

  const propertyNames = Object.keys(node.properties).sort();
  const requiredNames = [...node.required].sort();

  assert.deepEqual(requiredNames, propertyNames, `${path} must require every property`);

  for (const [propertyName, propertySchema] of Object.entries(node.properties)) {
    auditSchemaNode(propertySchema, `${path}.properties.${propertyName}`);
  }
}

test("accepts the canonical scan configuration without mutation", () => {
  const candidate = cloneConfig();
  const beforeValidation = structuredClone(candidate);

  assertValid(candidate);
  assert.deepEqual(candidate, beforeValidation);
  assert.doesNotThrow(() =>
    validateHeaderValue("user-agent", String(candidate.userAgent)),
  );
});

test("accepts safe lower resource limits", () => {
  const candidate = cloneConfig();

  setAtPath(candidate, ["limits", "concurrency", "globalHttp"], 1);
  setAtPath(candidate, ["limits", "timeMs", "browserSettle"], 0);
  setAtPath(candidate, ["limits", "timeMs", "retryAfterCap"], 0);
  setAtPath(candidate, ["limits", "timeMs", "dnsLookup"], 1);
  setAtPath(candidate, ["limits", "target", "redirectsPerChain"], 0);
  setAtPath(candidate, ["limits", "http", "transientRetriesPerRequest"], 0);
  setAtPath(candidate, ["limits", "pages", "catalogProbesPerDomain"], 0);
  setAtPath(candidate, ["limits", "scripts", "urlCandidatesPerDomain"], 0);
  setAtPath(candidate, ["limits", "scripts", "bodiesPerDomain"], 0);
  setAtPath(candidate, ["limits", "detector", "workers"], 1);
  setAtPath(candidate, ["limits", "detector", "catalogFiles"], 29);
  setAtPath(candidate, ["limits", "detector", "catalogFileBytes"], 524_288);
  setAtPath(candidate, ["limits", "detector", "catalogBytes"], 4_194_304);
  setAtPath(candidate, ["limits", "detector", "catalogJsonDepth"], 8);
  setAtPath(candidate, ["limits", "detector", "workerOldHeapBytes"], 16_777_216);
  setAtPath(candidate, ["limits", "detector", "workerYoungHeapBytes"], 4_194_304);
  setAtPath(candidate, ["limits", "detector", "workerStackBytes"], 1_048_576);
  setAtPath(candidate, ["limits", "tls", "issuerBytes"], 1);
  setAtPath(candidate, ["limits", "output", "jsonlRecordBytes"], 65_536);
  setAtPath(candidate, ["limits", "output", "evidencePerTechnology"], 1);

  assertValid(candidate);
});

test("rejects Parquet and representative scan limits above their v1 caps", () => {
  const cases: ReadonlyArray<readonly [readonly string[], number]> = [
    [["limits", "parquet", "rows"], 1_000_001],
    [["limits", "parquet", "rowsPerRowGroup"], 65_537],
    [["limits", "parquet", "metadataBytes"], 16_777_217],
    [["limits", "parquet", "selectedChunkCompressedBytes"], 33_554_433],
    [["limits", "parquet", "selectedChunkUncompressedBytes"], 33_554_433],
    [["limits", "target", "candidates"], 5],
    [["limits", "timeMs", "dnsLookup"], 10_001],
    [["limits", "hostname", "inputCodeUnits"], 2_049],
    [["limits", "http", "transactionsPerDomain"], 41],
    [["limits", "pages", "topLevelPerDomain"], 4],
    [["limits", "pages", "metadataPerPage"], 5_001],
    [["limits", "browser", "transferBytesPerDomain"], 31_457_281],
    [["limits", "tls", "issuerBytes"], 4_097],
    [["limits", "detector", "workers"], 3],
    [["limits", "detector", "catalogFiles"], 65],
    [["limits", "detector", "catalogFileBytes"], 1_048_577],
    [["limits", "detector", "catalogBytes"], 16_777_217],
    [["limits", "detector", "catalogJsonDepth"], 65],
    [["limits", "detector", "technologyNameCodePoints"], 257],
    [["limits", "detector", "categoriesPerCatalog"], 1_025],
    [["limits", "detector", "executionsPerDomain"], 500_001],
    [["limits", "evidence", "matchCodePoints"], 257],
    [["limits", "output", "jsonlRecordBytes"], 16_777_217],
    [["limits", "output", "evidencePerTechnology"], 257],
  ];

  for (const [path, value] of cases) {
    const candidate = cloneConfig();

    setAtPath(candidate, path, value);
    assertInvalid(candidate);
  }
});

test("rejects negative, fractional, missing, and unknown values", () => {
  const invalidMutations: ReadonlyArray<readonly [readonly string[], unknown]> = [
    [["limits", "parquet", "rows"], 0],
    [["limits", "timeMs", "activeDomain"], -1],
    [["limits", "timeMs", "dnsLookup"], 0],
    [["limits", "tls", "issuerBytes"], 0],
    [["limits", "http", "headerFields"], 1.5],
    [["limits", "detector", "catalogFiles"], 28],
    [["limits", "detector", "catalogFileBytes"], 524_287],
    [["limits", "detector", "catalogBytes"], 4_194_303],
    [["limits", "detector", "catalogJsonDepth"], 7],
    [["limits", "detector", "workerOldHeapBytes"], 17_000_000],
    [["limits", "detector", "workerYoungHeapBytes"], 4_194_305],
    [["limits", "detector", "workerStackBytes"], 1_048_577],
  ];

  for (const [path, value] of invalidMutations) {
    const candidate = cloneConfig();

    setAtPath(candidate, path, value);
    assertInvalid(candidate);
  }

  const missing = cloneConfig();
  deleteAtPath(missing, ["limits", "parquet", "metadataBytes"]);
  assertInvalid(missing);

  const unknownNested = cloneConfig();
  setAtPath(unknownNested, ["limits", "http", "unbounded"], true);
  assertInvalid(unknownNested);

  const operationalCliField = cloneConfig();
  operationalCliField.outputPath = "output/results.jsonl";
  assertInvalid(operationalCliField);

  const provenanceField = cloneConfig();
  provenanceField.catalogRevision = "not-part-of-scan-config";
  assertInvalid(provenanceField);
});

test("rejects changes to fixed input, registry, target, and security policies", () => {
  const cases: ReadonlyArray<readonly [readonly string[], unknown]> = [
    [["inputPolicy", "selectedColumn"], "domain"],
    [["inputPolicy", "allowedCodecs"], ["SNAPPY", "UNCOMPRESSED"]],
    [["policyVersions", "hostname"], 2],
    [["policyVersions", "infrastructure"], 2],
    [["policyVersions", "output"], 2],
    [["registryPins", "ianaIpv4UpdatedOn"], "2026-01-01"],
    [
      ["targetPolicy", "candidateOrder"],
      [
        "https://www.{domain}/",
        "https://{domain}/",
        "http://{domain}/",
        "http://www.{domain}/",
      ],
    ],
    [["targetPolicy", "portsByScheme", "http"], 443],
    [["security", "network", "allowIpInput"], true],
    [["security", "network", "verifyTls"], false],
    [["security", "browser", "allowedMethods"], ["GET", "POST"]],
    [["security", "browser", "proxyBypass"], true],
    [["security", "evidence", "persistRawObservations"], true],
  ];

  for (const [path, value] of cases) {
    const candidate = cloneConfig();

    setAtPath(candidate, path, value);
    assertInvalid(candidate);
  }
});

test("requires a bounded descriptive user agent with a contact", () => {
  const mailContact = cloneConfig();
  mailContact.userAgent =
    "WebsiteTechScraper/0.1.0 (mailto:crawler@website-tech-scraper.dev)";
  assertValid(mailContact);
  assert.doesNotThrow(() =>
    validateHeaderValue("user-agent", String(mailContact.userAgent)),
  );

  const invalidUserAgents = [
    "WebsiteTechScraper/0.1.0",
    "WebsiteTechScraper/0.1.0 (ftp://contact.website-tech-scraper.dev)",
    "WebsiteTechScraper/0.1.0 (https://contact.website-tech-scraper.dev/\n)",
    `WebsiteTechScraper/0.1.0 (https://${"a".repeat(500)}.dev)`,
    "WebsiteTechScraper/0.1.0 (https://contact.\ud800.dev)",
    "WebsiteTechScraper/0.1.0 (https://contact.😀.dev)",
  ];

  for (const userAgent of invalidUserAgents) {
    const candidate = cloneConfig();
    candidate.userAgent = userAgent;
    assertInvalid(candidate);
  }
});

test("keeps the schema local, closed, bounded, and default-free", () => {
  assert.equal(
    schema.$id,
    "urn:website-technologies-scraper:scan-config:v1",
  );
  auditSchemaNode(schema, "$schema");
});
