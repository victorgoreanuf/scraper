import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";

import { Ajv2020, type AnySchema } from "ajv/dist/2020.js";

type JsonObject = Record<string, unknown>;

const projectRoot = process.cwd();
const schema = JSON.parse(
  readFileSync(
    resolve(projectRoot, "schemas/domain-result.v1.schema.json"),
    "utf8",
  ),
) as AnySchema;
const ajv = new Ajv2020({
  allErrors: true,
  coerceTypes: false,
  removeAdditional: false,
  strict: true,
  useDefaults: false,
  validateFormats: false,
});
const validateDomainResult = ajv.compile(schema);

const ruleDigest = `sha256:${"0".repeat(64)}`;
const catalogDigest = `sha256:${"1".repeat(64)}`;
const configDigest = `sha256:${"2".repeat(64)}`;

function asObject(value: unknown): JsonObject {
  assert.ok(value !== null && typeof value === "object" && !Array.isArray(value));

  return value as JsonObject;
}

function asArray(value: unknown): unknown[] {
  assert.ok(Array.isArray(value));

  return value;
}

function firstTechnology(result: JsonObject): JsonObject {
  return asObject(asArray(result.technologies)[0]);
}

function firstEvidence(result: JsonObject): JsonObject {
  return asObject(asArray(firstTechnology(result).evidence)[0]);
}

function firstError(result: JsonObject): JsonObject {
  return asObject(asArray(result.errors)[0]);
}

function makeError(): JsonObject {
  return {
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
}

function makeDirectTechnology(): JsonObject {
  return {
    name: "Example",
    categories: [{ id: 6, name: "JavaScript frameworks" }],
    version: "1.2.0",
    confidence: 50,
    type: "direct",
    pageIds: ["p1"],
    evidence: [
      {
        collector: "http",
        source: "script_url",
        pageId: "p1",
        key: "src",
        match: {
          kind: "value",
          value: "https://cdn.vendor.tld/example-1.2.0.js",
          truncated: false,
        },
        ruleId: ruleDigest,
        pattern: "example-([0-9.]+)\\.js",
        confidence: 50,
        version: "1.2.0",
      },
    ],
    inferredFrom: [],
  };
}

function makeResult(): JsonObject {
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
      staticTransferredBytes: 18320,
      browserTransferredBytes: 130000,
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
        digest: catalogDigest,
      },
      configDigest,
    },
  };
}

function makePartialResult(): JsonObject {
  const result = makeResult();

  result.status = "partial";
  result.pages = [];
  result.errors = [makeError()];
  asObject(result.usage).pagesVisited = 0;

  const technology = firstTechnology(result);
  technology.version = null;
  technology.pageIds = [];

  const evidence = firstEvidence(result);
  evidence.source = "header";
  evidence.pageId = null;
  evidence.key = "server";
  evidence.match = { kind: "value", value: "nginx", truncated: false };
  evidence.pattern = "nginx";
  evidence.version = null;

  return result;
}

function makeDnsResult(): JsonObject {
  const result = makeResult();
  const technology = firstTechnology(result);
  technology.version = null;
  technology.pageIds = [];

  const evidence = firstEvidence(result);
  evidence.collector = "dns";
  evidence.source = "dns_record";
  evidence.pageId = null;
  evidence.key = "A";
  evidence.match = {
    kind: "value",
    value: "93.184.216.34",
    truncated: false,
  };
  evidence.pattern = "^93\\.184\\.216\\.34$";
  evidence.version = null;

  return result;
}

function expectValid(value: unknown): void {
  assert.equal(
    validateDomainResult(value),
    true,
    JSON.stringify(validateDomainResult.errors),
  );
}

function expectInvalid(value: unknown): void {
  assert.equal(validateDomainResult(value), false, "expected schema rejection");
}

test("keeps the result schema local, strict, and closed", () => {
  const root = asObject(schema);

  assert.equal(root.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(root.$id, "urn:website-technologies-scraper:domain-result:v1");

  function audit(value: unknown, path: string): void {
    if (Array.isArray(value)) {
      value.forEach((item, index) => audit(item, `${path}/${index}`));
      return;
    }

    if (value === null || typeof value !== "object") {
      return;
    }

    const object = value as JsonObject;

    assert.equal(object.format, undefined, `${path} must not use external formats`);

    if (typeof object.$ref === "string") {
      assert.match(object.$ref, /^#\//, `${path} must use only local references`);
    }

    if (
      object.type === "object" &&
      object.$ref === undefined &&
      !path.includes("/if/") &&
      !path.includes("/contains")
    ) {
      assert.equal(
        object.additionalProperties,
        false,
        `${path} must reject unknown object properties`,
      );
    }

    for (const [key, child] of Object.entries(object)) {
      audit(child, `${path}/${key}`);
    }
  }

  audit(schema, "#");
});

test("accepts the direct, inferred, redacted, partial, and failed shapes", () => {
  expectValid(makeResult());

  const zeroDetection = makeResult();
  zeroDetection.technologies = [];
  expectValid(zeroDetection);

  const inferred = makeResult();
  asArray(inferred.technologies).push({
    name: "Inferred Example",
    categories: [{ id: 1, name: "Other" }],
    version: null,
    confidence: 50,
    type: "inferred",
    pageIds: [],
    evidence: [],
    inferredFrom: [
      {
        technology: "Example",
        ruleId: ruleDigest,
        confidence: 50,
        version: null,
      },
    ],
  });
  expectValid(inferred);

  const redactedCookie = makeResult();
  const redactedTechnology = firstTechnology(redactedCookie);
  redactedTechnology.version = null;
  const redactedEvidence = firstEvidence(redactedCookie);
  redactedEvidence.source = "cookie";
  redactedEvidence.key = "session";
  redactedEvidence.match = {
    kind: "redacted",
    value: null,
    truncated: false,
  };
  redactedEvidence.pattern = ".+";
  redactedEvidence.version = null;
  expectValid(redactedCookie);

  const dnsEvidence = makeDnsResult();
  expectValid(dnsEvidence);

  const redactedTxtEvidence = structuredClone(dnsEvidence);
  const txtEvidence = firstEvidence(redactedTxtEvidence);
  txtEvidence.key = "TXT";
  txtEvidence.match = {
    kind: "redacted",
    value: null,
    truncated: false,
  };
  txtEvidence.pattern = "google-site-verification=.+";
  expectValid(redactedTxtEvidence);

  expectValid(makePartialResult());

  const failed = makeResult();
  failed.status = "failed";
  failed.finalUrl = null;
  failed.pages = [];
  failed.technologies = [];
  failed.errors = [
    {
      ...makeError(),
      stage: "target",
      code: "TARGET_NOT_FOUND",
      message: "No canonical target succeeded.",
    },
  ];
  asObject(failed.usage).pagesVisited = 0;
  expectValid(failed);
});

test("rejects unknown and missing fields at every result object boundary", () => {
  const mutations: Array<[string, (result: JsonObject) => void]> = [
    ["result", (result) => { result.extra = true; }],
    ["page", (result) => { asObject(asArray(result.pages)[0]).extra = true; }],
    ["technology", (result) => { firstTechnology(result).extra = true; }],
    [
      "category",
      (result) => {
        asObject(asArray(firstTechnology(result).categories)[0]).extra = true;
      },
    ],
    ["evidence", (result) => { firstEvidence(result).extra = true; }],
    ["match", (result) => { asObject(firstEvidence(result).match).extra = true; }],
    ["timings", (result) => { asObject(result.timings).extra = true; }],
    ["usage", (result) => { asObject(result.usage).extra = true; }],
    ["provenance", (result) => { asObject(result.provenance).extra = true; }],
    [
      "runtime",
      (result) => {
        asObject(asObject(result.provenance).runtime).extra = true;
      },
    ],
    [
      "catalog",
      (result) => {
        asObject(asObject(result.provenance).catalog).extra = true;
      },
    ],
  ];

  for (const [name, mutate] of mutations) {
    const result = makeResult();
    mutate(result);
    assert.equal(
      validateDomainResult(result),
      false,
      `${name} accepted an unknown field`,
    );
  }

  const inferredParent = makeResult();
  asArray(inferredParent.technologies).push({
    name: "Inferred Example",
    categories: [],
    version: null,
    confidence: 50,
    type: "inferred",
    pageIds: [],
    evidence: [],
    inferredFrom: [
      {
        technology: "Example",
        ruleId: ruleDigest,
        confidence: 50,
        version: null,
        extra: true,
      },
    ],
  });
  expectInvalid(inferredParent);

  const error = makePartialResult();
  firstError(error).extra = true;
  expectInvalid(error);

  const missing = makeResult();
  delete missing.provenance;
  expectInvalid(missing);
});

test("enforces deterministic page identifiers, roles, and collector order", () => {
  const wrongFirstId = makeResult();
  asObject(asArray(wrongFirstId.pages)[0]).id = "p2";
  expectInvalid(wrongFirstId);

  const wrongEntryRole = makeResult();
  asObject(asArray(wrongEntryRole.pages)[0]).role = "detail";
  expectInvalid(wrongEntryRole);

  const browserOnly = makeResult();
  asObject(asArray(browserOnly.pages)[0]).collectors = ["browser"];
  expectInvalid(browserOnly);

  const reversedCollectors = makeResult();
  asObject(asArray(reversedCollectors.pages)[0]).collectors = ["browser", "http"];
  expectInvalid(reversedCollectors);

  const secondPage = makeResult();
  asArray(secondPage.pages).push({
    id: "p2",
    role: "detail",
    url: "https://shop.vendor.tld/products/example",
    httpStatus: 200,
    collectors: ["http"],
  });
  asObject(secondPage.usage).pagesVisited = 2;
  expectValid(secondPage);

  asObject(asArray(secondPage.pages)[1]).role = "entry";
  expectInvalid(secondPage);

  const threePages = makeResult();
  asArray(threePages.pages).push(
    {
      id: "p2",
      role: "listing",
      url: "https://shop.vendor.tld/collections/example",
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
    {
      id: "p3",
      role: "detail",
      url: "https://shop.vendor.tld/products/example",
      httpStatus: 200,
      collectors: ["http", "browser"],
    },
  );
  asObject(threePages.usage).pagesVisited = 3;
  expectValid(threePages);

  asObject(asArray(threePages.pages)[1]).role = "detail";
  expectInvalid(threePages);
});

test("distinguishes direct detections from inferred detections", () => {
  const directWithoutEvidence = makeResult();
  firstTechnology(directWithoutEvidence).evidence = [];
  expectInvalid(directWithoutEvidence);

  const directWithParent = makeResult();
  firstTechnology(directWithParent).inferredFrom = [
    {
      technology: "Parent",
      ruleId: ruleDigest,
      confidence: 50,
      version: null,
    },
  ];
  expectInvalid(directWithParent);

  const inferred = makeResult();
  asArray(inferred.technologies).push({
    name: "Inferred Example",
    categories: [{ id: 1, name: "Other" }],
    version: null,
    confidence: 50,
    type: "inferred",
    pageIds: [],
    evidence: [],
    inferredFrom: [
      {
        technology: "Example",
        ruleId: ruleDigest,
        confidence: 50,
        version: null,
      },
    ],
  });
  const technology = asObject(asArray(inferred.technologies)[1]);
  expectValid(inferred);

  technology.pageIds = ["p1"];
  expectInvalid(inferred);
  technology.pageIds = [];
  technology.evidence = [makeDirectTechnology()];
  expectInvalid(inferred);
  technology.evidence = [];
  technology.inferredFrom = [];
  expectInvalid(inferred);

});

test("enforces evidence redaction and collector-source boundaries", () => {
  const presenceValue = makeResult();
  const presenceEvidence = firstEvidence(presenceValue);
  presenceEvidence.match = {
    kind: "presence",
    value: "secret",
    truncated: false,
  };
  presenceEvidence.pattern = null;
  presenceEvidence.version = null;
  expectInvalid(presenceValue);

  const redactedTruncation = makeResult();
  const redactedEvidence = firstEvidence(redactedTruncation);
  redactedEvidence.match = {
    kind: "redacted",
    value: null,
    truncated: true,
  };
  redactedEvidence.version = null;
  expectInvalid(redactedTruncation);

  const redactedVersion = makeResult();
  const versionEvidence = firstEvidence(redactedVersion);
  versionEvidence.match = {
    kind: "redacted",
    value: null,
    truncated: false,
  };
  versionEvidence.version = "1.2.0";
  expectInvalid(redactedVersion);

  const rawCookie = makeResult();
  const cookieEvidence = firstEvidence(rawCookie);
  cookieEvidence.source = "cookie";
  cookieEvidence.match = { kind: "value", value: "secret", truncated: false };
  expectInvalid(rawCookie);

  const rawContent = makeResult();
  const contentEvidence = firstEvidence(rawContent);
  contentEvidence.source = "script_content";
  contentEvidence.match = { kind: "value", value: "snippet", truncated: false };
  expectInvalid(rawContent);

  const longValue = makeResult();
  asObject(firstEvidence(longValue).match).value = "x".repeat(257);
  expectInvalid(longValue);

  const unsafeVersion = makeResult();
  firstEvidence(unsafeVersion).version = "version with spaces";
  expectInvalid(unsafeVersion);

  const wrongDnsCollector = makeResult();
  const dnsEvidence = firstEvidence(wrongDnsCollector);
  dnsEvidence.source = "dns_record";
  dnsEvidence.pageId = null;
  expectInvalid(wrongDnsCollector);

  const rawTxtRecord = makeDnsResult();
  const txtEvidence = firstEvidence(rawTxtRecord);
  txtEvidence.key = "TXT";
  txtEvidence.match = {
    kind: "value",
    value: "google-site-verification=secret-token",
    truncated: false,
  };
  txtEvidence.pattern = "google-site-verification=.+";
  expectInvalid(rawTxtRecord);

  const dnsWithoutType = makeDnsResult();
  firstEvidence(dnsWithoutType).key = null;
  expectInvalid(dnsWithoutType);

  const browserWithoutPage = makeResult();
  const browserEvidence = firstEvidence(browserWithoutPage);
  browserEvidence.collector = "browser";
  browserEvidence.source = "network_hostname";
  browserEvidence.pageId = null;
  expectInvalid(browserWithoutPage);

  const unsafeMetadata = makeResult();
  const metadataEvidence = firstEvidence(unsafeMetadata);
  metadataEvidence.source = "meta";
  metadataEvidence.key = "csrf-token";
  metadataEvidence.match = { kind: "value", value: "secret", truncated: false };
  expectInvalid(unsafeMetadata);
});

test("enforces status, lexical, digest, and numeric wire constraints", () => {
  const successWithError = makeResult();
  successWithError.errors = [makeError()];
  expectInvalid(successWithError);

  const partialWithoutError = makeResult();
  partialWithoutError.status = "partial";
  expectInvalid(partialWithoutError);

  const failedWithTechnology = makePartialResult();
  failedWithTechnology.status = "failed";
  expectInvalid(failedWithTechnology);

  const failedWithoutError = makeResult();
  failedWithoutError.status = "failed";
  failedWithoutError.technologies = [];
  expectInvalid(failedWithoutError);

  const invalidDomain = makeResult();
  invalidDomain.domain = "Shop.Vendor.tld.";
  expectInvalid(invalidDomain);

  const singleLabel = makeResult();
  singleLabel.domain = "localhost";
  expectInvalid(singleLabel);

  const numericSuffix = makeResult();
  numericSuffix.domain = "example.123";
  expectInvalid(numericSuffix);

  const invalidUuid = makeResult();
  invalidUuid.runId = "37937a78-f39d-19ed-a51d-6d398ae45a20";
  expectInvalid(invalidUuid);

  const invalidTimestamp = makeResult();
  invalidTimestamp.scannedAt = "2026-08-17T00:00:00Z";
  expectInvalid(invalidTimestamp);

  const invalidUrl = makeResult();
  invalidUrl.finalUrl = "ftp://shop.vendor.tld/";
  expectInvalid(invalidUrl);

  const invalidDigest = makeResult();
  asObject(invalidDigest.provenance).configDigest = "sha256:ABC";
  expectInvalid(invalidDigest);

  const negativeUsage = makeResult();
  asObject(negativeUsage.usage).httpRequests = -1;
  expectInvalid(negativeUsage);

  const fractionalTiming = makeResult();
  asObject(fractionalTiming.timings).totalMs = 1.5;
  expectInvalid(fractionalTiming);

  const lowercaseError = makePartialResult();
  firstError(lowercaseError).code = "http_timeout";
  expectInvalid(lowercaseError);

  const leakedRegexContext = makePartialResult();
  firstError(leakedRegexContext).ruleId = ruleDigest;
  expectInvalid(leakedRegexContext);

  const longTechnologyName = makeResult();
  firstTechnology(longTechnologyName).name = "x".repeat(257);
  expectInvalid(longTechnologyName);

  const longCategoryName = makeResult();
  asObject(asArray(firstTechnology(longCategoryName).categories)[0]).name =
    "x".repeat(129);
  expectInvalid(longCategoryName);

  const tooManyCategories = makeResult();
  firstTechnology(tooManyCategories).categories = Array.from(
    { length: 33 },
    (_, index) => ({ id: index + 1, name: `Category ${index + 1}` }),
  );
  expectInvalid(tooManyCategories);

  const tooManyErrors = makePartialResult();
  tooManyErrors.errors = Array.from({ length: 129 }, () => makeError());
  expectInvalid(tooManyErrors);

  const unsafeInteger = makeResult();
  asObject(unsafeInteger.usage).browserTransferredBytes =
    Number.MAX_SAFE_INTEGER + 1;
  expectInvalid(unsafeInteger);
});
