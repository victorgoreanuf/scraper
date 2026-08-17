import assert from "node:assert/strict";
import { test } from "node:test";

import {
  canonicalizeScanConfig,
  computeConfigDigest,
  createDefaultScanConfig,
  parseScanConfig,
  validateScanConfig,
} from "../src/config.ts";

type JsonRecord = Record<string, unknown>;

const userAgent =
  "WebsiteTechScraper/0.1.0 (https://contact.website-tech-scraper.dev/crawler)";

function mutableDefaultConfig(): JsonRecord {
  return structuredClone(createDefaultScanConfig(userAgent)) as unknown as JsonRecord;
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function setAtPath(
  root: JsonRecord,
  path: readonly string[],
  value: unknown,
): void {
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

function readAtPath(root: JsonRecord, path: readonly string[]): unknown {
  let current: unknown = root;

  for (const segment of path) {
    assert.ok(isRecord(current), `Expected object before ${segment}`);
    current = current[segment];
  }

  return current;
}

function reorderObjectKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => reorderObjectKeys(item));
  }

  if (!isRecord(value)) {
    return value;
  }

  return Object.fromEntries(
    Object.entries(value)
      .reverse()
      .map(([key, child]) => [key, reorderObjectKeys(child)]),
  );
}

function assertDeepFrozen(value: unknown, seen = new Set<object>()): void {
  if (typeof value !== "object" || value === null || seen.has(value)) {
    return;
  }

  seen.add(value);
  assert.equal(Object.isFrozen(value), true);

  for (const child of Object.values(value)) {
    assertDeepFrozen(child, seen);
  }
}

test("creates a schema-valid deeply immutable default configuration", () => {
  const config = createDefaultScanConfig(userAgent);

  assert.equal(validateScanConfig(config), true);
  assert.equal(config.userAgent, userAgent);
  assertDeepFrozen(config);
  assert.throws(
    () =>
      (config.targetPolicy.candidateOrder as unknown as string[]).push(
        "https://ignored.invalid/",
      ),
    TypeError,
  );
});

test("validates without mutation and parses to an independent frozen clone", () => {
  const input = mutableDefaultConfig();
  const beforeValidation = structuredClone(input);

  assert.equal(validateScanConfig(input), true);
  assert.deepEqual(input, beforeValidation);
  assert.equal(Object.isFrozen(input), false);

  const parsed = parseScanConfig(input);

  assert.notEqual(parsed, input);
  assert.deepEqual(parsed, input);
  assert.deepEqual(input, beforeValidation);
  assert.equal(Object.isFrozen(input), false);
  assertDeepFrozen(parsed);

  setAtPath(input, ["limits", "concurrency", "globalHttp"], 19);
  assert.equal(parsed.limits.concurrency.globalHttp, 20);
});

test("rejects invalid and non-cloneable configuration values", () => {
  const unknownField = mutableDefaultConfig();
  unknownField.outputPath = "output/results.jsonl";

  const invalidLimit = mutableDefaultConfig();
  setAtPath(invalidLimit, ["limits", "concurrency", "globalHttp"], 21);

  const invalidHeader = mutableDefaultConfig();
  invalidHeader.userAgent = `${userAgent}\n`;

  const changedPin = mutableDefaultConfig();
  setAtPath(changedPin, ["registryPins", "addressOverlayVersion"], 2);

  for (const candidate of [
    unknownField,
    invalidLimit,
    invalidHeader,
    changedPin,
  ]) {
    const beforeValidation = structuredClone(candidate);

    assert.equal(validateScanConfig(candidate), false);
    assert.deepEqual(candidate, beforeValidation);
    assert.throws(
      () => parseScanConfig(candidate),
      /Invalid scan configuration/,
    );
  }

  const nonCloneable = mutableDefaultConfig();
  nonCloneable.callback = (): void => undefined;
  assert.throws(
    () => parseScanConfig(nonCloneable),
    /value is not cloneable/,
  );
});

test("canonicalization ignores object insertion order and preserves array order", () => {
  const config = mutableDefaultConfig();
  const reordered = reorderObjectKeys(config);

  assert.equal(
    canonicalizeScanConfig(config),
    canonicalizeScanConfig(reordered),
  );
  assert.equal(computeConfigDigest(config), computeConfigDigest(reordered));

  const canonical = JSON.parse(canonicalizeScanConfig(config)) as JsonRecord;
  assert.deepEqual(readAtPath(canonical, ["inputPolicy", "allowedCodecs"]), [
    "UNCOMPRESSED",
    "SNAPPY",
  ]);
  assert.deepEqual(readAtPath(canonical, ["targetPolicy", "candidateOrder"]), [
    "https://{domain}/",
    "https://www.{domain}/",
    "http://{domain}/",
    "http://www.{domain}/",
  ]);
  assert.deepEqual(readAtPath(canonical, ["security", "browser", "allowedMethods"]), [
    "GET",
    "HEAD",
    "OPTIONS",
  ]);

  const changedArrayOrder = mutableDefaultConfig();
  setAtPath(changedArrayOrder, ["inputPolicy", "allowedCodecs"], [
    "SNAPPY",
    "UNCOMPRESSED",
  ]);
  assert.throws(
    () => canonicalizeScanConfig(changedArrayOrder),
    /Invalid scan configuration/,
  );
});

test("produces a deterministic digest for every admitted behavior change", () => {
  const baseline = mutableDefaultConfig();
  const baselineDigest = computeConfigDigest(baseline);
  const changes: ReadonlyArray<
    readonly [readonly string[], unknown]
  > = [
    [
      ["userAgent"],
      "WebsiteTechScraper/0.1.1 (https://contact.website-tech-scraper.dev/crawler)",
    ],
    [["limits", "concurrency", "globalHttp"], 19],
    [["limits", "timeMs", "activeDomain"], 59_999],
    [["limits", "parquet", "rows"], 999_999],
    [["limits", "target", "redirectsPerChain"], 4],
    [["limits", "detector", "workers"], 1],
    [["limits", "evidence", "matchCodePoints"], 255],
    [["limits", "output", "jsonlRecordBytes"], 16_777_215],
  ];
  const digests = new Set([baselineDigest]);

  assert.match(baselineDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(computeConfigDigest(baseline), baselineDigest);

  for (const [path, value] of changes) {
    const changed = mutableDefaultConfig();

    setAtPath(changed, path, value);
    assert.equal(validateScanConfig(changed), true, path.join("."));

    const digest = computeConfigDigest(changed);

    assert.notEqual(digest, baselineDigest, path.join("."));
    digests.add(digest);
  }

  assert.equal(digests.size, changes.length + 1);
});

test("rejects fixed policy and registry pin changes before digesting", () => {
  const fixedChanges: ReadonlyArray<
    readonly [readonly string[], unknown]
  > = [
    [["policyVersions", "hostname"], 2],
    [["policyVersions", "output"], 2],
    [["registryPins", "specialUseDomainsReviewedOn"], "2026-08-18"],
    [["registryPins", "ianaIpv4UpdatedOn"], "2026-01-01"],
    [["registryPins", "addressOverlayVersion"], 2],
    [
      ["targetPolicy", "candidateOrder"],
      [
        "https://www.{domain}/",
        "https://{domain}/",
        "http://{domain}/",
        "http://www.{domain}/",
      ],
    ],
  ];

  for (const [path, value] of fixedChanges) {
    const changed = mutableDefaultConfig();

    setAtPath(changed, path, value);
    assert.equal(validateScanConfig(changed), false, path.join("."));
    assert.throws(
      () => computeConfigDigest(changed),
      /Invalid scan configuration/,
    );
  }
});
