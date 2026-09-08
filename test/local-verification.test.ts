import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

type Counts = Record<"tests" | "pass" | "fail" | "cancelled" | "skipped" | "todo", number>;
type TestResults = { counts: Partial<Counts>; skippedTests: string[] };
type Check = { id: string; status: "PASS" | "FAIL" | "BLOCKED" | "NOT_APPLICABLE"; detail: string };

const { parseTestOutput, testChecks } = await import(
  new URL("../scripts/verify-local.mjs", import.meta.url).href
) as {
  parseTestOutput(output: string): TestResults;
  testChecks(results: TestResults, platform?: string): Check[];
};

const windowsTest = "Windows close waits for admitted operations and closes once after success or failure";
const posixTest = "rejects non-regular config and input files without blocking";
const passing: Counts = { tests: 3, pass: 3, fail: 0, cancelled: 0, skipped: 0, todo: 0 };

function skipped(name: string): TestResults {
  return { counts: { ...passing, pass: 2, skipped: 1 }, skippedTests: ["ok 3 - " + name + " # SKIP platform-specific fixture"] };
}

function omission(results: TestResults, platform: string): Check | undefined {
  return testChecks(results, platform).find(check => check.id === "omitted-tests");
}

test("verification parses real TAP output, including nested tests, UTF-8 and CRLF", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "scraper verification "));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const fixture = join(directory, "fixture.mjs");
  writeFileSync(fixture, [
    'import { test } from "node:test";',
    'test("parent", async (t) => { await t.test("UTF-8: verificări", () => {}); });',
    `test(${JSON.stringify(windowsTest)}, { skip: "Windows descriptor adapter lifecycle; POSIX uses Node FileHandle." }, () => {});`,
  ].join("\n"));
  // Nested test runners must not inherit the outer runner's child context.
  const environment = { ...process.env };
  delete environment.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, ["--test", "--test-reporter=tap", fixture], {
    encoding: "utf8", env: environment, timeout: 15_000, windowsHide: true,
  });
  assert.equal(result.status, 0, result.stderr);
  for (const output of [result.stdout, result.stdout.replace(/\n/g, "\r\n")]) {
    const parsed = parseTestOutput(output);
    assert.deepEqual(parsed.counts, { ...passing, pass: 2, skipped: 1 });
    assert.equal(parsed.skippedTests.length, 1);
    assert.match(parsed.skippedTests[0]!, /Windows descriptor adapter lifecycle/);
    assert.equal(omission(parsed, "darwin")?.status, "NOT_APPLICABLE");
    assert.equal(omission(parsed, "linux")?.status, "NOT_APPLICABLE");
    assert.equal(omission(parsed, "win32")?.status, "BLOCKED");
  }
});

test("verification accepts only the exact test belonging to another platform", () => {
  for (const platform of ["darwin", "linux", "win32"]) {
    const expected = platform === "win32" ? posixTest : windowsTest;
    const other = platform === "win32" ? windowsTest : posixTest;
    assert.equal(omission(skipped(expected), platform)?.status, "NOT_APPLICABLE");
    assert.equal(omission(skipped(other), platform)?.status, "BLOCKED");
    assert.equal(omission(skipped(expected + " with missing prerequisites"), platform)?.status, "BLOCKED");
    assert.equal(omission(skipped("browser launch unavailable"), platform)?.status, "BLOCKED");
    const extra = skipped(expected);
    extra.counts = { ...passing, pass: 1, skipped: 2 };
    extra.skippedTests.push("ok 2 - unrelated test # SKIP missing tool");
    assert.equal(omission(extra, platform)?.status, "BLOCKED");
  }
  assert.equal(omission(skipped(windowsTest), "freebsd")?.status, "BLOCKED");
  const nested = skipped(windowsTest);
  nested.skippedTests[0] = "    " + nested.skippedTests[0];
  assert.equal(omission(nested, "darwin")?.status, "BLOCKED");
});

test("verification blocks incomplete, inconsistent or unrecognized test results", () => {
  const invalid: TestResults[] = [
    parseTestOutput("ℹ tests 3\nℹ pass 2\nℹ skipped 1\n"),
    { counts: { tests: 3 }, skippedTests: [] },
    { counts: { ...passing, tests: 0, pass: 0 }, skippedTests: [] },
    { counts: { ...passing, pass: 2 }, skippedTests: [] },
    { counts: { ...passing, fail: -1, pass: 4 }, skippedTests: [] },
    { counts: { ...passing, tests: Number.MAX_SAFE_INTEGER + 1 }, skippedTests: [] },
    { counts: { ...passing, pass: 2, skipped: 1 }, skippedTests: [] },
    { counts: passing, skippedTests: skipped(windowsTest).skippedTests },
  ];
  for (const results of invalid) {
    const checks = testChecks(results, "linux");
    assert.equal(checks[0]?.id, "test-summary");
    assert.equal(checks[0]?.status, "BLOCKED");
  }
});

test("verification cannot pass TODO, failed or cancelled tests even with exit code zero", () => {
  assert.ok(testChecks({ counts: passing, skippedTests: [] }).every(check => check.status === "PASS"));
  for (const field of ["fail", "cancelled", "todo"] as const) {
    const counts = { ...passing, pass: 2, [field]: 1 };
    const checks = testChecks({ counts, skippedTests: [] });
    assert.ok(checks.some(check => check.status === (field === "todo" ? "BLOCKED" : "FAIL")));
  }
});

test("verification retains early omissions in long logs and ignores nested summaries", () => {
  const output = [
    "ok 1 - " + windowsTest + " # SKIP Windows-only test",
    "# " + "diagnostic ".repeat(20_000),
    "    # tests 99",
    "# tests 3", "# pass 2", "# fail 0", "# cancelled 0", "# skipped 1", "# todo 0",
  ].join("\n");
  const parsed = parseTestOutput(output);
  assert.deepEqual(parsed.counts, { ...passing, pass: 2, skipped: 1 });
  assert.equal(parsed.skippedTests.length, 1);
  assert.equal(omission(parsed, "linux")?.status, "NOT_APPLICABLE");
});
