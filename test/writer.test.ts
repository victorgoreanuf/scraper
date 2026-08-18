import assert from "node:assert/strict";
import {
  appendFile,
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  computeConfigDigest,
  createDefaultScanConfig,
  parseScanConfig,
  type ScanConfig,
} from "../src/config.ts";
import type {
  DomainResult,
  Provenance,
} from "../src/model.ts";
import {
  openResultWriter,
  OutputWriterError,
  type OutputWriterErrorCode,
  type ResultWriter,
} from "../src/output/writer.ts";

const USER_AGENT =
  "WebsiteTechScraper/0.1.0 (https://contact.website-tech-scraper.dev/crawler)";
const SCANNED_AT = "2026-08-18T10:11:12.345Z";

function configWithRecordLimit(limit?: number, rows?: number): ScanConfig {
  const value = structuredClone(
    createDefaultScanConfig(USER_AGENT),
  ) as unknown as Record<string, unknown>;
  if (limit !== undefined) {
    const limits = value.limits as Record<string, unknown>;
    const output = limits.output as Record<string, unknown>;
    output.jsonlRecordBytes = limit;
  }
  if (rows !== undefined) {
    const limits = value.limits as Record<string, unknown>;
    const parquet = limits.parquet as Record<string, unknown>;
    parquet.rows = rows;
  }
  return parseScanConfig(value);
}

function provenanceFor(config: ScanConfig): Provenance {
  return {
    scannerVersion: "0.1.0",
    runtime: {
      node: "24.19.0",
      playwright: "1.62.1",
      chromiumRevision: "chromium-123456",
    },
    catalog: {
      source: "local-fixture",
      revision: "writer-v1",
      digest: `sha256:${"a".repeat(64)}`,
    },
    configDigest: computeConfigDigest(config),
  };
}

function failedResult(
  runId: string,
  domain: string,
  provenance: Provenance,
  overrides: Partial<DomainResult> = {},
): DomainResult {
  return {
    schemaVersion: 1,
    runId,
    domain,
    scannedAt: SCANNED_AT,
    status: "failed",
    finalUrl: null,
    scanMode: "full",
    pages: [],
    technologies: [],
    detectionStats: {
      rawDirect: 0,
      gatedDirect: 0,
      suppressedDirect: 0,
      retainedDirect: 0,
    },
    errors: [{
      stage: "target",
      code: "TARGET_NOT_FOUND",
      pageId: null,
      retryable: false,
      message: "No canonical target succeeded.",
      ruleId: null,
      signal: null,
      limit: null,
      catalogRevision: null,
    }],
    timings: {
      totalMs: 1,
      targetMs: 1,
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
    provenance,
    ...overrides,
  };
}

async function temporaryDirectory(t: { after(callback: () => unknown): void }) {
  const directory = await mkdtemp(join(tmpdir(), "veridion-writer-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

async function expectWriterError(
  operation: Promise<unknown>,
  code: OutputWriterErrorCode,
): Promise<void> {
  await assert.rejects(operation, (error: unknown) => {
    assert.ok(error instanceof OutputWriterError);
    assert.equal(error.code, code);
    return true;
  });
}

async function closeQuietly(writer: ResultWriter | undefined): Promise<void> {
  await writer?.close().catch(() => undefined);
}

test("creates exclusively, serializes concurrent appends, and finalizes atomically", async (t) => {
  const directory = await temporaryDirectory(t);
  const resultPath = join(directory, "results.jsonl");
  const summaryPath = join(directory, "results.summary.json");
  const config = configWithRecordLimit();
  const provenance = provenanceFor(config);
  const writer = await openResultWriter({
    resultPath,
    mode: "create",
    config,
    provenance,
  });

  await expectWriterError(
    openResultWriter({ resultPath, mode: "create", config, provenance }),
    "OUTPUT_EXISTS",
  );

  const domains = ["one.vendor.com", "two.vendor.com", "three.vendor.com"];
  await Promise.all(domains.map((domain) =>
    writer.append(failedResult(writer.runId, domain, provenance))));
  assert.equal(writer.processedDomains, 3);
  for (const domain of domains) {
    assert.equal(writer.hasCompletedDomain(domain), true);
  }

  const beforeFinalize = await readFile(resultPath, "utf8");
  assert.equal(beforeFinalize.endsWith("\n"), true);
  assert.deepEqual(
    beforeFinalize.trimEnd().split("\n").map((line) =>
      (JSON.parse(line) as DomainResult).domain),
    domains,
  );

  const summary = await writer.finalize(3);
  assert.equal(summary.runId, writer.runId);
  assert.equal(summary.inputDomains, 3);
  assert.equal(summary.processedDomains, 3);
  assert.deepEqual(
    JSON.parse(await readFile(summaryPath, "utf8")),
    summary,
  );
  assert.equal((await lstat(resultPath)).mode & 0o777, 0o600);
  assert.equal((await lstat(summaryPath)).mode & 0o777, 0o600);
  assert.equal(
    (await readdir(directory)).some((name) => name.endsWith(".tmp")),
    false,
  );

  await expectWriterError(
    writer.append(failedResult(writer.runId, "four.vendor.com", provenance)),
    "OUTPUT_WRITER_CLOSED",
  );
  await writer.close();
  await writer.close();

  const lateResultPath = join(directory, "late.jsonl");
  const lateSummaryPath = join(directory, "late.summary.json");
  const lateSummary = Buffer.from("concurrent summary sentinel");
  const lateWriter = await openResultWriter({
    resultPath: lateResultPath,
    mode: "create",
    config,
    provenance,
  });
  await lateWriter.append(
    failedResult(lateWriter.runId, "late.vendor.com", provenance),
  );
  await writeFile(lateSummaryPath, lateSummary, { mode: 0o600 });
  await expectWriterError(lateWriter.finalize(1), "OUTPUT_EXISTS");
  assert.deepEqual(await readFile(lateSummaryPath), lateSummary);
  assert.equal(
    (await readdir(directory)).some((name) => name.endsWith(".tmp")),
    false,
  );
});

test("latches duplicate append failures without counting an unwritten record", async (t) => {
  const directory = await temporaryDirectory(t);
  const resultPath = join(directory, "results.jsonl");
  const config = configWithRecordLimit();
  const provenance = provenanceFor(config);
  const writer = await openResultWriter({
    resultPath,
    mode: "create",
    config,
    provenance,
  });
  const result = failedResult(writer.runId, "duplicate.vendor.com", provenance);

  await writer.append(result);
  await expectWriterError(
    writer.append(result),
    "OUTPUT_DUPLICATE_DOMAIN",
  );
  await expectWriterError(
    writer.append(failedResult(writer.runId, "later.vendor.com", provenance)),
    "OUTPUT_DUPLICATE_DOMAIN",
  );
  assert.equal(writer.processedDomains, 1);
  assert.equal((await readFile(resultPath, "utf8")).split("\n").length, 2);
  await writer.close();
});

test("resume reuses the run, removes one final fragment, and seeds its summary", async (t) => {
  const directory = await temporaryDirectory(t);
  const resultPath = join(directory, "results.jsonl");
  const config = configWithRecordLimit();
  const provenance = provenanceFor(config);
  let writer: ResultWriter | undefined = await openResultWriter({
    resultPath,
    mode: "create",
    config,
    provenance,
  });
  const originalRunId = writer.runId;
  await writer.append(failedResult(originalRunId, "one.vendor.com", provenance));
  await writer.append(failedResult(originalRunId, "two.vendor.com", provenance));
  await writer.close();
  writer = undefined;
  const validPrefix = await readFile(resultPath);
  await appendFile(resultPath, "{\"incomplete\":true}");

  const resumed = await openResultWriter({
    resultPath,
    mode: "resume",
    config,
    provenance,
  });
  t.after(() => closeQuietly(resumed));
  assert.equal(resumed.runId, originalRunId);
  assert.equal(resumed.processedDomains, 2);
  assert.equal(resumed.hasCompletedDomain("one.vendor.com"), true);
  assert.deepEqual(await readFile(resultPath), validPrefix);

  await resumed.append(
    failedResult(originalRunId, "three.vendor.com", provenance),
  );
  const summary = await resumed.finalize(3);
  assert.equal(summary.processedDomains, 3);
  assert.equal(summary.statusCounts.failed, 3);
});

test("resume gives an empty or fragment-only file a new run id", async (t) => {
  const directory = await temporaryDirectory(t);
  const config = configWithRecordLimit();
  const provenance = provenanceFor(config);

  for (const [name, bytes] of [
    ["empty.jsonl", Buffer.alloc(0)],
    ["fragment.jsonl", Buffer.from("{\"completeJsonButNoNewline\":true}")],
  ] as const) {
    const resultPath = join(directory, name);
    await writeFile(resultPath, bytes, { mode: 0o600 });
    const writer = await openResultWriter({
      resultPath,
      mode: "resume",
      config,
      provenance,
    });
    assert.match(writer.runId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
    assert.equal(writer.processedDomains, 0);
    assert.equal((await readFile(resultPath)).length, 0);
    await writer.close();
  }
});

test("resume rejects a domain outside the validated input before repair", async (t) => {
  const directory = await temporaryDirectory(t);
  const resultPath = join(directory, "results.jsonl");
  const config = configWithRecordLimit();
  const provenance = provenanceFor(config);
  const writer = await openResultWriter({
    resultPath,
    mode: "create",
    config,
    provenance,
  });
  await writer.append(
    failedResult(writer.runId, "outside.vendor.com", provenance),
  );
  await writer.close();
  await appendFile(resultPath, "{\"incomplete\":true}");
  const before = await readFile(resultPath);

  await expectWriterError(
    openResultWriter({
      resultPath,
      mode: "resume",
      config,
      provenance,
      resumeDomainAllowed: () => false,
    }),
    "OUTPUT_CONTEXT_MISMATCH",
  );
  assert.deepEqual(await readFile(resultPath), before);
});

test("resume rejects corruption without modifying the result prefix", async (t) => {
  const directory = await temporaryDirectory(t);
  const config = configWithRecordLimit(65_536);
  const provenance = provenanceFor(config);
  const runId = "37937a78-f39d-49ed-a51d-6d398ae45a20";
  const valid = `${JSON.stringify(
    failedResult(runId, "valid.vendor.com", provenance),
  )}\n`;
  const mismatchedProvenance: Provenance = {
    ...provenance,
    catalog: { ...provenance.catalog, revision: "other-revision" },
  };
  const cases: ReadonlyArray<readonly [
    name: string,
    bytes: Buffer,
    code: OutputWriterErrorCode,
  ]> = [
    ["bad-json", Buffer.from(`${valid}{]\n`), "OUTPUT_INVALID_RESUME"],
    ["bad-utf8", Buffer.concat([Buffer.from(valid), Buffer.from([0xff, 0x0a])]), "OUTPUT_INVALID_RESUME"],
    ["oversize", Buffer.concat([Buffer.alloc(65_536, 0x20), Buffer.from("\n")]), "OUTPUT_RECORD_LIMIT"],
    ["duplicate", Buffer.from(`${valid}${valid}`), "OUTPUT_DUPLICATE_DOMAIN"],
    [
      "mixed-run",
      Buffer.from(`${valid}${JSON.stringify(
        failedResult(
          "7ec85f42-c8d6-4d52-9cac-a0e99b8c097f",
          "other.vendor.com",
          provenance,
        ),
      )}\n`),
      "OUTPUT_CONTEXT_MISMATCH",
    ],
    [
      "provenance",
      Buffer.from(`${JSON.stringify(
        failedResult(runId, "other.vendor.com", mismatchedProvenance),
      )}\n`),
      "OUTPUT_CONTEXT_MISMATCH",
    ],
  ];

  for (const [name, bytes, code] of cases) {
    const resultPath = join(directory, `${name}.jsonl`);
    await writeFile(resultPath, bytes, { mode: 0o600 });
    await expectWriterError(
      openResultWriter({ resultPath, mode: "resume", config, provenance }),
      code,
    );
    assert.deepEqual(await readFile(resultPath), bytes);
  }
});

test("resume rejects an older scanner version without modifying the result", async (t) => {
  const directory = await temporaryDirectory(t);
  const resultPath = join(directory, "older-scanner.jsonl");
  const config = configWithRecordLimit();
  const previousProvenance = provenanceFor(config);
  const currentProvenance: Provenance = {
    ...previousProvenance,
    scannerVersion: "0.1.1",
  };
  const runId = "37937a78-f39d-49ed-a51d-6d398ae45a20";
  const bytes = Buffer.from(
    `${JSON.stringify(
      failedResult(runId, "version.vendor.com", previousProvenance),
    )}\n{"incomplete":true}`,
  );
  await writeFile(resultPath, bytes, { mode: 0o600 });

  await expectWriterError(
    openResultWriter({
      resultPath,
      mode: "resume",
      config,
      provenance: currentProvenance,
    }),
    "OUTPUT_CONTEXT_MISMATCH",
  );
  assert.deepEqual(await readFile(resultPath), bytes);
});

test("append and resume enforce persisted semantic and configuration invariants", async (t) => {
  const directory = await temporaryDirectory(t);
  const config = configWithRecordLimit();
  const provenance = provenanceFor(config);
  const resultPath = join(directory, "append.jsonl");
  const writer = await openResultWriter({
    resultPath,
    mode: "create",
    config,
    provenance,
  });
  const inconsistentStats = failedResult(
    writer.runId,
    "invalid.vendor.com",
    provenance,
    {
      detectionStats: {
        rawDirect: 1,
        gatedDirect: 0,
        suppressedDirect: 0,
        retainedDirect: 0,
      },
    },
  );
  await expectWriterError(
    writer.append(inconsistentStats),
    "OUTPUT_INVALID_RECORD",
  );
  assert.equal(writer.processedDomains, 0);
  assert.equal((await readFile(resultPath)).length, 0);
  await writer.close();

  const resumePath = join(directory, "resume.jsonl");
  const runId = "37937a78-f39d-49ed-a51d-6d398ae45a20";
  const invalidLine = Buffer.from(`${JSON.stringify(inconsistentStats)}\n`);
  await writeFile(resumePath, invalidLine, { mode: 0o600 });
  await expectWriterError(
    openResultWriter({ resultPath: resumePath, mode: "resume", config, provenance }),
    "OUTPUT_INVALID_RECORD",
  );
  assert.deepEqual(await readFile(resumePath), invalidLine);

  const otherConfig = configWithRecordLimit(65_536);
  const otherProvenance = provenanceFor(otherConfig);
  const configPath = join(directory, "config.jsonl");
  const originalLine = Buffer.from(`${JSON.stringify(
    failedResult(runId, "valid.vendor.com", provenance),
  )}\n`);
  await writeFile(configPath, originalLine, { mode: 0o600 });
  await expectWriterError(
    openResultWriter({
      resultPath: configPath,
      mode: "resume",
      config: otherConfig,
      provenance: otherProvenance,
    }),
    "OUTPUT_INVALID_RECORD",
  );
  assert.deepEqual(await readFile(configPath), originalLine);
});

test("force validates both targets before truncating and starts a new run", async (t) => {
  const directory = await temporaryDirectory(t);
  const resultPath = join(directory, "results.jsonl");
  const summaryPath = join(directory, "results.summary.json");
  const config = configWithRecordLimit();
  const provenance = provenanceFor(config);
  let writer = await openResultWriter({
    resultPath,
    mode: "create",
    config,
    provenance,
  });
  const previousRunId = writer.runId;
  await writer.append(failedResult(previousRunId, "old.vendor.com", provenance));
  await writer.finalize(1);

  writer = await openResultWriter({
    resultPath,
    mode: "force",
    config,
    provenance,
  });
  assert.notEqual(writer.runId, previousRunId);
  assert.equal((await readFile(resultPath)).length, 0);
  await writer.append(failedResult(writer.runId, "new.vendor.com", provenance));
  const replacement = await writer.finalize(1);
  assert.equal(replacement.runId, writer.runId);
  assert.equal(
    (JSON.parse(await readFile(summaryPath, "utf8")) as { runId: string }).runId,
    writer.runId,
  );

  const sentinel = Buffer.from("must-not-be-truncated");
  await writeFile(resultPath, sentinel);
  await rm(summaryPath);
  await symlink(join(directory, "elsewhere"), summaryPath);
  await expectWriterError(
    openResultWriter({ resultPath, mode: "force", config, provenance }),
    "OUTPUT_INVALID_TARGET",
  );
  assert.deepEqual(await readFile(resultPath), sentinel);

  const readOnlyResultPath = join(directory, "read-only.jsonl");
  const readOnlySummaryPath = join(directory, "read-only.summary.json");
  const readOnlyResult = Buffer.from("read-only result");
  const readOnlySummary = Buffer.from("summary must survive failed force");
  await writeFile(readOnlyResultPath, readOnlyResult, { mode: 0o400 });
  await writeFile(readOnlySummaryPath, readOnlySummary, { mode: 0o600 });
  await expectWriterError(
    openResultWriter({
      resultPath: readOnlyResultPath,
      mode: "force",
      config,
      provenance,
    }),
    "OUTPUT_INVALID_TARGET",
  );
  assert.deepEqual(await readFile(readOnlyResultPath), readOnlyResult);
  assert.deepEqual(await readFile(readOnlySummaryPath), readOnlySummary);
});

test("rejects symlink and directory targets without following them", async (t) => {
  const directory = await temporaryDirectory(t);
  const config = configWithRecordLimit();
  const provenance = provenanceFor(config);
  const realPath = join(directory, "real.jsonl");
  const symlinkPath = join(directory, "link.jsonl");
  const directoryPath = join(directory, "directory.jsonl");
  await writeFile(realPath, "", { mode: 0o600 });
  await symlink(realPath, symlinkPath);
  await mkdir(directoryPath);

  for (const resultPath of [symlinkPath, directoryPath]) {
    for (const mode of ["create", "resume", "force"] as const) {
      await expectWriterError(
        openResultWriter({ resultPath, mode, config, provenance }),
        "OUTPUT_INVALID_TARGET",
      );
    }
  }
});

test("bounds serialized appends and cleans failed summary temporaries", async (t) => {
  const directory = await temporaryDirectory(t);
  const resultPath = join(directory, "results.jsonl");
  const summaryPath = join(directory, "results.summary.json");
  const config = configWithRecordLimit(65_536);
  const provenance = provenanceFor(config);
  let writer = await openResultWriter({
    resultPath,
    mode: "create",
    config,
    provenance,
  });
  const oversized = {
    toJSON: () => ({ padding: "x".repeat(65_536) }),
  } as unknown as DomainResult;
  await expectWriterError(writer.append(oversized), "OUTPUT_RECORD_LIMIT");
  assert.equal(writer.processedDomains, 0);
  assert.equal((await readFile(resultPath)).length, 0);
  await writer.close();

  await rm(resultPath);
  writer = await openResultWriter({
    resultPath,
    mode: "create",
    config,
    provenance,
  });
  await writer.append(failedResult(writer.runId, "one.vendor.com", provenance));
  await mkdir(summaryPath);
  await expectWriterError(writer.finalize(1), "OUTPUT_INVALID_TARGET");
  assert.equal(
    (await readdir(directory)).some((name) => name.endsWith(".tmp")),
    false,
  );
  await writer.close();
  await writer.close();
});

test("finalize requires every validated input domain and closes on mismatch", async (t) => {
  const directory = await temporaryDirectory(t);
  const resultPath = join(directory, "results.data");
  const summaryPath = `${resultPath}.summary.json`;
  const config = configWithRecordLimit();
  const provenance = provenanceFor(config);
  const writer = await openResultWriter({
    resultPath,
    mode: "create",
    config,
    provenance,
  });
  await writer.append(failedResult(writer.runId, "one.vendor.com", provenance));
  await expectWriterError(writer.finalize(2), "OUTPUT_FINALIZE_MISMATCH");
  await assert.rejects(lstat(summaryPath), { code: "ENOENT" });
  await writer.close();
  await writer.close();
});

test("refuses an existing paired summary before creating a new result", async (t) => {
  const directory = await temporaryDirectory(t);
  const resultPath = join(directory, "results.jsonl");
  const summaryPath = join(directory, "results.summary.json");
  const config = configWithRecordLimit();
  const provenance = provenanceFor(config);
  await writeFile(summaryPath, "old summary", { mode: 0o600 });
  await chmod(summaryPath, 0o600);

  await expectWriterError(
    openResultWriter({ resultPath, mode: "create", config, provenance }),
    "OUTPUT_EXISTS",
  );
  await assert.rejects(lstat(resultPath), { code: "ENOENT" });
  assert.equal(await readFile(summaryPath, "utf8"), "old summary");
});

test("rejects an invalid mode before mutating either output target", async (t) => {
  const directory = await temporaryDirectory(t);
  const resultPath = join(directory, "results.jsonl");
  const summaryPath = join(directory, "results.summary.json");
  const resultBytes = Buffer.from("result sentinel");
  const summaryBytes = Buffer.from("summary sentinel");
  const config = configWithRecordLimit();
  const provenance = provenanceFor(config);
  await writeFile(resultPath, resultBytes, { mode: 0o600 });
  await writeFile(summaryPath, summaryBytes, { mode: 0o600 });

  await expectWriterError(
    openResultWriter({
      resultPath,
      mode: "invalid" as never,
      config,
      provenance,
    }),
    "OUTPUT_INVALID_MODE",
  );
  assert.deepEqual(await readFile(resultPath), resultBytes);
  assert.deepEqual(await readFile(summaryPath), summaryBytes);
});

test("rejects hard-linked results and safely unlinks paired summary aliases", async (t) => {
  const directory = await temporaryDirectory(t);
  const config = configWithRecordLimit();
  const provenance = provenanceFor(config);

  const resultSource = join(directory, "result-source");
  const resultPath = join(directory, "hard-linked.jsonl");
  const resultBytes = Buffer.from("hard-linked result sentinel");
  await writeFile(resultSource, resultBytes, { mode: 0o600 });
  await link(resultSource, resultPath);
  for (const mode of ["resume", "force"] as const) {
    await expectWriterError(
      openResultWriter({ resultPath, mode, config, provenance }),
      "OUTPUT_INVALID_TARGET",
    );
    assert.deepEqual(await readFile(resultPath), resultBytes);
    assert.deepEqual(await readFile(resultSource), resultBytes);
  }

  const createResultPath = join(directory, "create.jsonl");
  const createSummarySource = join(directory, "create-summary-source");
  const createSummaryPath = join(directory, "create.summary.json");
  const createSummaryBytes = Buffer.from("create summary victim");
  await writeFile(createSummarySource, createSummaryBytes, { mode: 0o600 });
  await link(createSummarySource, createSummaryPath);

  await expectWriterError(
    openResultWriter({
      resultPath: createResultPath,
      mode: "create",
      config,
      provenance,
    }),
    "OUTPUT_EXISTS",
  );
  await assert.rejects(lstat(createResultPath), { code: "ENOENT" });
  assert.deepEqual(await readFile(createSummaryPath), createSummaryBytes);
  assert.deepEqual(await readFile(createSummarySource), createSummaryBytes);

  const forceResultPath = join(directory, "force.jsonl");
  const forceSummarySource = join(directory, "force-summary-source");
  const forceSummaryPath = join(directory, "force.summary.json");
  const forceSummaryBytes = Buffer.from("force summary victim");
  await writeFile(forceResultPath, "force result sentinel", { mode: 0o600 });
  await writeFile(forceSummarySource, forceSummaryBytes, { mode: 0o600 });
  await link(forceSummarySource, forceSummaryPath);
  let opened: ResultWriter | undefined;
  try {
    opened = await openResultWriter({
      resultPath: forceResultPath,
      mode: "force",
      config,
      provenance,
    });
    await assert.rejects(lstat(forceSummaryPath), { code: "ENOENT" });
    assert.deepEqual(await readFile(forceSummarySource), forceSummaryBytes);
    assert.equal((await readFile(forceResultPath)).length, 0);
  } finally {
    await closeQuietly(opened);
  }

  const resumeResultPath = join(directory, "resume-hardlink.jsonl");
  const resumeSummarySource = join(directory, "resume-summary-source");
  const resumeSummaryPath = join(directory, "resume-hardlink.summary.json");
  const resumeSummaryBytes = Buffer.from("resume summary victim");
  const runId = "37937a78-f39d-49ed-a51d-6d398ae45a20";
  await writeFile(
    resumeResultPath,
    `${JSON.stringify(failedResult(runId, "resume.vendor.com", provenance))}\n`,
    { mode: 0o600 },
  );
  await writeFile(resumeSummarySource, resumeSummaryBytes, { mode: 0o600 });
  await link(resumeSummarySource, resumeSummaryPath);
  opened = undefined;
  try {
    opened = await openResultWriter({
      resultPath: resumeResultPath,
      mode: "resume",
      config,
      provenance,
    });
    await assert.rejects(lstat(resumeSummaryPath), { code: "ENOENT" });
    assert.deepEqual(await readFile(resumeSummarySource), resumeSummaryBytes);
    assert.equal(opened.processedDomains, 1);
  } finally {
    await closeQuietly(opened);
  }
});

test("resume and force remove a validated stale paired summary immediately", async (t) => {
  const directory = await temporaryDirectory(t);
  const resultPath = join(directory, "results.jsonl");
  const summaryPath = join(directory, "results.summary.json");
  const config = configWithRecordLimit();
  const provenance = provenanceFor(config);
  let writer = await openResultWriter({
    resultPath,
    mode: "create",
    config,
    provenance,
  });
  await writer.append(failedResult(writer.runId, "old.vendor.com", provenance));
  await writer.finalize(1);
  await writeFile(summaryPath, "stale resume summary", { mode: 0o600 });

  writer = await openResultWriter({
    resultPath,
    mode: "resume",
    config,
    provenance,
  });
  await assert.rejects(lstat(summaryPath), { code: "ENOENT" });
  await writer.close();

  await writeFile(summaryPath, "stale force summary", { mode: 0o600 });
  writer = await openResultWriter({
    resultPath,
    mode: "force",
    config,
    provenance,
  });
  await assert.rejects(lstat(summaryPath), { code: "ENOENT" });
  assert.equal((await readFile(resultPath)).length, 0);
  await writer.close();
});

test("allows one writer per output directory in-process and releases it on close", async (t) => {
  const directory = await temporaryDirectory(t);
  const resultPath = join(directory, "results.jsonl");
  const config = configWithRecordLimit();
  const provenance = provenanceFor(config);
  const writer = await openResultWriter({
    resultPath,
    mode: "create",
    config,
    provenance,
  });

  await expectWriterError(
    openResultWriter({ resultPath, mode: "resume", config, provenance }),
    "OUTPUT_BUSY",
  );
  await expectWriterError(
    openResultWriter({
      resultPath: join(directory, "RESULTS.JSONL"),
      mode: "resume",
      config,
      provenance,
    }),
    "OUTPUT_BUSY",
  );
  await expectWriterError(
    openResultWriter({
      resultPath: join(directory, "results.summary.json"),
      mode: "create",
      config,
      provenance,
    }),
    "OUTPUT_BUSY",
  );
  await expectWriterError(
    openResultWriter({
      resultPath: join(directory, "unrelated.jsonl"),
      mode: "create",
      config,
      provenance,
    }),
    "OUTPUT_BUSY",
  );
  await writer.close();

  const reopened = await openResultWriter({
    resultPath,
    mode: "resume",
    config,
    provenance,
  });
  assert.equal(reopened.processedDomains, 0);
  await reopened.close();
});

test("enforces the configured input row limit on append and resume", async (t) => {
  const directory = await temporaryDirectory(t);
  const config = configWithRecordLimit(undefined, 1);
  const provenance = provenanceFor(config);
  const appendPath = join(directory, "append.jsonl");
  const writer = await openResultWriter({
    resultPath: appendPath,
    mode: "create",
    config,
    provenance,
  });
  await writer.append(failedResult(writer.runId, "one.vendor.com", provenance));
  await expectWriterError(
    writer.append(failedResult(writer.runId, "two.vendor.com", provenance)),
    "OUTPUT_DOMAIN_LIMIT",
  );
  assert.equal(writer.processedDomains, 1);
  assert.equal((await readFile(appendPath, "utf8")).trimEnd().split("\n").length, 1);
  await writer.close();

  const resumePath = join(directory, "resume.jsonl");
  const runId = "37937a78-f39d-49ed-a51d-6d398ae45a20";
  const resumeBytes = Buffer.from([
    JSON.stringify(failedResult(runId, "one.vendor.com", provenance)),
    JSON.stringify(failedResult(runId, "two.vendor.com", provenance)),
    "",
  ].join("\n"));
  await writeFile(resumePath, resumeBytes, { mode: 0o600 });
  await expectWriterError(
    openResultWriter({ resultPath: resumePath, mode: "resume", config, provenance }),
    "OUTPUT_DOMAIN_LIMIT",
  );
  assert.deepEqual(await readFile(resumePath), resumeBytes);
});

test("never exposes corrupt resume bytes through an error or its cause", async (t) => {
  const directory = await temporaryDirectory(t);
  const config = configWithRecordLimit();
  const provenance = provenanceFor(config);
  const cases = [
    ["invalid-json", "OUTPUT_INVALID_RESUME", "{\"secret\":\"resume-json-secret\",]\n"],
    ["invalid-record", "OUTPUT_INVALID_RECORD", "{\"secret\":\"resume-record-secret\"}\n"],
  ] as const;

  for (const [name, code, text] of cases) {
    const resultPath = join(directory, `${name}.jsonl`);
    const bytes = Buffer.from(text);
    const secret = text.match(/resume-[a-z-]+-secret/u)?.[0];
    assert.ok(secret);
    await writeFile(resultPath, bytes, { mode: 0o600 });

    await assert.rejects(
      openResultWriter({ resultPath, mode: "resume", config, provenance }),
      (error: unknown) => {
        assert.ok(error instanceof OutputWriterError);
        assert.equal(error.code, code);
        assert.equal(error.cause, undefined);
        assert.equal(error.message.includes(secret), false);
        assert.equal(String(error.cause).includes(secret), false);
        return true;
      },
    );
    assert.deepEqual(await readFile(resultPath), bytes);
  }
});

test("snapshots config and provenance before caller-owned context mutates", async (t) => {
  const directory = await temporaryDirectory(t);
  const resultPath = join(directory, "results.jsonl");
  const baseConfig = configWithRecordLimit();
  const baseProvenance = provenanceFor(baseConfig);
  const mutableConfig = structuredClone(baseConfig) as ScanConfig;
  const mutableProvenance = structuredClone(baseProvenance) as Provenance;
  const expectedConfig = structuredClone(mutableConfig);
  const expectedProvenance = structuredClone(mutableProvenance);
  const writer = await openResultWriter({
    resultPath,
    mode: "create",
    config: mutableConfig,
    provenance: mutableProvenance,
  });

  (mutableConfig as unknown as {
    limits: { parquet: { rows: number } };
  }).limits.parquet.rows = 1;
  (mutableProvenance as unknown as {
    runtime: { chromiumRevision: string };
    catalog: { revision: string };
    configDigest: string;
  }).runtime.chromiumRevision = "caller-mutated";
  (mutableProvenance as unknown as {
    runtime: { chromiumRevision: string };
    catalog: { revision: string };
    configDigest: string;
  }).catalog.revision = "caller-mutated";
  (mutableProvenance as unknown as {
    runtime: { chromiumRevision: string };
    catalog: { revision: string };
    configDigest: string;
  }).configDigest = `sha256:${"f".repeat(64)}`;

  await writer.append(
    failedResult(writer.runId, "stable.vendor.com", expectedProvenance),
  );
  const summary = await writer.finalize(1);
  assert.deepEqual(summary.config, expectedConfig);
  assert.deepEqual(summary.provenance, expectedProvenance);
});
