import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Writable } from "node:stream";
import { setImmediate as waitForImmediate } from "node:timers/promises";
import { test } from "node:test";
import { promisify } from "node:util";

import { createDefaultScanConfig } from "../src/config.ts";
import type { BrowserPool } from "../src/crawl/browser.ts";
import type { ProtectedHttpTransport } from "../src/crawl/transport.ts";
import type { CompiledFingerprintCatalog } from "../src/detect/catalog.ts";
import type { DetectorPool } from "../src/detect/pool.ts";
import {
  openParquetDomainsFromFile,
  type PreparedParquetDomains,
} from "../src/input/parquet.ts";
import type { DomainResult, ErrorCode, Provenance } from "../src/model.ts";
import type {
  ScanDomainContext,
  ScanDomainOptions,
} from "../src/pipeline.ts";
import {
  parseCliArgs,
  runCli,
  type CliDependencies,
} from "../src/cli.ts";
import type {
  OpenResultWriterOptions,
  ResultWriter,
  ResultWriterMode,
} from "../src/output/writer.ts";
import type { RunSummary } from "../src/output/summary.ts";

const CONTACT = "https://crawler.veridion.com/contact";
const RUN_ID = "12345678-1234-4123-8123-123456789abc";
const execFileAsync = promisify(execFile);

class CapturedStream extends Writable {
  #chunks: Buffer[] = [];

  override _write(
    chunk: Buffer | string,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.#chunks.push(
      Buffer.isBuffer(chunk) ? Buffer.from(chunk) : Buffer.from(chunk, encoding),
    );
    callback();
  }

  text(): string {
    return Buffer.concat(this.#chunks).toString("utf8");
  }
}

interface Deferred<T> {
  readonly promise: Promise<T>;
  resolve(value: T): void;
  reject(reason: unknown): void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

async function waitUntil(
  predicate: () => boolean,
  label: string,
): Promise<void> {
  for (let attempt = 0; attempt < 1_000; attempt += 1) {
    if (predicate()) {
      return;
    }
    await waitForImmediate();
  }
  assert.fail(`Timed out waiting for ${label}.`);
}

function failedResult(
  domain: string,
  provenance: Provenance,
  code: ErrorCode = "TARGET_NOT_FOUND",
): DomainResult {
  return {
    schemaVersion: 1,
    runId: RUN_ID,
    domain,
    scannedAt: "2026-08-18T10:11:12.345Z",
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
      stage: code === "DETECTOR_UNAVAILABLE" ? "detect" : "target",
      code,
      pageId: null,
      retryable: code === "DETECTOR_UNAVAILABLE",
      message: code === "DETECTOR_UNAVAILABLE"
        ? "The isolated detector pool is unavailable."
        : "No canonical target succeeded.",
      ruleId: null,
      signal: null,
      limit: null,
      catalogRevision: null,
    }],
    timings: {
      totalMs: 1,
      targetMs: code === "DETECTOR_UNAVAILABLE" ? null : 1,
      robotsMs: null,
      httpMs: null,
      dnsMs: null,
      tlsMs: null,
      browserMs: null,
      detectMs: code === "DETECTOR_UNAVAILABLE" ? 0 : null,
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
  };
}

class FakePreparedInput implements PreparedParquetDomains {
  readonly domainCount: number;
  readonly sourcePath: string;
  readonly #values: readonly string[];
  readonly #domainSet: ReadonlySet<string>;
  readonly #events: string[];
  yielded = 0;
  closeCalls = 0;

  constructor(
    values: readonly string[],
    events: string[],
    sourcePath = resolve("package.json"),
  ) {
    this.domainCount = values.length;
    this.sourcePath = sourcePath;
    this.#values = values;
    this.#domainSet = new Set(values);
    this.#events = events;
  }

  hasDomain(domain: string): boolean {
    return this.#domainSet.has(domain);
  }

  async *domains(): AsyncGenerator<string> {
    for (const domain of this.#values) {
      this.yielded += 1;
      this.#events.push(`yield:${domain}`);
      yield domain;
    }
  }

  async close(): Promise<void> {
    this.closeCalls += 1;
    this.#events.push("input:close");
  }
}

class FakeWriter implements ResultWriter {
  readonly runId = RUN_ID;
  readonly #completed: Set<string>;
  readonly #events: string[];
  readonly appended: DomainResult[] = [];
  finalizeCalls: number[] = [];
  closeCalls = 0;
  #closed = false;

  constructor(events: string[], completed: readonly string[] = []) {
    this.#events = events;
    this.#completed = new Set(completed);
  }

  get processedDomains(): number {
    return this.#completed.size;
  }

  hasCompletedDomain(domain: string): boolean {
    return this.#completed.has(domain);
  }

  async append(result: DomainResult): Promise<void> {
    this.#events.push(`append:${result.domain}`);
    this.appended.push(result);
    this.#completed.add(result.domain);
  }

  async finalize(inputDomains: number): Promise<RunSummary> {
    this.#events.push(`writer:finalize:${inputDomains}`);
    this.finalizeCalls.push(inputDomains);
    await this.close();
    return {
      processedDomains: inputDomains,
      statusCounts: { success: 0, partial: 0, failed: inputDomains },
    } as unknown as RunSummary;
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    this.closeCalls += 1;
    this.#events.push("writer:close");
  }
}

interface HarnessOptions {
  readonly domains?: readonly string[];
  readonly completed?: readonly string[];
  readonly sourcePath?: string;
  readonly scan?: (
    domain: string,
    context: ScanDomainContext,
    options?: ScanDomainOptions,
  ) => Promise<DomainResult>;
  readonly openInput?: () => Promise<PreparedParquetDomains>;
}

interface Harness {
  readonly events: string[];
  readonly input: FakePreparedInput;
  readonly writer: FakeWriter;
  readonly dependencies: CliDependencies;
  readonly stdout: CapturedStream;
  readonly stderr: CapturedStream;
  writerMode(): ResultWriterMode | null;
  writerResultPath(): string | null;
}

function createHarness(options: HarnessOptions = {}): Harness {
  const events: string[] = [];
  const input = new FakePreparedInput(
    options.domains ?? ["one.vendor.com"],
    events,
    options.sourcePath,
  );
  const writer = new FakeWriter(events, options.completed);
  const stdout = new CapturedStream();
  const stderr = new CapturedStream();
  let openedMode: ResultWriterMode | null = null;
  let openedResultPath: string | null = null;

  const catalog = {
    source: "fixture-catalog",
    revision: "fixture-v1",
    digest: `sha256:${"a".repeat(64)}`,
  } as unknown as CompiledFingerprintCatalog;
  const detectorPool = {
    catalog,
    isAvailable: () => true,
    close: async () => {
      events.push("detector:close");
    },
  } as unknown as DetectorPool;
  const browserPool = {
    runtime: {
      playwright: "1.62.1",
      chromiumRevision: "1234",
      chromiumVersion: "151.0.7922.34",
    },
    isAvailable: () => true,
    close: async () => {
      events.push("browser:close");
    },
  } as unknown as BrowserPool;
  const transport = {} as ProtectedHttpTransport;
  const robots = {
    check: async () => {
      throw new Error("The fake robots service must not collect network data.");
    },
    allowsCached: () => false,
    clear: () => {
      events.push("robots:clear");
    },
  };

  const dependencies = {
    openInput: options.openInput ?? (async () => {
      events.push("input:prepared");
      return input;
    }),
    loadFingerprintCatalog: () => {
      events.push("catalog:loaded");
      return catalog;
    },
    createProtectedHttpTransport: () => {
      events.push("transport:created");
      return transport;
    },
    createDetectorPool: async () => {
      events.push("detector:ready");
      return detectorPool;
    },
    createBrowserPool: async () => {
      events.push("browser:ready");
      return browserPool;
    },
    createRobotsPolicyService: () => {
      events.push("robots:created");
      return robots;
    },
    openResultWriter: async (writerOptions: OpenResultWriterOptions) => {
      if (writerOptions.mode === "resume") {
        for (const domain of options.completed ?? []) {
          if (writerOptions.resumeDomainAllowed?.(domain) !== true) {
            events.push("writer:resume-rejected");
            throw new Error("Resume contains a domain outside the input.");
          }
        }
      }
      openedMode = writerOptions.mode;
      openedResultPath = writerOptions.resultPath;
      events.push(`writer:open:${writerOptions.mode}`);
      return writer;
    },
    resolveResultOutputPaths: async () => {
      events.push("output:resolved");
      return {
        resultPath: "/private/tmp/veridion-cli-results.jsonl",
        summaryPath: "/private/tmp/veridion-cli-results.summary.json",
      };
    },
    scanDomain: options.scan ?? (async (domain, context) => {
      events.push(`scan:${domain}`);
      return failedResult(domain, context.provenance);
    }),
  } as unknown as CliDependencies;

  return {
    events,
    input,
    writer,
    dependencies,
    stdout,
    stderr,
    writerMode: () => openedMode,
    writerResultPath: () => openedResultPath,
  };
}

function cliArguments(...extra: readonly string[]): string[] {
  return [
    "--contact",
    CONTACT,
    "--input",
    "fixture.parquet",
    "--output",
    "results.jsonl",
    ...extra,
  ];
}

test("parses the bounded operational surface without accepting ambiguous modes", () => {
  assert.doesNotThrow(() => parseCliArgs(cliArguments()));
  assert.doesNotThrow(() => parseCliArgs(["--config", "scan-config.json"]));
  assert.doesNotThrow(() => parseCliArgs(["--help"]));
  assert.doesNotThrow(() => parseCliArgs(["--version"]));

  for (const argv of [
    [],
    ["--contact", CONTACT, "--config", "scan-config.json"],
    cliArguments("--resume", "--force"),
    ["--contact", "mailto:.@veridion.com"],
    ["--contact", "mailto:a..b@veridion.com"],
    ["--contact", "mailto:a.@veridion.com"],
    ["--contact", CONTACT, "unexpected"],
    ["--contact", CONTACT, "--unknown"],
  ]) {
    assert.throws(() => parseCliArgs(argv));
  }
});

test("prints help, version, and usage failures without initializing the run", async () => {
  const help = createHarness();
  assert.equal(await runCli(["--help"], {
    dependencies: help.dependencies,
    stdout: help.stdout,
    stderr: help.stderr,
  }), 0);
  assert.match(help.stdout.text(), /Usage:/u);
  assert.equal(help.stderr.text(), "");
  assert.deepEqual(help.events, []);

  const version = createHarness();
  assert.equal(await runCli(["--version"], {
    dependencies: version.dependencies,
    stdout: version.stdout,
    stderr: version.stderr,
  }), 0);
  assert.equal(version.stdout.text(), "0.1.1\n");
  assert.equal(version.stderr.text(), "");
  assert.deepEqual(version.events, []);

  const invalid = createHarness();
  assert.equal(await runCli([], {
    dependencies: invalid.dependencies,
    stdout: invalid.stdout,
    stderr: invalid.stderr,
  }), 2);
  assert.equal(invalid.stdout.text(), "");
  assert.match(invalid.stderr.text(), /Usage:/u);
  assert.deepEqual(invalid.events, []);
});

test("loads one complete bounded JSON configuration before input preflight", async () => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-cli-config-"));
  const configPath = join(directory, "scan-config.json");
  const oversizedPath = join(directory, "oversized.json");

  try {
    await writeFile(
      configPath,
      JSON.stringify(createDefaultScanConfig(
        "WebsiteTechScraper/0.1.1 (https://crawler.veridion.com/contact)",
      )),
      { encoding: "utf8", mode: 0o600 },
    );
    const valid = createHarness();
    assert.equal(await runCli([
      "--config",
      configPath,
      "--input",
      "fixture.parquet",
      "--output",
      "results.jsonl",
      "--quiet",
    ], {
      dependencies: valid.dependencies,
      stdout: valid.stdout,
      stderr: valid.stderr,
    }), 0);
    assert.equal(valid.events[0], "input:prepared");

    await writeFile(
      oversizedPath,
      Buffer.alloc(1_048_577, 0x20),
      { mode: 0o600 },
    );
    const oversized = createHarness();
    assert.equal(await runCli([
      "--config",
      oversizedPath,
      "--input",
      "fixture.parquet",
      "--output",
      "results.jsonl",
    ], {
      dependencies: oversized.dependencies,
      stdout: oversized.stdout,
      stderr: oversized.stderr,
    }), 1);
    assert.deepEqual(oversized.events, []);
    assert.match(oversized.stderr.text(), /CLI_CONFIG_INVALID/u);

    const invalidContactPath = join(directory, "invalid-contact.json");
    const invalidContact = createDefaultScanConfig(
      "WebsiteTechScraper/0.1.1 (https://crawler.veridion.com/contact)",
    );
    await writeFile(
      invalidContactPath,
      JSON.stringify({ ...invalidContact, userAgent: "WebsiteTechScraper/0.1.1 (https://x)" }),
      { encoding: "utf8", mode: 0o600 },
    );
    const rejectedContact = createHarness();
    assert.equal(await runCli([
      "--config",
      invalidContactPath,
      "--input",
      "fixture.parquet",
      "--output",
      "results.jsonl",
    ], {
      dependencies: rejectedContact.dependencies,
      stdout: rejectedContact.stdout,
      stderr: rejectedContact.stderr,
    }), 1);
    assert.deepEqual(rejectedContact.events, []);
    assert.match(rejectedContact.stderr.text(), /CLI_CONFIG_INVALID/u);

    const invalidConfigs: readonly (readonly [string, string | Buffer])[] = [
      ["malformed.json", "{\"userAgent\":"],
      ["invalid-utf8.json", Buffer.from([0xc3, 0x28])],
      [
        "wrong-version.json",
        JSON.stringify({
          ...invalidContact,
          userAgent: "WebsiteTechScraper/9.9.9 (https://crawler.veridion.com/contact)",
        }),
      ],
    ];
    for (const [basename, contents] of invalidConfigs) {
      const invalidPath = join(directory, basename);
      await writeFile(invalidPath, contents, { mode: 0o600 });
      const invalid = createHarness();
      assert.equal(await runCli([
        "--config",
        invalidPath,
        "--input",
        "fixture.parquet",
        "--output",
        "results.jsonl",
      ], {
        dependencies: invalid.dependencies,
        stdout: invalid.stdout,
        stderr: invalid.stderr,
      }), 1);
      assert.deepEqual(invalid.events, []);
      assert.match(invalid.stderr.text(), /CLI_CONFIG_INVALID/u);
    }

    const alias = createHarness();
    const aliasDependencies: CliDependencies = {
      ...alias.dependencies,
      resolveResultOutputPaths: async () => ({
        resultPath: configPath,
        summaryPath: join(directory, "scan-config.summary.json"),
      }),
    };
    assert.equal(await runCli([
      "--config",
      configPath,
      "--input",
      "fixture.parquet",
      "--output",
      "results.jsonl",
      "--force",
    ], {
      dependencies: aliasDependencies,
      stdout: alias.stdout,
      stderr: alias.stderr,
    }), 1);
    assert.equal(alias.events.includes("catalog:loaded"), false);
    assert.match(alias.stderr.text(), /CLI_PATH_COLLISION/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("rejects non-regular config and input files without blocking", {
  skip: process.platform === "win32",
  timeout: 5_000,
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "veridion-cli-fifo-"));
  const configFifo = join(directory, "config.fifo");
  const inputFifo = join(directory, "input.fifo");

  try {
    await execFileAsync("mkfifo", [configFifo]);
    await execFileAsync("mkfifo", [inputFifo]);

    const config = createHarness();
    assert.equal(await runCli([
      "--config",
      configFifo,
      "--input",
      "fixture.parquet",
      "--output",
      "results.jsonl",
    ], {
      dependencies: config.dependencies,
      stdout: config.stdout,
      stderr: config.stderr,
    }), 1);
    assert.deepEqual(config.events, []);
    assert.match(config.stderr.text(), /CLI_CONFIG_INVALID/u);

    const input = createHarness();
    const dependencies: CliDependencies = {
      ...input.dependencies,
      openInput: openParquetDomainsFromFile,
    };
    assert.equal(await runCli([
      "--contact",
      CONTACT,
      "--input",
      inputFifo,
      "--output",
      "results.jsonl",
    ], {
      dependencies,
      stdout: input.stdout,
      stderr: input.stderr,
    }), 1);
    assert.deepEqual(input.events, []);
    assert.match(input.stderr.text(), /INPUT_OPEN_FAILED/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("preflights input and both required pools before opening output", async () => {
  const harness = createHarness({
    domains: ["one.vendor.com", "two.vendor.com"],
  });

  const exitCode = await runCli(cliArguments("--quiet"), {
    dependencies: harness.dependencies,
    stdout: harness.stdout,
    stderr: harness.stderr,
  });

  assert.equal(exitCode, 0);
  assert.equal(harness.stdout.text(), "");
  assert.equal(harness.stderr.text(), "");
  const inputReady = harness.events.indexOf("input:prepared");
  const catalogReady = harness.events.indexOf("catalog:loaded");
  const detectorReady = harness.events.indexOf("detector:ready");
  const browserReady = harness.events.indexOf("browser:ready");
  const writerOpen = harness.events.indexOf("writer:open:create");
  const firstScan = harness.events.indexOf("scan:one.vendor.com");
  assert.ok(inputReady >= 0 && inputReady < catalogReady);
  assert.ok(catalogReady < detectorReady);
  assert.ok(detectorReady < writerOpen);
  assert.ok(browserReady < writerOpen);
  assert.ok(writerOpen < firstScan);
  assert.equal(
    harness.writerResultPath(),
    "/private/tmp/veridion-cli-results.jsonl",
  );
  assert.deepEqual(harness.writer.finalizeCalls, [2]);
  assert.equal(harness.input.closeCalls, 1);
  assert.equal(harness.writer.closeCalls, 1);
  assert.equal(harness.events.includes("robots:clear"), true);
  assert.equal(harness.events.includes("browser:close"), true);
  assert.equal(harness.events.includes("detector:close"), true);
});

test("does not initialize catalog, pools, or output after input preflight fails", async () => {
  const secret = "secret-invalid-parquet-payload";
  const harness = createHarness({
    openInput: async () => {
      harness.events.push("input:failed");
      throw new Error(secret);
    },
  });

  const exitCode = await runCli(cliArguments(), {
    dependencies: harness.dependencies,
    stdout: harness.stdout,
    stderr: harness.stderr,
  });

  assert.equal(exitCode, 1);
  assert.deepEqual(harness.events, ["input:failed"]);
  assert.equal(harness.stdout.text(), "");
  assert.doesNotMatch(harness.stderr.text(), new RegExp(secret, "u"));
});

test("rejects an input and output pathname collision before destructive output work", async () => {
  const harness = createHarness({
    sourcePath: "/private/tmp/veridion-cli-results.jsonl",
  });

  assert.equal(await runCli(cliArguments("--force"), {
    dependencies: harness.dependencies,
    stdout: harness.stdout,
    stderr: harness.stderr,
  }), 1);
  assert.equal(harness.events.includes("output:resolved"), true);
  assert.equal(harness.events.includes("catalog:loaded"), false);
  assert.equal(
    harness.events.some((event) => event.startsWith("writer:open:")),
    false,
  );
  assert.equal(harness.input.closeCalls, 1);
  assert.match(harness.stderr.text(), /CLI_PATH_COLLISION/u);
});

test("resume validates its completed-domain subset before scanning and skips matches", async () => {
  const valid = createHarness({
    domains: ["one.vendor.com", "two.vendor.com", "three.vendor.com"],
    completed: ["two.vendor.com"],
  });
  assert.equal(await runCli(cliArguments("--resume", "--quiet"), {
    dependencies: valid.dependencies,
    stdout: valid.stdout,
    stderr: valid.stderr,
  }), 0);
  assert.equal(valid.writerMode(), "resume");
  assert.deepEqual(
    valid.events.filter((event) => event.startsWith("scan:")),
    ["scan:one.vendor.com", "scan:three.vendor.com"],
  );
  assert.deepEqual(valid.writer.finalizeCalls, [3]);

  const collision = createHarness({
    domains: ["one.vendor.com"],
    completed: ["outside.vendor.com"],
  });
  assert.equal(await runCli(cliArguments("--resume"), {
    dependencies: collision.dependencies,
    stdout: collision.stdout,
    stderr: collision.stderr,
  }), 1);
  assert.equal(
    collision.events.some((event) => event.startsWith("scan:")),
    false,
  );
  assert.deepEqual(collision.writer.finalizeCalls, []);
  assert.equal(collision.writer.closeCalls, 0);
  assert.equal(collision.events.includes("writer:resume-rejected"), true);
  assert.equal(collision.input.closeCalls, 1);
});

test("force selects a new writer mode and scans every input domain", async () => {
  const harness = createHarness({
    domains: ["one.vendor.com", "two.vendor.com"],
  });

  assert.equal(await runCli(cliArguments("--force", "--quiet"), {
    dependencies: harness.dependencies,
    stdout: harness.stdout,
    stderr: harness.stderr,
  }), 0);
  assert.equal(harness.writerMode(), "force");
  assert.deepEqual(
    harness.writer.appended.map((result) => result.domain),
    ["one.vendor.com", "two.vendor.com"],
  );
});

test("bounds scans with input backpressure and appends in completion order", async () => {
  const gates = new Map<string, Deferred<DomainResult>>();
  const started: string[] = [];
  let active = 0;
  let maximumActive = 0;
  const harness = createHarness({
    domains: [
      "one.vendor.com",
      "two.vendor.com",
      "three.vendor.com",
      "four.vendor.com",
    ],
    scan: async (domain, _context) => {
      started.push(domain);
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      const gate = deferred<DomainResult>();
      gates.set(domain, gate);
      try {
        return await gate.promise;
      } finally {
        active -= 1;
      }
    },
  });

  const run = runCli(cliArguments("--quiet"), {
    dependencies: harness.dependencies,
    stdout: harness.stdout,
    stderr: harness.stderr,
  });
  await waitUntil(() => started.length === 3, "the initial bounded scan set");
  assert.equal(active, 3);
  assert.ok(harness.input.yielded <= 4);

  const context = await waitForContext(harness, gates);
  gates.get("two.vendor.com")?.resolve(failedResult("two.vendor.com", context));
  await waitUntil(() => started.includes("four.vendor.com"), "the fourth scan");
  gates.get("four.vendor.com")?.resolve(failedResult("four.vendor.com", context));
  gates.get("three.vendor.com")?.resolve(failedResult("three.vendor.com", context));
  gates.get("one.vendor.com")?.resolve(failedResult("one.vendor.com", context));

  assert.equal(await run, 0);
  assert.equal(maximumActive, 3);
  assert.deepEqual(
    harness.writer.appended.map((result) => result.domain),
    [
      "two.vendor.com",
      "four.vendor.com",
      "three.vendor.com",
      "one.vendor.com",
    ],
  );
});

async function waitForContext(
  harness: Harness,
  gates: ReadonlyMap<string, Deferred<DomainResult>>,
): Promise<Provenance> {
  await waitUntil(() => gates.size > 0, "a scan context");
  const event = harness.events.find((value) => value.startsWith("writer:open:"));
  assert.ok(event);
  return {
    scannerVersion: "0.1.1",
    runtime: {
      node: "24.19.0",
      playwright: "1.62.1",
      chromiumRevision: "1234",
    },
    catalog: {
      source: "fixture-catalog",
      revision: "fixture-v1",
      digest: `sha256:${"a".repeat(64)}`,
    },
    configDigest: `sha256:${"b".repeat(64)}`,
  };
}

test("aborts sibling work, sanitizes fatal diagnostics, and closes every resource", async () => {
  const secret = "secret-scan-exception";
  let siblingAborted = false;
  const harness = createHarness({
    domains: ["one.vendor.com", "two.vendor.com"],
    scan: async (domain, _context, options) => {
      if (domain === "one.vendor.com") {
        await waitForImmediate();
        throw new Error(secret);
      }
      const signal = options?.signal;
      assert.ok(signal);
      if (!signal.aborted) {
        await new Promise<void>((resolve) => {
          signal.addEventListener("abort", () => resolve(), { once: true });
        });
      }
      siblingAborted = true;
      throw signal.reason;
    },
  });

  assert.equal(await runCli(cliArguments(), {
    dependencies: harness.dependencies,
    stdout: harness.stdout,
    stderr: harness.stderr,
  }), 1);
  assert.equal(siblingAborted, true);
  assert.deepEqual(harness.writer.finalizeCalls, []);
  assert.equal(harness.writer.closeCalls, 1);
  assert.equal(harness.input.closeCalls, 1);
  assert.equal(harness.events.includes("robots:clear"), true);
  assert.equal(harness.events.includes("browser:close"), true);
  assert.equal(harness.events.includes("detector:close"), true);
  assert.doesNotMatch(harness.stderr.text(), new RegExp(secret, "u"));
});

test("maps caller cancellation to 130 after bounded cleanup", async () => {
  const controller = new AbortController();
  let scanStarted = false;
  const harness = createHarness({
    scan: async (_domain, _context, options) => {
      scanStarted = true;
      const signal = options?.signal;
      assert.ok(signal);
      if (!signal.aborted) {
        await new Promise<void>((resolve) => {
          signal.addEventListener("abort", () => resolve(), { once: true });
        });
      }
      throw signal.reason;
    },
  });

  const run = runCli(cliArguments(), {
    dependencies: harness.dependencies,
    signal: controller.signal,
    stdout: harness.stdout,
    stderr: harness.stderr,
  });
  await waitUntil(
    () => scanStarted,
    "the cancellable scan",
  );
  controller.abort(new DOMException("Interrupted", "AbortError"));

  assert.equal(await run, 130);
  assert.deepEqual(harness.writer.finalizeCalls, []);
  assert.equal(harness.writer.closeCalls, 1);
  assert.equal(harness.input.closeCalls, 1);
});

test("honors cancellation that arrives while the summary is finalizing", async () => {
  const controller = new AbortController();
  const finalizeEntered = deferred<void>();
  const releaseFinalize = deferred<RunSummary>();
  const harness = createHarness({ domains: [] });
  const writer: ResultWriter = {
    runId: RUN_ID,
    processedDomains: 0,
    hasCompletedDomain: () => false,
    append: async () => {
      assert.fail("An empty input must not append a result.");
    },
    finalize: async () => {
      finalizeEntered.resolve();
      return releaseFinalize.promise;
    },
    close: async () => undefined,
  };
  const dependencies: CliDependencies = {
    ...harness.dependencies,
    openResultWriter: async () => writer,
  };

  const run = runCli(cliArguments(), {
    dependencies,
    signal: controller.signal,
    stdout: harness.stdout,
    stderr: harness.stderr,
  });
  await finalizeEntered.promise;
  controller.abort(new DOMException("Interrupted", "AbortError"));
  releaseFinalize.resolve({
    processedDomains: 0,
    statusCounts: { success: 0, partial: 0, failed: 0 },
  } as unknown as RunSummary);

  assert.equal(await run, 130);
  assert.match(harness.stderr.text(), /CLI_CANCELLED/u);
  assert.doesNotMatch(harness.stderr.text(), /\[COMPLETE\]/u);
});

test("honors cancellation that arrives during final resource cleanup", async () => {
  const controller = new AbortController();
  const closeEntered = deferred<void>();
  const releaseClose = deferred<void>();
  const harness = createHarness({ domains: [] });
  const dependencies: CliDependencies = {
    ...harness.dependencies,
    createBrowserPool: async () => ({
      runtime: {
        playwright: "1.62.1",
        chromiumRevision: "1234",
        chromiumVersion: "151.0.7922.34",
      },
      isAvailable: () => true,
      close: async () => {
        closeEntered.resolve();
        await releaseClose.promise;
      },
    } as unknown as BrowserPool),
  };

  const run = runCli(cliArguments(), {
    dependencies,
    signal: controller.signal,
    stdout: harness.stdout,
    stderr: harness.stderr,
  });
  await closeEntered.promise;
  controller.abort(new DOMException("Interrupted", "AbortError"));
  releaseClose.resolve();

  assert.equal(await run, 130);
  assert.match(harness.stderr.text(), /CLI_CANCELLED/u);
  assert.doesNotMatch(harness.stderr.text(), /\[COMPLETE\]/u);
});

test("finalizes the batch but exits nonzero after a required pool is lost", async () => {
  const harness = createHarness({ domains: [] });
  const dependencies: CliDependencies = {
    ...harness.dependencies,
    createBrowserPool: async () => ({
      runtime: {
        playwright: "1.62.1",
        chromiumRevision: "1234",
        chromiumVersion: "151.0.7922.34",
      },
      isAvailable: () => false,
      close: async () => undefined,
    } as unknown as BrowserPool),
  };

  assert.equal(await runCli(cliArguments(), {
    dependencies,
    stdout: harness.stdout,
    stderr: harness.stderr,
  }), 1);
  assert.deepEqual(harness.writer.finalizeCalls, [0]);
  assert.match(harness.stderr.text(), /\[COMPLETE\]/u);
  assert.match(harness.stderr.text(), /\[CLI_DEGRADED\] unavailable=browser/u);

  const detector = createHarness({ domains: [] });
  const detectorDependencies: CliDependencies = {
    ...detector.dependencies,
    createDetectorPool: async () => ({
      catalog: {} as CompiledFingerprintCatalog,
      isAvailable: () => false,
      close: async () => undefined,
    } as unknown as DetectorPool),
  };
  assert.equal(await runCli(cliArguments(), {
    dependencies: detectorDependencies,
    stdout: detector.stdout,
    stderr: detector.stderr,
  }), 1);
  assert.deepEqual(detector.writer.finalizeCalls, [0]);
  assert.match(
    detector.stderr.text(),
    /\[CLI_DEGRADED\] unavailable=detector\n/u,
  );

  const both = createHarness({ domains: [] });
  const bothDependencies: CliDependencies = {
    ...both.dependencies,
    createDetectorPool: async () => ({
      catalog: {} as CompiledFingerprintCatalog,
      isAvailable: () => false,
      close: async () => undefined,
    } as unknown as DetectorPool),
    createBrowserPool: async () => ({
      runtime: {
        playwright: "1.62.1",
        chromiumRevision: "1234",
        chromiumVersion: "151.0.7922.34",
      },
      isAvailable: () => false,
      close: async () => undefined,
    } as unknown as BrowserPool),
  };
  assert.equal(await runCli(cliArguments(), {
    dependencies: bothDependencies,
    stdout: both.stdout,
    stderr: both.stderr,
  }), 1);
  assert.match(
    both.stderr.text(),
    /\[CLI_DEGRADED\] unavailable=detector,browser/u,
  );
});

test("keeps domain failures successful at the batch level and progress on stderr", async () => {
  const harness = createHarness({ domains: ["one.vendor.com"] });

  assert.equal(await runCli(cliArguments(), {
    dependencies: harness.dependencies,
    stdout: harness.stdout,
    stderr: harness.stderr,
  }), 0);
  assert.equal(harness.stdout.text(), "");
  assert.match(
    harness.stderr.text(),
    /\[PROGRESS\] completed=1 domain=one\.vendor\.com status=failed/u,
  );
  assert.deepEqual(harness.writer.finalizeCalls, [1]);
});
