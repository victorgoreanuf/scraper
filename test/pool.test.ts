import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { setImmediate as waitForImmediate } from "node:timers/promises";
import { test } from "node:test";
import type { Worker, WorkerOptions } from "node:worker_threads";

import {
  createDefaultScanConfig,
  type ScanConfig,
} from "../src/config.ts";
import {
  FingerprintCatalogError,
  type CompiledFingerprintCatalog,
  type CompiledFingerprintRule,
} from "../src/detect/catalog.ts";
import {
  createDetectorPool,
  type DetectorCandidate,
  type DetectorWorkerData,
  type DetectorWorkerFactory,
  type DetectorWorkerRequest,
  type DetectorWorkerResponse,
  type WorkerMatch,
} from "../src/detect/pool.ts";

const userAgent =
  "WebsiteTechScraper/0.1.0 (https://contact.website-tech-scraper.dev/crawler)";

interface DetectorOverrides {
  readonly workers?: number;
  readonly compileWatchdogMs?: number;
  readonly ruleWatchdogMs?: number;
  readonly watchdogPollMs?: number;
  readonly activeMsPerDomain?: number;
  readonly timeoutsPerDomain?: number;
  readonly checkpointRules?: number;
  readonly executionsPerDomain?: number;
  readonly evidencePerDomain?: number;
}

function testConfig(overrides: DetectorOverrides = {}): ScanConfig {
  const config = structuredClone(createDefaultScanConfig(userAgent));
  const { evidencePerDomain, ...detectorOverrides } = overrides;
  Object.assign(config.limits.detector, {
    workers: 1,
    compileWatchdogMs: 5_000,
    ruleWatchdogMs: 20,
    watchdogPollMs: 5,
    activeMsPerDomain: 1_000,
    timeoutsPerDomain: 3,
    checkpointRules: 1,
    executionsPerDomain: 100,
    ...detectorOverrides,
  });
  if (evidencePerDomain !== undefined) {
    Object.assign(config.limits.output, { evidencePerDomain });
  }
  return config;
}

interface RuleInput {
  readonly pattern: string | null;
  readonly matchMode?: "presence" | "literal" | "regex";
  readonly versionTemplate?: string | null;
}

function testCatalog(inputs: readonly RuleInput[]): CompiledFingerprintCatalog {
  const rules: CompiledFingerprintRule[] = inputs.map((input, ordinal) => ({
    ruleId: `sha256:${String(ordinal).padStart(64, "0")}`,
    namespace: "test/pool:rule-v1",
    technology: `Technology ${ordinal}`,
    source: "html",
    locator: null,
    locatorPattern: null,
    original: input.pattern ?? "",
    pattern: input.pattern,
    matchMode: input.matchMode ?? "regex",
    confidence: 100,
    versionTemplate: input.versionTemplate ?? null,
  }));

  return {
    source: "test/pool",
    revision: "fixture-v1",
    digest: `sha256:${"0".repeat(64)}`,
    categories: [],
    technologies: [],
    rules,
    indexes: [{
      source: "html",
      unkeyedRuleOrdinals: rules.map((_rule, ordinal) => ordinal),
      keyed: [],
      patternLocatorRuleOrdinals: [],
    }],
    inspectionPlan: {
      dom: [],
      javascript: [],
      probePaths: [],
      dnsRecordTypes: [],
      tlsIssuer: false,
    },
    declarationCount: rules.length,
    relationshipCount: 0,
    regexSourceCount: rules.filter((rule) => rule.matchMode === "regex").length,
    regexSourceCodeUnits: rules.reduce(
      (total, rule) => total + (rule.pattern?.length ?? 0),
      0,
    ),
  };
}

function candidate(value: string): DetectorCandidate {
  return {
    id: "0001",
    kind: "value",
    source: "html",
    key: null,
    value,
  };
}

function identifiedCandidate(id: string, value: string): DetectorCandidate {
  return { ...candidate(value), id };
}

type PostHandler = (
  worker: FakeWorker,
  request: DetectorWorkerRequest,
) => void;

class FakeWorker extends EventEmitter {
  readonly options: WorkerOptions;
  readonly #onPost: PostHandler | undefined;
  terminateCalls = 0;

  constructor(
    options: WorkerOptions,
    startup: "ready" | "error" | "silent",
    onPost?: PostHandler,
  ) {
    super();
    this.options = options;
    this.#onPost = onPost;
    if (startup === "ready") {
      queueMicrotask(() => this.emit("message", {
        type: "ready",
      } satisfies DetectorWorkerResponse));
    } else if (startup === "error") {
      queueMicrotask(() => this.emit("error", new Error("controlled startup failure")));
    }
  }

  postMessage(value: unknown): void {
    this.#onPost?.(this, value as DetectorWorkerRequest);
  }

  terminate(): Promise<number> {
    this.terminateCalls += 1;
    return Promise.resolve(1);
  }
}

function asWorker(worker: FakeWorker): Worker {
  return worker as unknown as Worker;
}

function workerState(worker: FakeWorker): Int32Array {
  const data = worker.options.workerData as DetectorWorkerData;
  return new Int32Array(data.progressBuffer);
}

function match(
  ruleOrdinal: number,
  candidateOrdinal = 0,
): WorkerMatch {
  return {
    ruleOrdinal,
    candidateOrdinal,
    index: 0,
    length: 1,
    version: null,
  };
}

test("worker startup rejects invalid regex syntax without exposing the pattern", async () => {
  const catalog = testCatalog([{ pattern: "[" }]);

  await assert.rejects(
    createDetectorPool(catalog, testConfig()),
    (error: unknown) => {
      assert.ok(error instanceof FingerprintCatalogError);
      assert.equal(error.code, "CATALOG_INVALID");
      assert.equal(error.message, `Detector worker could not compile rule ${catalog.rules[0]?.ruleId}`);
      assert.equal(error.cause, undefined);
      assert.equal(error.message.includes("["), false);
      return true;
    },
  );
});

test("workers inherit no parent execArgv and startup watchdogs terminate silent workers", async () => {
  let fake: FakeWorker | undefined;
  const factory: DetectorWorkerFactory = (_moduleUrl, options) => {
    fake = new FakeWorker(options, "silent");
    return asWorker(fake);
  };

  await assert.rejects(
    createDetectorPool(
      testCatalog([{ pattern: "ok" }]),
      testConfig({ compileWatchdogMs: 20 }),
      factory,
    ),
    (error: unknown) => {
      assert.ok(error instanceof FingerprintCatalogError);
      assert.equal(error.code, "CATALOG_LIMIT_EXCEEDED");
      return true;
    },
  );
  assert.deepEqual(fake?.options.execArgv, []);
  assert.equal(fake?.terminateCalls, 1);
});

test("pool creation terminates successful workers when a peer fails preflight", async () => {
  const workers: FakeWorker[] = [];
  const factory: DetectorWorkerFactory = (_moduleUrl, options) => {
    const worker = new FakeWorker(
      options,
      workers.length === 0 ? "ready" : "error",
    );
    workers.push(worker);
    return asWorker(worker);
  };

  await assert.rejects(
    createDetectorPool(
      testCatalog([{ pattern: "ok" }]),
      testConfig({ workers: 2 }),
      factory,
    ),
    FingerprintCatalogError,
  );
  assert.equal(workers.length, 2);
  assert.deepEqual(workers.map((worker) => worker.terminateCalls), [1, 1]);
});

test("confirmed checkpoint matches and resume position survive a worker crash", async () => {
  const requests: DetectorWorkerRequest[] = [];
  let firstExecutionBuffer: SharedArrayBuffer | undefined;
  let factoryCall = 0;
  const factory: DetectorWorkerFactory = (_moduleUrl, options) => {
    factoryCall += 1;
    if (factoryCall === 1) {
      return asWorker(new FakeWorker(options, "ready", (worker, request) => {
        requests.push(request);
        firstExecutionBuffer = request.executionBuffer;
        Atomics.add(new Int32Array(request.executionBuffer), 0, 1);
        const state = workerState(worker);
        Atomics.store(state, 0, 3);
        Atomics.store(state, 1, 1);
        Atomics.add(state, 2, 1);
        worker.emit("message", {
          type: "checkpoint",
          taskId: request.taskId,
          nextWorkIndex: 1,
          matches: [match(0)],
        } satisfies DetectorWorkerResponse);
        worker.emit("error", new Error("controlled runtime crash"));
      }));
    }
    return asWorker(new FakeWorker(options, "ready", (worker, request) => {
      requests.push(request);
      assert.equal(request.startWorkIndex, 1);
      assert.equal(request.executionBuffer, firstExecutionBuffer);
      assert.equal(Atomics.load(new Int32Array(request.executionBuffer), 0), 1);
      Atomics.add(new Int32Array(request.executionBuffer), 0, 1);
      worker.emit("message", {
        type: "complete",
        taskId: request.taskId,
        nextWorkIndex: request.work.length,
        matches: [match(1)],
      } satisfies DetectorWorkerResponse);
    }));
  };

  const pool = await createDetectorPool(
    testCatalog([{ pattern: "a" }, { pattern: "b" }]),
    testConfig(),
    factory,
  );
  try {
    const result = await pool.match([candidate("ab")]);
    assert.deepEqual(result.matches.map((item) => item.ruleOrdinal), [0, 1]);
    assert.deepEqual(result.errors.map((error) => error.code), ["REGEX_WORKER_CRASH"]);
    assert.equal(result.completed, false);
    assert.equal(result.executions, 2);
    assert.equal(requests.length, 2);
    assert.equal(pool.isAvailable(), true);
  } finally {
    await pool.close();
  }
});

test("catastrophic regex timeout preserves checkpoints and resumes after the rule", {
  timeout: 10_000,
}, async () => {
  const pool = await createDetectorPool(
    testCatalog([
      { pattern: "^a" },
      { pattern: "(a+)+$" },
      { pattern: "!$" },
    ]),
    testConfig({ executionsPerDomain: 10 }),
  );
  try {
    const result = await pool.match([candidate(`${"a".repeat(30_000)}!`)]);
    assert.deepEqual(result.matches.map((item) => item.ruleOrdinal), [0, 2]);
    assert.deepEqual(result.errors.map((error) => error.code), ["REGEX_RULE_TIMEOUT"]);
    assert.equal(result.completed, false);
    assert.equal(result.executions, 3);
    assert.equal(pool.isAvailable(), true);
  } finally {
    await pool.close();
  }
});

test("a timeout removes earlier checkpoint matches from every chunk of that rule", {
  timeout: 10_000,
}, async () => {
  const pool = await createDetectorPool(
    testCatalog([{ pattern: "(a+)+$" }]),
    testConfig({
      executionsPerDomain: 10,
      evidencePerDomain: 2,
      checkpointRules: 1,
    }),
  );
  try {
    const result = await pool.match([
      identifiedCandidate("0001", "a"),
      identifiedCandidate("0002", "!"),
      identifiedCandidate("0003", "!"),
      identifiedCandidate("0004", `${"a".repeat(30_000)}!`),
    ]);
    assert.deepEqual(result.matches, []);
    assert.deepEqual(result.errors.map((error) => error.code), [
      "REGEX_RULE_TIMEOUT",
    ]);
    assert.equal(result.completed, false);
    assert.equal(result.executions, 4);
    assert.equal(pool.isAvailable(), true);
  } finally {
    await pool.close();
  }
});

test("cumulative execution budget counts replay after a catastrophic timeout", {
  timeout: 10_000,
}, async () => {
  const pool = await createDetectorPool(
    testCatalog([
      { pattern: "^a" },
      { pattern: "(a+)+$" },
      { pattern: "!$" },
    ]),
    testConfig({ checkpointRules: 2, executionsPerDomain: 3 }),
  );
  try {
    const result = await pool.match([candidate(`${"a".repeat(30_000)}!`)]);
    assert.deepEqual(result.matches.map((item) => item.ruleOrdinal), [0]);
    assert.deepEqual(result.errors.map((error) => error.code), [
      "REGEX_RULE_TIMEOUT",
      "REGEX_EXECUTION_LIMIT",
    ]);
    assert.equal(result.completed, false);
    assert.equal(result.executions, 3);
  } finally {
    await pool.close();
  }
});

test("worker responses expose positions and bounded safe versions, never raw candidates", async () => {
  const pool = await createDetectorPool(
    testCatalog([{
      pattern: "secret=([^;]+)",
      versionTemplate: "\\1",
    }]),
    testConfig(),
  );
  const rawCapture = "abcdef0123456789abcdef0123456789";
  const rawValue = `prefix secret=${rawCapture}; suffix`;
  try {
    const result = await pool.match([candidate(rawValue)]);
    assert.deepEqual(result.matches, [{
      ruleOrdinal: 0,
      candidateOrdinal: 0,
      index: "prefix ".length,
      length: `secret=${rawCapture}`.length,
      version: null,
    }]);
    assert.equal(JSON.stringify(result).includes(rawValue), false);
    assert.equal(JSON.stringify(result).includes(rawCapture), false);
  } finally {
    await pool.close();
  }
});

test("literal matching maps case-folded Unicode offsets back to the observation", async () => {
  const pool = await createDetectorPool(
    testCatalog([{
      pattern: "robots",
      matchMode: "literal",
    }]),
    testConfig(),
  );
  try {
    const result = await pool.match([candidate("İrobots.txt")]);
    assert.deepEqual(result.matches, [{
      ruleOrdinal: 0,
      candidateOrdinal: 0,
      index: 1,
      length: "robots".length,
      version: null,
    }]);
    assert.equal(result.executions, 0);
  } finally {
    await pool.close();
  }
});

test("presence and literal rules consume the bounded rule-candidate work budget", async () => {
  let dispatchedPairs = 0;
  let dispatchedCandidates = 0;
  const factory: DetectorWorkerFactory = (_moduleUrl, options) =>
    asWorker(new FakeWorker(options, "ready", (worker, request) => {
      dispatchedPairs = request.work.reduce(
        (total, item) => total + item.candidateOrdinals.length,
        0,
      );
      dispatchedCandidates = request.candidates.length;
      const matches = request.work.flatMap((item) =>
        item.candidateOrdinals.map((candidateOrdinal) =>
          match(item.ruleOrdinal, candidateOrdinal)));
      worker.emit("message", {
        type: "complete",
        taskId: request.taskId,
        nextWorkIndex: request.work.length,
        matches,
      } satisfies DetectorWorkerResponse);
    }));

  const pool = await createDetectorPool(
    testCatalog([
      { pattern: null, matchMode: "presence" },
      { pattern: "a", matchMode: "literal" },
    ]),
    testConfig({ executionsPerDomain: 3 }),
    factory,
  );
  try {
    const result = await pool.match([
      identifiedCandidate("0001", "a"),
      identifiedCandidate("0002", "a"),
    ]);
    assert.equal(dispatchedPairs, 2);
    assert.equal(dispatchedCandidates, 1);
    assert.deepEqual(result.matches, [match(0), match(1)]);
    assert.deepEqual(result.errors.map((error) => error.code), [
      "REGEX_EXECUTION_LIMIT",
    ]);
    assert.equal(result.completed, false);
    assert.equal(result.executions, 0);
  } finally {
    await pool.close();
  }
});

test("match materialization stops at the evidence limit with one bounded sentinel", async () => {
  const pool = await createDetectorPool(
    testCatalog([{ pattern: null, matchMode: "presence" }]),
    testConfig({
      executionsPerDomain: 100,
      evidencePerDomain: 2,
      checkpointRules: 1,
    }),
  );
  try {
    const result = await pool.match([
      identifiedCandidate("0001", "a"),
      identifiedCandidate("0002", "a"),
      identifiedCandidate("0003", "a"),
      identifiedCandidate("0004", "a"),
    ]);
    assert.deepEqual(result.matches, [
      { ...match(0, 0), length: 0 },
      { ...match(0, 1), length: 0 },
    ]);
    assert.deepEqual(result.errors.map((error) => error.code), [
      "REGEX_EXECUTION_LIMIT",
    ]);
    assert.equal(result.errors[0]?.limit, "2 matches");
    assert.equal(result.completed, false);
    assert.equal(result.executions, 0);
    assert.equal(pool.isAvailable(), true);
  } finally {
    await pool.close();
  }
});

test("an idle worker failure is handled once while queued work waits for replacement", async () => {
  let first: FakeWorker | undefined;
  let replacement: FakeWorker | undefined;
  let factoryCalls = 0;
  const factory: DetectorWorkerFactory = (_moduleUrl, options) => {
    factoryCalls += 1;
    if (factoryCalls === 1) {
      first = new FakeWorker(options, "ready");
      return asWorker(first);
    }
    replacement = new FakeWorker(options, "silent", (worker, request) => {
      worker.emit("message", {
        type: "complete",
        taskId: request.taskId,
        nextWorkIndex: request.work.length,
        matches: [match(0)],
      } satisfies DetectorWorkerResponse);
    });
    return asWorker(replacement);
  };

  const pool = await createDetectorPool(
    testCatalog([{ pattern: "a" }]),
    testConfig(),
    factory,
  );
  try {
    first?.emit("error", new Error("controlled idle failure"));
    first?.emit("exit", 1);
    assert.equal(pool.isAvailable(), true);

    const pending = pool.match([candidate("a")]);
    await waitForImmediate();
    assert.notEqual(replacement, undefined);
    replacement?.emit("message", { type: "ready" } satisfies DetectorWorkerResponse);

    const result = await pending;
    assert.deepEqual(result.matches, [match(0)]);
    assert.deepEqual(result.errors, []);
    assert.equal(result.completed, true);
    assert.equal(factoryCalls, 2);
    assert.equal(first?.terminateCalls, 1);
    assert.equal(pool.isAvailable(), true);
  } finally {
    await pool.close();
  }
});

test("an idle replacement failure latches the last detector worker unavailable", async () => {
  let first: FakeWorker | undefined;
  let factoryCalls = 0;
  const factory: DetectorWorkerFactory = (_moduleUrl, options) => {
    factoryCalls += 1;
    if (factoryCalls === 1) {
      first = new FakeWorker(options, "ready");
      return asWorker(first);
    }
    return asWorker(new FakeWorker(options, "error"));
  };

  const pool = await createDetectorPool(
    testCatalog([{ pattern: "a" }]),
    testConfig(),
    factory,
  );
  try {
    first?.emit("exit", 1);
    await waitForImmediate();
    await waitForImmediate();
    assert.equal(factoryCalls, 2);
    assert.equal(pool.isAvailable(), false);
    const result = await pool.match([candidate("a")]);
    assert.deepEqual(result.errors.map((error) => error.code), [
      "DETECTOR_UNAVAILABLE",
    ]);
  } finally {
    await pool.close();
  }
});

test("one failed replacement leaves a healthy peer available in degraded mode", async () => {
  let factoryCall = 0;
  const factory: DetectorWorkerFactory = (_moduleUrl, options) => {
    factoryCall += 1;
    if (factoryCall === 1) {
      return asWorker(new FakeWorker(options, "ready", (worker) => {
        const state = workerState(worker);
        Atomics.store(state, 0, 3);
        Atomics.store(state, 1, 0);
        Atomics.add(state, 2, 1);
        worker.emit("error", new Error("controlled runtime crash"));
      }));
    }
    if (factoryCall === 2) {
      return asWorker(new FakeWorker(options, "ready", (worker, request) => {
        Atomics.add(new Int32Array(request.executionBuffer), 0, 1);
        worker.emit("message", {
          type: "complete",
          taskId: request.taskId,
          nextWorkIndex: request.work.length,
          matches: [match(0)],
        } satisfies DetectorWorkerResponse);
      }));
    }
    return asWorker(new FakeWorker(options, "error"));
  };

  const pool = await createDetectorPool(
    testCatalog([{ pattern: "a" }]),
    testConfig({ workers: 2 }),
    factory,
  );
  try {
    const degraded = await pool.match([candidate("a")]);
    assert.deepEqual(degraded.errors.map((error) => error.code), [
      "REGEX_WORKER_CRASH",
      "REGEX_WORKER_RESTART_FAILED",
    ]);
    assert.equal(pool.isAvailable(), true);

    const healthy = await pool.match([candidate("a")]);
    assert.deepEqual(healthy.matches, [match(0)]);
    assert.deepEqual(healthy.errors, []);
    assert.equal(healthy.completed, true);
  } finally {
    await pool.close();
  }
});

test("closing during replacement terminates the newly started worker", async () => {
  let factoryCall = 0;
  let replacement: FakeWorker | undefined;
  const factory: DetectorWorkerFactory = (_moduleUrl, options) => {
    factoryCall += 1;
    if (factoryCall === 1) {
      return asWorker(new FakeWorker(options, "ready", (worker) => {
        const state = workerState(worker);
        Atomics.store(state, 0, 3);
        Atomics.store(state, 1, 0);
        Atomics.add(state, 2, 1);
        worker.emit("error", new Error("controlled runtime crash"));
      }));
    }
    replacement = new FakeWorker(options, "silent");
    return asWorker(replacement);
  };

  const pool = await createDetectorPool(
    testCatalog([{ pattern: "a" }]),
    testConfig(),
    factory,
  );
  const matching = pool.match([candidate("a")]);
  await waitForImmediate();
  assert.notEqual(replacement, undefined);
  const closing = pool.close();
  replacement?.emit("message", { type: "ready" } satisfies DetectorWorkerResponse);

  const result = await matching;
  await closing;
  assert.deepEqual(result.errors.map((error) => error.code), [
    "REGEX_WORKER_CRASH",
    "REGEX_WORKER_RESTART_FAILED",
  ]);
  assert.equal(replacement?.terminateCalls, 1);
  assert.equal(pool.isAvailable(), false);
});

test("last worker failure rejects queued work and latches the whole pool unavailable", async () => {
  let runningWorker: FakeWorker | undefined;
  let runtimeRequest: DetectorWorkerRequest | undefined;
  let factoryCall = 0;
  const factory: DetectorWorkerFactory = (_moduleUrl, options) => {
    factoryCall += 1;
    if (factoryCall === 1) {
      runningWorker = new FakeWorker(options, "ready", (worker, request) => {
        runtimeRequest = request;
        const state = workerState(worker);
        Atomics.store(state, 0, 3);
        Atomics.store(state, 1, 0);
        Atomics.add(state, 2, 1);
      });
      return asWorker(runningWorker);
    }
    return asWorker(new FakeWorker(options, "error"));
  };

  const pool = await createDetectorPool(
    testCatalog([{ pattern: "a" }]),
    testConfig(),
    factory,
  );
  try {
    const first = pool.match([candidate("a")]);
    await waitForImmediate();
    assert.notEqual(runtimeRequest, undefined);
    const queued = pool.match([candidate("a")]);
    runningWorker?.emit("error", new Error("controlled terminal crash"));

    const [firstResult, queuedResult] = await Promise.all([first, queued]);
    assert.deepEqual(firstResult.errors.map((error) => error.code), [
      "REGEX_WORKER_CRASH",
      "REGEX_WORKER_RESTART_FAILED",
    ]);
    assert.deepEqual(queuedResult.errors.map((error) => error.code), [
      "DETECTOR_UNAVAILABLE",
    ]);
    assert.equal(pool.isAvailable(), false);

    const later = await pool.match([candidate("a")]);
    assert.deepEqual(later.errors.map((error) => error.code), [
      "DETECTOR_UNAVAILABLE",
    ]);
  } finally {
    await pool.close();
  }
});

test("presence candidates cannot satisfy literal or regex value rules", async () => {
  const pool = await createDetectorPool(
    testCatalog([
      { pattern: null, matchMode: "presence" },
      { pattern: "", matchMode: "literal" },
      { pattern: "$", matchMode: "regex" },
    ]),
    testConfig(),
  );

  try {
    const result = await pool.match([{
      ...candidate(""),
      kind: "presence",
    }]);

    assert.deepEqual(result.matches.map((item) => item.ruleOrdinal), [0]);
    assert.equal(result.completed, true);
  } finally {
    await pool.close();
  }
});
