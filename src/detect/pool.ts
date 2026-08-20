import { performance } from "node:perf_hooks";
import { Worker, type WorkerOptions } from "node:worker_threads";

import type { ScanConfig } from "../config.ts";
import type { EvidenceSource, ScanError } from "../model.ts";
import {
  FingerprintCatalogError,
  type CompiledFingerprintCatalog,
  type CompiledFingerprintRule,
} from "./catalog.ts";

const PHASE = 0;
const CURRENT_RULE = 1;
const PROGRESS = 2;
const PHASE_MATCHING = 3;

export interface DetectorCandidate {
  readonly id: string;
  readonly priority: boolean;
  readonly kind: "presence" | "value";
  readonly source: EvidenceSource;
  readonly key: string | null;
  readonly value: string;
}

export interface DetectorWorkItem {
  readonly ruleOrdinal: number;
  readonly candidateOrdinals: readonly number[];
}

export interface WorkerMatch {
  readonly ruleOrdinal: number;
  readonly candidateOrdinal: number;
  readonly index: number;
  readonly length: number;
  readonly version: string | null;
}

export interface DetectorWorkerData {
  readonly rules: readonly CompiledFingerprintRule[];
  readonly progressBuffer: SharedArrayBuffer;
  readonly versionCodeUnits: number;
  readonly hexTokenMinCodeUnits: number;
  readonly base64UrlTokenMinCodeUnits: number;
}

export type DetectorWorkerRequest = {
  readonly type: "match";
  readonly taskId: number;
  readonly candidates: readonly DetectorCandidate[];
  readonly work: readonly DetectorWorkItem[];
  readonly startWorkIndex: number;
  readonly skipRuleOrdinals: readonly number[];
  readonly executionBuffer: SharedArrayBuffer;
  readonly executionLimit: number;
  readonly checkpointRules: number;
  readonly priorityWorkEndIndex: number;
};

export type DetectorWorkerResponse =
  | { readonly type: "ready" }
  | {
      readonly type: "checkpoint" | "complete" | "execution-limit";
      readonly taskId: number;
      readonly nextWorkIndex: number;
      readonly matches: readonly WorkerMatch[];
    };

export interface DetectorMatchResult {
  readonly matches: readonly WorkerMatch[];
  readonly errors: readonly ScanError[];
  readonly completed: boolean;
  readonly executions: number;
}

export interface DetectorPool {
  readonly catalog: CompiledFingerprintCatalog;
  match(
    candidates: readonly DetectorCandidate[],
    signal?: AbortSignal,
  ): Promise<DetectorMatchResult>;
  isAvailable(): boolean;
  close(): Promise<void>;
}

interface WorkerSlot {
  readonly id: number;
  worker: Worker;
  state: Int32Array;
  lifecycle: WorkerLifecycle;
  busy: boolean;
  ready: boolean;
  activeAttemptWorker: Worker | null;
  replacement: Promise<boolean> | null;
}

interface WorkerLifecycle {
  failed: boolean;
  handler: (() => void) | null;
  detach(): void;
}

interface Waiter {
  readonly resolve: (slot: WorkerSlot) => void;
  readonly reject: (error: unknown) => void;
  readonly signal: AbortSignal | undefined;
  readonly onAbort: (() => void) | undefined;
}

type AttemptResult =
  | {
      readonly kind: "complete";
      readonly matches: readonly WorkerMatch[];
      readonly nextWorkIndex: number;
    }
  | {
      readonly kind: "execution-limit";
      readonly matches: readonly WorkerMatch[];
      readonly nextWorkIndex: number;
    }
  | {
      readonly kind: "match-limit";
      readonly matches: readonly WorkerMatch[];
      readonly nextWorkIndex: number;
    }
  | {
      readonly kind: "timeout" | "crash" | "domain-budget";
      readonly ruleOrdinal: number | null;
      readonly matches: readonly WorkerMatch[];
      readonly nextWorkIndex: number;
    }
  | { readonly kind: "aborted"; readonly reason: unknown };

export type DetectorWorkerFactory = (
  moduleUrl: URL,
  options: WorkerOptions,
) => Worker;

const nodeWorkerFactory: DetectorWorkerFactory = (moduleUrl, options) =>
  new Worker(moduleUrl, options);

function compareString(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function makeDetectError(
  catalog: CompiledFingerprintCatalog,
  code: ScanError["code"],
  message: string,
  rule: CompiledFingerprintRule | null,
  limit: string | null,
): ScanError {
  return {
    stage: "detect",
    code,
    pageId: null,
    retryable: false,
    message,
    ruleId: rule?.ruleId ?? null,
    signal: rule?.source ?? null,
    limit,
    catalogRevision: catalog.revision,
  };
}

function workerModuleUrl(): URL {
  return new URL(import.meta.url.endsWith(".ts") ? "./worker.ts" : "./worker.js", import.meta.url);
}

async function spawnWorker(
  id: number,
  catalog: CompiledFingerprintCatalog,
  config: ScanConfig,
  workerFactory: DetectorWorkerFactory,
): Promise<WorkerSlot> {
  const progressBuffer = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 4);
  const state = new Int32Array(progressBuffer);
  Atomics.store(state, CURRENT_RULE, -1);
  const worker = workerFactory(workerModuleUrl(), {
    // Workers execute only the fixed detector module. Inheriting loaders,
    // imports, inspectors, or CLI-only flags would widen that boundary.
    execArgv: [],
    name: `fingerprint-detector-${id}`,
    resourceLimits: {
      maxOldGenerationSizeMb:
        config.limits.detector.workerOldHeapBytes / 1_048_576,
      maxYoungGenerationSizeMb:
        config.limits.detector.workerYoungHeapBytes / 1_048_576,
      stackSizeMb: config.limits.detector.workerStackBytes / 1_048_576,
    },
    workerData: {
      rules: catalog.rules,
      progressBuffer,
      versionCodeUnits: config.limits.evidence.versionCodeUnits,
      hexTokenMinCodeUnits: config.limits.evidence.hexTokenMinCodeUnits,
      base64UrlTokenMinCodeUnits:
        config.limits.evidence.base64UrlTokenMinCodeUnits,
    } satisfies DetectorWorkerData,
  });
  const lifecycle: WorkerLifecycle = {
    failed: false,
    handler: null,
    detach: () => undefined,
  };

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      cleanupStartup();
      lifecycle.detach();
      void worker.terminate().then(() => {
        reject(new FingerprintCatalogError(
          "CATALOG_LIMIT_EXCEEDED",
          "Detector worker catalog compilation exceeded its watchdog",
        ));
      }, () => {
        reject(new FingerprintCatalogError(
          "CATALOG_LIMIT_EXCEEDED",
          "Detector worker catalog compilation exceeded its watchdog",
        ));
      });
    }, config.limits.detector.compileWatchdogMs);
    timer.unref();

    const cleanupStartup = (): void => {
      clearTimeout(timer);
      worker.off("message", onMessage);
    };
    lifecycle.detach = (): void => {
      lifecycle.handler = null;
      worker.off("error", onError);
      worker.off("exit", onExit);
    };
    const fail = (error: unknown): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanupStartup();
      lifecycle.detach();
      void worker.terminate().then(
        () => reject(error),
        () => reject(error),
      );
    };
    const onMessage = (message: DetectorWorkerResponse): void => {
      if (message.type !== "ready" || settled) {
        return;
      }
      settled = true;
      cleanupStartup();
      resolve();
    };
    const onError = (): void => {
      if (settled) {
        if (!lifecycle.failed) {
          lifecycle.failed = true;
          lifecycle.handler?.();
        }
        return;
      }
      const ordinal = Atomics.load(state, CURRENT_RULE);
      const rule = catalog.rules[ordinal];
      fail(new FingerprintCatalogError(
        "CATALOG_INVALID",
        rule === undefined
          ? "Detector worker could not compile the catalog"
          : `Detector worker could not compile rule ${rule.ruleId}`,
      ));
    };
    const onExit = (): void => {
      onError();
    };
    worker.on("message", onMessage);
    worker.on("error", onError);
    worker.on("exit", onExit);
  });

  return {
    id,
    worker,
    state,
    lifecycle,
    busy: false,
    ready: true,
    activeAttemptWorker: null,
    replacement: null,
  };
}

class DetectorPoolImplementation implements DetectorPool {
  readonly catalog: CompiledFingerprintCatalog;
  readonly #config: ScanConfig;
  readonly #workerFactory: DetectorWorkerFactory;
  readonly #slots: WorkerSlot[];
  readonly #index = new Map<
    EvidenceSource,
    {
      readonly unkeyed: readonly number[];
      readonly keyed: ReadonlyMap<string, readonly number[]>;
      readonly patternLocator: readonly number[];
    }
  >();
  readonly #waiters: Waiter[] = [];
  #closed = false;
  #unavailable = false;
  #nextTaskId = 1;

  constructor(
    catalog: CompiledFingerprintCatalog,
    config: ScanConfig,
    slots: WorkerSlot[],
    workerFactory: DetectorWorkerFactory,
  ) {
    this.catalog = catalog;
    this.#config = config;
    this.#slots = slots;
    this.#workerFactory = workerFactory;
    for (const slot of slots) {
      this.#monitor(slot);
    }
    for (const index of catalog.indexes) {
      this.#index.set(index.source, {
        unkeyed: index.unkeyedRuleOrdinals,
        keyed: new Map(index.keyed.map((item) => [item.locator, item.ruleOrdinals])),
        patternLocator: index.patternLocatorRuleOrdinals,
      });
    }
  }

  isAvailable(): boolean {
    return !this.#closed
      && !this.#unavailable
      && this.#slots.some((slot) =>
        slot.ready || slot.replacement !== null);
  }

  #monitor(slot: WorkerSlot): void {
    const worker = slot.worker;
    const lifecycle = slot.lifecycle;
    lifecycle.handler = () => {
      if (
        this.#closed
        || slot.worker !== worker
        || slot.lifecycle !== lifecycle
        || slot.activeAttemptWorker === worker
      ) {
        return;
      }
      slot.ready = false;
      void this.#replace(slot, true);
    };
    if (lifecycle.failed) {
      lifecycle.handler();
    }
  }

  async #acquire(signal: AbortSignal | undefined): Promise<WorkerSlot> {
    signal?.throwIfAborted();
    if (!this.isAvailable()) {
      throw new Error("Detector pool is unavailable");
    }
    const available = this.#slots.find((slot) => slot.ready && !slot.busy);
    if (available !== undefined) {
      available.busy = true;
      return available;
    }
    if (this.#waiters.length >= this.#config.limits.concurrency.fullScans) {
      throw new Error("Detector queue is full");
    }
    return await new Promise<WorkerSlot>((resolve, reject) => {
      const waiter: Waiter = {
        resolve,
        reject,
        signal,
        onAbort: signal === undefined
          ? undefined
          : () => {
              const index = this.#waiters.indexOf(waiter);
              if (index !== -1) {
                this.#waiters.splice(index, 1);
              }
              reject(signal.reason);
            },
      };
      if (waiter.onAbort !== undefined) {
        signal?.addEventListener("abort", waiter.onAbort, { once: true });
      }
      this.#waiters.push(waiter);
    });
  }

  #release(slot: WorkerSlot): void {
    slot.busy = false;
    this.#dispatchWaiters();
  }

  #dispatchWaiters(): void {
    while (this.#waiters.length > 0) {
      const slot = this.#slots.find((candidate) => candidate.ready && !candidate.busy);
      if (slot === undefined) {
        return;
      }
      const waiter = this.#waiters.shift();
      if (waiter === undefined) {
        return;
      }
      if (waiter.onAbort !== undefined) {
        waiter.signal?.removeEventListener("abort", waiter.onAbort);
      }
      if (waiter.signal?.aborted) {
        waiter.reject(waiter.signal.reason);
        continue;
      }
      slot.busy = true;
      waiter.resolve(slot);
    }
  }

  #latchUnavailable(): void {
    this.#unavailable = true;
    for (const waiter of this.#waiters.splice(0)) {
      if (waiter.onAbort !== undefined) {
        waiter.signal?.removeEventListener("abort", waiter.onAbort);
      }
      waiter.reject(new Error("Detector pool is unavailable"));
    }
  }

  #applicableRules(candidate: DetectorCandidate): readonly number[] {
    const index = this.#index.get(candidate.source);
    if (index === undefined) {
      return [];
    }
    const ordinals = new Set<number>(index.unkeyed);
    if (candidate.key !== null) {
      for (const ordinal of index.keyed.get(candidate.key) ?? []) {
        ordinals.add(ordinal);
      }
    }
    for (const ordinal of index.patternLocator) {
      ordinals.add(ordinal);
    }
    return [...ordinals]
      .filter((ordinal) =>
        candidate.kind === "value"
        || this.catalog.rules[ordinal]?.matchMode === "presence")
      .sort((left, right) => left - right);
  }

  #executionCost(rule: CompiledFingerprintRule): number {
    return (rule.locatorPattern === null ? 0 : 1)
      + (rule.matchMode === "regex" ? 1 : 0);
  }

  #buildWork(candidates: readonly DetectorCandidate[]): {
    readonly work: readonly DetectorWorkItem[];
    readonly candidates: readonly DetectorCandidate[];
    readonly candidateOrdinals: readonly number[];
    readonly priorityWorkEndIndex: number;
    readonly truncated: boolean;
    readonly truncatedSource: EvidenceSource | null;
  } {
    const priorityByRule = new Map<number, number[]>();
    const remainderByRule = new Map<number, number[]>();
    const dispatchedCandidates: DetectorCandidate[] = [];
    const candidateOrdinals: number[] = [];
    let executions = 0;
    let workPairs = 0;
    let truncated = false;
    let truncatedSource: EvidenceSource | null = null;
    const limit = this.#config.limits.detector.executionsPerDomain;
    const matchSentinel = Math.min(
      limit,
      this.#config.limits.output.evidencePerDomain + 1,
    );
    const checkpointRules = Math.min(
      this.#config.limits.detector.checkpointRules,
      matchSentinel,
    );
    const candidatesPerWorkItem = Math.max(
      1,
      Math.floor(matchSentinel / checkpointRules),
    );

    const orderedCandidateOrdinals = candidates
      .map((_candidate, candidateOrdinal) => candidateOrdinal)
      .sort((left, right) =>
        Number(candidates[right]!.priority)
        - Number(candidates[left]!.priority)
        || left - right);

    for (const candidateOrdinal of orderedCandidateOrdinals) {
      const candidate = candidates[candidateOrdinal];
      if (candidate === undefined) {
        continue;
      }
      const applicable = this.#applicableRules(candidate);
      let candidateCost = 0;
      for (const ruleOrdinal of applicable) {
        const rule = this.catalog.rules[ruleOrdinal];
        if (rule !== undefined) {
          candidateCost += this.#executionCost(rule);
        }
      }
      if (
        executions + candidateCost > limit
        || workPairs + applicable.length > limit
      ) {
        truncated = true;
        truncatedSource = candidate.source;
        break;
      }
      executions += candidateCost;
      workPairs += applicable.length;
      if (applicable.length === 0) {
        continue;
      }
      const dispatchedOrdinal = dispatchedCandidates.length;
      dispatchedCandidates.push(candidate);
      candidateOrdinals.push(candidateOrdinal);
      const byRule = candidate.priority ? priorityByRule : remainderByRule;
      for (const ruleOrdinal of applicable) {
        const list = byRule.get(ruleOrdinal) ?? [];
        list.push(dispatchedOrdinal);
        byRule.set(ruleOrdinal, list);
      }
    }

    const materializePhase = (
      byRule: ReadonlyMap<number, readonly number[]>,
    ): readonly DetectorWorkItem[] => [...byRule]
      .sort(([left], [right]) => left - right)
      .flatMap(([ruleOrdinal, candidateOrdinals]) => {
        const chunks: DetectorWorkItem[] = [];
        for (
          let offset = 0;
          offset < candidateOrdinals.length;
          offset += candidatesPerWorkItem
        ) {
          chunks.push({
            ruleOrdinal,
            candidateOrdinals: candidateOrdinals.slice(
              offset,
              offset + candidatesPerWorkItem,
            ),
          });
        }
        return chunks;
      });

    const priorityWork = materializePhase(priorityByRule);
    return {
      work: [...priorityWork, ...materializePhase(remainderByRule)],
      candidates: dispatchedCandidates,
      candidateOrdinals,
      priorityWorkEndIndex: priorityWork.length,
      truncated,
      truncatedSource,
    };
  }

  async #runAttempt(
    slot: WorkerSlot,
    request: DetectorWorkerRequest,
    signal: AbortSignal | undefined,
    detectionStartedAt: number,
  ): Promise<AttemptResult> {
    return await new Promise<AttemptResult>((resolve) => {
      const worker = slot.worker;
      const state = slot.state;
      slot.activeAttemptWorker = worker;
      const retainedMatchLimit = Math.min(
        request.executionLimit,
        this.#config.limits.output.evidencePerDomain,
      );
      const matchSentinel = Math.min(
        request.executionLimit,
        this.#config.limits.output.evidencePerDomain + 1,
      );
      let settled = false;
      let nextWorkIndex = request.startWorkIndex;
      const confirmed: WorkerMatch[] = [];
      let lastProgress = Atomics.load(state, PROGRESS);
      let ruleStartedAt = performance.now();

      const cleanup = (retainAttemptOwnership = false): void => {
        clearInterval(watchdog);
        worker.off("message", onMessage);
        worker.off("error", onError);
        worker.off("exit", onExit);
        signal?.removeEventListener("abort", onAbort);
        if (!retainAttemptOwnership && slot.activeAttemptWorker === worker) {
          slot.activeAttemptWorker = null;
        }
      };
      const finish = (result: AttemptResult): void => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        resolve(result);
      };
      const terminateAndFinish = (result: AttemptResult): void => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup(true);
        void worker.terminate().then(
          () => {
            if (slot.activeAttemptWorker === worker) {
              slot.activeAttemptWorker = null;
            }
            resolve(result);
          },
          () => {
            if (slot.activeAttemptWorker === worker) {
              slot.activeAttemptWorker = null;
            }
            resolve(result);
          },
        );
      };
      const onMessage = (message: DetectorWorkerResponse): void => {
        if (message.type === "ready" || message.taskId !== request.taskId) {
          return;
        }
        for (const item of message.matches) {
          if (confirmed.length >= matchSentinel) {
            terminateAndFinish({
              kind: "crash",
              ruleOrdinal: Atomics.load(state, CURRENT_RULE),
              matches: confirmed.slice(0, retainedMatchLimit),
              nextWorkIndex,
            });
            return;
          }
          confirmed.push(item);
          if (confirmed.length > retainedMatchLimit) {
            terminateAndFinish({
              kind: "match-limit",
              matches: confirmed.slice(0, retainedMatchLimit),
              nextWorkIndex,
            });
            return;
          }
        }
        nextWorkIndex = message.nextWorkIndex;
        if (message.type === "checkpoint") {
          return;
        }
        finish({
          kind: message.type,
          matches: confirmed,
          nextWorkIndex,
        });
      };
      const onError = (): void => {
        terminateAndFinish({
          kind: "crash",
          ruleOrdinal: Atomics.load(state, CURRENT_RULE),
          matches: confirmed,
          nextWorkIndex,
        });
      };
      const onExit = (): void => {
        onError();
      };
      const onAbort = (): void => {
        terminateAndFinish({ kind: "aborted", reason: signal?.reason });
      };
      const watchdog = setInterval(() => {
        const now = performance.now();
        if (
          now - detectionStartedAt
          > this.#config.limits.detector.activeMsPerDomain
        ) {
          terminateAndFinish({
            kind: "domain-budget",
            ruleOrdinal: Atomics.load(state, CURRENT_RULE),
            matches: confirmed,
            nextWorkIndex,
          });
          return;
        }
        const progress = Atomics.load(state, PROGRESS);
        if (progress !== lastProgress) {
          lastProgress = progress;
          ruleStartedAt = now;
          return;
        }
        if (
          Atomics.load(state, PHASE) === PHASE_MATCHING
          && now - ruleStartedAt > this.#config.limits.detector.ruleWatchdogMs
        ) {
          terminateAndFinish({
            kind: "timeout",
            ruleOrdinal: Atomics.load(state, CURRENT_RULE),
            matches: confirmed,
            nextWorkIndex,
          });
        }
      }, this.#config.limits.detector.watchdogPollMs);
      watchdog.unref();

      worker.on("message", onMessage);
      worker.once("error", onError);
      worker.once("exit", onExit);
      signal?.addEventListener("abort", onAbort, { once: true });
      if (signal?.aborted) {
        onAbort();
        return;
      }
      try {
        worker.postMessage(request);
      } catch {
        onError();
      }
    });
  }

  #replace(slot: WorkerSlot, terminateCurrent = false): Promise<boolean> {
    if (slot.replacement !== null) {
      return slot.replacement;
    }
    slot.ready = false;
    slot.lifecycle.detach();
    const replacement = this.#replaceOnce(slot, terminateCurrent);
    slot.replacement = replacement;
    const clearReplacement = (): void => {
      if (slot.replacement === replacement) {
        slot.replacement = null;
      }
      if (
        !this.#closed
        && !this.#unavailable
        && !this.#slots.some((candidate) =>
          candidate.ready || candidate.replacement !== null)
      ) {
        this.#latchUnavailable();
      }
    };
    void replacement.then(clearReplacement, clearReplacement);
    return replacement;
  }

  async #replaceOnce(
    slot: WorkerSlot,
    terminateCurrent: boolean,
  ): Promise<boolean> {
    if (terminateCurrent) {
      await slot.worker.terminate().catch(() => undefined);
    }
    if (this.#closed) {
      this.#latchUnavailable();
      return false;
    }
    try {
      const replacement = await spawnWorker(
        slot.id,
        this.catalog,
        this.#config,
        this.#workerFactory,
      );
      if (this.#closed) {
        replacement.lifecycle.detach();
        await replacement.worker.terminate();
        this.#latchUnavailable();
        return false;
      }
      if (replacement.lifecycle.failed) {
        replacement.lifecycle.detach();
        await replacement.worker.terminate().catch(() => undefined);
        throw new Error("Detector replacement failed after startup");
      }
      slot.worker = replacement.worker;
      slot.state = replacement.state;
      slot.lifecycle = replacement.lifecycle;
      slot.ready = true;
      this.#monitor(slot);
      this.#dispatchWaiters();
      return true;
    } catch {
      if (!this.#slots.some((candidate) =>
        candidate !== slot
        && (candidate.ready || candidate.replacement !== null))) {
        this.#latchUnavailable();
      }
      return false;
    }
  }

  async match(
    inputCandidates: readonly DetectorCandidate[],
    signal?: AbortSignal,
  ): Promise<DetectorMatchResult> {
    const workLimit = this.#config.limits.detector.executionsPerDomain;
    const materializedMatchLimit = Math.min(
      workLimit,
      this.#config.limits.output.evidencePerDomain,
    );
    const checkpointRules = Math.min(
      this.#config.limits.detector.checkpointRules,
      Math.min(workLimit, materializedMatchLimit + 1),
    );
    const candidates = inputCandidates.slice().sort((left, right) =>
      compareString(left.id, right.id));
    let slot: WorkerSlot;
    try {
      slot = await this.#acquire(signal);
    } catch (error) {
      if (signal?.aborted) {
        throw error;
      }
      return {
        matches: [],
        errors: [makeDetectError(
          this.catalog,
          "DETECTOR_UNAVAILABLE",
          "Detector pool is unavailable",
          null,
          null,
        )],
        completed: false,
        executions: 0,
      };
    }

    const errors: ScanError[] = [];
    const confirmed = new Map<string, WorkerMatch>();
    const executionBuffer = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
    const executionCounter = new Int32Array(executionBuffer);
    const plan = this.#buildWork(candidates);
    const planTruncated = plan.truncated;
    if (planTruncated) {
      errors.push({
        ...makeDetectError(
          this.catalog,
          "REGEX_EXECUTION_LIMIT",
          "Detector candidate plan was truncated at the work limit",
          null,
          `${workLimit} rule-candidate pairs`,
        ),
        signal: plan.truncatedSource,
      });
    }
    const taskId = this.#nextTaskId;
    this.#nextTaskId += 1;
    let startWorkIndex = 0;
    const skipped = new Set<number>();
    let timeouts = 0;
    let completed = !planTruncated;
    let matchMaterializationLimited = false;
    const detectionStartedAt = performance.now();

    try {
      while (startWorkIndex < plan.work.length) {
        const attempt = await this.#runAttempt(slot, {
          type: "match",
          taskId,
          candidates: plan.candidates,
          work: plan.work,
          startWorkIndex,
          skipRuleOrdinals: [...skipped].sort((left, right) => left - right),
          executionBuffer,
          executionLimit: this.#config.limits.detector.executionsPerDomain,
          checkpointRules,
          priorityWorkEndIndex: plan.priorityWorkEndIndex,
        }, signal, detectionStartedAt);

        const timedOutRuleOrdinal = attempt.kind === "timeout"
          && attempt.ruleOrdinal !== null
          && attempt.ruleOrdinal >= 0
          ? attempt.ruleOrdinal
          : null;
        if (timedOutRuleOrdinal !== null) {
          skipped.add(timedOutRuleOrdinal);
          for (const [identity, match] of confirmed) {
            if (match.ruleOrdinal === timedOutRuleOrdinal) {
              confirmed.delete(identity);
            }
          }
        }
        if (attempt.kind !== "aborted") {
          for (const match of attempt.matches) {
            if (match.ruleOrdinal === timedOutRuleOrdinal) {
              continue;
            }
            const identity = `${match.ruleOrdinal}\u0000${match.candidateOrdinal}`;
            if (
              !confirmed.has(identity)
              && confirmed.size >= materializedMatchLimit
            ) {
              matchMaterializationLimited = true;
              break;
            }
            confirmed.set(identity, match);
          }
          startWorkIndex = attempt.nextWorkIndex;
        }

        if (matchMaterializationLimited) {
          errors.push(makeDetectError(
            this.catalog,
            "REGEX_EXECUTION_LIMIT",
            "Detector reached the bounded match materialization limit",
            null,
            `${materializedMatchLimit} matches`,
          ));
          completed = false;
          if (
            attempt.kind !== "complete"
            && attempt.kind !== "execution-limit"
          ) {
            await this.#replace(slot);
          }
          break;
        }

        if (attempt.kind === "match-limit") {
          errors.push(makeDetectError(
            this.catalog,
            "REGEX_EXECUTION_LIMIT",
            "Detector reached the bounded match materialization limit",
            null,
            `${materializedMatchLimit} matches`,
          ));
          completed = false;
          await this.#replace(slot);
          break;
        }

        if (attempt.kind === "complete" || attempt.kind === "execution-limit") {
          if (attempt.kind === "execution-limit") {
            errors.push(makeDetectError(
              this.catalog,
              "REGEX_EXECUTION_LIMIT",
              "Detector reached the cumulative regex execution limit",
              this.catalog.rules[plan.work[startWorkIndex]?.ruleOrdinal ?? -1] ?? null,
              `${this.#config.limits.detector.executionsPerDomain} executions`,
            ));
            completed = false;
          }
          break;
        }
        if (attempt.kind === "aborted") {
          await this.#replace(slot);
          throw attempt.reason;
        }

        const rule = attempt.ruleOrdinal === null
          ? null
          : this.catalog.rules[attempt.ruleOrdinal] ?? null;
        if (attempt.kind === "domain-budget") {
          errors.push(makeDetectError(
            this.catalog,
            "REGEX_DOMAIN_BUDGET_EXCEEDED",
            "Detector exceeded the active per-domain budget",
            rule,
            `${this.#config.limits.detector.activeMsPerDomain}ms`,
          ));
          completed = false;
          if (!(await this.#replace(slot))) {
            errors.push(makeDetectError(
              this.catalog,
              "REGEX_WORKER_RESTART_FAILED",
              "Detector worker replacement failed",
              rule,
              null,
            ));
          }
          break;
        }

        if (attempt.kind === "timeout") {
          timeouts += 1;
          errors.push(makeDetectError(
            this.catalog,
            "REGEX_RULE_TIMEOUT",
            "A fingerprint rule exceeded its watchdog",
            rule,
            `${this.#config.limits.detector.ruleWatchdogMs}ms`,
          ));
        } else {
          errors.push(makeDetectError(
            this.catalog,
            "REGEX_WORKER_CRASH",
            "A detector worker crashed during matching",
            rule,
            null,
          ));
        }
        completed = false;

        if (timeouts >= this.#config.limits.detector.timeoutsPerDomain) {
          errors.push(makeDetectError(
            this.catalog,
            "REGEX_DOMAIN_BUDGET_EXCEEDED",
            "Detector reached the per-domain timeout limit",
            rule,
            `${this.#config.limits.detector.timeoutsPerDomain} timeouts`,
          ));
          if (!(await this.#replace(slot))) {
            errors.push(makeDetectError(
              this.catalog,
              "REGEX_WORKER_RESTART_FAILED",
              "Detector worker replacement failed",
              rule,
              null,
            ));
          }
          break;
        }
        if (!(await this.#replace(slot))) {
          errors.push(makeDetectError(
            this.catalog,
            "REGEX_WORKER_RESTART_FAILED",
            "Detector worker replacement failed",
            rule,
            null,
          ));
          break;
        }
        if (
          performance.now() - detectionStartedAt
          > this.#config.limits.detector.activeMsPerDomain
        ) {
          errors.push(makeDetectError(
            this.catalog,
            "REGEX_DOMAIN_BUDGET_EXCEEDED",
            "Detector exceeded the active per-domain budget",
            rule,
            `${this.#config.limits.detector.activeMsPerDomain}ms`,
          ));
          break;
        }
      }
    } finally {
      this.#release(slot);
    }

    return {
      matches: [...confirmed.values()]
        .map((match) => ({
          ...match,
          candidateOrdinal: plan.candidateOrdinals[match.candidateOrdinal]!,
        }))
        .sort((left, right) =>
          left.ruleOrdinal - right.ruleOrdinal
          || left.candidateOrdinal - right.candidateOrdinal),
      errors,
      completed,
      executions: Atomics.load(executionCounter, 0),
    };
  }

  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#unavailable = true;
    for (const waiter of this.#waiters.splice(0)) {
      if (waiter.onAbort !== undefined) {
        waiter.signal?.removeEventListener("abort", waiter.onAbort);
      }
      waiter.reject(new Error("Detector pool closed"));
    }
    await Promise.all(this.#slots.map(async (slot) => {
      slot.ready = false;
      slot.lifecycle.detach();
      await slot.worker.terminate().catch(() => undefined);
      await slot.replacement;
    }));
  }
}

export async function createDetectorPool(
  catalog: CompiledFingerprintCatalog,
  config: ScanConfig,
  workerFactory: DetectorWorkerFactory = nodeWorkerFactory,
): Promise<DetectorPool> {
  const created = await Promise.allSettled(
    Array.from({ length: config.limits.detector.workers }, (_value, index) =>
      spawnWorker(index + 1, catalog, config, workerFactory)),
  );
  const failed = created.find(
    (result): result is PromiseRejectedResult => result.status === "rejected",
  );
  if (failed !== undefined) {
    await Promise.all(created.map(async (result) => {
      if (result.status === "fulfilled") {
        result.value.lifecycle.detach();
        await result.value.worker.terminate();
      }
    }));
    throw failed.reason;
  }
  const slots = created
    .filter((result): result is PromiseFulfilledResult<WorkerSlot> =>
      result.status === "fulfilled")
    .map((result) => result.value);
  return new DetectorPoolImplementation(catalog, config, slots, workerFactory);
}
