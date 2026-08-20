import { parentPort, workerData } from "node:worker_threads";

import type {
  DetectorWorkerData,
  DetectorWorkerRequest,
  DetectorWorkerResponse,
  WorkerMatch,
} from "./pool.ts";

const PHASE = 0;
const CURRENT_RULE = 1;
const PROGRESS = 2;
const CHECKPOINT = 3;
const PHASE_COMPILING = 1;
const PHASE_IDLE = 2;
const PHASE_MATCHING = 3;

const port = parentPort;
if (port === null) {
  throw new Error("Detector worker requires a parent port");
}

const data = workerData as DetectorWorkerData;
const state = new Int32Array(data.progressBuffer);
Atomics.store(state, PHASE, PHASE_COMPILING);
const compiled = data.rules.map((rule, ordinal) => {
  Atomics.store(state, CURRENT_RULE, ordinal);
  Atomics.add(state, PROGRESS, 1);
  return {
    locator: rule.locatorPattern === null
      ? null
      : new RegExp(rule.locatorPattern, "i"),
    value: rule.matchMode === "regex" && rule.pattern !== null
      ? new RegExp(rule.pattern, "i")
      : null,
  };
});

Atomics.store(state, CURRENT_RULE, -1);
Atomics.store(state, PHASE, PHASE_IDLE);
port.postMessage({ type: "ready" } satisfies DetectorWorkerResponse);

function reserveExecution(counter: Int32Array, maximum: number): boolean {
  while (true) {
    const current = Atomics.load(counter, 0);
    if (current >= maximum) {
      return false;
    }
    if (Atomics.compareExchange(counter, 0, current, current + 1) === current) {
      return true;
    }
  }
}

function renderVersion(
  template: string | null,
  match: RegExpExecArray | null,
  maximumCodeUnits: number,
  hexTokenMinimum: number,
  base64UrlTokenMinimum: number,
): string | null {
  if (template === null || match === null) {
    return null;
  }

  let selected = template;
  const conditional = /^\\([1-9]\d*)\?([^:]*):([^:]*)$/u.exec(selected);
  if (conditional !== null) {
    const capture = match[Number(conditional[1])];
    selected = capture === undefined || capture === ""
      ? conditional[3] ?? ""
      : conditional[2] ?? "";
  }
  selected = selected.replace(/\\([1-9]\d*)/gu, (_value, rawIndex: string) =>
    match[Number(rawIndex)] ?? "");
  selected = selected.replace(/^[ \t\r\n\f]+|[ \t\r\n\f]+$/gu, "");

  if (
    selected.length > maximumCodeUnits
    || !/^[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}$/u.test(selected)
    || containsOpaqueToken(selected, hexTokenMinimum, base64UrlTokenMinimum)
  ) {
    return null;
  }
  return selected;
}

function containsOpaqueToken(
  value: string,
  hexMinimum: number,
  base64UrlMinimum: number,
): boolean {
  let hexRun = 0;
  let base64UrlRun = 0;
  for (const character of value) {
    hexRun = /^[0-9a-f]$/iu.test(character) ? hexRun + 1 : 0;
    base64UrlRun = /^[A-Za-z0-9_-]$/u.test(character)
      ? base64UrlRun + 1
      : 0;
    if (hexRun >= hexMinimum || base64UrlRun >= base64UrlMinimum) {
      return true;
    }
  }
  return false;
}

function literalMatch(value: string, pattern: string): { index: number; length: number } | null {
  const foldedValue = value.toLowerCase();
  const foldedPattern = pattern.toLowerCase();
  const foldedIndex = foldedValue.indexOf(foldedPattern);
  if (foldedIndex === -1) {
    return null;
  }

  let originalOffset = 0;
  let foldedOffset = 0;
  let start: number | null = foldedIndex === 0 ? 0 : null;
  let end: number | null = foldedPattern.length === 0 ? start : null;
  while (originalOffset < value.length && end === null) {
    const codePoint = value.codePointAt(originalOffset);
    if (codePoint === undefined) {
      break;
    }
    const originalCharacter = String.fromCodePoint(codePoint);
    originalOffset += originalCharacter.length;
    foldedOffset += originalCharacter.toLowerCase().length;
    if (foldedOffset === foldedIndex) {
      start = originalOffset;
    }
    if (foldedOffset === foldedIndex + foldedPattern.length) {
      end = originalOffset;
    } else if (foldedOffset > foldedIndex + foldedPattern.length) {
      return null;
    }
  }

  return start === null || end === null
    ? null
    : { index: start, length: end - start };
}

port.on("message", (message: DetectorWorkerRequest) => {
  if (message.type !== "match") {
    return;
  }

  const counter = new Int32Array(message.executionBuffer);
  const skipped = new Set(message.skipRuleOrdinals);
  let pending: WorkerMatch[] = [];
  const shouldCheckpoint = (nextWorkIndex: number): boolean =>
    nextWorkIndex < message.work.length
    && (
      nextWorkIndex % message.checkpointRules === 0
      || nextWorkIndex === message.priorityWorkEndIndex
    );
  Atomics.store(state, PHASE, PHASE_MATCHING);
  Atomics.store(state, CHECKPOINT, message.startWorkIndex);

  for (
    let workIndex = message.startWorkIndex;
    workIndex < message.work.length;
    workIndex += 1
  ) {
    const item = message.work[workIndex];
    if (item === undefined) {
      continue;
    }
    const rule = data.rules[item.ruleOrdinal];
    const regex = compiled[item.ruleOrdinal];
    if (rule === undefined || regex === undefined || skipped.has(item.ruleOrdinal)) {
      const nextWorkIndex = workIndex + 1;
      if (shouldCheckpoint(nextWorkIndex)) {
        Atomics.store(state, CHECKPOINT, nextWorkIndex);
        port.postMessage({
          type: "checkpoint",
          taskId: message.taskId,
          nextWorkIndex,
          matches: pending,
        } satisfies DetectorWorkerResponse);
        pending = [];
      }
      continue;
    }

    Atomics.store(state, CURRENT_RULE, item.ruleOrdinal);
    Atomics.add(state, PROGRESS, 1);
    const ruleMatches: WorkerMatch[] = [];

    for (const candidateOrdinal of item.candidateOrdinals) {
      const candidate = message.candidates[candidateOrdinal];
      if (candidate === undefined) {
        continue;
      }
      if (regex.locator !== null) {
        if (!reserveExecution(counter, message.executionLimit)) {
          Atomics.store(state, CHECKPOINT, workIndex);
          Atomics.store(state, CURRENT_RULE, -1);
          Atomics.store(state, PHASE, PHASE_IDLE);
          port.postMessage({
            type: "execution-limit",
            taskId: message.taskId,
            nextWorkIndex: workIndex,
            matches: pending,
          } satisfies DetectorWorkerResponse);
          return;
        }
        if (regex.locator.exec(candidate.key ?? "") === null) {
          continue;
        }
      }

      let index = 0;
      let length = 0;
      let match: RegExpExecArray | null = null;
      if (rule.matchMode === "regex") {
        if (!reserveExecution(counter, message.executionLimit)) {
          Atomics.store(state, CHECKPOINT, workIndex);
          Atomics.store(state, CURRENT_RULE, -1);
          Atomics.store(state, PHASE, PHASE_IDLE);
          port.postMessage({
            type: "execution-limit",
            taskId: message.taskId,
            nextWorkIndex: workIndex,
            matches: pending,
          } satisfies DetectorWorkerResponse);
          return;
        }
        match = regex.value?.exec(candidate.value) ?? null;
        if (match === null) {
          continue;
        }
        index = match.index;
        length = match[0].length;
      } else if (rule.matchMode === "literal") {
        const found = literalMatch(candidate.value, rule.pattern ?? "");
        if (found === null) {
          continue;
        }
        index = found.index;
        length = found.length;
      }

      ruleMatches.push({
        ruleOrdinal: item.ruleOrdinal,
        candidateOrdinal,
        index,
        length,
        version: renderVersion(
          rule.versionTemplate,
          match,
          data.versionCodeUnits,
          data.hexTokenMinCodeUnits,
          data.base64UrlTokenMinCodeUnits,
        ),
      });
    }

    pending.push(...ruleMatches);
    const nextWorkIndex = workIndex + 1;
    if (shouldCheckpoint(nextWorkIndex)) {
      Atomics.store(state, CHECKPOINT, nextWorkIndex);
      port.postMessage({
        type: "checkpoint",
        taskId: message.taskId,
        nextWorkIndex,
        matches: pending,
      } satisfies DetectorWorkerResponse);
      pending = [];
    }
  }

  Atomics.store(state, CURRENT_RULE, -1);
  Atomics.store(state, CHECKPOINT, message.work.length);
  Atomics.store(state, PHASE, PHASE_IDLE);
  port.postMessage({
    type: "complete",
    taskId: message.taskId,
    nextWorkIndex: message.work.length,
    matches: pending,
  } satisfies DetectorWorkerResponse);
});
