import { createHash, randomUUID } from "node:crypto";
import { constants, type Stats } from "node:fs";
import {
  link,
  lstat,
  open,
  realpath,
  stat,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  calibrateShadowDevelopmentSource,
  canonicalizeShadowFrozenCandidate,
  digestShadowFrozenCandidate,
  evaluateFrozenShadowCandidate,
  validateShadowFrozenCandidate,
  type ShadowCalibrationReport,
  type ShadowDevelopmentCalibrationReport,
  type ShadowFrozenCandidate,
  type ShadowFrozenHoldoutReport,
} from "../evaluation-calibration.ts";
import {
  createShadowEvaluationAccumulator,
  SHADOW_EVALUATION_DOMAIN_COUNT,
  SHADOW_EVALUATION_PROTOCOL_REVISION,
  SHADOW_EVALUATION_SCHEMA_VERSION,
  type ShadowEvaluationArtifact,
  type ShadowEvaluationSnapshot,
} from "../evaluation.ts";
import type { Provenance } from "../model.ts";

const FILE_MODE = 0o600;
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const MAX_STRUCTURE_ITEMS = 500_000;
const MAX_STRUCTURE_DEPTH = 32;
const PATH_CODE_UNITS = 4_096;

export const SHADOW_EVALUATION_ARTIFACT_BYTES = 64 * 1_024 * 1_024;

export type EvaluationWriterErrorCode =
  | "EVALUATION_EXISTS"
  | "EVALUATION_ARTIFACT_LIMIT"
  | "EVALUATION_INVALID_ARTIFACT"
  | "EVALUATION_INVALID_TARGET"
  | "EVALUATION_IO_FAILED"
  | "EVALUATION_PATH_COLLISION"
  | "EVALUATION_SOURCE_INVALID"
  | "EVALUATION_DIGEST_MISMATCH"
  | "EVALUATION_CANDIDATE_REJECTED";

export class EvaluationWriterError extends Error {
  readonly code: EvaluationWriterErrorCode;

  constructor(
    code: EvaluationWriterErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "EvaluationWriterError";
    this.code = code;
  }
}

export interface PreflightShadowEvaluationOutputOptions {
  readonly resultPath: string;
  readonly reservedPaths?: readonly string[] | undefined;
  readonly sourcePaths?: readonly string[] | undefined;
}

export interface PreparedShadowEvaluationOutput {
  readonly evaluationPath: string;
  readonly parentPath: string;
  readonly parentDevice: number;
  readonly parentInode: number;
}

export interface PreflightShadowCandidateOutputOptions {
  readonly candidatePath: string;
  readonly reservedPaths?: readonly string[] | undefined;
  readonly sourcePaths?: readonly string[] | undefined;
}

export interface PreparedShadowCandidateOutput {
  readonly candidatePath: string;
  readonly parentPath: string;
  readonly parentDevice: number;
  readonly parentInode: number;
}

export interface PublishedShadowEvaluationArtifact
  extends ShadowEvaluationArtifact {
  readonly calibration: ShadowCalibrationReport | ShadowFrozenHoldoutReport;
}

export interface LoadedShadowDevelopmentArtifact {
  readonly artifact: ShadowEvaluationArtifact;
  readonly sourcePath: string;
  readonly digest: string;
}

export interface LoadedShadowFrozenCandidate {
  readonly candidate: ShadowFrozenCandidate;
  readonly sourcePath: string;
  readonly digest: string;
}

export interface ShadowEvaluationPublicationOptions {
  readonly frozenCandidate?: ShadowFrozenCandidate | undefined;
  readonly candidateDigest?: string | undefined;
}

function evaluationError(
  code: EvaluationWriterErrorCode,
  message: string,
  cause?: unknown,
): EvaluationWriterError {
  return new EvaluationWriterError(
    code,
    message,
    cause === undefined ? undefined : { cause },
  );
}

function errorCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("code" in error)) {
    return undefined;
  }
  return typeof error.code === "string" ? error.code : undefined;
}

function evaluationBasename(resultBasename: string): string {
  return resultBasename.endsWith(".jsonl")
    ? `${resultBasename.slice(0, -".jsonl".length)}.evaluation.json`
    : `${resultBasename}.evaluation.json`;
}

async function inspectAbsentTarget(path: string): Promise<void> {
  let targetStats: Stats;
  try {
    targetStats = await lstat(path);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return;
    throw evaluationError(
      "EVALUATION_INVALID_TARGET",
      "The shadow evaluation target could not be inspected safely.",
      error,
    );
  }

  if (
    targetStats.isSymbolicLink()
    || !targetStats.isFile()
    || targetStats.nlink !== 1
  ) {
    throw evaluationError(
      "EVALUATION_INVALID_TARGET",
      "An existing shadow evaluation target is not a standalone regular file.",
    );
  }
  throw evaluationError(
    "EVALUATION_EXISTS",
    "The shadow evaluation target already exists.",
  );
}

function sameIdentity(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function invalidArtifact(message: string): never {
  throw evaluationError("EVALUATION_INVALID_ARTIFACT", message);
}

function artifactLimit(message: string): never {
  throw evaluationError("EVALUATION_ARTIFACT_LIMIT", message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (
    actual.length !== sortedExpected.length
    || actual.some((key, index) => key !== sortedExpected[index])
  ) {
    invalidArtifact(`${label} does not have the exact published shape.`);
  }
}

function assertPlainRecord(
  value: unknown,
  label: string,
): asserts value is Record<string, unknown> {
  if (!isRecord(value)) invalidArtifact(`${label} must be a plain object.`);
}

function addEstimatedBytes(current: number, added: number): number {
  const next = current + added;
  if (
    !Number.isSafeInteger(next)
    || next > SHADOW_EVALUATION_ARTIFACT_BYTES
  ) {
    artifactLimit("The shadow evaluation artifact exceeds 64 MiB.");
  }
  return next;
}

interface StructuralEntry {
  readonly value: unknown;
  readonly depth: number;
  readonly exit?: object | undefined;
}

function preflightJsonStructure(value: unknown): void {
  const stack: StructuralEntry[] = [{ value, depth: 0 }];
  const active = new WeakSet<object>();
  let estimatedBytes = 0;
  let items = 0;
  let scheduledItems = 1;

  while (stack.length > 0) {
    const entry = stack.pop()!;
    if (entry.exit !== undefined) {
      active.delete(entry.exit);
      continue;
    }
    items += 1;
    if (items > MAX_STRUCTURE_ITEMS) {
      artifactLimit("The shadow evaluation artifact has too many values.");
    }
    if (entry.depth > MAX_STRUCTURE_DEPTH) {
      artifactLimit("The shadow evaluation artifact is nested too deeply.");
    }

    const current = entry.value;
    if (current === null) {
      estimatedBytes = addEstimatedBytes(estimatedBytes, 4);
      continue;
    }
    if (typeof current === "string") {
      estimatedBytes = addEstimatedBytes(
        estimatedBytes,
        2 + (6 * current.length),
      );
      continue;
    }
    if (typeof current === "boolean") {
      estimatedBytes = addEstimatedBytes(estimatedBytes, 5);
      continue;
    }
    if (typeof current === "number") {
      if (!Number.isFinite(current)) {
        invalidArtifact("The shadow evaluation artifact contains a non-finite number.");
      }
      estimatedBytes = addEstimatedBytes(estimatedBytes, 32);
      continue;
    }
    if (typeof current !== "object") {
      invalidArtifact("The shadow evaluation artifact contains a non-JSON value.");
    }
    if (active.has(current)) {
      invalidArtifact("The shadow evaluation artifact contains a cycle.");
    }
    active.add(current);
    stack.push({ value: null, depth: entry.depth, exit: current });

    if (Array.isArray(current)) {
      if (Object.getPrototypeOf(current) !== Array.prototype) {
        invalidArtifact("The shadow evaluation artifact contains a non-plain array.");
      }
      if (current.length > MAX_STRUCTURE_ITEMS) {
        artifactLimit("A shadow evaluation array has too many values.");
      }
      scheduledItems += current.length;
      if (scheduledItems > MAX_STRUCTURE_ITEMS) {
        artifactLimit("The shadow evaluation artifact has too many values.");
      }
      const keys = Reflect.ownKeys(current);
      if (
        keys.some((key) => typeof key !== "string")
        || keys.length !== current.length + 1
        || keys[keys.length - 1] !== "length"
      ) {
        invalidArtifact("A shadow evaluation array is sparse or has extra properties.");
      }
      estimatedBytes = addEstimatedBytes(
        estimatedBytes,
        2 + Math.max(0, current.length - 1),
      );
      for (let index = current.length - 1; index >= 0; index -= 1) {
        if (keys[index] !== String(index)) {
          invalidArtifact("A shadow evaluation array has non-canonical indices.");
        }
        const descriptor = Object.getOwnPropertyDescriptor(current, String(index));
        if (
          descriptor === undefined
          || !("value" in descriptor)
          || !descriptor.enumerable
        ) {
          invalidArtifact("A shadow evaluation array contains an accessor.");
        }
        stack.push({ value: descriptor.value, depth: entry.depth + 1 });
      }
      continue;
    }

    const prototype = Object.getPrototypeOf(current);
    if (prototype !== Object.prototype && prototype !== null) {
      invalidArtifact("The shadow evaluation artifact contains a non-plain object.");
    }
    const keys = Reflect.ownKeys(current);
    if (keys.some((key) => typeof key !== "string")) {
      invalidArtifact("The shadow evaluation artifact contains symbol keys.");
    }
    scheduledItems += keys.length;
    if (scheduledItems > MAX_STRUCTURE_ITEMS) {
      artifactLimit("The shadow evaluation artifact has too many values.");
    }
    estimatedBytes = addEstimatedBytes(
      estimatedBytes,
      2 + Math.max(0, keys.length - 1) + keys.length,
    );
    for (let index = keys.length - 1; index >= 0; index -= 1) {
      const key = keys[index]! as string;
      estimatedBytes = addEstimatedBytes(
        estimatedBytes,
        2 + (6 * key.length),
      );
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (
        descriptor === undefined
        || !("value" in descriptor)
        || !descriptor.enumerable
      ) {
        invalidArtifact("The shadow evaluation artifact contains an accessor.");
      }
      stack.push({ value: descriptor.value, depth: entry.depth + 1 });
    }
  }
}

function canonicalShadowEvaluationArtifact(
  value: unknown,
  allowPublishedCalibration: boolean,
): ShadowEvaluationArtifact {
  assertPlainRecord(value, "artifact");
  const baseKeys = [
    "schemaVersion",
    "protocolRevision",
    "runId",
    "inputDomains",
    "provenance",
    "snapshots",
    "browserLimitAggregates",
  ] as const;
  const hasCalibration = Object.hasOwn(value, "calibration");
  if (hasCalibration && !allowPublishedCalibration) {
    invalidArtifact("The unpublished shadow evaluation artifact includes calibration.");
  }
  assertExactKeys(
    value,
    hasCalibration ? [...baseKeys, "calibration"] : baseKeys,
    "artifact",
  );
  if (value.schemaVersion !== SHADOW_EVALUATION_SCHEMA_VERSION) {
    invalidArtifact("The shadow evaluation schema version does not match.");
  }
  if (value.protocolRevision !== SHADOW_EVALUATION_PROTOCOL_REVISION) {
    invalidArtifact("The shadow evaluation protocol revision does not match.");
  }
  if (typeof value.runId !== "string" || !RUN_ID.test(value.runId)) {
    invalidArtifact("The shadow evaluation runId is invalid.");
  }
  if (value.inputDomains !== SHADOW_EVALUATION_DOMAIN_COUNT) {
    invalidArtifact("The shadow evaluation cohort size does not match.");
  }
  if (
    !Array.isArray(value.snapshots)
    || value.snapshots.length !== SHADOW_EVALUATION_DOMAIN_COUNT
  ) {
    invalidArtifact("The shadow evaluation snapshot cohort does not match.");
  }
  const accumulator = createShadowEvaluationAccumulator({
    runId: value.runId,
    provenance: value.provenance as Provenance,
  });
  for (const snapshot of value.snapshots) {
    accumulator.add(snapshot as ShadowEvaluationSnapshot);
  }
  const canonical = accumulator.build(value.inputDomains);
  const comparable = hasCalibration
    ? Object.freeze({
        schemaVersion: value.schemaVersion,
        protocolRevision: value.protocolRevision,
        runId: value.runId,
        inputDomains: value.inputDomains,
        provenance: value.provenance,
        snapshots: value.snapshots,
        browserLimitAggregates: value.browserLimitAggregates,
      })
    : value;
  if (!isDeepStrictEqual(comparable, canonical)) {
    invalidArtifact("The shadow evaluation artifact is not canonical.");
  }
  return canonical;
}

function canonicalPublishedArtifact(
  value: unknown,
  options: ShadowEvaluationPublicationOptions,
): PublishedShadowEvaluationArtifact {
  const canonical = canonicalShadowEvaluationArtifact(value, false);
  const hasCandidate = options.frozenCandidate !== undefined;
  const hasDigest = options.candidateDigest !== undefined;
  if (hasCandidate !== hasDigest) {
    invalidArtifact("A frozen shadow candidate and digest must be provided together.");
  }
  return Object.freeze({
    ...canonical,
    calibration: hasCandidate
      ? evaluateFrozenShadowCandidate(
          canonical,
          options.frozenCandidate!,
          { candidateDigest: options.candidateDigest! },
        )
      : calibrateShadowDevelopmentSource(canonical),
  });
}

async function readPinnedJsonSource(
  requestedPath: string,
  expectedDigest: string,
): Promise<{
  readonly sourcePath: string;
  readonly digest: string;
  readonly text: string;
  readonly value: unknown;
}> {
  if (!SHA256_DIGEST.test(expectedDigest)) {
    throw evaluationError(
      "EVALUATION_SOURCE_INVALID",
      "The pinned shadow artifact digest is invalid.",
    );
  }
  if (
    requestedPath.length === 0
    || requestedPath.length > PATH_CODE_UNITS
    || !requestedPath.isWellFormed()
    || requestedPath.includes("\0")
  ) {
    throw evaluationError(
      "EVALUATION_SOURCE_INVALID",
      "The pinned shadow artifact path is invalid.",
    );
  }

  let handle: FileHandle | undefined;
  try {
    const absolutePath = resolve(requestedPath);
    const requestedStats = await lstat(absolutePath);
    if (
      requestedStats.isSymbolicLink()
      || !requestedStats.isFile()
      || requestedStats.nlink !== 1
      || requestedStats.size > SHADOW_EVALUATION_ARTIFACT_BYTES
    ) {
      throw new Error("invalid source target");
    }
    const sourcePath = join(
      await realpath(dirname(absolutePath)),
      basename(absolutePath),
    );
    const sourceStats = await lstat(sourcePath);
    if (
      sourceStats.isSymbolicLink()
      || !sourceStats.isFile()
      || sourceStats.nlink !== 1
      || sourceStats.size > SHADOW_EVALUATION_ARTIFACT_BYTES
      || !sameIdentity(requestedStats, sourceStats)
    ) {
      throw new Error("invalid source identity");
    }

    handle = await open(
      sourcePath,
      constants.O_RDONLY | constants.O_NONBLOCK | NO_FOLLOW,
    );
    const descriptor = await handle.stat();
    if (
      !descriptor.isFile()
      || descriptor.nlink !== 1
      || descriptor.size > SHADOW_EVALUATION_ARTIFACT_BYTES
      || !sameIdentity(sourceStats, descriptor)
    ) {
      throw new Error("invalid source descriptor");
    }

    const bytes = Buffer.alloc(descriptor.size + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(
        bytes,
        offset,
        bytes.length - offset,
        null,
      );
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    const finalDescriptor = await handle.stat();
    const finalPathStats = await lstat(sourcePath);
    if (
      offset !== descriptor.size
      || finalDescriptor.size !== descriptor.size
      || !sameIdentity(descriptor, finalDescriptor)
      || finalPathStats.isSymbolicLink()
      || !finalPathStats.isFile()
      || finalPathStats.nlink !== 1
      || finalPathStats.size !== descriptor.size
      || !sameIdentity(descriptor, finalPathStats)
    ) {
      throw new Error("source changed while reading");
    }

    const contents = bytes.subarray(0, offset);
    const digest = `sha256:${createHash("sha256").update(contents).digest("hex")}`;
    if (digest !== expectedDigest) {
      throw evaluationError(
        "EVALUATION_DIGEST_MISMATCH",
        "The shadow artifact does not match its operator-pinned digest.",
      );
    }
    const text = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true,
    }).decode(contents);
    return Object.freeze({
      sourcePath,
      digest,
      text,
      value: JSON.parse(text) as unknown,
    });
  } catch (error) {
    if (error instanceof EvaluationWriterError) throw error;
    throw evaluationError(
      "EVALUATION_SOURCE_INVALID",
      "The pinned shadow artifact is unavailable or invalid.",
      error,
    );
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

export async function readPinnedShadowDevelopmentArtifact(
  path: string,
  expectedDigest: string,
): Promise<LoadedShadowDevelopmentArtifact> {
  const loaded = await readPinnedJsonSource(path, expectedDigest);
  try {
    preflightJsonStructure(loaded.value);
    const artifact = canonicalShadowEvaluationArtifact(loaded.value, true);
    return Object.freeze({
      artifact,
      sourcePath: loaded.sourcePath,
      digest: loaded.digest,
    });
  } catch (error) {
    if (error instanceof EvaluationWriterError) throw error;
    throw evaluationError(
      "EVALUATION_SOURCE_INVALID",
      "The pinned development artifact failed validation.",
      error,
    );
  }
}

export async function readPinnedShadowFrozenCandidate(
  path: string,
  expectedDigest: string,
): Promise<LoadedShadowFrozenCandidate> {
  const loaded = await readPinnedJsonSource(path, expectedDigest);
  try {
    preflightJsonStructure(loaded.value);
    const candidate = validateShadowFrozenCandidate(loaded.value);
    const canonical = canonicalizeShadowFrozenCandidate(candidate);
    const digest = digestShadowFrozenCandidate(candidate);
    if (loaded.text !== canonical || loaded.digest !== digest) {
      throw evaluationError(
        "EVALUATION_SOURCE_INVALID",
        "The frozen shadow candidate file is not canonical.",
      );
    }
    return Object.freeze({
      candidate,
      sourcePath: loaded.sourcePath,
      digest,
    });
  } catch (error) {
    if (error instanceof EvaluationWriterError) throw error;
    throw evaluationError(
      "EVALUATION_SOURCE_INVALID",
      "The frozen shadow candidate failed validation.",
      error,
    );
  }
}

export async function preflightShadowEvaluationOutput(
  options: PreflightShadowEvaluationOutputOptions,
): Promise<PreparedShadowEvaluationOutput> {
  const absoluteResultPath = resolve(options.resultPath);
  const requestedParent = dirname(absoluteResultPath);
  let parentPath: string;
  let parentStats: Stats;
  try {
    parentPath = await realpath(requestedParent);
    parentStats = await stat(parentPath);
  } catch (error) {
    throw evaluationError(
      "EVALUATION_INVALID_TARGET",
      "The shadow evaluation parent directory is unavailable.",
      error,
    );
  }
  if (!parentStats.isDirectory()) {
    throw evaluationError(
      "EVALUATION_INVALID_TARGET",
      "The shadow evaluation parent is not a directory.",
    );
  }

  const evaluationPath = join(
    parentPath,
    evaluationBasename(basename(absoluteResultPath)),
  );
  for (const path of [
    ...(options.reservedPaths ?? []),
    ...(options.sourcePaths ?? []),
  ]) {
    let comparablePath: string;
    try {
      const absolutePath = resolve(path);
      comparablePath = join(
        await realpath(dirname(absolutePath)),
        basename(absolutePath),
      );
    } catch (error) {
      throw evaluationError(
        "EVALUATION_INVALID_TARGET",
        "A reserved or input path could not be canonicalized safely.",
        error,
      );
    }
    if (comparablePath === evaluationPath) {
      throw evaluationError(
        "EVALUATION_PATH_COLLISION",
        "The shadow evaluation target aliases a reserved or input path.",
      );
    }
  }

  await inspectAbsentTarget(evaluationPath);
  return Object.freeze({
    evaluationPath,
    parentPath,
    parentDevice: parentStats.dev,
    parentInode: parentStats.ino,
  });
}

export async function preflightShadowCandidateOutput(
  options: PreflightShadowCandidateOutputOptions,
): Promise<PreparedShadowCandidateOutput> {
  if (
    options.candidatePath.length === 0
    || options.candidatePath.length > PATH_CODE_UNITS
    || !options.candidatePath.isWellFormed()
    || options.candidatePath.includes("\0")
  ) {
    throw evaluationError(
      "EVALUATION_INVALID_TARGET",
      "The shadow candidate target path is invalid.",
    );
  }
  const absoluteCandidatePath = resolve(options.candidatePath);
  const requestedParent = dirname(absoluteCandidatePath);
  let parentPath: string;
  let parentStats: Stats;
  try {
    parentPath = await realpath(requestedParent);
    parentStats = await stat(parentPath);
  } catch (error) {
    throw evaluationError(
      "EVALUATION_INVALID_TARGET",
      "The shadow candidate parent directory is unavailable.",
      error,
    );
  }
  if (!parentStats.isDirectory()) {
    throw evaluationError(
      "EVALUATION_INVALID_TARGET",
      "The shadow candidate parent is not a directory.",
    );
  }

  const candidatePath = join(parentPath, basename(absoluteCandidatePath));
  for (const path of [
    ...(options.reservedPaths ?? []),
    ...(options.sourcePaths ?? []),
  ]) {
    let comparablePath: string;
    try {
      const absolutePath = resolve(path);
      comparablePath = join(
        await realpath(dirname(absolutePath)),
        basename(absolutePath),
      );
    } catch (error) {
      throw evaluationError(
        "EVALUATION_INVALID_TARGET",
        "A reserved or source path could not be canonicalized safely.",
        error,
      );
    }
    if (comparablePath === candidatePath) {
      throw evaluationError(
        "EVALUATION_PATH_COLLISION",
        "The shadow candidate target aliases a reserved or source path.",
      );
    }
  }

  await inspectAbsentTarget(candidatePath);
  return Object.freeze({
    candidatePath,
    parentPath,
    parentDevice: parentStats.dev,
    parentInode: parentStats.ino,
  });
}

async function writeAll(handle: FileHandle, bytes: Buffer): Promise<void> {
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesWritten } = await handle.write(
      bytes,
      offset,
      bytes.length - offset,
      null,
    );
    if (bytesWritten <= 0) {
      throw new Error("The shadow evaluation write made no progress.");
    }
    offset += bytesWritten;
  }
}

async function unlinkOwnedPath(path: string, expected: Stats): Promise<boolean> {
  try {
    const current = await lstat(path);
    if (
      current.isSymbolicLink()
      || !current.isFile()
      || !sameIdentity(current, expected)
    ) {
      return false;
    }
    await unlink(path);
    return true;
  } catch (error) {
    if (errorCode(error) === "ENOENT") return true;
    return false;
  }
}

async function verifyOwnedRegularFile(
  path: string,
  expected: Stats,
  expectedLinks: number,
): Promise<void> {
  const current = await lstat(path);
  if (
    current.isSymbolicLink()
    || !current.isFile()
    || current.nlink !== expectedLinks
    || !sameIdentity(current, expected)
  ) {
    throw evaluationError(
      "EVALUATION_INVALID_TARGET",
      "A shadow evaluation publication target changed unexpectedly.",
    );
  }
}

interface PreparedAtomicOutput {
  readonly parentPath: string;
  readonly parentDevice: number;
  readonly parentInode: number;
}

async function publishAtomicBytes(
  prepared: PreparedAtomicOutput,
  targetPath: string,
  bytes: Buffer,
): Promise<void> {
  let currentParentPath: string;
  let currentParentStats: Stats;
  try {
    currentParentPath = await realpath(prepared.parentPath);
    currentParentStats = await stat(currentParentPath);
  } catch (error) {
    throw evaluationError(
      "EVALUATION_INVALID_TARGET",
      "The shadow artifact parent directory is unavailable.",
      error,
    );
  }
  if (
    !currentParentStats.isDirectory()
    || currentParentPath !== prepared.parentPath
    || currentParentStats.dev !== prepared.parentDevice
    || currentParentStats.ino !== prepared.parentInode
  ) {
    throw evaluationError(
      "EVALUATION_INVALID_TARGET",
      "The shadow artifact parent directory changed after preflight.",
    );
  }
  await inspectAbsentTarget(targetPath);

  const tempPath = join(
    prepared.parentPath,
    `.${basename(targetPath)}.${randomUUID()}.tmp`,
  );
  let tempHandle: FileHandle | undefined;
  let tempStats: Stats | undefined;
  let linked = false;
  let committed = false;
  try {
    tempHandle = await open(
      tempPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW,
      FILE_MODE,
    );
    tempStats = await tempHandle.stat();
    if (!tempStats.isFile() || tempStats.nlink !== 1) {
      throw evaluationError(
        "EVALUATION_INVALID_TARGET",
        "The shadow artifact temporary descriptor is not a regular file.",
      );
    }
    await writeAll(tempHandle, bytes);
    await tempHandle.sync();
    await tempHandle.close();
    tempHandle = undefined;
    await verifyOwnedRegularFile(tempPath, tempStats, 1);

    try {
      await link(tempPath, targetPath);
      linked = true;
    } catch (error) {
      if (errorCode(error) === "EEXIST") {
        await inspectAbsentTarget(targetPath);
      }
      throw error;
    }
    await verifyOwnedRegularFile(targetPath, tempStats, 2);
    if (!await unlinkOwnedPath(tempPath, tempStats)) {
      throw evaluationError(
        "EVALUATION_INVALID_TARGET",
        "The shadow artifact temporary target changed before cleanup.",
      );
    }
    await verifyOwnedRegularFile(targetPath, tempStats, 1);
    committed = true;
  } catch (error) {
    if (linked && !committed && tempStats !== undefined) {
      await unlinkOwnedPath(targetPath, tempStats);
    }
    if (error instanceof EvaluationWriterError) throw error;
    throw evaluationError(
      "EVALUATION_IO_FAILED",
      "The shadow artifact could not be published atomically.",
      error,
    );
  } finally {
    await tempHandle?.close().catch(() => undefined);
    if (tempStats !== undefined) {
      await unlinkOwnedPath(tempPath, tempStats);
    }
  }
}

export async function writeShadowFrozenCandidateArtifact(
  prepared: PreparedShadowCandidateOutput,
  report: ShadowDevelopmentCalibrationReport,
): Promise<string> {
  const candidate = report.candidate;
  const guardrails = report.deployable.provisionalGuardrails;
  const costGuardrails = guardrails.realBrowserCosts;
  if (
    candidate === null
    || !guardrails.passed
    || !guardrails.canonicalDirectNames.passed
    || !guardrails.domainTechnologyPairs.passed
    || !guardrails.routedDomains.passed
    || !costGuardrails.passed
    || !costGuardrails.browserPagesAttempted.passed
    || !costGuardrails.browserPagesAdmitted.passed
    || !costGuardrails.browserRequests.passed
    || !costGuardrails.browserTransferredBytes.passed
    || !costGuardrails.browserMs.passed
  ) {
    throw evaluationError(
      "EVALUATION_CANDIDATE_REJECTED",
      "The development GO/NO-GO verdict does not permit candidate publication.",
    );
  }

  let canonical: string;
  let digest: string;
  try {
    preflightJsonStructure(candidate);
    const validated = validateShadowFrozenCandidate(candidate);
    canonical = canonicalizeShadowFrozenCandidate(validated);
    digest = digestShadowFrozenCandidate(validated);
    if (
      Buffer.byteLength(canonical, "utf8") > SHADOW_EVALUATION_ARTIFACT_BYTES
    ) {
      artifactLimit("The frozen shadow candidate exceeds 64 MiB.");
    }
  } catch (error) {
    if (error instanceof EvaluationWriterError) throw error;
    throw evaluationError(
      "EVALUATION_INVALID_ARTIFACT",
      "The frozen shadow candidate failed structural validation.",
      error,
    );
  }

  await publishAtomicBytes(
    prepared,
    prepared.candidatePath,
    Buffer.from(canonical, "utf8"),
  );
  return digest;
}

export async function writeShadowEvaluationArtifact(
  prepared: PreparedShadowEvaluationOutput,
  artifact: ShadowEvaluationArtifact,
  options: ShadowEvaluationPublicationOptions = {},
): Promise<void> {
  let published: PublishedShadowEvaluationArtifact;
  try {
    preflightJsonStructure(artifact);
    published = canonicalPublishedArtifact(artifact, options);
    preflightJsonStructure(published);
  } catch (error) {
    if (error instanceof EvaluationWriterError) throw error;
    throw evaluationError(
      "EVALUATION_INVALID_ARTIFACT",
      "The shadow evaluation artifact failed structural validation.",
      error,
    );
  }

  let bytes: Buffer;
  try {
    const json = JSON.stringify(published);
    if (json === undefined) throw new TypeError("Artifact is not serializable");
    if (Buffer.byteLength(json, "utf8") + 1 > SHADOW_EVALUATION_ARTIFACT_BYTES) {
      artifactLimit("The shadow evaluation artifact exceeds 64 MiB.");
    }
    bytes = Buffer.from(`${json}\n`, "utf8");
  } catch (error) {
    if (error instanceof EvaluationWriterError) throw error;
    throw evaluationError(
      "EVALUATION_INVALID_ARTIFACT",
      "The shadow evaluation artifact could not be serialized.",
    );
  }

  await publishAtomicBytes(prepared, prepared.evaluationPath, bytes);
}
