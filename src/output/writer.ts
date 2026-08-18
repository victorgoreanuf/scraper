import { randomUUID } from "node:crypto";
import {
  constants,
  type Stats,
} from "node:fs";
import {
  link,
  lstat,
  open,
  realpath,
  stat,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import {
  basename,
  dirname,
  join,
  resolve,
} from "node:path";

import {
  canonicalizeScanConfig,
  computeConfigDigest,
  type ScanConfig,
} from "../config.ts";
import {
  validatePersistedDomainResult,
  type DomainResult,
  type Provenance,
} from "../model.ts";
import {
  createRunSummaryAccumulator,
  type RunSummary,
} from "./summary.ts";

const READ_BUFFER_BYTES = 64 * 1_024;
const FILE_MODE = 0o600;
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const activeOutputDirectories = new Set<string>();

export type ResultWriterMode = "create" | "resume" | "force";

export interface OpenResultWriterOptions {
  readonly resultPath: string;
  readonly mode: ResultWriterMode;
  readonly config: ScanConfig;
  readonly provenance: Provenance;
}

export interface ResultWriter {
  readonly runId: string;
  readonly processedDomains: number;
  hasCompletedDomain(domain: string): boolean;
  append(result: DomainResult): Promise<void>;
  finalize(inputDomains: number): Promise<RunSummary>;
  close(): Promise<void>;
}

export type OutputWriterErrorCode =
  | "OUTPUT_CONTEXT_MISMATCH"
  | "OUTPUT_DOMAIN_LIMIT"
  | "OUTPUT_DUPLICATE_DOMAIN"
  | "OUTPUT_EXISTS"
  | "OUTPUT_FINALIZE_MISMATCH"
  | "OUTPUT_INVALID_MODE"
  | "OUTPUT_INVALID_RECORD"
  | "OUTPUT_INVALID_RESUME"
  | "OUTPUT_INVALID_TARGET"
  | "OUTPUT_IO_FAILED"
  | "OUTPUT_BUSY"
  | "OUTPUT_MISSING"
  | "OUTPUT_RECORD_LIMIT"
  | "OUTPUT_WRITER_CLOSED";

export class OutputWriterError extends Error {
  readonly code: OutputWriterErrorCode;

  constructor(
    code: OutputWriterErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "OutputWriterError";
    this.code = code;
  }
}

interface CanonicalOutputPaths {
  readonly parentPath: string;
  readonly parentIdentity: string;
  readonly resultPath: string;
  readonly summaryPath: string;
}

interface TargetInspection {
  readonly exists: boolean;
  readonly stats: Stats | null;
}

interface CreatedResult {
  readonly handle: FileHandle;
  readonly stats: Stats;
}

type SummaryAccumulator = ReturnType<typeof createRunSummaryAccumulator>;

interface ResumeState {
  readonly runId: string;
  readonly completedDomains: Set<string>;
  readonly accumulator: SummaryAccumulator;
}

function writerError(
  code: OutputWriterErrorCode,
  message: string,
  cause?: unknown,
): OutputWriterError {
  return new OutputWriterError(
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

function summaryBasename(resultBasename: string): string {
  return resultBasename.endsWith(".jsonl")
    ? `${resultBasename.slice(0, -".jsonl".length)}.summary.json`
    : `${resultBasename}.summary.json`;
}

async function canonicalOutputPaths(
  resultPath: string,
): Promise<CanonicalOutputPaths> {
  if (resultPath.length === 0) {
    throw writerError(
      "OUTPUT_INVALID_TARGET",
      "The result path must not be empty.",
    );
  }

  const absoluteResultPath = resolve(resultPath);
  const requestedParent = dirname(absoluteResultPath);
  let parentPath: string;
  let parentStats: Stats;

  try {
    parentPath = await realpath(requestedParent);
    parentStats = await stat(parentPath);
    if (!parentStats.isDirectory()) {
      throw writerError(
        "OUTPUT_INVALID_TARGET",
        "The result parent is not a directory.",
      );
    }
  } catch (error) {
    if (error instanceof OutputWriterError) {
      throw error;
    }
    throw writerError(
      "OUTPUT_INVALID_TARGET",
      "The result parent directory is unavailable.",
      error,
    );
  }

  const resultBasename = basename(absoluteResultPath);
  return {
    parentPath,
    parentIdentity: `${parentStats.dev}:${parentStats.ino}`,
    resultPath: join(parentPath, resultBasename),
    summaryPath: join(parentPath, summaryBasename(resultBasename)),
  };
}

async function inspectTarget(
  path: string,
  allowMultipleLinks = false,
): Promise<TargetInspection> {
  let targetStats: Stats;
  try {
    targetStats = await lstat(path);
  } catch (error) {
    if (errorCode(error) === "ENOENT") {
      return { exists: false, stats: null };
    }
    throw writerError(
      "OUTPUT_INVALID_TARGET",
      "An output target could not be inspected safely.",
      error,
    );
  }

  if (
    targetStats.isSymbolicLink()
    || !targetStats.isFile()
    || (!allowMultipleLinks && targetStats.nlink !== 1)
  ) {
    throw writerError(
      "OUTPUT_INVALID_TARGET",
      "An existing output target must be an unlinked regular non-symlink file.",
    );
  }

  return { exists: true, stats: targetStats };
}

async function verifyExistingRegularFile(
  path: string,
  expectedStats: Stats,
  allowMultipleLinks = false,
): Promise<void> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(path, constants.O_RDONLY | NO_FOLLOW);
    const descriptorStats = await handle.stat();
    if (
      !descriptorStats.isFile()
      || (!allowMultipleLinks && descriptorStats.nlink !== 1)
      || descriptorStats.dev !== expectedStats.dev
      || descriptorStats.ino !== expectedStats.ino
    ) {
      throw writerError(
        "OUTPUT_INVALID_TARGET",
        "An existing output descriptor is not a regular file.",
      );
    }
  } catch (error) {
    if (error instanceof OutputWriterError) {
      throw error;
    }
    throw writerError(
      "OUTPUT_INVALID_TARGET",
      "An existing output target could not be opened safely.",
      error,
    );
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function removeValidatedTarget(
  path: string,
  expectedStats: Stats,
): Promise<void> {
  let currentStats: Stats;
  try {
    currentStats = await lstat(path);
  } catch (error) {
    throw writerError(
      "OUTPUT_INVALID_TARGET",
      "An output target changed before it could be replaced.",
      error,
    );
  }
  if (
    !currentStats.isFile()
    || currentStats.isSymbolicLink()
    || currentStats.dev !== expectedStats.dev
    || currentStats.ino !== expectedStats.ino
  ) {
    throw writerError(
      "OUTPUT_INVALID_TARGET",
      "An output target changed before it could be replaced.",
    );
  }
  try {
    await unlink(path);
  } catch (error) {
    throw writerError(
      "OUTPUT_IO_FAILED",
      "A validated paired summary could not be removed.",
      error,
    );
  }
}

async function unlinkOwnedPath(
  path: string,
  expectedStats: Stats,
): Promise<boolean> {
  let currentStats: Stats;
  try {
    currentStats = await lstat(path);
  } catch {
    return false;
  }
  if (
    currentStats.isSymbolicLink()
    || !currentStats.isFile()
    || currentStats.dev !== expectedStats.dev
    || currentStats.ino !== expectedStats.ino
  ) {
    return false;
  }
  try {
    await unlink(path);
    return true;
  } catch {
    return false;
  }
}

async function openExistingResult(
  path: string,
  expectedStats: Stats,
): Promise<FileHandle> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(
      path,
      constants.O_RDWR | constants.O_APPEND | NO_FOLLOW,
    );
    const descriptorStats = await handle.stat();
    if (
      !descriptorStats.isFile()
      || descriptorStats.nlink !== 1
      || descriptorStats.dev !== expectedStats.dev
      || descriptorStats.ino !== expectedStats.ino
    ) {
      throw writerError(
        "OUTPUT_INVALID_TARGET",
        "The result descriptor is not a regular file.",
      );
    }
    return handle;
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (error instanceof OutputWriterError) {
      throw error;
    }
    throw writerError(
      errorCode(error) === "ENOENT" ? "OUTPUT_MISSING" : "OUTPUT_INVALID_TARGET",
      errorCode(error) === "ENOENT"
        ? "The result file does not exist."
        : "The result file could not be opened safely.",
      error,
    );
  }
}

async function createResult(path: string): Promise<CreatedResult> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(
      path,
      constants.O_WRONLY
        | constants.O_CREAT
        | constants.O_EXCL
        | constants.O_APPEND
        | NO_FOLLOW,
      FILE_MODE,
    );
    const descriptorStats = await handle.stat();
    if (!descriptorStats.isFile() || descriptorStats.nlink !== 1) {
      throw writerError(
        "OUTPUT_INVALID_TARGET",
        "The new result descriptor is not a regular file.",
      );
    }
    return { handle, stats: descriptorStats };
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (error instanceof OutputWriterError) {
      throw error;
    }
    throw writerError(
      errorCode(error) === "EEXIST" ? "OUTPUT_EXISTS" : "OUTPUT_IO_FAILED",
      errorCode(error) === "EEXIST"
        ? "An output target already exists."
        : "The result file could not be created.",
      error,
    );
  }
}

function sameProvenance(left: Provenance, right: Provenance): boolean {
  return left.scannerVersion === right.scannerVersion
    && left.runtime.node === right.runtime.node
    && left.runtime.playwright === right.runtime.playwright
    && left.runtime.chromiumRevision === right.runtime.chromiumRevision
    && left.catalog.source === right.catalog.source
    && left.catalog.revision === right.catalog.revision
    && left.catalog.digest === right.catalog.digest
    && left.configDigest === right.configDigest;
}

function ensureResultContext(
  result: DomainResult,
  runId: string,
  config: ScanConfig,
  provenance: Provenance,
): void {
  if (
    result.runId !== runId
    || result.scanMode !== config.scanMode
    || !sameProvenance(result.provenance, provenance)
  ) {
    throw writerError(
      "OUTPUT_CONTEXT_MISMATCH",
      "The result does not match the active run context.",
    );
  }
}

function validatePersisted(
  value: unknown,
  config: ScanConfig,
  provenance: Provenance,
): DomainResult {
  try {
    return validatePersistedDomainResult(value, {
      scanConfig: config,
      expectedConfigDigest: provenance.configDigest,
    });
  } catch {
    throw writerError(
      "OUTPUT_INVALID_RECORD",
      "A persisted domain result is invalid.",
    );
  }
}

function decodeCompleteLine(bytes: Buffer): unknown {
  if (
    bytes.length >= 3
    && bytes[0] === 0xef
    && bytes[1] === 0xbb
    && bytes[2] === 0xbf
  ) {
    throw writerError(
      "OUTPUT_INVALID_RESUME",
      "A complete JSONL record contains a UTF-8 byte-order mark.",
    );
  }

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw writerError(
      "OUTPUT_INVALID_RESUME",
      "A complete JSONL record is not valid UTF-8.",
    );
  }

  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw writerError(
      "OUTPUT_INVALID_RESUME",
      "A complete JSONL record is not valid JSON.",
    );
  }
}

async function scanResumeFile(
  handle: FileHandle,
  config: ScanConfig,
  provenance: Provenance,
): Promise<ResumeState> {
  const descriptorStats = await handle.stat();
  if (!Number.isSafeInteger(descriptorStats.size) || descriptorStats.size < 0) {
    throw writerError(
      "OUTPUT_INVALID_RESUME",
      "The result file has an unsupported size.",
    );
  }

  const limit = config.limits.output.jsonlRecordBytes;
  const readBuffer = Buffer.allocUnsafe(READ_BUFFER_BYTES);
  const fragments: Buffer[] = [];
  let fragmentBytes = 0;
  let readOffset = 0;
  let lastCompleteOffset = 0;
  let runId: string | undefined;
  let accumulator: SummaryAccumulator | undefined;
  const completedDomains = new Set<string>();

  const acceptLine = (lineWithNewline: Buffer): void => {
    const wireValue = decodeCompleteLine(
      lineWithNewline.subarray(0, lineWithNewline.length - 1),
    );
    const result = validatePersisted(wireValue, config, provenance);

    if (runId === undefined) {
      runId = result.runId;
      accumulator = createRunSummaryAccumulator({
        runId,
        config,
        provenance,
      });
    }

    ensureResultContext(result, runId, config, provenance);
    if (completedDomains.has(result.domain)) {
      throw writerError(
        "OUTPUT_DUPLICATE_DOMAIN",
        "The result file contains a duplicate domain key.",
      );
    }
    if (completedDomains.size >= config.limits.parquet.rows) {
      throw writerError(
        "OUTPUT_DOMAIN_LIMIT",
        "The result file exceeds the configured input row limit.",
      );
    }

    accumulator?.add(result);
    completedDomains.add(result.domain);
  };

  while (readOffset < descriptorStats.size) {
    const requestedBytes = Math.min(
      readBuffer.length,
      descriptorStats.size - readOffset,
    );
    const { bytesRead } = await handle.read(
      readBuffer,
      0,
      requestedBytes,
      readOffset,
    );
    if (bytesRead === 0) {
      throw writerError(
        "OUTPUT_IO_FAILED",
        "The result file changed while it was being scanned.",
      );
    }

    let cursor = 0;
    while (cursor < bytesRead) {
      const relativeNewlineIndex = readBuffer
        .subarray(cursor, bytesRead)
        .indexOf(0x0a);
      const newlineIndex = relativeNewlineIndex === -1
        ? -1
        : cursor + relativeNewlineIndex;
      const segmentEnd = newlineIndex === -1 ? bytesRead : newlineIndex + 1;
      const segment = Buffer.from(readBuffer.subarray(cursor, segmentEnd));
      fragmentBytes += segment.length;
      if (fragmentBytes > limit) {
        throw writerError(
          "OUTPUT_RECORD_LIMIT",
          "A raw JSONL record exceeds the configured byte limit.",
        );
      }
      fragments.push(segment);
      cursor = segmentEnd;

      if (newlineIndex !== -1) {
        acceptLine(Buffer.concat(fragments, fragmentBytes));
        fragments.length = 0;
        fragmentBytes = 0;
        lastCompleteOffset = readOffset + cursor;
      }
    }

    readOffset += bytesRead;
  }

  if (fragmentBytes > 0) {
    await handle.truncate(lastCompleteOffset);
  }

  const resumedRunId = runId ?? randomUUID();
  const resumedAccumulator = accumulator ?? createRunSummaryAccumulator({
    runId: resumedRunId,
    config,
    provenance,
  });
  return {
    runId: resumedRunId,
    completedDomains,
    accumulator: resumedAccumulator,
  };
}

async function writeAll(handle: FileHandle, bytes: Buffer): Promise<void> {
  let offset = 0;
  while (offset < bytes.length) {
    let bytesWritten: number;
    try {
      ({ bytesWritten } = await handle.write(
        bytes,
        offset,
        bytes.length - offset,
        null,
      ));
    } catch (error) {
      throw writerError(
        "OUTPUT_IO_FAILED",
        "An output write failed.",
        error,
      );
    }
    if (bytesWritten <= 0) {
      throw writerError(
        "OUTPUT_IO_FAILED",
        "An output write made no progress.",
      );
    }
    offset += bytesWritten;
  }
}

async function writeSummaryAtomically(
  paths: CanonicalOutputPaths,
  summary: RunSummary,
): Promise<void> {
  const summaryBytes = Buffer.from(`${JSON.stringify(summary)}\n`, "utf8");
  const tempPath = join(
    paths.parentPath,
    `.${basename(paths.summaryPath)}.${randomUUID()}.tmp`,
  );
  let tempHandle: FileHandle | undefined;
  let tempStats: Stats | undefined;

  try {
    tempHandle = await open(
      tempPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW,
      FILE_MODE,
    );
    const descriptorStats = await tempHandle.stat();
    if (!descriptorStats.isFile() || descriptorStats.nlink !== 1) {
      throw writerError(
        "OUTPUT_INVALID_TARGET",
        "The summary temporary descriptor is not a regular file.",
      );
    }
    tempStats = descriptorStats;
    await writeAll(tempHandle, summaryBytes);
    await tempHandle.sync();
    await tempHandle.close();
    tempHandle = undefined;

    const sourceInspection = await inspectTarget(tempPath);
    if (
      !sourceInspection.exists
      || sourceInspection.stats!.dev !== descriptorStats.dev
      || sourceInspection.stats!.ino !== descriptorStats.ino
    ) {
      throw writerError(
        "OUTPUT_INVALID_TARGET",
        "The summary temporary target changed before publication.",
      );
    }

    try {
      await link(tempPath, paths.summaryPath);
    } catch (error) {
      if (errorCode(error) === "EEXIST") {
        const inspection = await inspectTarget(paths.summaryPath, true);
        if (!inspection.exists) {
          throw writerError(
            "OUTPUT_INVALID_TARGET",
            "The paired summary target changed during publication.",
          );
        }
        throw writerError(
          "OUTPUT_EXISTS",
          "The paired summary target already exists.",
        );
      }
      throw error;
    }
    await verifyExistingRegularFile(
      paths.summaryPath,
      descriptorStats,
      true,
    );
    if (await unlinkOwnedPath(tempPath, descriptorStats)) {
      tempStats = undefined;
    }
  } catch (error) {
    if (error instanceof OutputWriterError) {
      throw error;
    }
    throw writerError(
      "OUTPUT_IO_FAILED",
      "The paired summary could not be written atomically.",
      error,
    );
  } finally {
    await tempHandle?.close().catch(() => undefined);
    if (tempStats !== undefined) {
      await unlinkOwnedPath(tempPath, tempStats);
    }
  }
}

class NodeResultWriter implements ResultWriter {
  readonly runId: string;
  readonly #paths: CanonicalOutputPaths;
  readonly #config: ScanConfig;
  readonly #provenance: Provenance;
  readonly #handle: FileHandle;
  readonly #resultStats: Stats;
  readonly #completedDomains: Set<string>;
  readonly #accumulator: SummaryAccumulator;
  readonly #releasePath: () => void;
  #tail: Promise<void> = Promise.resolve();
  #failure: unknown;
  #accepting = true;
  #closed = false;

  constructor(options: {
    readonly runId: string;
    readonly paths: CanonicalOutputPaths;
    readonly config: ScanConfig;
    readonly provenance: Provenance;
    readonly handle: FileHandle;
    readonly resultStats: Stats;
    readonly completedDomains: Set<string>;
    readonly accumulator: SummaryAccumulator;
    readonly releasePath: () => void;
  }) {
    this.runId = options.runId;
    this.#paths = options.paths;
    this.#config = options.config;
    this.#provenance = options.provenance;
    this.#handle = options.handle;
    this.#resultStats = options.resultStats;
    this.#completedDomains = options.completedDomains;
    this.#accumulator = options.accumulator;
    this.#releasePath = options.releasePath;
  }

  get processedDomains(): number {
    return this.#completedDomains.size;
  }

  hasCompletedDomain(domain: string): boolean {
    return this.#completedDomains.has(domain);
  }

  append(result: DomainResult): Promise<void> {
    if (!this.#accepting || this.#closed) {
      return Promise.reject(writerError(
        "OUTPUT_WRITER_CLOSED",
        "The result writer is no longer accepting records.",
      ));
    }

    return this.#enqueue(async () => {
      let json: string;
      try {
        const serialized = JSON.stringify(result);
        if (serialized === undefined) {
          throw new TypeError("DomainResult is not JSON-serializable");
        }
        json = serialized;
      } catch {
        throw writerError(
          "OUTPUT_INVALID_RECORD",
          "The domain result could not be serialized.",
        );
      }

      const bytes = Buffer.from(`${json}\n`, "utf8");
      if (bytes.length > this.#config.limits.output.jsonlRecordBytes) {
        throw writerError(
          "OUTPUT_RECORD_LIMIT",
          "The serialized domain result exceeds the configured byte limit.",
        );
      }

      let value: unknown;
      try {
        value = JSON.parse(json) as unknown;
      } catch {
        throw writerError(
          "OUTPUT_INVALID_RECORD",
          "The serialized domain result is not valid JSON.",
        );
      }
      const persisted = validatePersisted(
        value,
        this.#config,
        this.#provenance,
      );
      ensureResultContext(
        persisted,
        this.runId,
        this.#config,
        this.#provenance,
      );
      if (this.#completedDomains.has(persisted.domain)) {
        throw writerError(
          "OUTPUT_DUPLICATE_DOMAIN",
          "The active run already contains this domain.",
        );
      }
      if (this.#completedDomains.size >= this.#config.limits.parquet.rows) {
        throw writerError(
          "OUTPUT_DOMAIN_LIMIT",
          "The active run exceeds the configured input row limit.",
        );
      }

      await writeAll(this.#handle, bytes);
      this.#accumulator.add(persisted);
      this.#completedDomains.add(persisted.domain);
    });
  }

  async finalize(inputDomains: number): Promise<RunSummary> {
    if (!this.#accepting || this.#closed) {
      throw writerError(
        "OUTPUT_WRITER_CLOSED",
        "The result writer cannot be finalized in its current state.",
      );
    }
    this.#accepting = false;

    try {
      let summary: RunSummary | undefined;
      await this.#enqueue(async () => {
        if (
          !Number.isSafeInteger(inputDomains)
          || inputDomains < 0
          || inputDomains !== this.#completedDomains.size
        ) {
          throw writerError(
            "OUTPUT_FINALIZE_MISMATCH",
            "The processed domain count does not match the validated input count.",
          );
        }

        summary = this.#accumulator.build(inputDomains);
        try {
          await this.#handle.sync();
        } catch (error) {
          throw writerError(
            "OUTPUT_IO_FAILED",
            "The result file could not be synchronized.",
            error,
          );
        }
        await verifyExistingRegularFile(
          this.#paths.resultPath,
          this.#resultStats,
        );
        await writeSummaryAtomically(
          this.#paths,
          summary,
        );
      });
      await this.#closeHandle();
      if (summary === undefined) {
        throw writerError(
          "OUTPUT_IO_FAILED",
          "The run summary was not materialized.",
        );
      }
      return summary;
    } catch (error) {
      await this.#closeHandle().catch(() => undefined);
      throw error;
    }
  }

  async close(): Promise<void> {
    this.#accepting = false;
    await this.#tail;
    await this.#closeHandle();
  }

  #enqueue(operation: () => Promise<void>): Promise<void> {
    const scheduled = this.#tail.then(async () => {
      if (this.#failure !== undefined) {
        throw this.#failure;
      }
      try {
        await operation();
      } catch (error) {
        this.#failure = error;
        throw error;
      }
    });
    this.#tail = scheduled.catch(() => undefined);
    return scheduled;
  }

  async #closeHandle(): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    try {
      await this.#handle.close();
    } catch (error) {
      throw writerError(
        "OUTPUT_IO_FAILED",
        "The result file could not be closed.",
        error,
      );
    } finally {
      this.#releasePath();
    }
  }
}

export async function openResultWriter(
  options: OpenResultWriterOptions,
): Promise<ResultWriter> {
  if (
    options.mode !== "create"
    && options.mode !== "resume"
    && options.mode !== "force"
  ) {
    throw writerError(
      "OUTPUT_INVALID_MODE",
      "The output mode must be create, resume, or force.",
    );
  }
  const config = JSON.parse(canonicalizeScanConfig(options.config)) as ScanConfig;
  const provenance: Provenance = {
    scannerVersion: options.provenance.scannerVersion,
    runtime: {
      node: options.provenance.runtime.node,
      playwright: options.provenance.runtime.playwright,
      chromiumRevision: options.provenance.runtime.chromiumRevision,
    },
    catalog: {
      source: options.provenance.catalog.source,
      revision: options.provenance.catalog.revision,
      digest: options.provenance.catalog.digest,
    },
    configDigest: options.provenance.configDigest,
  };
  if (computeConfigDigest(config) !== provenance.configDigest) {
    throw writerError(
      "OUTPUT_CONTEXT_MISMATCH",
      "The output provenance does not match the validated scan configuration.",
    );
  }

  const paths = await canonicalOutputPaths(options.resultPath);
  const resultInspection = await inspectTarget(paths.resultPath);
  const summaryInspection = await inspectTarget(paths.summaryPath, true);

  if (resultInspection.exists) {
    await verifyExistingRegularFile(paths.resultPath, resultInspection.stats!);
  }
  if (summaryInspection.exists) {
    await verifyExistingRegularFile(
      paths.summaryPath,
      summaryInspection.stats!,
      true,
    );
  }

  if (
    options.mode === "create"
    && (resultInspection.exists || summaryInspection.exists)
  ) {
    throw writerError(
      "OUTPUT_EXISTS",
      "A result or paired summary target already exists.",
    );
  }

  if (activeOutputDirectories.has(paths.parentIdentity)) {
    throw writerError(
      "OUTPUT_BUSY",
      "The output directory already has an active writer in this process.",
    );
  }
  activeOutputDirectories.add(paths.parentIdentity);
  let released = false;
  const releasePath = (): void => {
    if (!released) {
      released = true;
      activeOutputDirectories.delete(paths.parentIdentity);
    }
  };

  let handle: FileHandle | undefined;
  let createdResultStats: Stats | undefined;
  try {
    if (options.mode === "create") {
      ({ handle, stats: createdResultStats } = await createResult(paths.resultPath));
      const runId = randomUUID();
      return new NodeResultWriter({
        runId,
        paths,
        config,
        provenance,
        handle,
        resultStats: createdResultStats,
        completedDomains: new Set<string>(),
        releasePath,
        accumulator: createRunSummaryAccumulator({
          runId,
          config,
          provenance,
        }),
      });
    }

    if (options.mode === "resume") {
      if (!resultInspection.exists) {
        throw writerError(
          "OUTPUT_MISSING",
          "The result file does not exist.",
        );
      }
      handle = await openExistingResult(paths.resultPath, resultInspection.stats!);
      const state = await scanResumeFile(
        handle,
        config,
        provenance,
      );
      if (summaryInspection.exists) {
        await removeValidatedTarget(
          paths.summaryPath,
          summaryInspection.stats!,
        );
      }
      return new NodeResultWriter({
        ...state,
        paths,
        config,
        provenance,
        handle,
        resultStats: resultInspection.stats!,
        releasePath,
      });
    }

    if (resultInspection.exists) {
      handle = await openExistingResult(paths.resultPath, resultInspection.stats!);
    } else {
      ({ handle, stats: createdResultStats } = await createResult(paths.resultPath));
    }
    if (summaryInspection.exists) {
      await removeValidatedTarget(
        paths.summaryPath,
        summaryInspection.stats!,
      );
    }
    if (resultInspection.exists) {
      await handle.truncate(0);
    }
    const runId = randomUUID();
    return new NodeResultWriter({
      runId,
      paths,
      config,
      provenance,
      handle,
      resultStats: resultInspection.stats ?? createdResultStats!,
      completedDomains: new Set<string>(),
      releasePath,
      accumulator: createRunSummaryAccumulator({
        runId,
        config,
        provenance,
      }),
    });
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (createdResultStats !== undefined) {
      await unlinkOwnedPath(paths.resultPath, createdResultStats);
    }
    releasePath();
    if (error instanceof OutputWriterError) {
      throw error;
    }
    throw writerError(
      "OUTPUT_IO_FAILED",
      "The result writer could not be opened.",
      error,
    );
  }
}
