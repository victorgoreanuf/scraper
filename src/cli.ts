#!/usr/bin/env node

import { constants as fsConstants, readFileSync, realpathSync } from "node:fs";
import { open, realpath, stat } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import {
  computeConfigDigest,
  createDefaultScanConfig,
  parseScanConfig,
  type ScanConfig,
} from "./config.ts";
import {
  createBrowserPool,
  BrowserLifecycleFailure,
  type BrowserPool,
} from "./crawl/browser.ts";
import { createRobotsPolicyService, type RobotsPolicyService } from "./crawl/robots.ts";
import {
  createProtectedHttpTransport,
  type ProtectedHttpTransport,
} from "./crawl/transport.ts";
import {
  FingerprintCatalogError,
  loadFingerprintCatalog,
  type CompiledFingerprintCatalog,
} from "./detect/catalog.ts";
import {
  createDetectorPool,
  type DetectorPool,
} from "./detect/pool.ts";
import {
  createShadowEvaluationAccumulator,
  SHADOW_EVALUATION_DOMAIN_COUNT,
  SHADOW_EVALUATION_PROTOCOL_REVISION,
  SHADOW_EVALUATION_SCHEMA_VERSION,
  type ShadowEvaluationArtifact,
  type ShadowEvaluationSnapshot,
} from "./evaluation.ts";
import {
  assertShadowFrozenCandidateCompatibility,
  type ShadowFrozenCandidate,
} from "./evaluation-calibration.ts";
import {
  openParquetDomainsFromFile,
  ParquetInputError,
  type PreparedParquetDomains,
} from "./input/parquet.ts";
import type { Provenance, DomainResult } from "./model.ts";
import {
  EvaluationWriterError,
  preflightShadowEvaluationOutput,
  readPinnedShadowFrozenCandidate,
  writeShadowEvaluationArtifact,
  type PreparedShadowEvaluationOutput,
} from "./output/evaluation-writer.ts";
import {
  openResultWriter,
  OutputWriterError,
  resolveResultOutputPaths,
  type ResultOutputPaths,
  type ResultWriter,
  type ResultWriterMode,
} from "./output/writer.ts";
import {
  scanDomain,
  type ScanDomainContext,
  type ShadowDetectorPools,
} from "./pipeline.ts";

const DEFAULT_INPUT_PATH = "input/domains.parquet";
const DEFAULT_OUTPUT_PATH = "results.jsonl";
const CONFIG_FILE_BYTES = 1_048_576;
const PATH_CODE_UNITS = 4_096;
const VERSION_PATTERN = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const EMAIL_LOCAL = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/u;

interface ScannerMetadata {
  readonly version: string;
  readonly nodeVersion: string;
}

interface LoadedConfig {
  readonly config: ScanConfig;
  readonly sourcePath: string | null;
}

export type CliOptions =
  | { readonly kind: "help" }
  | { readonly kind: "version" }
  | {
      readonly kind: "run";
      readonly inputPath: string;
      readonly outputPath: string;
      readonly configPath: string | null;
      readonly contact: string | null;
      readonly mode: ResultWriterMode;
      readonly quiet: boolean;
      readonly shadowEvaluation: boolean;
      readonly shadowCandidatePath: string | null;
      readonly shadowCandidateDigest: string | null;
    };

export interface CliDependencies {
  readonly openInput: typeof openParquetDomainsFromFile;
  readonly loadFingerprintCatalog: typeof loadFingerprintCatalog;
  readonly createProtectedHttpTransport: typeof createProtectedHttpTransport;
  readonly createDetectorPool: typeof createDetectorPool;
  readonly createBrowserPool: typeof createBrowserPool;
  readonly createRobotsPolicyService: typeof createRobotsPolicyService;
  readonly openResultWriter: typeof openResultWriter;
  readonly resolveResultOutputPaths: typeof resolveResultOutputPaths;
  readonly preflightShadowEvaluationOutput: typeof preflightShadowEvaluationOutput;
  readonly readPinnedShadowFrozenCandidate: typeof readPinnedShadowFrozenCandidate;
  readonly writeShadowEvaluationArtifact: typeof writeShadowEvaluationArtifact;
  readonly scanDomain: typeof scanDomain;
}

export interface CliRunOptions {
  readonly dependencies?: CliDependencies | undefined;
  readonly signal?: AbortSignal | undefined;
  readonly stdout?: { write(text: string): unknown } | undefined;
  readonly stderr?: { write(text: string): unknown } | undefined;
}

class CliUsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CliUsageError";
  }
}

class CliStartupError extends Error {
  readonly code: string;

  constructor(code: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "CliStartupError";
    this.code = code;
  }
}

class CliTermination extends Error {
  readonly exitCode: 130 | 143;

  constructor(exitCode: 130 | 143) {
    super(exitCode === 130 ? "Interrupted" : "Terminated");
    this.name = "CliTermination";
    this.exitCode = exitCode;
  }
}

const productionDependencies: CliDependencies = Object.freeze({
  openInput: openParquetDomainsFromFile,
  loadFingerprintCatalog,
  createProtectedHttpTransport,
  createDetectorPool,
  createBrowserPool,
  createRobotsPolicyService,
  openResultWriter,
  resolveResultOutputPaths,
  preflightShadowEvaluationOutput,
  readPinnedShadowFrozenCandidate,
  writeShadowEvaluationArtifact,
  scanDomain,
});

function scannerMetadata(): ScannerMetadata {
  let value: unknown;
  try {
    value = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    ) as unknown;
  } catch {
    throw new CliStartupError(
      "CLI_RUNTIME_INVALID",
      "The scanner package metadata is unavailable.",
    );
  }
  if (
    typeof value !== "object"
    || value === null
    || !("version" in value)
    || typeof value.version !== "string"
    || !VERSION_PATTERN.test(value.version)
    || !("engines" in value)
    || typeof value.engines !== "object"
    || value.engines === null
    || !("node" in value.engines)
    || typeof value.engines.node !== "string"
    || !VERSION_PATTERN.test(value.engines.node)
  ) {
    throw new CliStartupError(
      "CLI_RUNTIME_INVALID",
      "The scanner package metadata is invalid.",
    );
  }
  return Object.freeze({
    version: value.version,
    nodeVersion: value.engines.node,
  });
}

function usage(): string {
  return [
    "Usage: website-technologies-scraper [options]",
    "",
    `  --input <path>       Parquet input (default: ${DEFAULT_INPUT_PATH})`,
    `  --output <path>      JSONL result (default: ${DEFAULT_OUTPUT_PATH})`,
    "  --contact <value>    Real https:// or mailto: crawler contact",
    "  --config <path>      Complete ScanConfig v1 JSON (instead of --contact)",
    "  --resume             Continue a compatible result file",
    "  --force              Replace a validated result file",
    "  --shadow-evaluation  Persist the fixed 200-domain shadow artifact",
    "  --shadow-candidate <path>",
    "                      Evaluate a frozen standalone shadow candidate",
    "  --shadow-candidate-digest <sha256:digest>",
    "                      Pin the exact frozen candidate file",
    "  --quiet              Suppress per-domain progress on stderr",
    "  --help                Show this help",
    "  --version             Show the scanner version",
    "",
  ].join("\n");
}

function validatedPath(value: string, label: string): string {
  if (
    value.length === 0
    || value.length > PATH_CODE_UNITS
    || !value.isWellFormed()
    || value.includes("\0")
  ) {
    throw new CliUsageError(`${label} must be a bounded filesystem path.`);
  }
  return value;
}

function canonicalContact(value: string): string {
  if (
    value.length === 0
    || value.length > 448
    || !value.isWellFormed()
    || /[\u0000-\u0020\u007f-\u009f]/u.test(value)
  ) {
    throw new CliUsageError("--contact must be a bounded https:// or mailto: value.");
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new CliUsageError("--contact must be a valid https:// or mailto: value.");
  }

  if (url.protocol === "https:") {
    if (
      url.username !== ""
      || url.password !== ""
      || url.port !== ""
      || url.search !== ""
      || url.hash !== ""
      || isIP(url.hostname) !== 0
    ) {
      throw new CliUsageError("--contact must be a credential-free HTTPS URL.");
    }
    const hostname = contactHostname(url.hostname);
    if (hostname === null) {
      throw new CliUsageError("--contact must contain a valid hostname.");
    }
    url.hostname = hostname;
    return url.href;
  }

  if (url.protocol === "mailto:") {
    if (url.search !== "" || url.hash !== "" || url.pathname.includes("%")) {
      throw new CliUsageError("--contact must be a simple mailto address.");
    }
    const separator = url.pathname.lastIndexOf("@");
    const local = url.pathname.slice(0, separator);
    const domain = url.pathname.slice(separator + 1);
    if (
      separator <= 0
      || domain.length === 0
      || local.includes("@")
      || !EMAIL_LOCAL.test(local)
      || local.startsWith(".")
      || local.endsWith(".")
      || local.includes("..")
    ) {
      throw new CliUsageError("--contact must be a simple mailto address.");
    }
    const hostname = contactHostname(domain);
    if (hostname === null) {
      throw new CliUsageError("--contact must contain a valid email domain.");
    }
    return `mailto:${local}@${hostname}`;
  }

  throw new CliUsageError("--contact must use https:// or mailto:.");
}

function contactHostname(value: string): string | null {
  const hostname = value.toLowerCase();
  if (
    hostname.length === 0
    || hostname.length > 253
    || hostname.endsWith(".")
    || !hostname.isWellFormed()
  ) {
    return null;
  }
  const labels = hostname.split(".");
  if (labels.length < 2) return null;
  for (const label of labels) {
    if (
      label.length === 0
      || label.length > 63
      || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label)
    ) {
      return null;
    }
  }
  return hostname;
}

export function parseCliArgs(argv: readonly string[]): CliOptions {
  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs({
      args: [...argv],
      allowPositionals: false,
      strict: true,
      tokens: true,
      options: {
        input: { type: "string" },
        output: { type: "string" },
        contact: { type: "string" },
        config: { type: "string" },
        resume: { type: "boolean" },
        force: { type: "boolean" },
        "shadow-evaluation": { type: "boolean" },
        "shadow-candidate": { type: "string" },
        "shadow-candidate-digest": { type: "string" },
        quiet: { type: "boolean" },
        help: { type: "boolean", short: "h" },
        version: { type: "boolean", short: "V" },
      },
    });
  } catch {
    throw new CliUsageError("The command-line arguments are invalid.");
  }

  const occurrences = new Map<string, number>();
  for (const token of parsed.tokens ?? []) {
    if (token.kind !== "option") continue;
    const count = (occurrences.get(token.name) ?? 0) + 1;
    occurrences.set(token.name, count);
    if (count > 1) {
      throw new CliUsageError(`--${token.name} may be provided only once.`);
    }
  }

  const help = parsed.values.help === true;
  const version = parsed.values.version === true;
  if (help && version) {
    throw new CliUsageError("--help and --version are mutually exclusive.");
  }
  if (help) return Object.freeze({ kind: "help" });
  if (version) return Object.freeze({ kind: "version" });

  const resume = parsed.values.resume === true;
  const force = parsed.values.force === true;
  if (resume && force) {
    throw new CliUsageError("--resume and --force are mutually exclusive.");
  }
  const shadowEvaluation = parsed.values["shadow-evaluation"] === true;
  if (shadowEvaluation && (resume || force)) {
    throw new CliUsageError(
      "--shadow-evaluation is available only for a fresh create run.",
    );
  }

  const shadowCandidateValue = typeof parsed.values["shadow-candidate"] === "string"
    ? parsed.values["shadow-candidate"]
    : undefined;
  const shadowCandidateDigestValue =
    typeof parsed.values["shadow-candidate-digest"] === "string"
      ? parsed.values["shadow-candidate-digest"]
      : undefined;
  if (
    (shadowCandidateValue === undefined)
    !== (shadowCandidateDigestValue === undefined)
  ) {
    throw new CliUsageError(
      "--shadow-candidate and --shadow-candidate-digest must be provided together.",
    );
  }
  if (shadowCandidateValue !== undefined && !shadowEvaluation) {
    throw new CliUsageError(
      "--shadow-candidate requires --shadow-evaluation.",
    );
  }
  if (
    shadowCandidateDigestValue !== undefined
    && !SHA256_DIGEST.test(shadowCandidateDigestValue)
  ) {
    throw new CliUsageError(
      "--shadow-candidate-digest must be sha256 followed by 64 lowercase hex digits.",
    );
  }

  const inputValue = typeof parsed.values.input === "string"
    ? parsed.values.input
    : undefined;
  const outputValue = typeof parsed.values.output === "string"
    ? parsed.values.output
    : undefined;
  const contactValue = typeof parsed.values.contact === "string"
    ? parsed.values.contact
    : undefined;
  const configValue = typeof parsed.values.config === "string"
    ? parsed.values.config
    : undefined;
  if ((contactValue === undefined) === (configValue === undefined)) {
    throw new CliUsageError("Provide exactly one of --contact or --config.");
  }

  return Object.freeze({
    kind: "run",
    inputPath: validatedPath(
      inputValue ?? DEFAULT_INPUT_PATH,
      "--input",
    ),
    outputPath: validatedPath(
      outputValue ?? DEFAULT_OUTPUT_PATH,
      "--output",
    ),
    configPath: configValue === undefined
      ? null
      : validatedPath(configValue, "--config"),
    contact: contactValue === undefined ? null : canonicalContact(contactValue),
    mode: resume ? "resume" : force ? "force" : "create",
    quiet: parsed.values.quiet === true,
    shadowEvaluation,
    shadowCandidatePath: shadowCandidateValue === undefined
      ? null
      : validatedPath(shadowCandidateValue, "--shadow-candidate"),
    shadowCandidateDigest: shadowCandidateDigestValue ?? null,
  });
}

async function readBoundedConfig(path: string): Promise<{ value: unknown; sourcePath: string }> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    const sourcePath = await realpath(path);
    handle = await open(
      sourcePath,
      fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
    );
    const descriptor = await handle.stat();
    if (!descriptor.isFile() || descriptor.size > CONFIG_FILE_BYTES) {
      throw new Error("invalid config target");
    }
    const bytes = Buffer.alloc(CONFIG_FILE_BYTES + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const result = await handle.read(bytes, offset, bytes.length - offset, null);
      if (result.bytesRead === 0) break;
      offset += result.bytesRead;
    }
    if (offset > CONFIG_FILE_BYTES) {
      throw new Error("config limit exceeded");
    }
    const text = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true,
    }).decode(bytes.subarray(0, offset));
    return { value: JSON.parse(text) as unknown, sourcePath };
  } catch {
    throw new CliStartupError(
      "CLI_CONFIG_INVALID",
      "The scan configuration file is unavailable or invalid.",
    );
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function loadConfig(
  options: Extract<CliOptions, { readonly kind: "run" }>,
  metadata: ScannerMetadata,
): Promise<LoadedConfig> {
  let config: ScanConfig;
  let sourcePath: string | null = null;
  if (options.contact !== null) {
    config = createDefaultScanConfig(
      `WebsiteTechScraper/${metadata.version} (${options.contact})`,
    );
  } else {
    const loaded = await readBoundedConfig(options.configPath!);
    sourcePath = loaded.sourcePath;
    try {
      config = parseScanConfig(loaded.value);
    } catch {
      throw new CliStartupError(
        "CLI_CONFIG_INVALID",
        "The scan configuration does not satisfy ScanConfig v1.",
      );
    }
  }
  const userAgentPrefix = `WebsiteTechScraper/${metadata.version} (`;
  if (
    !config.userAgent.startsWith(userAgentPrefix)
    || !config.userAgent.endsWith(")")
  ) {
    throw new CliStartupError(
      "CLI_CONFIG_INVALID",
      "The configured user agent does not match the scanner version.",
    );
  }
  const configuredContact = config.userAgent.slice(userAgentPrefix.length, -1);
  try {
    if (canonicalContact(configuredContact) !== configuredContact) {
      throw new Error("non-canonical contact");
    }
  } catch {
    throw new CliStartupError(
      "CLI_CONFIG_INVALID",
      "The configured user agent does not contain a canonical contact.",
    );
  }
  return Object.freeze({ config, sourcePath });
}

function sameIdentity(
  left: Awaited<ReturnType<typeof stat>>,
  right: Awaited<ReturnType<typeof stat>>,
): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

async function assertDistinctSources(
  input: PreparedParquetDomains,
  configPath: string | null,
  output: ResultOutputPaths,
  additionalSourcePaths: readonly string[] = [],
): Promise<void> {
  const sourcePaths = [
    input.sourcePath,
    ...(configPath === null ? [] : [configPath]),
    ...additionalSourcePaths,
  ];
  const targetPaths = [output.resultPath, output.summaryPath];
  for (const sourcePath of sourcePaths) {
    if (targetPaths.includes(sourcePath)) {
      throw new CliStartupError(
        "CLI_PATH_COLLISION",
        "An output target aliases an input file.",
      );
    }
  }
  const sourceStats = await Promise.all(sourcePaths.map(async (sourcePath) => ({
    sourcePath,
    stats: await stat(sourcePath),
  })));
  for (let left = 0; left < sourceStats.length; left += 1) {
    for (let right = left + 1; right < sourceStats.length; right += 1) {
      if (
        sourceStats[left]!.sourcePath === sourceStats[right]!.sourcePath
        || sameIdentity(sourceStats[left]!.stats, sourceStats[right]!.stats)
      ) {
        throw new CliStartupError(
          "CLI_PATH_COLLISION",
          "The shadow candidate must be distinct from every other input.",
        );
      }
    }
  }
  for (const source of sourceStats) {
    for (const targetPath of targetPaths) {
      try {
        const targetStats = await stat(targetPath);
        if (sameIdentity(source.stats, targetStats)) {
          throw new CliStartupError(
            "CLI_PATH_COLLISION",
            "An output target aliases an input file.",
          );
        }
      } catch (error) {
        if (error instanceof CliStartupError) throw error;
        if (
          typeof error !== "object"
          || error === null
          || !("code" in error)
          || error.code !== "ENOENT"
        ) {
          throw new CliStartupError(
            "CLI_PATH_INVALID",
            "An output target could not be inspected safely.",
          );
        }
      }
    }
  }
}

function provenanceFor(
  metadata: ScannerMetadata,
  config: ScanConfig,
  catalog: CompiledFingerprintCatalog,
  browserPool: BrowserPool,
): Provenance {
  return Object.freeze({
    scannerVersion: metadata.version,
    runtime: Object.freeze({
      node: process.versions.node,
      playwright: browserPool.runtime.playwright,
      chromiumRevision: browserPool.runtime.chromiumRevision,
    }),
    catalog: Object.freeze({
      source: catalog.source,
      revision: catalog.revision,
      digest: catalog.digest,
    }),
    configDigest: computeConfigDigest(config),
  });
}

function progressLine(completed: number, result: DomainResult): string {
  return `[PROGRESS] completed=${completed} domain=${result.domain} status=${result.status}\n`;
}

async function scheduleDomains(input: {
  readonly prepared: PreparedParquetDomains;
  readonly writer: ResultWriter;
  readonly context: ScanDomainContext;
  readonly concurrency: number;
  readonly signal: AbortSignal;
  readonly quiet: boolean;
  readonly stderr: (text: string) => void;
  readonly scan: typeof scanDomain;
  readonly onShadowSnapshot?: (
    snapshot: ShadowEvaluationSnapshot,
  ) => void | Promise<void>;
  readonly shadowDetectorPools?: ShadowDetectorPools;
}): Promise<void> {
  const active = new Set<Promise<void>>();
  const fatal = new AbortController();
  const signal = AbortSignal.any([input.signal, fatal.signal]);
  let firstFailure: unknown;
  let completed = input.writer.processedDomains;

  const start = (domain: string): void => {
    let task: Promise<void>;
    task = (async () => {
      const result = await input.scan(domain, input.context, {
        signal,
        ...(input.shadowDetectorPools === undefined
          ? {}
          : { shadowDetectorPools: input.shadowDetectorPools }),
        ...(input.onShadowSnapshot === undefined
          ? {}
          : { onShadowSnapshot: input.onShadowSnapshot }),
      });
      await input.writer.append(result);
      completed += 1;
      if (!input.quiet) input.stderr(progressLine(completed, result));
    })().catch((error: unknown) => {
      if (firstFailure === undefined) {
        firstFailure = error;
        fatal.abort(error);
      }
    }).finally(() => {
      active.delete(task);
    });
    active.add(task);
  };

  try {
    for await (const domain of input.prepared.domains()) {
      signal.throwIfAborted();
      if (input.writer.hasCompletedDomain(domain)) continue;
      while (active.size >= input.concurrency) {
        await Promise.race(active);
        if (firstFailure !== undefined) throw firstFailure;
        signal.throwIfAborted();
      }
      start(domain);
    }
    await Promise.all(active);
    if (firstFailure !== undefined) throw firstFailure;
    signal.throwIfAborted();
  } catch (error) {
    fatal.abort(error);
    await Promise.all(active);
    throw firstFailure ?? error;
  }
}

async function executeRun(
  options: Extract<CliOptions, { readonly kind: "run" }>,
  dependencies: CliDependencies,
  signal: AbortSignal,
  stderr: (text: string) => void,
): Promise<number> {
  const metadata = scannerMetadata();
  if (process.versions.node !== metadata.nodeVersion) {
    throw new CliStartupError(
      "CLI_RUNTIME_INVALID",
      `This scanner requires Node.js ${metadata.nodeVersion}.`,
    );
  }
  signal.throwIfAborted();
  const loaded = await loadConfig(options, metadata);
  signal.throwIfAborted();

  let prepared: PreparedParquetDomains | undefined;
  let detectorPool: DetectorPool | undefined;
  let shadowDetectorPoolT1: DetectorPool | undefined;
  let shadowDetectorPoolT2: DetectorPool | undefined;
  let browserPool: BrowserPool | undefined;
  let robots: RobotsPolicyService | undefined;
  let writer: ResultWriter | undefined;
  let preparedEvaluation: PreparedShadowEvaluationOutput | undefined;
  let frozenCandidate: ShadowFrozenCandidate | undefined;
  let frozenCandidateDigest: string | undefined;
  let frozenCandidateSourcePath: string | undefined;
  let pendingEvaluationArtifact: ShadowEvaluationArtifact | undefined;
  let finalized = false;
  let runFailure: unknown;
  let exitCode = 0;
  let completionLine: string | undefined;
  const degradedPools: Array<"detector" | "browser"> = [];

  try {
    prepared = await dependencies.openInput(options.inputPath, {
      limits: loaded.config.limits.parquet,
      hostnameCodeUnits: loaded.config.limits.hostname.inputCodeUnits,
    });
    signal.throwIfAborted();
    const outputPaths = await dependencies.resolveResultOutputPaths(options.outputPath);
    if (
      options.shadowCandidatePath !== null
      && options.shadowCandidateDigest !== null
    ) {
      const loadedCandidate = await dependencies.readPinnedShadowFrozenCandidate(
        options.shadowCandidatePath,
        options.shadowCandidateDigest,
      );
      if (
        loadedCandidate.candidate.trainingIdentity.domainSetDigest
          === prepared.domainSetDigest
      ) {
        throw new CliStartupError(
          "CLI_EVALUATION_CANDIDATE_INVALID",
          "The frozen shadow candidate requires a distinct evaluation cohort.",
        );
      }
      frozenCandidate = loadedCandidate.candidate;
      frozenCandidateDigest = loadedCandidate.digest;
      frozenCandidateSourcePath = loadedCandidate.sourcePath;
    }
    await assertDistinctSources(
      prepared,
      loaded.sourcePath,
      outputPaths,
      frozenCandidateSourcePath === undefined ? [] : [frozenCandidateSourcePath],
    );
    if (options.shadowEvaluation) {
      if (prepared.domainCount !== SHADOW_EVALUATION_DOMAIN_COUNT) {
        throw new CliStartupError(
          "CLI_EVALUATION_INPUT_INVALID",
          `--shadow-evaluation requires exactly ${SHADOW_EVALUATION_DOMAIN_COUNT} input domains.`,
        );
      }
      preparedEvaluation = await dependencies.preflightShadowEvaluationOutput({
        resultPath: outputPaths.resultPath,
        reservedPaths: [outputPaths.resultPath, outputPaths.summaryPath],
        sourcePaths: [
          prepared.sourcePath,
          ...(loaded.sourcePath === null ? [] : [loaded.sourcePath]),
          ...(frozenCandidateSourcePath === undefined
            ? []
            : [frozenCandidateSourcePath]),
        ],
      });
    }

    const catalog = dependencies.loadFingerprintCatalog(loaded.config);
    signal.throwIfAborted();
    if (frozenCandidate !== undefined) {
      try {
        frozenCandidate = assertShadowFrozenCandidateCompatibility(
          frozenCandidate,
          {
            schemaVersion: SHADOW_EVALUATION_SCHEMA_VERSION,
            protocolRevision: SHADOW_EVALUATION_PROTOCOL_REVISION,
            scannerVersion: metadata.version,
            catalog: Object.freeze({
              source: catalog.source,
              revision: catalog.revision,
              digest: catalog.digest,
            }),
            configDigest: computeConfigDigest(loaded.config),
          },
        );
      } catch (error) {
        throw new CliStartupError(
          "CLI_EVALUATION_CANDIDATE_INVALID",
          "The frozen shadow candidate is incompatible with this evaluation run.",
          { cause: error },
        );
      }
    }
    detectorPool = await dependencies.createDetectorPool(catalog, loaded.config);
    signal.throwIfAborted();
    if (options.shadowEvaluation) {
      shadowDetectorPoolT1 = await dependencies.createDetectorPool(
        catalog,
        loaded.config,
      );
      signal.throwIfAborted();
      shadowDetectorPoolT2 = await dependencies.createDetectorPool(
        catalog,
        loaded.config,
      );
      signal.throwIfAborted();
    }
    const transport: ProtectedHttpTransport =
      dependencies.createProtectedHttpTransport(loaded.config);
    browserPool = await dependencies.createBrowserPool(
      transport,
      loaded.config,
      undefined,
      signal,
    );
    signal.throwIfAborted();
    robots = dependencies.createRobotsPolicyService(loaded.config);
    const provenance = provenanceFor(metadata, loaded.config, catalog, browserPool);
    writer = await dependencies.openResultWriter({
      resultPath: outputPaths.resultPath,
      mode: options.mode,
      config: loaded.config,
      provenance,
      ...(options.mode === "resume"
        ? { resumeDomainAllowed: (domain: string) => prepared!.hasDomain(domain) }
        : {}),
    });
    const context: ScanDomainContext = Object.freeze({
      runId: writer.runId,
      config: loaded.config,
      provenance,
      transport,
      robots,
      browserPool,
      detectorPool,
      catalog,
    });
    const shadowAccumulator = options.shadowEvaluation
      ? createShadowEvaluationAccumulator({ runId: writer.runId, provenance })
      : undefined;
    await scheduleDomains({
      prepared,
      writer,
      context,
      concurrency: loaded.config.limits.concurrency.fullScans,
      signal,
      quiet: options.quiet,
      stderr,
      scan: dependencies.scanDomain,
      ...(shadowDetectorPoolT1 === undefined || shadowDetectorPoolT2 === undefined
        ? {}
        : {
            shadowDetectorPools: Object.freeze({
              t1: shadowDetectorPoolT1,
              t2: shadowDetectorPoolT2,
            }),
          }),
      ...(shadowAccumulator === undefined
        ? {}
        : {
            onShadowSnapshot: (snapshot: ShadowEvaluationSnapshot): void => {
              shadowAccumulator.add(snapshot);
            },
          }),
    });
    signal.throwIfAborted();
    if (
      shadowDetectorPoolT1 !== undefined
      && shadowDetectorPoolT2 !== undefined
      && (!shadowDetectorPoolT1.isAvailable()
        || !shadowDetectorPoolT2.isAvailable())
    ) {
      throw new CliStartupError(
        "CLI_EVALUATION_INVALID",
        "The isolated shadow detector pools became unavailable.",
      );
    }
    const summary = await writer.finalize(prepared.domainCount);
    finalized = true;
    signal.throwIfAborted();
    if (shadowAccumulator !== undefined) {
      pendingEvaluationArtifact = shadowAccumulator.build(prepared.domainCount);
    }
    if (!options.quiet) {
      completionLine = `[COMPLETE] processed=${summary.processedDomains} success=${summary.statusCounts.success} partial=${summary.statusCounts.partial} failed=${summary.statusCounts.failed}\n`;
    }
    if (!detectorPool.isAvailable()) degradedPools.push("detector");
    if (!browserPool.isAvailable()) degradedPools.push("browser");
    if (degradedPools.length > 0) {
      exitCode = 1;
    }
  } catch (error) {
    runFailure = error;
  } finally {
    await prepared?.close().catch((error: unknown) => {
      runFailure ??= error;
    });
    if (!finalized) {
      await writer?.close().catch((error: unknown) => {
        runFailure ??= error;
      });
    }
    try {
      robots?.clear();
    } catch (error) {
      runFailure ??= error;
    }
    const closed = await Promise.allSettled([
      browserPool?.close() ?? Promise.resolve(),
      detectorPool?.close() ?? Promise.resolve(),
      shadowDetectorPoolT1?.close() ?? Promise.resolve(),
      shadowDetectorPoolT2?.close() ?? Promise.resolve(),
    ]);
    for (const result of closed) {
      if (result.status === "rejected") runFailure ??= result.reason;
    }
  }

  if (runFailure !== undefined) throw runFailure;
  signal.throwIfAborted();
  if (pendingEvaluationArtifact !== undefined) {
    if (preparedEvaluation === undefined) {
      throw new CliStartupError(
        "CLI_EVALUATION_INVALID",
        "The shadow evaluation output was not prepared.",
      );
    }
    await dependencies.writeShadowEvaluationArtifact(
      preparedEvaluation,
      pendingEvaluationArtifact,
      frozenCandidate === undefined || frozenCandidateDigest === undefined
        ? undefined
        : {
            frozenCandidate,
            candidateDigest: frozenCandidateDigest,
          },
    );
    signal.throwIfAborted();
  }
  if (completionLine !== undefined) stderr(completionLine);
  if (degradedPools.length > 0) {
    stderr(`[CLI_DEGRADED] unavailable=${degradedPools.join(",")}\n`);
  }
  return exitCode;
}

function knownDiagnostic(error: unknown): { readonly code: string; readonly message: string } {
  if (
    error instanceof CliStartupError
    || error instanceof ParquetInputError
    || error instanceof FingerprintCatalogError
    || error instanceof OutputWriterError
    || error instanceof EvaluationWriterError
    || error instanceof BrowserLifecycleFailure
  ) {
    return { code: error.code, message: error.message };
  }
  return {
    code: "CLI_FAILED",
    message: "The scan run could not be completed.",
  };
}

export async function runCli(
  argv: readonly string[],
  options: CliRunOptions = {},
): Promise<number> {
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  let cliOptions: CliOptions;
  try {
    cliOptions = parseCliArgs(argv);
  } catch (error) {
    const message = error instanceof CliUsageError
      ? error.message
      : "The command-line arguments are invalid.";
    stderr.write(`[CLI_USAGE] ${message}\n${usage()}`);
    return 2;
  }

  if (cliOptions.kind === "help") {
    stdout.write(usage());
    return 0;
  }
  if (cliOptions.kind === "version") {
    try {
      stdout.write(`${scannerMetadata().version}\n`);
      return 0;
    } catch (error) {
      const diagnostic = knownDiagnostic(error);
      stderr.write(`[${diagnostic.code}] ${diagnostic.message}\n`);
      return 1;
    }
  }

  const signal = options.signal ?? new AbortController().signal;
  try {
    return await executeRun(
      cliOptions,
      options.dependencies ?? productionDependencies,
      signal,
      (text) => { stderr.write(text); },
    );
  } catch (error) {
    if (signal.aborted) {
      const reason = signal.reason;
      const exitCode = reason instanceof CliTermination ? reason.exitCode : 130;
      stderr.write(`[CLI_CANCELLED] The scan run was cancelled.\n`);
      return exitCode;
    }
    const diagnostic = knownDiagnostic(error);
    stderr.write(`[${diagnostic.code}] ${diagnostic.message}\n`);
    return 1;
  }
}

function isMainModule(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return resolve(entry) === fileURLToPath(import.meta.url);
  }
}

async function main(): Promise<void> {
  const controller = new AbortController();
  const onInterrupt = (): void => {
    process.off("SIGINT", onInterrupt);
    process.off("SIGTERM", onTerminate);
    controller.abort(new CliTermination(130));
  };
  const onTerminate = (): void => {
    process.off("SIGINT", onInterrupt);
    process.off("SIGTERM", onTerminate);
    controller.abort(new CliTermination(143));
  };
  process.once("SIGINT", onInterrupt);
  process.once("SIGTERM", onTerminate);
  try {
    process.exitCode = await runCli(process.argv.slice(2), {
      signal: controller.signal,
    });
  } finally {
    process.off("SIGINT", onInterrupt);
    process.off("SIGTERM", onTerminate);
  }
}

if (isMainModule()) {
  void main();
}
