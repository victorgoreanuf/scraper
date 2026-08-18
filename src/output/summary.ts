import {
  canonicalizeScanConfig,
  computeConfigDigest,
  type ScanConfig,
} from "../config.ts";
import {
  ERROR_STAGES,
  type DetectionStats,
  type DomainResult,
  type ErrorCode,
  type ErrorStage,
  type Provenance,
  type Usage,
} from "../model.ts";

export interface RunSummaryStatusCounts {
  readonly success: number;
  readonly partial: number;
  readonly failed: number;
}

export interface RunSummaryTechnologyCounts {
  readonly direct: number;
  readonly inferred: number;
  readonly total: number;
  readonly unique: number;
}

export interface RunSummaryDurationMs {
  readonly average: number;
  readonly p50: number;
  readonly p95: number;
  readonly p99: number;
}

export interface RunSummaryEvidenceAttribution {
  readonly directWithOnlyHttpEvidence: number;
  readonly directWithBrowserEvidence: number;
  readonly directWithProbeEvidence: number;
  readonly directWithInternalPageEvidence: number;
  readonly directWithScriptContentEvidence: number;
}

export interface RunSummaryErrorCount {
  readonly stage: ErrorStage;
  readonly code: ErrorCode;
  readonly count: number;
}

export interface RunSummary {
  readonly schemaVersion: 1;
  readonly runId: string;
  readonly scanMode: "full";
  readonly inputDomains: number;
  readonly processedDomains: number;
  readonly statusCounts: RunSummaryStatusCounts;
  readonly technologies: RunSummaryTechnologyCounts;
  readonly detectionStats: DetectionStats;
  readonly durationMs: RunSummaryDurationMs;
  readonly usage: Usage;
  readonly evidenceAttribution: RunSummaryEvidenceAttribution;
  readonly hardLimitHits: number;
  readonly errors: readonly RunSummaryErrorCount[];
  readonly provenance: Provenance;
  readonly config: ScanConfig;
}

export interface RunSummaryAccumulator {
  add(result: DomainResult): void;
  build(inputDomains: number): RunSummary;
}

export interface RunSummaryAccumulatorInput {
  readonly runId: string;
  readonly config: ScanConfig;
  readonly provenance: Provenance;
}

type MutableCounts<T> = {
  -readonly [Key in keyof T]: number;
};

const stageRank = new Map(
  ERROR_STAGES.map((stage, index) => [stage, index]),
);
const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function compareString(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }

  for (const nested of Object.values(value as Record<string, unknown>)) {
    deepFreeze(nested);
  }
  return Object.freeze(value);
}

function sameProvenance(left: Provenance, right: Provenance): boolean {
  return left.scannerVersion === right.scannerVersion
    && left.configDigest === right.configDigest
    && left.runtime.node === right.runtime.node
    && left.runtime.playwright === right.runtime.playwright
    && left.runtime.chromiumRevision === right.runtime.chromiumRevision
    && left.catalog.source === right.catalog.source
    && left.catalog.revision === right.catalog.revision
    && left.catalog.digest === right.catalog.digest;
}

function percentile(sorted: readonly number[], ratio: number): number {
  if (sorted.length === 0) {
    return 0;
  }
  return sorted[Math.ceil(ratio * sorted.length) - 1] ?? 0;
}

function isHardLimit(code: ErrorCode): boolean {
  return code.endsWith("_LIMIT_EXCEEDED")
    || code === "REGEX_DOMAIN_BUDGET_EXCEEDED"
    || code === "REGEX_EXECUTION_LIMIT";
}

function safeTotal(current: number, increment: number, label: string): number {
  const next = current + increment;
  if (
    !Number.isSafeInteger(current)
    || !Number.isSafeInteger(increment)
    || increment < 0
    || !Number.isSafeInteger(next)
  ) {
    throw new TypeError(`Run summary ${label} exceeds the safe integer range`);
  }
  return next;
}

function zeroUsage(): MutableCounts<Usage> {
  return {
    httpRequests: 0,
    browserRequests: 0,
    retries: 0,
    pagesVisited: 0,
    probesIssued: 0,
    scriptBodiesInspected: 0,
    staticTransferredBytes: 0,
    browserTransferredBytes: 0,
  };
}

function zeroDetectionStats(): MutableCounts<DetectionStats> {
  return {
    rawDirect: 0,
    gatedDirect: 0,
    suppressedDirect: 0,
    retainedDirect: 0,
  };
}

function zeroAttribution(): MutableCounts<RunSummaryEvidenceAttribution> {
  return {
    directWithOnlyHttpEvidence: 0,
    directWithBrowserEvidence: 0,
    directWithProbeEvidence: 0,
    directWithInternalPageEvidence: 0,
    directWithScriptContentEvidence: 0,
  };
}

export function createRunSummaryAccumulator(
  input: RunSummaryAccumulatorInput,
): RunSummaryAccumulator {
  const runId = input.runId;
  if (!RUN_ID.test(runId)) {
    throw new TypeError("Run summary runId must be a canonical UUID v4");
  }
  const config = deepFreeze(
    JSON.parse(canonicalizeScanConfig(input.config)) as ScanConfig,
  );
  const provenance = deepFreeze({
    scannerVersion: input.provenance.scannerVersion,
    runtime: {
      node: input.provenance.runtime.node,
      playwright: input.provenance.runtime.playwright,
      chromiumRevision: input.provenance.runtime.chromiumRevision,
    },
    catalog: {
      source: input.provenance.catalog.source,
      revision: input.provenance.catalog.revision,
      digest: input.provenance.catalog.digest,
    },
    configDigest: input.provenance.configDigest,
  } satisfies Provenance);
  if (provenance.configDigest !== computeConfigDigest(config)) {
    throw new TypeError(
      "Run summary provenance does not match the validated configuration",
    );
  }

  const domains = new Set<string>();
  const technologyNames = new Set<string>();
  const durations: number[] = [];
  const statusCounts = { success: 0, partial: 0, failed: 0 };
  const technologies = { direct: 0, inferred: 0, total: 0 };
  const detectionStats = zeroDetectionStats();
  const usage = zeroUsage();
  const attribution = zeroAttribution();
  const errorCounts = new Map<string, RunSummaryErrorCount>();
  let hardLimitHits = 0;
  let durationTotal = 0;

  const add = (result: DomainResult): void => {
    if (
      result.schemaVersion !== 1
      || result.runId !== runId
      || result.scanMode !== "full"
      || !sameProvenance(result.provenance, provenance)
    ) {
      throw new TypeError("Domain result does not match the run summary context");
    }
    if (domains.has(result.domain)) {
      throw new TypeError(`Domain ${result.domain} was already summarized`);
    }
    if (domains.size >= config.limits.parquet.rows) {
      throw new TypeError("Run summary exceeds the configured input row limit");
    }

    const technologyDelta = { direct: 0, inferred: 0, total: 0 };
    const attributionDelta = zeroAttribution();
    const errorDelta = new Map<string, RunSummaryErrorCount>();
    let hardLimitDelta = 0;

    for (const technology of result.technologies) {
      technologyDelta[technology.type] += 1;
      technologyDelta.total += 1;

      if (technology.type !== "direct") {
        continue;
      }
      if (technology.evidence.every((evidence) => evidence.collector === "http")) {
        attributionDelta.directWithOnlyHttpEvidence += 1;
      }
      if (technology.evidence.some((evidence) => evidence.collector === "browser")) {
        attributionDelta.directWithBrowserEvidence += 1;
      }
      if (technology.evidence.some((evidence) => evidence.source === "probe")) {
        attributionDelta.directWithProbeEvidence += 1;
      }
      if (technology.evidence.some((evidence) =>
        evidence.pageId === "p2" || evidence.pageId === "p3")) {
        attributionDelta.directWithInternalPageEvidence += 1;
      }
      if (technology.evidence.some((evidence) =>
        evidence.source === "script_content")) {
        attributionDelta.directWithScriptContentEvidence += 1;
      }
    }

    for (const error of result.errors) {
      if (isHardLimit(error.code)) {
        hardLimitDelta += 1;
      }
      const key = `${error.stage}\u0000${error.code}`;
      const previous = errorDelta.get(key);
      errorDelta.set(key, {
        stage: error.stage,
        code: error.code,
        count: (previous?.count ?? 0) + 1,
      });
    }

    const nextStatus = safeTotal(statusCounts[result.status], 1, "status count");
    const nextDurationTotal = safeTotal(
      durationTotal,
      result.timings.totalMs,
      "duration total",
    );
    const nextDetectionStats = {
      rawDirect: safeTotal(
        detectionStats.rawDirect,
        result.detectionStats.rawDirect,
        "raw direct count",
      ),
      gatedDirect: safeTotal(
        detectionStats.gatedDirect,
        result.detectionStats.gatedDirect,
        "gated direct count",
      ),
      suppressedDirect: safeTotal(
        detectionStats.suppressedDirect,
        result.detectionStats.suppressedDirect,
        "suppressed direct count",
      ),
      retainedDirect: safeTotal(
        detectionStats.retainedDirect,
        result.detectionStats.retainedDirect,
        "retained direct count",
      ),
    };
    const nextUsage = {
      httpRequests: safeTotal(usage.httpRequests, result.usage.httpRequests, "HTTP requests"),
      browserRequests: safeTotal(
        usage.browserRequests,
        result.usage.browserRequests,
        "browser requests",
      ),
      retries: safeTotal(usage.retries, result.usage.retries, "retries"),
      pagesVisited: safeTotal(
        usage.pagesVisited,
        result.usage.pagesVisited,
        "visited pages",
      ),
      probesIssued: safeTotal(
        usage.probesIssued,
        result.usage.probesIssued,
        "issued probes",
      ),
      scriptBodiesInspected: safeTotal(
        usage.scriptBodiesInspected,
        result.usage.scriptBodiesInspected,
        "inspected script bodies",
      ),
      staticTransferredBytes: safeTotal(
        usage.staticTransferredBytes,
        result.usage.staticTransferredBytes,
        "static transferred bytes",
      ),
      browserTransferredBytes: safeTotal(
        usage.browserTransferredBytes,
        result.usage.browserTransferredBytes,
        "browser transferred bytes",
      ),
    };
    const nextTechnologies = {
      direct: safeTotal(technologies.direct, technologyDelta.direct, "direct technologies"),
      inferred: safeTotal(
        technologies.inferred,
        technologyDelta.inferred,
        "inferred technologies",
      ),
      total: safeTotal(technologies.total, technologyDelta.total, "technologies"),
    };
    const nextAttribution = {
      directWithOnlyHttpEvidence: safeTotal(
        attribution.directWithOnlyHttpEvidence,
        attributionDelta.directWithOnlyHttpEvidence,
        "HTTP-only attribution",
      ),
      directWithBrowserEvidence: safeTotal(
        attribution.directWithBrowserEvidence,
        attributionDelta.directWithBrowserEvidence,
        "browser attribution",
      ),
      directWithProbeEvidence: safeTotal(
        attribution.directWithProbeEvidence,
        attributionDelta.directWithProbeEvidence,
        "probe attribution",
      ),
      directWithInternalPageEvidence: safeTotal(
        attribution.directWithInternalPageEvidence,
        attributionDelta.directWithInternalPageEvidence,
        "internal-page attribution",
      ),
      directWithScriptContentEvidence: safeTotal(
        attribution.directWithScriptContentEvidence,
        attributionDelta.directWithScriptContentEvidence,
        "script-content attribution",
      ),
    };
    const nextHardLimitHits = safeTotal(
      hardLimitHits,
      hardLimitDelta,
      "hard-limit hits",
    );
    const nextErrors = [...errorDelta].map(([key, delta]) => ({
      key,
      value: {
        ...delta,
        count: safeTotal(
          errorCounts.get(key)?.count ?? 0,
          delta.count,
          "grouped error count",
        ),
      },
    }));

    statusCounts[result.status] = nextStatus;
    durations.push(result.timings.totalMs);
    durationTotal = nextDurationTotal;
    Object.assign(detectionStats, nextDetectionStats);
    Object.assign(usage, nextUsage);
    Object.assign(technologies, nextTechnologies);
    Object.assign(attribution, nextAttribution);
    hardLimitHits = nextHardLimitHits;
    for (const technology of result.technologies) {
      technologyNames.add(technology.name);
    }
    for (const error of nextErrors) {
      errorCounts.set(error.key, error.value);
    }

    domains.add(result.domain);
  };

  const build = (inputDomains: number): RunSummary => {
    if (!Number.isSafeInteger(inputDomains) || inputDomains < 0) {
      throw new TypeError("Summary inputDomains must be a non-negative safe integer");
    }
    if (inputDomains > config.limits.parquet.rows) {
      throw new TypeError("Summary inputDomains exceeds the configured input row limit");
    }
    if (inputDomains < domains.size) {
      throw new TypeError("Summary inputDomains is lower than processedDomains");
    }

    const orderedDurations = durations.slice().sort((left, right) => left - right);
    const processedDomains = domains.size;
    const errors = [...errorCounts.values()].sort((left, right) =>
      (stageRank.get(left.stage) ?? Number.MAX_SAFE_INTEGER)
        - (stageRank.get(right.stage) ?? Number.MAX_SAFE_INTEGER)
      || compareString(left.code, right.code));

    return deepFreeze({
      schemaVersion: 1 as const,
      runId,
      scanMode: "full" as const,
      inputDomains,
      processedDomains,
      statusCounts: { ...statusCounts },
      technologies: {
        ...technologies,
        unique: technologyNames.size,
      },
      detectionStats: { ...detectionStats },
      durationMs: {
        average: processedDomains === 0
          ? 0
          : Math.round((durationTotal / processedDomains) * 1_000) / 1_000,
        p50: percentile(orderedDurations, 0.5),
        p95: percentile(orderedDurations, 0.95),
        p99: percentile(orderedDurations, 0.99),
      },
      usage: { ...usage },
      evidenceAttribution: { ...attribution },
      hardLimitHits,
      errors: errors.map((error) => ({ ...error })),
      provenance,
      config,
    });
  };

  return Object.freeze({ add, build });
}
