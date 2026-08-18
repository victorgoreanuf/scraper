import type { ScanConfig } from "../config.ts";
import {
  type ErrorCode,
  type ErrorStage,
  type HttpProbeObservation,
  type HttpProbeResult,
  type HttpRobotsObservation,
  type ScanError,
} from "../model.ts";
import {
  type RobotsPolicyService,
  RobotsPolicyError,
} from "./robots.ts";
import {
  ProtectedTransportError,
  type ProtectedTransportSession,
} from "./transport.ts";

const DENIAL_STATUS_CODES = new Set([401, 403, 407, 451]);
const TRANSIENT_STATUS_CODES = new Set([408, 425, 429]);
const DOMAIN_DEADLINE_MESSAGE = "The active domain deadline was exceeded.";

export interface CollectCatalogProbesOptions {
  readonly config: ScanConfig;
  readonly session: ProtectedTransportSession;
  readonly robots: RobotsPolicyService;
  readonly probePaths: readonly string[];
  readonly callerSignal?: AbortSignal;
}

function compareString(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function scanError(
  stage: ErrorStage,
  code: ErrorCode,
  retryable: boolean,
  message: string,
): ScanError {
  return Object.freeze({
    stage,
    code,
    pageId: null,
    retryable,
    message,
    ruleId: null,
    signal: null,
    limit: null,
    catalogRevision: null,
  });
}

function observedError(
  error: ProtectedTransportError | RobotsPolicyError,
): ScanError {
  return scanError(error.stage, error.code, error.retryable, error.message);
}

function validateProbePaths(
  paths: readonly string[],
  config: ScanConfig,
): readonly string[] {
  if (paths.length > config.limits.pages.catalogProbesPerDomain) {
    throw new TypeError("Catalog probe plan exceeds the configured limit");
  }

  const unique = new Set<string>();
  const validated: string[] = [];
  for (const path of paths) {
    let resolved: URL;
    try {
      resolved = new URL(path, "https://catalog-probe.invalid/");
    } catch {
      throw new TypeError("Catalog probe plan contains an invalid path");
    }
    if (
      path.length === 0
      || path.length > config.limits.url.codeUnits
      || !path.startsWith("/")
      || path.startsWith("//")
      || path.includes("\\")
      || path.includes("?")
      || path.includes("#")
      || resolved.origin !== "https://catalog-probe.invalid"
      || resolved.pathname !== path
      || resolved.search !== ""
      || resolved.hash !== ""
      || unique.has(path)
    ) {
      throw new TypeError("Catalog probe plan contains an unsafe path");
    }
    unique.add(path);
    validated.push(path);
  }

  return Object.freeze(validated.sort(compareString));
}

function probeUrl(
  finalNetworkUrl: string,
  path: string,
  maximumCodeUnits: number,
): string | null {
  const final = new URL(finalNetworkUrl);
  if (
    (final.protocol !== "http:" && final.protocol !== "https:")
    || final.username !== ""
    || final.password !== ""
  ) {
    throw new TypeError("Final probe origin is not canonical HTTP(S)");
  }
  const resolved = new URL(path, `${final.origin}/`);
  if (
    resolved.origin !== final.origin
    || resolved.pathname !== path
    || resolved.search !== ""
    || resolved.hash !== ""
  ) {
    throw new TypeError("Catalog probe escaped the final origin");
  }
  return resolved.href.length <= maximumCodeUnits ? resolved.href : null;
}

function addRobotsObservation(
  observations: Map<string, HttpRobotsObservation>,
  observation: HttpRobotsObservation,
): void {
  observations.set(JSON.stringify([
    observation.ownerOrigin,
    observation.fetchedUrl,
    observation.text,
  ]), observation);
}

function stoppedByDomainDeadline(
  options: CollectCatalogProbesOptions,
  errors: ScanError[],
): boolean {
  options.callerSignal?.throwIfAborted();
  if (!options.session.getSignal().aborted) return false;
  if (!errors.some((error) => error.code === "DOMAIN_DEADLINE_EXCEEDED")) {
    errors.push(scanError(
      "http",
      "DOMAIN_DEADLINE_EXCEEDED",
      true,
      DOMAIN_DEADLINE_MESSAGE,
    ));
  }
  return true;
}

export async function collectCatalogProbes(
  finalNetworkUrl: string,
  options: CollectCatalogProbesOptions,
): Promise<HttpProbeResult> {
  const paths = validateProbePaths(options.probePaths, options.config);
  const observations: HttpProbeObservation[] = [];
  const robots = new Map<string, HttpRobotsObservation>();
  const errors: ScanError[] = [];

  for (const path of paths) {
    if (stoppedByDomainDeadline(options, errors)) break;
    const url = probeUrl(
      finalNetworkUrl,
      path,
      options.config.limits.url.codeUnits,
    );
    if (url === null) {
      errors.push(scanError(
        "http",
        "HTTP_LIMIT_EXCEEDED",
        false,
        "A catalog probe URL exceeded the configured limit.",
      ));
      break;
    }
    let check;
    try {
      check = await options.robots.check(options.session, url);
    } catch (error) {
      if (
        error instanceof ProtectedTransportError
        || error instanceof RobotsPolicyError
      ) {
        errors.push(observedError(error));
        break;
      }
      if (stoppedByDomainDeadline(options, errors)) break;
      throw error;
    }

    if (check.robotsText !== null) {
      addRobotsObservation(robots, Object.freeze({
        ownerOrigin: check.ownerOrigin,
        fetchedUrl: check.fetchedUrl,
        text: check.robotsText,
      }));
    }
    if (!check.allowed) {
      continue;
    }

    let response;
    try {
      response = await options.session.requestHop({
        url,
        purpose: "probe",
      });
    } catch (error) {
      if (error instanceof ProtectedTransportError) {
        errors.push(observedError(error));
        break;
      }
      if (stoppedByDomainDeadline(options, errors)) break;
      throw error;
    }

    if (response.statusCode < 200 || response.statusCode > 299) {
      if (DENIAL_STATUS_CODES.has(response.statusCode)) {
        errors.push(scanError(
          "http",
          "HTTP_REQUEST_FAILED",
          false,
          "A catalog probe was denied.",
        ));
        break;
      }
      if (
        TRANSIENT_STATUS_CODES.has(response.statusCode)
        || (response.statusCode >= 500 && response.statusCode <= 599)
      ) {
        errors.push(scanError(
          "http",
          "HTTP_REQUEST_FAILED",
          true,
          "A catalog probe received a transient response.",
        ));
        break;
      }
      continue;
    }

    const body = new TextDecoder("utf-8").decode(response.body);
    observations.push(Object.freeze({ path, body }));
  }

  stoppedByDomainDeadline(options, errors);

  return Object.freeze({
    observations: Object.freeze(observations),
    robots: Object.freeze([...robots.values()]),
    errors: Object.freeze(errors),
    completed: errors.length === 0,
  });
}
