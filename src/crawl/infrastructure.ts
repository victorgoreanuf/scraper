import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";

import type { ScanConfig } from "../config.ts";
import {
  DNS_RECORD_TYPES,
  type CatalogInspectionPlan,
  type DnsRecordObservation,
  type DnsRecordType,
  type ErrorCode,
  type HttpEntryResult,
  type HttpResponseObservations,
  type InfrastructureResult,
  type ScanError,
} from "../model.ts";
import {
  TargetPolicyError,
  normalizeHostname,
  validateAddressAnswers,
} from "../network-policy.ts";
import type { ProtectedTransportSession } from "./transport.ts";

export interface CollectInfrastructureOptions {
  readonly config: ScanConfig;
  readonly session: ProtectedTransportSession;
  readonly inspectionPlan: CatalogInspectionPlan;
  readonly httpResult: HttpEntryResult;
}

const DNS_TIMEOUT = Symbol("dns-timeout");
const NO_DATA_CODES = new Set(["ENODATA", "ENOTFOUND"]);
const DNS_MESSAGES = Object.freeze({
  DNS_LOOKUP_FAILED: "An infrastructure DNS query failed.",
  DNS_LIMIT_EXCEEDED: "Infrastructure DNS observations exceeded a safety limit.",
  SSRF_NON_PUBLIC_ADDRESS: "An infrastructure DNS answer was not public.",
  SSRF_MIXED_ADDRESSES:
    "Infrastructure DNS answers mixed public and non-public addresses.",
  DOMAIN_DEADLINE_EXCEEDED: "The active domain deadline was exceeded.",
  TLS_CONNECTION_FAILED: "The verified TLS response metadata was invalid.",
  TLS_LIMIT_EXCEEDED: "The TLS issuer exceeded a safety limit.",
} as const);

type InfrastructureErrorCode = keyof typeof DNS_MESSAGES;

interface QueryResult {
  readonly type: DnsRecordType;
  readonly status: "fulfilled" | "rejected";
  readonly value?: unknown;
  readonly reason?: unknown;
}

function errorCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("code" in error)) {
    return undefined;
  }
  return typeof error.code === "string" ? error.code : undefined;
}

function scanError(
  stage: "dns" | "tls",
  code: InfrastructureErrorCode,
  retryable: boolean,
): ScanError {
  return Object.freeze({
    stage,
    code: code as ErrorCode,
    pageId: null,
    retryable,
    message: DNS_MESSAGES[code],
    ruleId: null,
    signal: null,
    limit: null,
    catalogRevision: null,
  });
}

function addError(errors: ScanError[], error: ScanError): void {
  if (!errors.some((item) =>
    item.stage === error.stage
    && item.code === error.code
    && item.retryable === error.retryable
    && item.limit === error.limit)) {
    errors.push(error);
  }
}

function elapsedMilliseconds(startedAt: number): number {
  return Math.max(0, Math.ceil(performance.now() - startedAt));
}

function compareRecord(
  left: DnsRecordObservation,
  right: DnsRecordObservation,
): number {
  const leftRank = DNS_RECORD_TYPES.indexOf(left.type);
  const rightRank = DNS_RECORD_TYPES.indexOf(right.type);
  return leftRank - rightRank
    || (left.value < right.value ? -1 : left.value > right.value ? 1 : 0);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isDnsInteger(value: unknown, maximum = 0xffff_ffff): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0
    && (value as number) <= maximum;
}

function normalizeRecordHostname(value: unknown): string {
  if (typeof value !== "string") {
    throw new TypeError("DNS hostname answer is not a string");
  }
  return normalizeHostname(value, 253);
}

function canonicalIpAddress(value: string, family: 4 | 6): string {
  if (isIP(value) !== family) {
    throw new TypeError("DNS address answer is invalid");
  }
  const hostname = family === 4
    ? new URL(`http://${value}/`).hostname
    : new URL(`http://[${value}]/`).hostname.slice(1, -1);
  if (isIP(hostname) !== family) {
    throw new TypeError("DNS address answer is invalid");
  }
  return hostname;
}

function asArray(value: unknown): readonly unknown[] {
  if (!Array.isArray(value)) {
    throw new TypeError("DNS answer is not an array");
  }
  return value;
}

function rawRecordCount(type: DnsRecordType, value: unknown): number {
  return type === "SOA" ? 1 : asArray(value).length;
}

function normalizeNonAddressRecords(
  type: Exclude<DnsRecordType, "A" | "AAAA">,
  raw: unknown,
  config: ScanConfig,
): readonly string[] {
  if (type === "SOA") {
    if (
      !isRecord(raw)
      || typeof raw.nsname !== "string"
      || typeof raw.hostmaster !== "string"
      || !isDnsInteger(raw.serial)
      || !isDnsInteger(raw.refresh)
      || !isDnsInteger(raw.retry)
      || !isDnsInteger(raw.expire)
      || !isDnsInteger(raw.minttl)
    ) {
      throw new TypeError("SOA answer is malformed");
    }
    return [normalizeRecordHostname(raw.nsname)];
  }

  const answers = asArray(raw);
  if (type === "CNAME" || type === "NS" || type === "PTR") {
    return answers.map(normalizeRecordHostname);
  }
  if (type === "MX") {
    return answers.map((answer) => {
      if (
        !isRecord(answer)
        || !isDnsInteger(answer.priority, 0xffff)
        || typeof answer.exchange !== "string"
      ) {
        throw new TypeError("MX answer is malformed");
      }
      return normalizeRecordHostname(answer.exchange);
    });
  }
  if (type === "SRV") {
    return answers.map((answer) => {
      if (
        !isRecord(answer)
        || typeof answer.name !== "string"
        || !isDnsInteger(answer.port, 0xffff)
        || !isDnsInteger(answer.priority, 0xffff)
        || !isDnsInteger(answer.weight, 0xffff)
      ) {
        throw new TypeError("SRV answer is malformed");
      }
      return normalizeRecordHostname(answer.name);
    });
  }
  if (type === "CAA") {
    return answers.map((answer) => {
      if (!isRecord(answer) || !isDnsInteger(answer.critical, 0xff)) {
        throw new TypeError("CAA answer is malformed");
      }
      const values = ["issue", "issuewild", "iodef"]
        .filter((property) => Object.hasOwn(answer, property))
        .map((property) => answer[property]);
      if (
        values.length !== 1
        || typeof values[0] !== "string"
        || !values[0].isWellFormed()
      ) {
        throw new TypeError("CAA answer is malformed");
      }
      return values[0];
    });
  }

  return answers.map((answer) => {
    if (!Array.isArray(answer) || !answer.every((chunk) =>
      typeof chunk === "string" && chunk.isWellFormed())) {
      throw new TypeError("TXT answer is malformed");
    }
    const value = answer.join("");
    if (Buffer.byteLength(value, "utf8") > config.limits.dns.txtItemBytes) {
      throw new RangeError("TXT answer exceeds its item budget");
    }
    return value;
  });
}

function queryResolver(
  resolver: Resolver,
  domain: string,
  type: DnsRecordType,
): Promise<unknown> {
  return resolver.resolve(domain, type);
}

function settleQueries(
  resolver: Resolver,
  domain: string,
  types: readonly DnsRecordType[],
  settled: QueryResult[],
): Promise<void> {
  return Promise.all(types.map(async (type): Promise<void> => {
    try {
      settled.push({ type, status: "fulfilled", value: await queryResolver(
        resolver,
        domain,
        type,
      ) });
    } catch (reason) {
      settled.push({ type, status: "rejected", reason });
    }
  })).then(() => undefined);
}

function waitForQueries(
  operation: Promise<void>,
  signal: AbortSignal,
): Promise<void> {
  if (signal.aborted) {
    return Promise.reject(signal.reason);
  }
  return new Promise((resolve, reject) => {
    const onAbort = (): void => {
      reject(signal.reason);
    };
    signal.addEventListener("abort", onAbort, { once: true });
    void operation.then(
      () => {
        signal.removeEventListener("abort", onAbort);
        resolve();
      },
      (error) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

function targetPolicyError(error: TargetPolicyError): ScanError {
  if (error.code === "SSRF_NON_PUBLIC_ADDRESS") {
    return scanError("dns", "SSRF_NON_PUBLIC_ADDRESS", false);
  }
  if (error.code === "SSRF_MIXED_ADDRESSES") {
    return scanError("dns", "SSRF_MIXED_ADDRESSES", false);
  }
  if (error.code === "DNS_LIMIT_EXCEEDED") {
    return scanError("dns", "DNS_LIMIT_EXCEEDED", false);
  }
  return scanError("dns", "DNS_LOOKUP_FAILED", false);
}

async function collectDns(
  domain: string,
  types: readonly DnsRecordType[],
  config: ScanConfig,
  session: ProtectedTransportSession,
): Promise<{
  readonly records: readonly DnsRecordObservation[];
  readonly errors: readonly ScanError[];
  readonly dnsMs: number;
}> {
  const startedAt = performance.now();
  const errors: ScanError[] = [];
  let canonicalDomain: string;
  try {
    canonicalDomain = normalizeHostname(domain, config.limits.url.codeUnits);
  } catch {
    return {
      records: Object.freeze([]),
      errors: Object.freeze([scanError("dns", "DNS_LOOKUP_FAILED", false)]),
      dnsMs: elapsedMilliseconds(startedAt),
    };
  }

  if (session.getSignal().aborted) {
    return {
      records: Object.freeze([]),
      errors: Object.freeze([
        scanError("dns", "DOMAIN_DEADLINE_EXCEEDED", true),
      ]),
      dnsMs: elapsedMilliseconds(startedAt),
    };
  }

  const timeoutController = new AbortController();
  const timeoutTimer = setTimeout(
    () => timeoutController.abort(DNS_TIMEOUT),
    config.limits.timeMs.dnsLookup,
  );
  const signal = AbortSignal.any([session.getSignal(), timeoutController.signal]);
  const resolver = new Resolver({
    timeout: config.limits.timeMs.dnsLookup,
    tries: 1,
    maxTimeout: config.limits.timeMs.dnsLookup,
  });
  const onAbort = (): void => {
    try {
      resolver.cancel();
    } catch {
      // Resolver cancellation is best effort after the stage has already failed.
    }
  };
  signal.addEventListener("abort", onAbort, { once: true });

  const settledResults: QueryResult[] = [];
  let interrupted = false;
  try {
    const operation = settleQueries(
      resolver,
      canonicalDomain,
      types,
      settledResults,
    );
    await waitForQueries(operation, signal);
  } catch {
    interrupted = true;
    addError(
      errors,
      session.getSignal().aborted
        ? scanError("dns", "DOMAIN_DEADLINE_EXCEEDED", true)
        : scanError("dns", "DNS_LOOKUP_FAILED", true),
    );
  } finally {
    clearTimeout(timeoutTimer);
    signal.removeEventListener("abort", onAbort);
    try {
      resolver.cancel();
    } catch {
      // Resolver cleanup is best effort after all query promises have settled.
    }
  }
  const results = [...settledResults];

  const normalized: DnsRecordObservation[] = [];
  const addressAnswers: Array<{ readonly address: string; readonly family: 4 | 6 }> = [];
  let addressFailed = false;
  let rawRecords = 0;
  let stopForTotalLimit = false;

  for (const type of types) {
    if (stopForTotalLimit) break;
    const result = results.find((item) => item.type === type);
    if (result === undefined) {
      if (!interrupted) {
        addError(errors, scanError("dns", "DNS_LOOKUP_FAILED", false));
      }
      continue;
    }
    if (result.status === "rejected") {
      const code = errorCode(result.reason) ?? "";
      if (interrupted && code === "ECANCELLED") {
        continue;
      }
      if (!NO_DATA_CODES.has(code)) {
        addError(errors, scanError("dns", "DNS_LOOKUP_FAILED", true));
        if (type === "A" || type === "AAAA") addressFailed = true;
      }
      continue;
    }

    try {
      const count = rawRecordCount(type, result.value);
      if (count > config.limits.dns.recordsPerType) {
        addError(errors, scanError("dns", "DNS_LIMIT_EXCEEDED", false));
        if (type === "A" || type === "AAAA") addressFailed = true;
        continue;
      }
      if (rawRecords + count > config.limits.dns.recordsPerDomain) {
        addError(errors, scanError("dns", "DNS_LIMIT_EXCEEDED", false));
        stopForTotalLimit = true;
        continue;
      }
      rawRecords += count;

      if (type === "A" || type === "AAAA") {
        for (const answer of asArray(result.value)) {
          if (typeof answer !== "string") {
            throw new TypeError("Address answer is malformed");
          }
          addressAnswers.push({ address: answer, family: type === "A" ? 4 : 6 });
        }
      } else {
        for (const value of normalizeNonAddressRecords(type, result.value, config)) {
          normalized.push({ type, value });
        }
      }
    } catch (error) {
      if (error instanceof RangeError && type === "TXT") {
        addError(errors, scanError("dns", "DNS_LIMIT_EXCEEDED", false));
      } else {
        addError(errors, scanError("dns", "DNS_LOOKUP_FAILED", false));
      }
      if (type === "A" || type === "AAAA") addressFailed = true;
    }
  }

  if (!addressFailed && addressAnswers.length > 0) {
    try {
      for (const answer of validateAddressAnswers(
        addressAnswers,
        Math.min(128, config.limits.dns.recordsPerDomain),
      )) {
        normalized.push({
          type: answer.family === 4 ? "A" : "AAAA",
          value: canonicalIpAddress(answer.address, answer.family),
        });
      }
    } catch (error) {
      addError(
        errors,
        error instanceof TargetPolicyError
          ? targetPolicyError(error)
          : scanError("dns", "DNS_LOOKUP_FAILED", false),
      );
    }
  }

  const unique = new Map<string, DnsRecordObservation>();
  for (const record of normalized.sort(compareRecord)) {
    unique.set(`${record.type}\0${record.value}`, Object.freeze(record));
  }

  try {
    const admission = session.admitDnsRecords([...unique.values()]);
    if (admission.limitExceeded) {
      addError(errors, scanError("dns", "DNS_LIMIT_EXCEEDED", false));
    }
    return {
      records: admission.records,
      errors: Object.freeze(errors),
      dnsMs: elapsedMilliseconds(startedAt),
    };
  } catch {
    addError(
      errors,
      session.getSignal().aborted
        ? scanError("dns", "DOMAIN_DEADLINE_EXCEEDED", true)
        : scanError("dns", "DNS_LOOKUP_FAILED", false),
    );
    return {
      records: Object.freeze([]),
      errors: Object.freeze(errors),
      dnsMs: elapsedMilliseconds(startedAt),
    };
  }
}

function responseFromHttpResult(
  result: HttpEntryResult,
): HttpResponseObservations | null {
  return result.kind === "html" ? result.page.response : result.response;
}

function collectTls(
  httpResult: HttpEntryResult,
  config: ScanConfig,
): {
  readonly issuer: string | null;
  readonly error: ScanError | null;
  readonly tlsMs: number | null;
} {
  const response = responseFromHttpResult(httpResult);
  if (response === null) return { issuer: null, error: null, tlsMs: null };

  let finalUrl: URL;
  try {
    finalUrl = new URL(response.finalNetworkUrl);
  } catch {
    return { issuer: null, error: null, tlsMs: null };
  }
  if (
    finalUrl.protocol !== "https:"
    || response.tlsIssuer === null
    || response.tlsIssuer.length === 0
  ) {
    return { issuer: null, error: null, tlsMs: null };
  }
  const issuer = response.tlsIssuer;
  const tlsMs = response.tlsHandshakeMs !== null
      && Number.isSafeInteger(response.tlsHandshakeMs)
      && response.tlsHandshakeMs >= 0
    ? response.tlsHandshakeMs
    : null;
  if (tlsMs === null) {
    return {
      issuer: null,
      error: scanError("tls", "TLS_CONNECTION_FAILED", false),
      tlsMs: null,
    };
  }
  if (
    !issuer.isWellFormed()
    || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(issuer)
    || Buffer.byteLength(issuer, "utf8") > config.limits.tls.issuerBytes
  ) {
    return {
      issuer: null,
      error: scanError(
        "tls",
        "TLS_LIMIT_EXCEEDED",
        false,
      ),
      tlsMs,
    };
  }
  return { issuer, error: null, tlsMs };
}

export async function collectInfrastructure(
  domain: string,
  options: CollectInfrastructureOptions,
): Promise<InfrastructureResult> {
  const requestedTypes = DNS_RECORD_TYPES.filter((type) =>
    options.inspectionPlan.dnsRecordTypes.includes(type));
  const dns = requestedTypes.length === 0
    ? { records: Object.freeze([]), errors: Object.freeze([]), dnsMs: null }
    : await collectDns(domain, requestedTypes, options.config, options.session);
  const tls = options.inspectionPlan.tlsIssuer
    ? collectTls(options.httpResult, options.config)
    : { issuer: null, error: null, tlsMs: null };
  const errors = [...dns.errors];
  if (tls.error !== null) errors.push(tls.error);

  return Object.freeze({
    observations: Object.freeze({
      dnsRecords: dns.records,
      tlsIssuer: tls.issuer,
    }),
    errors: Object.freeze(errors),
    dnsMs: dns.dnsMs,
    tlsMs: tls.tlsMs,
    completed: errors.length === 0,
  });
}
