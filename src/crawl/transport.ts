import { randomBytes } from "node:crypto";
import { lookup as lookupAddress } from "node:dns/promises";
import { once } from "node:events";
import {
  Agent,
  createServer as createHttpServer,
  request as makeHttpRequest,
  type ClientRequestArgs,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type Server as HttpServer,
  type ServerResponse,
} from "node:http";
import {
  createConnection,
  isIP,
  type Socket,
} from "node:net";
import { pipeline } from "node:stream/promises";
import { Transform, Writable } from "node:stream";
import {
  checkServerIdentity,
  connect as connectTls,
  type TLSSocket,
} from "node:tls";
import {
  createBrotliDecompress,
  createGunzip,
  createInflate,
} from "node:zlib";

import type { ScanConfig } from "../config.ts";
import { DNS_RECORD_TYPES } from "../model.ts";
import type {
  DnsRecordObservation,
  DnsRecordType,
  ErrorCode,
  ErrorStage,
  PageId,
} from "../model.ts";
import {
  TARGET_POLICY_ERROR_CODES,
  TargetPolicyError,
  normalizeHostname,
  validateAddressAnswers,
  type ValidatedAddressAnswer,
} from "../network-policy.ts";

const LOOKUP_OPTIONS = Object.freeze({
  all: true,
  order: "verbatim",
} as const);
const MAX_RAW_DNS_ANSWERS_PER_LOOKUP = 128;
const DNS_RECORD_RANK = new Map<DnsRecordType, number>(
  DNS_RECORD_TYPES.map((type, index) => [type, index]),
);

const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);
const CERTIFICATE_ERROR_CODES = new Set([
  "CERT_CHAIN_TOO_LONG",
  "CERT_HAS_EXPIRED",
  "CERT_NOT_YET_VALID",
  "CERT_REJECTED",
  "CERT_REVOKED",
  "CERT_SIGNATURE_FAILURE",
  "CERT_UNTRUSTED",
  "CRL_HAS_EXPIRED",
  "CRL_NOT_YET_VALID",
  "CRL_SIGNATURE_FAILURE",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "ERROR_IN_CERT_NOT_AFTER_FIELD",
  "ERROR_IN_CERT_NOT_BEFORE_FIELD",
  "ERROR_IN_CRL_LAST_UPDATE_FIELD",
  "ERROR_IN_CRL_NEXT_UPDATE_FIELD",
  "ERR_TLS_CERT_ALTNAME_INVALID",
  "HOSTNAME_MISMATCH",
  "INVALID_CA",
  "INVALID_PURPOSE",
  "PATH_LENGTH_EXCEEDED",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY",
  "UNABLE_TO_DECRYPT_CERT_SIGNATURE",
  "UNABLE_TO_DECRYPT_CRL_SIGNATURE",
  "UNABLE_TO_GET_CRL",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
]);
const TRANSIENT_NETWORK_ERROR_CODES = new Set([
  "ECONNABORTED",
  "ECONNREFUSED",
  "ECONNRESET",
  "EHOSTUNREACH",
  "ENETDOWN",
  "ENETRESET",
  "ENETUNREACH",
  "EPIPE",
  "ERR_STREAM_PREMATURE_CLOSE",
  "ETIMEDOUT",
]);

const TRANSPORT_MESSAGES = {
  TARGET_REDIRECT_INVALID: "The HTTP destination URL is invalid.",
  DNS_LOOKUP_FAILED: "The destination hostname could not be resolved.",
  DNS_NO_ADDRESS: "The destination hostname returned no address.",
  DNS_LIMIT_EXCEEDED: "The DNS address budget was exceeded.",
  SSRF_NON_PUBLIC_ADDRESS: "The destination resolved to a non-public address.",
  SSRF_MIXED_ADDRESSES:
    "The destination returned both public and non-public addresses.",
  SSRF_REMOTE_ADDRESS_MISMATCH:
    "The connected address did not match the validated destination.",
  HTTP_REQUEST_FAILED: "The HTTP transaction failed.",
  HTTP_TIMEOUT: "The HTTP transaction exceeded its deadline.",
  HTTP_LIMIT_EXCEEDED: "The HTTP transaction budget was exceeded.",
  HTTP_RESPONSE_LIMIT_EXCEEDED: "The HTTP response exceeded a safety limit.",
  HTTP_DECOMPRESSION_FAILED: "The HTTP response could not be decompressed safely.",
  TLS_CONNECTION_FAILED: "The TLS connection failed.",
  TLS_CERTIFICATE_INVALID: "The TLS certificate could not be verified.",
  TLS_TIMEOUT: "The TLS handshake exceeded its deadline.",
  BROWSER_LIMIT_EXCEEDED: "Browser collection exceeded a safety limit.",
  BROWSER_PROXY_FAILED: "The protected browser proxy failed.",
  DOMAIN_DEADLINE_EXCEEDED: "The active domain deadline was exceeded.",
} as const;

type TransportErrorCode = keyof typeof TRANSPORT_MESSAGES;
type RequestPhase = "queue" | "dns" | "connect" | "tls" | "headers" | "body";
type BodyPurpose = "page" | "robots" | "probe";

interface ParsedNetworkUrl {
  readonly url: URL;
  readonly logicalHostname: string;
  readonly addressFamily: 0 | 4 | 6;
}

interface HeaderBudget {
  fields: number;
  bytes: number;
}

interface HeaderBlockStart {
  readonly httpVersion: string;
  readonly statusCode: number;
  readonly statusMessage: string;
}

interface BodyLimits {
  readonly compressedBytes: number;
  readonly decompressedBytes: number;
}

export interface ProtectedTransportUsage {
  readonly httpRequests: number;
  readonly retries: number;
  readonly staticTransferredBytes: number;
}

export interface ProtectedBrowserProxyUsage {
  readonly browserRequests: number;
  readonly browserTransferredBytes: number;
}

export interface BrowserProxyRequestAttempt {
  readonly pageId: PageId;
  readonly url: string;
  readonly forward: boolean;
}

export interface ProtectedBrowserProxyCanary {
  readonly targetUrl: string;
  readonly chromiumHostResolverArg: string;
  verify(): void;
  close(): Promise<void>;
}

export interface ProtectedBrowserProxy {
  readonly server: string;
  activateDomain(signal?: AbortSignal): void;
  startPage(pageId: PageId): void;
  recordRequestAttempt(attempt: BrowserProxyRequestAttempt): void;
  finishPage(pageId: PageId): Promise<void>;
  finishDomain(): Promise<void>;
  getUsage(): ProtectedBrowserProxyUsage;
  getFailure(): ProtectedTransportError | null;
  getFailureSignal(): AbortSignal;
  prepareCanary(): Promise<ProtectedBrowserProxyCanary>;
  close(): Promise<void>;
}

export interface ProtectedTransportHeader {
  readonly name: string;
  readonly value: string;
}

export interface ProtectedTransportResponse {
  readonly url: string;
  readonly statusCode: number;
  readonly headers: readonly ProtectedTransportHeader[];
  readonly body: Uint8Array;
  readonly redirectUrl: string | null;
  readonly tlsIssuer: string | null;
  readonly tlsHandshakeMs: number | null;
}

export interface ProtectedTransportRequest {
  readonly url: string;
  readonly purpose: BodyPurpose;
  readonly isRetry?: boolean;
  readonly acceptBody?: (head: ProtectedTransportResponseHead) => boolean;
}

export interface ProtectedTransportResponseHead {
  readonly url: string;
  readonly statusCode: number;
  readonly headers: readonly ProtectedTransportHeader[];
  readonly tlsIssuer: string | null;
  readonly tlsHandshakeMs: number | null;
}

export interface ProtectedDnsRecordAdmission {
  readonly records: readonly DnsRecordObservation[];
  readonly limitExceeded: boolean;
}

export interface ProtectedTransportSessionOptions {
  readonly signal?: AbortSignal;
}

export interface ProtectedTransportSession {
  requestHop(request: ProtectedTransportRequest): Promise<ProtectedTransportResponse>;
  admitDnsRecords(
    records: readonly DnsRecordObservation[],
  ): ProtectedDnsRecordAdmission;
  getSignal(): AbortSignal;
  getUsage(): ProtectedTransportUsage;
  close(): void;
}

export interface ProtectedHttpTransport {
  createSession(
    options?: ProtectedTransportSessionOptions,
  ): ProtectedTransportSession;
  createBrowserProxy(): Promise<ProtectedBrowserProxy>;
}

export class ProtectedTransportError extends Error {
  readonly code: TransportErrorCode;
  readonly stage: ErrorStage;
  readonly retryable: boolean;

  constructor(code: TransportErrorCode, stage: ErrorStage, retryable: boolean) {
    super(TRANSPORT_MESSAGES[code]);
    this.name = "ProtectedTransportError";
    this.code = code;
    this.stage = stage;
    this.retryable = retryable;
  }
}

class AbortMarker {
  readonly kind: "domain-timeout" | "request-timeout";

  constructor(kind: "domain-timeout" | "request-timeout") {
    this.kind = kind;
  }
}

class ConcurrencyScheduler {
  private readonly globalLimit: number;
  private readonly perOriginLimit: number;
  private activeGlobal = 0;
  private readonly activeByOrigin = new Map<string, number>();
  private readonly waiters: Array<{
    readonly origin: string;
    readonly signal: AbortSignal;
    readonly resolve: (release: () => void) => void;
    readonly reject: (error: unknown) => void;
    readonly onAbort: () => void;
  }> = [];

  constructor(globalLimit: number, perOriginLimit: number) {
    this.globalLimit = globalLimit;
    this.perOriginLimit = perOriginLimit;
  }

  acquire(origin: string, signal: AbortSignal): Promise<() => void> {
    if (signal.aborted) {
      return Promise.reject(signal.reason);
    }

    return new Promise<() => void>((resolve, reject) => {
      const waiter = {
        origin,
        signal,
        resolve,
        reject,
        onAbort: (): void => {
          const index = this.waiters.indexOf(waiter);

          if (index >= 0) {
            this.waiters.splice(index, 1);
          }

          reject(signal.reason);
          this.dispatch();
        },
      };

      signal.addEventListener("abort", waiter.onAbort, { once: true });
      this.waiters.push(waiter);
      this.dispatch();
    });
  }

  private dispatch(): void {
    while (this.activeGlobal < this.globalLimit) {
      const index = this.waiters.findIndex(
        ({ origin }) =>
          (this.activeByOrigin.get(origin) ?? 0) < this.perOriginLimit,
      );

      if (index < 0) {
        return;
      }

      const waiter = this.waiters.splice(index, 1)[0];

      if (waiter === undefined) {
        return;
      }

      waiter.signal.removeEventListener("abort", waiter.onAbort);

      if (waiter.signal.aborted) {
        waiter.reject(waiter.signal.reason);
        continue;
      }

      this.activeGlobal += 1;
      this.activeByOrigin.set(
        waiter.origin,
        (this.activeByOrigin.get(waiter.origin) ?? 0) + 1,
      );

      let released = false;
      waiter.resolve((): void => {
        if (released) {
          return;
        }

        released = true;
        this.activeGlobal -= 1;

        const remaining = (this.activeByOrigin.get(waiter.origin) ?? 1) - 1;

        if (remaining === 0) {
          this.activeByOrigin.delete(waiter.origin);
        } else {
          this.activeByOrigin.set(waiter.origin, remaining);
        }

        this.dispatch();
      });
    }
  }
}

class DestinationResolver {
  private readonly config: ScanConfig;
  private readonly dnsScheduler: ConcurrencyScheduler;
  private readonly ipv4Records = new Set<string>();
  private readonly ipv6Records = new Set<string>();
  private readonly otherRecords = new Map<DnsRecordType, Set<string>>();

  constructor(config: ScanConfig, dnsScheduler: ConcurrencyScheduler) {
    this.config = config;
    this.dnsScheduler = dnsScheduler;
  }

  reset(): void {
    this.ipv4Records.clear();
    this.ipv6Records.clear();
    this.otherRecords.clear();
  }

  admitRecords(
    records: readonly DnsRecordObservation[],
  ): ProtectedDnsRecordAdmission {
    const nextIpv4 = new Set(this.ipv4Records);
    const nextIpv6 = new Set(this.ipv6Records);
    const nextOther = new Map<DnsRecordType, Set<string>>(
      [...this.otherRecords].map(([type, values]) => [type, new Set(values)]),
    );
    const admitted: DnsRecordObservation[] = [];
    const seen = new Set<string>();
    let limitExceeded = false;

    const ordered = [...records].sort((left, right) =>
      (DNS_RECORD_RANK.get(left.type) ?? Number.MAX_SAFE_INTEGER)
        - (DNS_RECORD_RANK.get(right.type) ?? Number.MAX_SAFE_INTEGER)
      || (left.value < right.value ? -1 : left.value > right.value ? 1 : 0));

    for (const record of ordered) {
      if (
        !DNS_RECORD_RANK.has(record.type)
        || !record.value.isWellFormed()
      ) {
        throw new TypeError("DNS record admission received an invalid record");
      }
      const identity = `${record.type}\0${record.value}`;
      if (seen.has(identity)) {
        continue;
      }
      seen.add(identity);

      const target = record.type === "A"
        ? nextIpv4
        : record.type === "AAAA"
          ? nextIpv6
          : (nextOther.get(record.type) ?? new Set<string>());
      const alreadyPresent = target.has(record.value);
      target.add(record.value);
      if (record.type !== "A" && record.type !== "AAAA") {
        nextOther.set(record.type, target);
      }

      const recordCount = nextIpv4.size + nextIpv6.size
        + [...nextOther.values()].reduce((sum, values) => sum + values.size, 0);
      const textBytes = [...nextIpv4, ...nextIpv6].reduce(
        (sum, value) => sum + Buffer.byteLength(value, "utf8"),
        0,
      ) + [...nextOther.values()].reduce(
        (sum, values) => sum + [...values].reduce(
          (subtotal, value) => subtotal + Buffer.byteLength(value, "utf8"),
          0,
        ),
        0,
      );

      if (
        target.size > this.config.limits.dns.recordsPerType
        || recordCount > this.config.limits.dns.recordsPerDomain
        || textBytes > this.config.limits.dns.textBytesPerDomain
      ) {
        if (!alreadyPresent) {
          target.delete(record.value);
        }
        limitExceeded = true;
        break;
      }

      admitted.push(Object.freeze({ type: record.type, value: record.value }));
    }

    this.ipv4Records.clear();
    this.ipv6Records.clear();
    this.otherRecords.clear();
    for (const value of nextIpv4) this.ipv4Records.add(value);
    for (const value of nextIpv6) this.ipv6Records.add(value);
    for (const [type, values] of nextOther) {
      this.otherRecords.set(type, values);
    }

    return Object.freeze({
      records: Object.freeze(admitted),
      limitExceeded,
    });
  }

  async resolve(
    parsed: ParsedNetworkUrl,
    signal: AbortSignal,
    fixedAnswers?: readonly ValidatedAddressAnswer[],
  ): Promise<ValidatedAddressAnswer> {
    let answers: unknown;

    if (fixedAnswers !== undefined) {
      answers = fixedAnswers;
    } else if (parsed.addressFamily === 4 || parsed.addressFamily === 6) {
      answers = [{
        address: parsed.logicalHostname,
        family: parsed.addressFamily,
      }];
    } else {
      const releaseLookup = await this.dnsScheduler.acquire("dns", signal);

      if (signal.aborted) {
        releaseLookup();
        throw signal.reason;
      }

      const operation = Promise.resolve().then(() =>
        lookupAddress(parsed.logicalHostname, LOOKUP_OPTIONS),
      );
      void operation.then(releaseLookup, releaseLookup);
      answers = await raceWithSignal(() => operation, signal);
    }

    const validated = validateAddressAnswers(
      answers,
      parsed.addressFamily === 0 || fixedAnswers !== undefined
        ? MAX_RAW_DNS_ANSWERS_PER_LOOKUP
        : undefined,
    );

    if (
      fixedAnswers === undefined
      && (parsed.addressFamily === 4 || parsed.addressFamily === 6)
    ) {
      const selected = validated[0];
      if (selected === undefined) {
        throw transportError("DNS_NO_ADDRESS", "dns", true);
      }
      return selected;
    }

    const nextIpv4 = new Set(this.ipv4Records);
    const nextIpv6 = new Set(this.ipv6Records);

    for (const answer of validated) {
      const canonical = canonicalIpAddress(answer.address);

      if (canonical === undefined) {
        throw transportError("DNS_LOOKUP_FAILED", "dns", true);
      }

      if (answer.family === 4) {
        nextIpv4.add(canonical);
      } else {
        nextIpv6.add(canonical);
      }
    }

    const otherRecordCount = [...this.otherRecords.values()].reduce(
      (sum, records) => sum + records.size,
      0,
    );
    const textBytes = [...nextIpv4, ...nextIpv6].reduce(
      (sum, value) => sum + Buffer.byteLength(value, "utf8"),
      0,
    ) + [...this.otherRecords.values()].reduce(
      (sum, records) => sum + [...records].reduce(
        (subtotal, value) => subtotal + Buffer.byteLength(value, "utf8"),
        0,
      ),
      0,
    );

    if (
      nextIpv4.size > this.config.limits.dns.recordsPerType
      || nextIpv6.size > this.config.limits.dns.recordsPerType
      || nextIpv4.size + nextIpv6.size + otherRecordCount
        > this.config.limits.dns.recordsPerDomain
      || textBytes > this.config.limits.dns.textBytesPerDomain
    ) {
      throw transportError("DNS_LIMIT_EXCEEDED", "dns", false);
    }

    this.ipv4Records.clear();
    this.ipv6Records.clear();
    for (const address of nextIpv4) {
      this.ipv4Records.add(address);
    }
    for (const address of nextIpv6) {
      this.ipv6Records.add(address);
    }

    const selected = validated[0];
    if (selected === undefined) {
      throw transportError("DNS_NO_ADDRESS", "dns", true);
    }
    return selected;
  }
}

class PinnedSocketAgent extends Agent {
  private socket: Socket | TLSSocket | undefined;

  constructor(socket: Socket | TLSSocket) {
    super({ keepAlive: false, maxSockets: 1, maxTotalSockets: 1 });
    this.socket = socket;
  }

  override createConnection(_options: ClientRequestArgs): Socket | TLSSocket {
    const socket = this.socket;

    if (socket === undefined) {
      throw new Error("The pinned socket has already been assigned.");
    }

    this.socket = undefined;
    return socket;
  }
}

async function connectSocket(
  address: string,
  family: 4 | 6,
  port: 80 | 443,
  signal: AbortSignal,
): Promise<Socket> {
  signal.throwIfAborted();

  const socket = createConnection({
    host: address,
    port,
    family,
    autoSelectFamily: false,
  });

  try {
    await once(socket, "connect", { signal });
  } catch (error) {
    socket.destroy();
    throw error;
  }

  return socket;
}

function transportError(
  code: TransportErrorCode,
  stage: ErrorStage,
  retryable: boolean,
): ProtectedTransportError {
  return new ProtectedTransportError(code, stage, retryable);
}

function errorCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("code" in error)) {
    return undefined;
  }

  return typeof error.code === "string" ? error.code : undefined;
}

function isCertificateError(error: unknown): boolean {
  const code = errorCode(error);

  return (
    code !== undefined &&
    (CERTIFICATE_ERROR_CODES.has(code) ||
      code.includes("CERT") ||
      code.includes("CRL") ||
      code.includes("HOSTNAME") ||
      code.includes("ISSUER") ||
      code.includes("REJECTED") ||
      code.includes("SIGNATURE") ||
      code.includes("UNTRUSTED"))
  );
}

function isTransientNetworkError(error: unknown): boolean {
  const code = errorCode(error);
  return code !== undefined && TRANSIENT_NETWORK_ERROR_CODES.has(code);
}

function canonicalIpAddress(address: string): string | undefined {
  const family = isIP(address);

  try {
    if (family === 4) {
      return new URL(`http://${address}/`).hostname;
    }

    if (family === 6) {
      const hostname = new URL(`http://[${address}]/`).hostname;
      return hostname.slice(1, -1);
    }
  } catch {
    return undefined;
  }

  return undefined;
}

function sameIpAddress(left: string, right: string): boolean {
  const canonicalLeft = canonicalIpAddress(left);
  const canonicalRight = canonicalIpAddress(right);

  return canonicalLeft !== undefined && canonicalLeft === canonicalRight;
}

function verifyConnectedAddress(
  selected: ValidatedAddressAnswer,
  socket: Socket,
  stage: "http" | "browser",
): void {
  const remoteAddress = socket.remoteAddress;
  const remoteFamily = remoteAddress === undefined ? 0 : isIP(remoteAddress);

  if (
    remoteFamily !== selected.family
    || remoteAddress === undefined
    || !sameIpAddress(remoteAddress, selected.address)
  ) {
    socket.destroy();
    throw transportError("SSRF_REMOTE_ADDRESS_MISMATCH", stage, false);
  }
}

function rawAuthorityHostname(input: string): string | undefined {
  const match = /^(?:[a-z][a-z0-9+.-]*:)?\/\/([^/?#]*)/i.exec(input);
  const authority = match?.[1];

  if (authority === undefined) {
    return undefined;
  }

  const hostPort = authority.slice(authority.lastIndexOf("@") + 1);

  if (hostPort.startsWith("[")) {
    const closingBracket = hostPort.indexOf("]");
    return closingBracket < 0 ? hostPort : hostPort.slice(0, closingBracket + 1);
  }

  const lastColon = hostPort.lastIndexOf(":");
  return lastColon < 0 ? hostPort : hostPort.slice(0, lastColon);
}

function parseNetworkUrl(
  input: string,
  maximumCodeUnits: number,
  base?: string,
): ParsedNetworkUrl {
  if (
    !Number.isSafeInteger(maximumCodeUnits) ||
    maximumCodeUnits < 1 ||
    maximumCodeUnits > 2_048 ||
    typeof input !== "string" ||
    input.length === 0 ||
    input.length > maximumCodeUnits ||
    !input.isWellFormed() ||
    /[\s\p{Cc}]/u.test(input) ||
    input.includes("\\")
  ) {
    throw transportError("TARGET_REDIRECT_INVALID", "target", false);
  }

  const hasScheme = /^[a-z][a-z0-9+.-]*:/i.test(input);

  if (
    (base === undefined && !/^https?:\/\//i.test(input)) ||
    (hasScheme && !/^https?:\/\//i.test(input))
  ) {
    throw transportError("TARGET_REDIRECT_INVALID", "target", false);
  }

  let url: URL;

  try {
    url = base === undefined ? new URL(input) : new URL(input, base);
  } catch {
    throw transportError("TARGET_REDIRECT_INVALID", "target", false);
  }

  if (
    (url.protocol !== "http:" && url.protocol !== "https:") ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.port.length > 0
  ) {
    throw transportError("TARGET_REDIRECT_INVALID", "target", false);
  }

  const rawHostname = rawAuthorityHostname(input);
  const serializedHostname = url.hostname;
  const bracketed =
    serializedHostname.startsWith("[") && serializedHostname.endsWith("]");
  const logicalHostname = bracketed
    ? serializedHostname.slice(1, -1)
    : serializedHostname;
  const detectedFamily = isIP(logicalHostname);
  const addressFamily: 0 | 4 | 6 =
    detectedFamily === 4 || detectedFamily === 6 ? detectedFamily : 0;

  if (addressFamily === 4 || addressFamily === 6) {
    if (
      rawHostname !== undefined &&
      rawHostname.toLowerCase() !== serializedHostname
    ) {
      throw transportError("TARGET_REDIRECT_INVALID", "target", false);
    }
  } else {
    if (rawHostname?.includes("%") === true) {
      throw transportError("TARGET_REDIRECT_INVALID", "target", false);
    }

    let canonicalHostname: string;

    try {
      canonicalHostname = normalizeHostname(serializedHostname);
    } catch {
      throw transportError("TARGET_REDIRECT_INVALID", "target", false);
    }

    url.hostname = canonicalHostname;
  }

  url.hash = "";

  if (url.href.length > maximumCodeUnits) {
    throw transportError("TARGET_REDIRECT_INVALID", "target", false);
  }

  return {
    url,
    logicalHostname:
      addressFamily === 4 || addressFamily === 6
        ? logicalHostname
        : url.hostname,
    addressFamily,
  };
}

export function resolveRedirectTarget(
  currentUrl: string,
  location: string,
  maximumUrlCodeUnits = 2_048,
): string {
  parseNetworkUrl(currentUrl, maximumUrlCodeUnits);
  const parsed = parseNetworkUrl(location, maximumUrlCodeUnits, currentUrl);

  if (parsed.addressFamily === 4 || parsed.addressFamily === 6) {
    try {
      validateAddressAnswers([
        {
          address: parsed.logicalHostname,
          family: parsed.addressFamily,
        },
      ]);
    } catch (error) {
      if (error instanceof TargetPolicyError) {
        throw mapPolicyError(error);
      }

      throw error;
    }
  }

  return parsed.url.href;
}

function abortError(reason: unknown): Error {
  return reason instanceof Error
    ? reason
    : new DOMException("The operation was aborted.", "AbortError");
}

function delayAbortController(
  milliseconds: number,
  marker: AbortMarker,
): { readonly controller: AbortController; readonly timer: NodeJS.Timeout } {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(marker), milliseconds);
  timer.unref();
  return { controller, timer };
}

function phaseStage(phase: RequestPhase): ErrorStage {
  if (phase === "dns") {
    return "dns";
  }

  if (phase === "tls") {
    return "tls";
  }

  return "http";
}

function mapPolicyError(error: TargetPolicyError): ProtectedTransportError {
  if (
    error.code === TARGET_POLICY_ERROR_CODES.invalidHostname ||
    error.code === TARGET_POLICY_ERROR_CODES.invalidHostnameLimit
  ) {
    return transportError("TARGET_REDIRECT_INVALID", "target", false);
  }

  const retryable =
    error.code === TARGET_POLICY_ERROR_CODES.invalidAddressAnswer ||
    error.code === TARGET_POLICY_ERROR_CODES.noAddressAnswer;

  return transportError(error.code, "dns", retryable);
}

function mapPhaseError(error: unknown, phase: RequestPhase): ProtectedTransportError {
  if (error instanceof ProtectedTransportError) {
    return error;
  }

  if (error instanceof TargetPolicyError) {
    return mapPolicyError(error);
  }

  if (phase === "dns") {
    return transportError("DNS_LOOKUP_FAILED", "dns", true);
  }

  if (phase === "tls") {
    const certificateError = isCertificateError(error);
    return transportError(
      certificateError
        ? "TLS_CERTIFICATE_INVALID"
        : "TLS_CONNECTION_FAILED",
      "tls",
      !certificateError && isTransientNetworkError(error),
    );
  }

  if (errorCode(error) === "HPE_HEADER_OVERFLOW") {
    return transportError("HTTP_RESPONSE_LIMIT_EXCEEDED", "http", false);
  }

  if (errorCode(error)?.startsWith("HPE_") === true) {
    return transportError("HTTP_REQUEST_FAILED", "http", false);
  }

  return transportError("HTTP_REQUEST_FAILED", "http", true);
}

function timeoutError(phase: RequestPhase): ProtectedTransportError {
  if (phase === "tls") {
    return transportError("TLS_TIMEOUT", "tls", true);
  }

  return transportError("HTTP_TIMEOUT", "http", true);
}

function raceWithSignal<T>(
  start: () => Promise<T>,
  signal: AbortSignal,
): Promise<T> {
  if (signal.aborted) {
    return Promise.reject(signal.reason);
  }

  let operation: Promise<T>;

  try {
    operation = start();
  } catch (error) {
    return Promise.reject(error);
  }

  if (signal.aborted) {
    void operation.catch(() => undefined);
    return Promise.reject(signal.reason);
  }

  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });

    operation.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

function rawHeaderMetrics(
  rawHeaders: readonly string[],
  start: HeaderBlockStart | undefined,
): {
  readonly fields: number;
  readonly bytes: number;
} {
  let bytes = 2;

  if (start !== undefined) {
    bytes += Buffer.byteLength(
      `HTTP/${start.httpVersion} ${start.statusCode}${
        start.statusMessage.length === 0 ? "" : ` ${start.statusMessage}`
      }\r\n`,
      "latin1",
    );
  }

  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index] ?? "";
    const value = rawHeaders[index + 1] ?? "";
    bytes += Buffer.byteLength(name, "latin1");
    bytes += 2;
    bytes += Buffer.byteLength(value, "latin1");
    bytes += 2;
  }

  return {
    fields: Math.ceil(rawHeaders.length / 2),
    bytes,
  };
}

function consumeHeaders(
  budget: HeaderBudget,
  rawHeaders: readonly string[],
  config: ScanConfig,
  start?: HeaderBlockStart,
): void {
  const metrics = rawHeaderMetrics(rawHeaders, start);
  budget.fields += metrics.fields;
  budget.bytes += metrics.bytes;

  if (
    rawHeaders.length % 2 !== 0 ||
    budget.fields > config.limits.http.headerFields ||
    budget.bytes > config.limits.http.headerBytes
  ) {
    throw transportError("HTTP_RESPONSE_LIMIT_EXCEEDED", "http", false);
  }
}

function toHeaders(rawHeaders: readonly string[]): readonly ProtectedTransportHeader[] {
  const headers: ProtectedTransportHeader[] = [];

  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index];
    const value = rawHeaders[index + 1];

    if (name !== undefined && value !== undefined) {
      headers.push(
        Object.freeze({
          name: name.toLowerCase(),
          value,
        }),
      );
    }
  }

  return Object.freeze(headers);
}

function rawHeaderValues(
  rawHeaders: readonly string[],
  targetName: string,
): readonly string[] {
  const values: string[] = [];

  for (let index = 0; index < rawHeaders.length; index += 2) {
    if (rawHeaders[index]?.toLowerCase() === targetName) {
      const value = rawHeaders[index + 1];

      if (value !== undefined) {
        values.push(value);
      }
    }
  }

  return values;
}

function bodyLimits(config: ScanConfig, purpose: BodyPurpose): BodyLimits {
  if (purpose === "robots") {
    return {
      compressedBytes: config.limits.robots.bodyBytes,
      decompressedBytes: config.limits.robots.bodyBytes,
    };
  }

  if (purpose === "probe") {
    return {
      compressedBytes: config.limits.http.probeCompressedBytes,
      decompressedBytes: config.limits.http.probeDecompressedBytes,
    };
  }

  return {
    compressedBytes: config.limits.http.htmlCompressedBytesPerPage,
    decompressedBytes: config.limits.http.htmlDecompressedBytesPerPage,
  };
}

function contentEncoding(headers: IncomingHttpHeaders): string {
  const value = headers["content-encoding"];

  if (value === undefined) {
    return "identity";
  }

  if (Array.isArray(value)) {
    throw transportError("HTTP_DECOMPRESSION_FAILED", "http", false);
  }

  const normalized = value.trim().toLowerCase();

  if (
    normalized.length === 0 ||
    normalized.includes(",") ||
    !["identity", "gzip", "deflate", "br"].includes(normalized)
  ) {
    throw transportError("HTTP_DECOMPRESSION_FAILED", "http", false);
  }

  return normalized;
}

function decoderFor(encoding: string): Transform | undefined {
  if (encoding === "identity") {
    return undefined;
  }

  if (encoding === "gzip") {
    return createGunzip();
  }

  if (encoding === "deflate") {
    return createInflate();
  }

  if (encoding === "br") {
    return createBrotliDecompress();
  }

  throw transportError("HTTP_DECOMPRESSION_FAILED", "http", false);
}

function isRedirect(statusCode: number): boolean {
  return REDIRECT_STATUS_CODES.has(statusCode);
}

const PROXY_HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

interface BrowserProxyCanaryState {
  readonly hostname: string;
  targetUrl: string;
  readonly server: HttpServer;
  connections: number;
  proxyRejected: boolean;
  closed: boolean;
}

interface PinnedProxySocket {
  readonly socket: Socket;
  readonly release: () => void;
  readonly signal: AbortSignal;
}

class BrowserProxyPageFinished extends Error {
  constructor() {
    super("The protected browser proxy page finished.");
    this.name = "BrowserProxyPageFinished";
  }
}

function proxyError(retryable = false): ProtectedTransportError {
  return transportError("BROWSER_PROXY_FAILED", "browser", retryable);
}

function proxyLimitError(): ProtectedTransportError {
  return transportError("BROWSER_LIMIT_EXCEEDED", "browser", false);
}

function assertProxyHeaderBudget(
  rawHeaders: readonly string[],
  config: ScanConfig,
): void {
  const metrics = rawHeaderMetrics(rawHeaders, undefined);
  if (
    rawHeaders.length % 2 !== 0
    || metrics.fields > config.limits.http.headerFields
    || metrics.bytes > config.limits.http.headerBytes
  ) {
    throw proxyLimitError();
  }
}

function rawProxyHeaderValues(
  rawHeaders: readonly string[],
  targetName: string,
): readonly string[] {
  return rawHeaderValues(rawHeaders, targetName.toLowerCase());
}

function connectionHeaderNames(rawHeaders: readonly string[]): Set<string> {
  const names = new Set<string>();
  for (const value of rawProxyHeaderValues(rawHeaders, "connection")) {
    for (const token of value.split(",")) {
      const normalized = token.trim().toLowerCase();
      if (normalized !== "") {
        names.add(normalized);
      }
    }
  }
  return names;
}

function filteredProxyRequestHeaders(
  rawHeaders: readonly string[],
  url: URL,
  userAgent: string,
): string[] {
  const blocked = connectionHeaderNames(rawHeaders);
  for (const name of PROXY_HOP_BY_HOP_HEADERS) {
    blocked.add(name);
  }
  blocked.add("host");
  blocked.add("user-agent");

  const headers: string[] = [];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index];
    const value = rawHeaders[index + 1];
    if (
      name !== undefined
      && value !== undefined
      && !blocked.has(name.toLowerCase())
    ) {
      headers.push(name, value);
    }
  }
  headers.push("Host", url.host, "User-Agent", userAgent, "Connection", "close");
  return headers;
}

function filteredProxyResponseHeaders(
  rawHeaders: readonly string[],
): string[] {
  const blocked = connectionHeaderNames(rawHeaders);
  for (const name of PROXY_HOP_BY_HOP_HEADERS) {
    blocked.add(name);
  }

  const headers: string[] = [];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index];
    const value = rawHeaders[index + 1];
    if (
      name !== undefined
      && value !== undefined
      && !blocked.has(name.toLowerCase())
    ) {
      headers.push(name, value);
    }
  }
  headers.push("Connection", "close");
  return headers;
}

function assertNoProxyRequestBody(request: IncomingMessage): void {
  const transferEncoding = rawProxyHeaderValues(
    request.rawHeaders,
    "transfer-encoding",
  );
  const contentLength = rawProxyHeaderValues(request.rawHeaders, "content-length");
  if (
    transferEncoding.length > 0
    || contentLength.length > 1
    || (contentLength.length === 1 && contentLength[0] !== "0")
  ) {
    throw proxyError();
  }
}

function parseProxyHttpTarget(
  input: string,
  config: ScanConfig,
  canary: BrowserProxyCanaryState | null,
): ParsedNetworkUrl {
  if (canary !== null && input === canary.targetUrl) {
    const url = new URL(input);
    return {
      url,
      logicalHostname: canary.hostname,
      addressFamily: 0,
    };
  }

  try {
    if (input.includes("#")) {
      throw proxyError();
    }
    const parsed = parseNetworkUrl(input, config.limits.url.codeUnits);
    if (parsed.url.protocol !== "http:") {
      throw proxyError();
    }
    return parsed;
  } catch (error) {
    if (error instanceof ProtectedTransportError && error.code === "BROWSER_PROXY_FAILED") {
      throw error;
    }
    throw proxyError();
  }
}

function parseProxyConnectTarget(
  input: string,
  config: ScanConfig,
): ParsedNetworkUrl {
  if (
    input.length === 0
    || input.length > config.limits.url.codeUnits
    || !input.isWellFormed()
    || /[\s\p{Cc}]/u.test(input)
    || input.includes("\\")
    || !input.endsWith(":443")
  ) {
    throw proxyError();
  }

  const authority = input.slice(0, -4);
  if (
    authority.length === 0
    || authority.includes("@")
    || authority.includes("/")
    || authority.includes("?")
    || authority.includes("#")
  ) {
    throw proxyError();
  }

  try {
    const parsed = parseNetworkUrl(
      `https://${authority}:443/`,
      config.limits.url.codeUnits,
    );
    if (parsed.url.protocol !== "https:") {
      throw proxyError();
    }
    return parsed;
  } catch (error) {
    if (error instanceof ProtectedTransportError && error.code === "BROWSER_PROXY_FAILED") {
      throw error;
    }
    throw proxyError();
  }
}

function assertProxyHost(
  request: IncomingMessage,
  parsed: ParsedNetworkUrl,
  connect: boolean,
): void {
  const values = rawProxyHeaderValues(request.rawHeaders, "host");
  if (values.length !== 1) {
    throw proxyError();
  }
  const value = values[0];
  if (value === undefined) {
    throw proxyError();
  }
  if (connect && !value.endsWith(":443")) {
    throw proxyError();
  }

  let hostUrl: URL;
  try {
    hostUrl = new URL(`${connect ? "https" : "http"}://${value}/`);
  } catch {
    throw proxyError();
  }
  if (
    hostUrl.username !== ""
    || hostUrl.password !== ""
    || hostUrl.hash !== ""
    || hostUrl.search !== ""
    || hostUrl.host !== parsed.url.host
  ) {
    throw proxyError();
  }
}

function writeProxyHttpFailure(response: ServerResponse): void {
  if (!response.headersSent) {
    response.writeHead(502, {
      Connection: "close",
      "Content-Length": "0",
    });
  }
  response.end();
}

function writeProxyConnectFailure(socket: Socket): void {
  if (!socket.destroyed && socket.writable) {
    socket.end(
      "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
    );
  } else {
    socket.destroy();
  }
}

async function closeSockets(sockets: ReadonlySet<Socket>): Promise<void> {
  const closing: Promise<void>[] = [];
  for (const socket of sockets) {
    if (!socket.destroyed) {
      closing.push(
        once(socket, "close").then(() => undefined, () => undefined),
      );
      socket.destroy();
    }
  }
  await Promise.all(closing);
}

class ProtectedBrowserProxyImpl implements ProtectedBrowserProxy {
  readonly server: string;
  private readonly config: ScanConfig;
  private readonly scheduler: ConcurrencyScheduler;
  private readonly destinationResolver: DestinationResolver;
  private readonly httpServer: HttpServer;
  private readonly serverSockets = new Set<Socket>();
  private readonly pageClientSockets = new Set<Socket>();
  private readonly pageUpstreamSockets = new Set<Socket>();
  private authorizedHttpsOrigins = new Set<string>();
  private httpOriginGrants = new Map<string, number>();
  private failureController = new AbortController();
  private failure: ProtectedTransportError | null = null;
  private domainCloseController: AbortController | null = null;
  private domainTimeoutController: AbortController | null = null;
  private domainTimeoutTimer: NodeJS.Timeout | null = null;
  private domainSignal: AbortSignal | null = null;
  private domainAbortListener: (() => void) | null = null;
  private pageCloseController: AbortController | null = null;
  private pageSignal: AbortSignal | null = null;
  private pageGeneration = 0;
  private activePage: PageId | null = null;
  private pageRequests = 0;
  private pageTransferredBytes = 0;
  private browserRequests = 0;
  private browserTransferredBytes = 0;
  private canary: BrowserProxyCanaryState | null = null;
  private finishing = false;
  private closed = false;

  private constructor(
    config: ScanConfig,
    scheduler: ConcurrencyScheduler,
    dnsScheduler: ConcurrencyScheduler,
    httpServer: HttpServer,
    server: string,
  ) {
    this.config = config;
    this.scheduler = scheduler;
    this.destinationResolver = new DestinationResolver(config, dnsScheduler);
    this.httpServer = httpServer;
    this.server = server;

    httpServer.on("connection", (socket) => {
      this.serverSockets.add(socket);
      if (this.activePage !== null) {
        this.pageClientSockets.add(socket);
      }
      socket.once("close", () => {
        this.serverSockets.delete(socket);
        this.pageClientSockets.delete(socket);
      });
    });
    httpServer.on("request", (request, response) => {
      void this.handleHttp(request, response).catch((error: unknown) => {
        this.handleProxyFailure(error);
        writeProxyHttpFailure(response);
      });
    });
    httpServer.on("connect", (request, socket, head) => {
      const client = socket as Socket;
      void this.handleConnect(request, client, head).catch((error: unknown) => {
        this.handleProxyFailure(error);
        writeProxyConnectFailure(client);
      });
    });
    httpServer.on("checkContinue", (_request, response) => {
      this.latchFailure(proxyError());
      writeProxyHttpFailure(response);
    });
    httpServer.on("checkExpectation", (_request, response) => {
      this.latchFailure(proxyError());
      writeProxyHttpFailure(response);
    });
    httpServer.on("dropRequest", (_request, socket) => {
      this.latchFailure(proxyError());
      socket.destroy();
    });
    httpServer.on("upgrade", (_request, socket) => {
      this.latchFailure(proxyError());
      socket.destroy();
    });
    httpServer.on("clientError", (_error, socket) => {
      if (this.domainSignal !== null && !this.finishing) {
        this.latchFailure(proxyError());
      }
      socket.destroy();
    });
  }

  static async create(
    config: ScanConfig,
    scheduler: ConcurrencyScheduler,
    dnsScheduler: ConcurrencyScheduler,
  ): Promise<ProtectedBrowserProxyImpl> {
    const httpServer = createHttpServer({
      headersTimeout: config.limits.timeMs.httpRequest,
      requestTimeout: config.limits.timeMs.browserPage,
      keepAliveTimeout: 1_000,
      keepAliveTimeoutBuffer: 250,
      insecureHTTPParser: false,
      joinDuplicateHeaders: false,
      maxHeaderSize: config.limits.http.headerBytes,
      requireHostHeader: true,
    });
    httpServer.maxHeadersCount = config.limits.http.headerFields + 1;
    httpServer.maxRequestsPerSocket = 1;
    httpServer.listen({ host: "127.0.0.1", port: 0, exclusive: true });

    try {
      await once(httpServer, "listening");
    } catch (error) {
      httpServer.close();
      throw proxyError(isTransientNetworkError(error));
    }

    const address = httpServer.address();
    if (address === null || typeof address === "string") {
      httpServer.close();
      throw proxyError();
    }
    return new ProtectedBrowserProxyImpl(
      config,
      scheduler,
      dnsScheduler,
      httpServer,
      `http://127.0.0.1:${address.port}`,
    );
  }

  activateDomain(signal?: AbortSignal): void {
    if (this.closed || this.domainSignal !== null) {
      throw proxyError();
    }
    if (signal?.aborted === true) {
      throw abortError(signal.reason);
    }

    this.destinationResolver.reset();
    this.failure = null;
    this.failureController = new AbortController();
    this.domainCloseController = new AbortController();
    const timeout = delayAbortController(
      this.config.limits.timeMs.activeDomain,
      new AbortMarker("domain-timeout"),
    );
    this.domainTimeoutController = timeout.controller;
    this.domainTimeoutTimer = timeout.timer;
    const signals = [
      this.domainCloseController.signal,
      this.domainTimeoutController.signal,
      ...(signal === undefined ? [] : [signal]),
    ];
    this.domainSignal = AbortSignal.any(signals);
    this.domainAbortListener = (): void => {
      const timeoutReason = this.domainTimeoutController?.signal.reason;
      if (
        timeoutReason instanceof AbortMarker
        && timeoutReason.kind === "domain-timeout"
      ) {
        this.latchFailure(
          transportError("DOMAIN_DEADLINE_EXCEEDED", "browser", true),
        );
      }
      this.destroyPageSockets();
    };
    this.domainSignal.addEventListener("abort", this.domainAbortListener, {
      once: true,
    });
    this.activePage = null;
    this.authorizedHttpsOrigins.clear();
    this.httpOriginGrants.clear();
    this.pageRequests = 0;
    this.pageTransferredBytes = 0;
    this.browserRequests = 0;
    this.browserTransferredBytes = 0;
  }

  startPage(pageId: PageId): void {
    this.assertActiveDomain();
    if (this.activePage !== null || this.failure !== null) {
      throw this.failure ?? proxyError();
    }
    const domainSignal = this.domainSignal;
    if (domainSignal === null) {
      throw proxyError();
    }
    this.pageCloseController = new AbortController();
    this.pageSignal = AbortSignal.any([
      domainSignal,
      this.pageCloseController.signal,
    ]);
    this.pageGeneration += 1;
    this.activePage = pageId;
    this.authorizedHttpsOrigins = new Set<string>();
    this.httpOriginGrants = new Map<string, number>();
    this.pageRequests = 0;
    this.pageTransferredBytes = 0;
  }

  recordRequestAttempt(attempt: BrowserProxyRequestAttempt): void {
    this.assertActivePage(attempt.pageId);
    if (
      this.pageRequests >= this.config.limits.browser.requestsPerPage
      || this.browserRequests >= this.config.limits.browser.requestsPerDomain
    ) {
      const error = proxyLimitError();
      this.latchFailure(error);
      throw error;
    }

    this.pageRequests += 1;
    this.browserRequests += 1;
    if (attempt.forward !== true) {
      return;
    }

    let parsed: ParsedNetworkUrl;
    try {
      parsed = parseNetworkUrl(attempt.url, this.config.limits.url.codeUnits);
    } catch {
      const error = proxyError();
      this.latchFailure(error);
      throw error;
    }
    if (parsed.url.protocol === "http:") {
      this.httpOriginGrants.set(
        parsed.url.origin,
        (this.httpOriginGrants.get(parsed.url.origin) ?? 0) + 1,
      );
    } else {
      this.authorizedHttpsOrigins.add(parsed.url.origin);
    }
  }

  async finishPage(pageId: PageId): Promise<void> {
    this.assertActivePage(pageId, true);
    this.finishing = true;
    const pageCloseController = this.pageCloseController;
    this.activePage = null;
    this.authorizedHttpsOrigins.clear();
    this.httpOriginGrants.clear();
    pageCloseController?.abort(new BrowserProxyPageFinished());
    try {
      await this.closePageSockets();
    } finally {
      if (this.pageCloseController === pageCloseController) {
        this.pageCloseController = null;
        this.pageSignal = null;
      }
      this.pageRequests = 0;
      this.pageTransferredBytes = 0;
      this.finishing = false;
    }
  }

  async finishDomain(): Promise<void> {
    if (this.domainSignal === null) {
      return;
    }
    this.finishing = true;
    const pageId = this.activePage;
    const pageCloseController = this.pageCloseController;
    this.activePage = null;
    this.authorizedHttpsOrigins.clear();
    this.httpOriginGrants.clear();
    pageCloseController?.abort(new BrowserProxyPageFinished());
    this.domainCloseController?.abort(
      new DOMException("The browser proxy domain finished.", "AbortError"),
    );
    if (this.domainTimeoutTimer !== null) {
      clearTimeout(this.domainTimeoutTimer);
    }
    try {
      await this.closePageSockets();
      await closeSockets(this.serverSockets);
    } finally {
      if (pageId !== null) {
        this.pageRequests = 0;
        this.pageTransferredBytes = 0;
      }
      if (this.pageCloseController === pageCloseController) {
        this.pageCloseController = null;
        this.pageSignal = null;
      }
      this.domainSignal = null;
      this.domainAbortListener = null;
      this.domainCloseController = null;
      this.domainTimeoutController = null;
      this.domainTimeoutTimer = null;
      this.finishing = false;
    }
  }

  getUsage(): ProtectedBrowserProxyUsage {
    return Object.freeze({
      browserRequests: this.browserRequests,
      browserTransferredBytes: this.browserTransferredBytes,
    });
  }

  getFailure(): ProtectedTransportError | null {
    return this.failure;
  }

  getFailureSignal(): AbortSignal {
    return this.failureController.signal;
  }

  async prepareCanary(): Promise<ProtectedBrowserProxyCanary> {
    if (this.closed || this.domainSignal !== null || this.canary !== null) {
      throw proxyError();
    }

    const hostname = `canary-${randomBytes(16).toString("hex")}.example.com`;
    const canaryServer = createHttpServer((_request, response) => {
      response.writeHead(204, { Connection: "close" });
      response.end();
    });
    const state: BrowserProxyCanaryState = {
      hostname,
      targetUrl: "",
      server: canaryServer,
      connections: 0,
      proxyRejected: false,
      closed: false,
    };
    canaryServer.on("connection", (socket) => {
      state.connections += 1;
      socket.once("error", () => undefined);
    });
    canaryServer.listen({ host: "127.0.0.1", port: 0, exclusive: true });

    try {
      await once(canaryServer, "listening");
      const address = canaryServer.address();
      if (address === null || typeof address === "string") {
        throw proxyError();
      }
      state.targetUrl = `http://${hostname}:${address.port}/`;
      this.canary = state;
      this.activateCanaryDomain();
    } catch (error) {
      canaryServer.close();
      this.canary = null;
      throw error instanceof ProtectedTransportError ? error : proxyError();
    }

    let closed = false;
    return Object.freeze({
      targetUrl: state.targetUrl,
      chromiumHostResolverArg:
        `--host-resolver-rules=MAP ${hostname} 127.0.0.1`,
      verify: (): void => {
        if (closed || state.closed) {
          throw proxyError();
        }
        if (!state.proxyRejected || state.connections !== 0) {
          throw proxyError();
        }
      },
      close: async (): Promise<void> => {
        if (closed) {
          return;
        }
        closed = true;
        state.closed = true;
        await this.finishDomain();
        if (canaryServer.listening) {
          await new Promise<void>((resolve) => canaryServer.close(() => resolve()));
        }
        if (this.canary === state) {
          this.canary = null;
        }
      },
    });
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    const canary = this.canary;
    if (canary !== null) {
      canary.closed = true;
    }
    await this.finishDomain();
    await closeSockets(this.serverSockets);
    if (this.httpServer.listening) {
      await new Promise<void>((resolve) => this.httpServer.close(() => resolve()));
    }
    if (canary?.server.listening === true) {
      await new Promise<void>((resolve) => canary.server.close(() => resolve()));
    }
    this.canary = null;
  }

  private activateCanaryDomain(): void {
    const canary = this.canary;
    if (canary === null || this.domainSignal !== null) {
      throw proxyError();
    }
    this.activateDomain();
    this.startPage("p1");
    this.httpOriginGrants.set(new URL(canary.targetUrl).origin, 1);
  }

  private assertActiveDomain(allowFailure = false): void {
    if (
      this.closed
      || this.finishing
      || this.domainSignal === null
      || (!allowFailure
        && (this.domainSignal.aborted || this.failure !== null))
    ) {
      if (this.failure !== null) {
        throw this.failure;
      }
      throw proxyError();
    }
  }

  private assertActivePage(pageId: PageId, allowFailure = false): void {
    this.assertActiveDomain(allowFailure);
    if (this.activePage !== pageId || (!allowFailure && this.failure !== null)) {
      throw this.failure ?? proxyError();
    }
  }

  private latchFailure(error: ProtectedTransportError): void {
    if (this.failure !== null || this.finishing || this.domainSignal === null) {
      return;
    }
    this.failure = error;
    this.pageCloseController?.abort(error);
    this.failureController.abort(error);
    this.destroyPageSockets();
  }

  private handleProxyFailure(error: unknown): void {
    if (
      error instanceof BrowserProxyPageFinished
      || this.finishing
      || this.domainSignal?.aborted === true
    ) {
      return;
    }
    if (error instanceof ProtectedTransportError) {
      this.latchFailure(error);
      return;
    }
    this.latchFailure(proxyError(isTransientNetworkError(error)));
  }

  private consumeBrowserBytes(byteLength: number): void {
    if (
      !Number.isSafeInteger(byteLength)
      || byteLength < 0
      || this.activePage === null
    ) {
      throw proxyError();
    }
    if (
      this.pageTransferredBytes + byteLength
        > this.config.limits.browser.transferBytesPerPage
      || this.browserTransferredBytes + byteLength
        > this.config.limits.browser.transferBytesPerDomain
    ) {
      const error = proxyLimitError();
      this.latchFailure(error);
      throw error;
    }
    this.pageTransferredBytes += byteLength;
    this.browserTransferredBytes += byteLength;
  }

  private downstreamCounter(): Transform {
    return new Transform({
      transform: (chunk: Buffer, _encoding, callback): void => {
        try {
          this.consumeBrowserBytes(chunk.byteLength);
          callback(null, chunk);
        } catch (error) {
          callback(error as Error);
        }
      },
    });
  }

  private destroyPageSockets(): void {
    for (const socket of this.pageClientSockets) {
      socket.destroy();
    }
    for (const socket of this.pageUpstreamSockets) {
      socket.destroy();
    }
  }

  private async closePageSockets(): Promise<void> {
    await Promise.all([
      closeSockets(this.pageClientSockets),
      closeSockets(this.pageUpstreamSockets),
    ]);
    this.pageClientSockets.clear();
    this.pageUpstreamSockets.clear();
  }

  private consumeHttpGrant(parsed: ParsedNetworkUrl): void {
    const grants = this.httpOriginGrants.get(parsed.url.origin) ?? 0;
    if (this.activePage === null || grants === 0) {
      throw proxyError();
    }
    if (grants === 1) {
      this.httpOriginGrants.delete(parsed.url.origin);
    } else {
      this.httpOriginGrants.set(parsed.url.origin, grants - 1);
    }
  }

  private assertHttpsAuthorized(parsed: ParsedNetworkUrl): void {
    if (
      this.activePage === null
      || !this.authorizedHttpsOrigins.has(parsed.url.origin)
    ) {
      throw proxyError();
    }
  }

  private canaryAnswers(
    parsed: ParsedNetworkUrl,
  ): readonly ValidatedAddressAnswer[] | undefined {
    const canary = this.canary;
    if (
      canary !== null
      && parsed.logicalHostname === canary.hostname
      && parsed.url.href === canary.targetUrl
    ) {
      return [{ address: "127.0.0.1", family: 4 }];
    }
    return undefined;
  }

  private expectedCanaryRejection(
    parsed: ParsedNetworkUrl,
    error: unknown,
  ): boolean {
    const canary = this.canary;
    if (
      canary !== null
      && parsed.url.href === canary.targetUrl
      && error instanceof ProtectedTransportError
      && error.code === "SSRF_NON_PUBLIC_ADDRESS"
    ) {
      canary.proxyRejected = true;
      return true;
    }
    return false;
  }

  private async openPinnedProxySocket(
    parsed: ParsedNetworkUrl,
    pageGeneration: number,
  ): Promise<PinnedProxySocket> {
    const signal = this.pageSignal;
    if (signal === null || this.pageGeneration !== pageGeneration) {
      throw proxyError();
    }

    let selected: ValidatedAddressAnswer;
    try {
      selected = await this.destinationResolver.resolve(
        parsed,
        signal,
        this.canaryAnswers(parsed),
      );
    } catch (error) {
      if (error instanceof ProtectedTransportError) {
        throw error;
      }
      if (error instanceof TargetPolicyError) {
        throw mapPolicyError(error);
      }
      if (signal.aborted) {
        throw abortError(signal.reason);
      }
      throw mapPhaseError(error, "dns");
    }

    this.assertPageGeneration(pageGeneration, signal);

    const release = await this.scheduler.acquire(parsed.url.origin, signal);
    try {
      this.assertPageGeneration(pageGeneration, signal);
      const port = parsed.url.protocol === "https:" ? 443 : 80;
      const socket = await raceWithSignal(
        () => connectSocket(selected.address, selected.family, port, signal),
        signal,
      );
      verifyConnectedAddress(selected, socket, "browser");
      this.pageUpstreamSockets.add(socket);
      socket.once("close", () => this.pageUpstreamSockets.delete(socket));
      return { socket, release, signal };
    } catch (error) {
      release();
      if (error instanceof ProtectedTransportError) {
        throw error;
      }
      if (signal.aborted) {
        throw abortError(signal.reason);
      }
      throw proxyError(isTransientNetworkError(error));
    }
  }

  private assertPageGeneration(
    pageGeneration: number,
    signal: AbortSignal,
  ): void {
    if (
      signal.aborted
      || this.activePage === null
      || this.pageSignal !== signal
      || this.pageGeneration !== pageGeneration
    ) {
      throw abortError(signal.reason ?? new BrowserProxyPageFinished());
    }
  }

  private validateProxyRequest(request: IncomingMessage): void {
    this.assertActiveDomain();
    assertProxyHeaderBudget(request.rawHeaders, this.config);
    if (request.httpVersion !== "1.1") {
      throw proxyError();
    }
    assertNoProxyRequestBody(request);
  }

  private async handleHttp(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    let parsed: ParsedNetworkUrl | undefined;
    let pinned: PinnedProxySocket | undefined;
    let agent: PinnedSocketAgent | undefined;

    try {
      this.validateProxyRequest(request);
      this.pageClientSockets.add(request.socket);
      if (
        request.method === undefined
        || !this.config.security.browser.allowedMethods.includes(
          request.method as "GET" | "HEAD" | "OPTIONS",
        )
      ) {
        throw proxyError();
      }
      parsed = parseProxyHttpTarget(request.url ?? "", this.config, this.canary);
      assertProxyHost(request, parsed, false);
      this.consumeHttpGrant(parsed);
      const pageGeneration = this.pageGeneration;
      request.resume();

      pinned = await this.openPinnedProxySocket(parsed, pageGeneration);
      agent = new PinnedSocketAgent(pinned.socket);
      const upstream = await this.requestProxyHttpResponse(
        request,
        parsed.url,
        agent,
        pinned.signal,
      );
      const statusCode = upstream.statusCode;
      if (statusCode === undefined) {
        upstream.destroy();
        throw proxyError();
      }
      assertProxyHeaderBudget(upstream.rawHeaders, this.config);
      response.writeHead(
        statusCode,
        upstream.statusMessage,
        filteredProxyResponseHeaders(upstream.rawHeaders),
      );
      await pipeline(upstream, this.downstreamCounter(), response, {
        signal: pinned.signal,
      });
      if (!upstream.complete || upstream.rawTrailers.length !== 0) {
        throw proxyError();
      }
    } catch (error) {
      if (pinned?.signal.aborted === true) {
        throw abortError(pinned.signal.reason);
      }
      if (parsed !== undefined && this.expectedCanaryRejection(parsed, error)) {
        writeProxyHttpFailure(response);
        return;
      }
      throw error;
    } finally {
      agent?.destroy();
      pinned?.socket.destroy();
      pinned?.release();
    }
  }

  private requestProxyHttpResponse(
    incoming: IncomingMessage,
    url: URL,
    agent: PinnedSocketAgent,
    signal: AbortSignal,
  ): Promise<IncomingMessage> {
    return new Promise<IncomingMessage>((resolve, reject) => {
      let settled = false;
      const upstreamRequest = makeHttpRequest({
        hostname: url.hostname,
        port: 80,
        method: incoming.method,
        path: `${url.pathname}${url.search}`,
        agent,
        setHost: false,
        insecureHTTPParser: false,
        joinDuplicateHeaders: false,
        maxHeaderSize: this.config.limits.http.headerBytes,
        headers: filteredProxyRequestHeaders(
          incoming.rawHeaders,
          url,
          this.config.userAgent,
        ),
      });
      upstreamRequest.maxHeadersCount = this.config.limits.http.headerFields + 1;

      const settle = (
        error: unknown | null,
        upstream?: IncomingMessage,
      ): void => {
        if (settled) {
          upstream?.destroy();
          return;
        }
        settled = true;
        signal.removeEventListener("abort", onAbort);
        if (error === null && upstream !== undefined) {
          resolve(upstream);
        } else {
          reject(error ?? proxyError());
        }
      };
      const onAbort = (): void => {
        const error = abortError(signal.reason);
        upstreamRequest.destroy(error);
        settle(error);
      };
      signal.addEventListener("abort", onAbort, { once: true });
      upstreamRequest.on("information", () => {
        const error = proxyError();
        upstreamRequest.destroy(error);
        settle(error);
      });
      upstreamRequest.once("response", (upstream) => settle(null, upstream));
      upstreamRequest.once("upgrade", (_upstream, socket) => {
        socket.destroy();
        settle(proxyError());
      });
      upstreamRequest.once("error", (error) => settle(error));
      upstreamRequest.end();
    });
  }

  private async handleConnect(
    request: IncomingMessage,
    client: Socket,
    head: Buffer,
  ): Promise<void> {
    this.validateProxyRequest(request);
    this.pageClientSockets.add(client);
    if (request.method !== "CONNECT") {
      throw proxyError();
    }
    const parsed = parseProxyConnectTarget(request.url ?? "", this.config);
    assertProxyHost(request, parsed, true);
    this.assertHttpsAuthorized(parsed);
    const pageGeneration = this.pageGeneration;
    const pinned = await this.openPinnedProxySocket(parsed, pageGeneration);
    const upstream = pinned.socket;

    try {
      await new Promise<void>((resolve, reject) => {
        let settled = false;
        const counter = this.downstreamCounter();
        const cleanup = (): void => {
          client.removeListener("error", onError);
          upstream.removeListener("error", onError);
          client.removeListener("close", onClose);
          upstream.removeListener("close", onClose);
          counter.removeListener("error", onError);
        };
        const settle = (error?: unknown): void => {
          if (settled) {
            return;
          }
          settled = true;
          cleanup();
          client.destroy();
          upstream.destroy();
          if (error === undefined || this.finishing) {
            resolve();
          } else {
            reject(error);
          }
        };
        const onError = (error: Error): void => settle(error);
        const onClose = (): void => settle();
        client.once("error", onError);
        upstream.once("error", onError);
        client.once("close", onClose);
        upstream.once("close", onClose);
        counter.once("error", onError);

        client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (head.byteLength > 0) {
          upstream.write(head);
        }
        client.pipe(upstream);
        upstream.pipe(counter).pipe(client);
      });
    } finally {
      upstream.destroy();
      pinned.release();
    }
  }
}

class ProtectedHttpTransportImpl implements ProtectedHttpTransport {
  private readonly config: ScanConfig;
  private readonly scheduler: ConcurrencyScheduler;
  private readonly dnsScheduler: ConcurrencyScheduler;

  constructor(config: ScanConfig) {
    this.config = config;
    this.scheduler = new ConcurrencyScheduler(
      config.limits.concurrency.globalHttp,
      config.limits.concurrency.perOriginHttp,
    );
    this.dnsScheduler = new ConcurrencyScheduler(
      config.limits.concurrency.globalHttp,
      config.limits.concurrency.globalHttp,
    );
  }

  createSession(
    options: ProtectedTransportSessionOptions = {},
  ): ProtectedTransportSession {
    return new ProtectedTransportSessionImpl(
      this.config,
      this.scheduler,
      this.dnsScheduler,
      options.signal,
    );
  }

  createBrowserProxy(): Promise<ProtectedBrowserProxy> {
    return ProtectedBrowserProxyImpl.create(
      this.config,
      this.scheduler,
      this.dnsScheduler,
    );
  }
}

class ProtectedTransportSessionImpl implements ProtectedTransportSession {
  private readonly config: ScanConfig;
  private readonly scheduler: ConcurrencyScheduler;
  private readonly destinationResolver: DestinationResolver;
  private readonly timeoutController: AbortController;
  private readonly timeoutTimer: NodeJS.Timeout;
  private readonly signal: AbortSignal;
  private httpRequests = 0;
  private retries = 0;
  private staticTransferredBytes = 0;
  private staticDecompressedBytes = 0;
  private dnsAdmissionUsed = false;
  private closed = false;

  constructor(
    config: ScanConfig,
    scheduler: ConcurrencyScheduler,
    dnsScheduler: ConcurrencyScheduler,
    externalSignal: AbortSignal | undefined,
  ) {
    this.config = config;
    this.scheduler = scheduler;
    this.destinationResolver = new DestinationResolver(config, dnsScheduler);

    const timeout = delayAbortController(
      config.limits.timeMs.activeDomain,
      new AbortMarker("domain-timeout"),
    );
    this.timeoutController = timeout.controller;
    this.timeoutTimer = timeout.timer;
    this.signal =
      externalSignal === undefined
        ? this.timeoutController.signal
        : AbortSignal.any([externalSignal, this.timeoutController.signal]);
  }

  async requestHop(
    request: ProtectedTransportRequest,
  ): Promise<ProtectedTransportResponse> {
    if (this.closed) {
      throw new DOMException("The transport session is closed.", "AbortError");
    }

    const parsed = parseNetworkUrl(
      request.url,
      this.config.limits.url.codeUnits,
    );
    let phase: RequestPhase = "queue";
    let release: (() => void) | undefined;
    let socket: Socket | TLSSocket | undefined;
    let tlsIssuer: string | null = null;
    let tlsHandshakeMs: number | null = null;

    try {
      this.throwIfDomainAborted(phase);
      this.reserveTransaction(request.isRetry === true);

      const timeout = delayAbortController(
        this.config.limits.timeMs.httpRequest,
        new AbortMarker("request-timeout"),
      );
      const attemptSignal = AbortSignal.any([
        this.signal,
        timeout.controller.signal,
      ]);

      try {
        phase = "dns";
        const selected = await this.destinationResolver.resolve(
          parsed,
          attemptSignal,
        );

        phase = "queue";
        release = await this.scheduler.acquire(
          parsed.url.origin,
          attemptSignal,
        );

        phase = "connect";
        socket = await raceWithSignal(
          () => connectSocket(
            selected.address,
            selected.family,
            parsed.url.protocol === "https:" ? 443 : 80,
            attemptSignal,
          ),
          attemptSignal,
        );
        verifyConnectedAddress(selected, socket, "http");

        if (parsed.url.protocol === "https:") {
          phase = "tls";
          const tlsStartedAt = performance.now();
          const securedSocket = await this.secureSocket(
            socket,
            parsed.logicalHostname,
            parsed.addressFamily,
            attemptSignal,
          );
          socket = securedSocket;
          tlsHandshakeMs = Math.max(0, Math.ceil(performance.now() - tlsStartedAt));
          tlsIssuer = securedSocket.getPeerX509Certificate()?.issuer ?? null;
        }

        phase = "headers";
        const response = await this.requestResponse(
          socket,
          parsed.url,
          attemptSignal,
        );
        const statusCode = response.statusCode;

        if (statusCode === undefined) {
          response.destroy();
          throw transportError("HTTP_REQUEST_FAILED", "http", true);
        }

        const rawHeaders = response.rawHeaders;
        const headers = toHeaders(rawHeaders);
        const redirectUrl = this.redirectTarget(
          parsed.url.href,
          statusCode,
          rawHeaders,
        );

        let body: Uint8Array = new Uint8Array();

        const head = Object.freeze({
          url: parsed.url.href,
          statusCode,
          headers,
          tlsIssuer,
          tlsHandshakeMs,
        });
        const bodyAccepted =
          statusCode >= 200 &&
          statusCode <= 299 &&
          statusCode !== 204 &&
          statusCode !== 205 &&
          (request.acceptBody?.(head) ?? true);

        if (isRedirect(statusCode) || !bodyAccepted) {
          response.destroy();
        } else {
          phase = "body";
          body = await this.readBody(
            response,
            request.purpose,
            attemptSignal,
          );
        }

        return Object.freeze({
          url: parsed.url.href,
          statusCode,
          headers,
          body,
          redirectUrl,
          tlsIssuer,
          tlsHandshakeMs,
        });
      } catch (error) {
        if (this.domainTimedOut()) {
          throw transportError(
            "DOMAIN_DEADLINE_EXCEEDED",
            phaseStage(phase),
            true,
          );
        }

        if (timeout.controller.signal.aborted) {
          throw timeoutError(phase);
        }

        if (this.signal.aborted || attemptSignal.aborted) {
          throw abortError(attemptSignal.reason);
        }

        throw mapPhaseError(error, phase);
      } finally {
        clearTimeout(timeout.timer);
      }
    } catch (error) {
      if (this.domainTimedOut()) {
        throw transportError(
          "DOMAIN_DEADLINE_EXCEEDED",
          phaseStage(phase),
          true,
        );
      }

      if (this.signal.aborted) {
        throw abortError(this.signal.reason);
      }

      throw error;
    } finally {
      socket?.destroy();
      release?.();
    }
  }

  admitDnsRecords(
    records: readonly DnsRecordObservation[],
  ): ProtectedDnsRecordAdmission {
    if (this.closed) {
      throw new DOMException("The transport session is closed.", "AbortError");
    }
    this.signal.throwIfAborted();
    if (this.dnsAdmissionUsed) {
      throw new TypeError("Infrastructure DNS records were already admitted");
    }
    this.dnsAdmissionUsed = true;
    return this.destinationResolver.admitRecords(records);
  }

  getUsage(): ProtectedTransportUsage {
    return Object.freeze({
      httpRequests: this.httpRequests,
      retries: this.retries,
      staticTransferredBytes: this.staticTransferredBytes,
    });
  }

  getSignal(): AbortSignal {
    return this.signal;
  }

  close(): void {
    if (this.closed) {
      return;
    }

    this.closed = true;
    clearTimeout(this.timeoutTimer);
    this.timeoutController.abort(
      new DOMException("The transport session is closed.", "AbortError"),
    );
  }

  private throwIfDomainAborted(phase: RequestPhase): void {
    if (!this.signal.aborted) {
      return;
    }

    if (this.domainTimedOut()) {
      throw transportError(
        "DOMAIN_DEADLINE_EXCEEDED",
        phaseStage(phase),
        true,
      );
    }

    throw abortError(this.signal.reason);
  }

  private reserveTransaction(isRetry: boolean): void {
    if (this.httpRequests >= this.config.limits.http.transactionsPerDomain) {
      throw transportError("HTTP_LIMIT_EXCEEDED", "http", false);
    }

    const nextRequests = this.httpRequests + 1;
    const nextRetries = this.retries + (isRetry ? 1 : 0);
    const nextInitialRequests = nextRequests - nextRetries;

    if (
      nextRetries >
      nextInitialRequests *
        this.config.limits.http.transientRetriesPerRequest
    ) {
      throw transportError("HTTP_LIMIT_EXCEEDED", "http", false);
    }

    this.httpRequests += 1;

    if (isRetry) {
      this.retries += 1;
    }
  }

  private async secureSocket(
    socket: Socket,
    logicalHostname: string,
    addressFamily: 0 | 4 | 6,
    signal: AbortSignal,
  ): Promise<TLSSocket> {
    signal.throwIfAborted();

    const tlsSocket = connectTls({
      socket,
      ...(addressFamily === 0 ? { servername: logicalHostname } : {}),
      rejectUnauthorized: true,
      ALPNProtocols: ["http/1.1"],
      checkServerIdentity: (_hostname, certificate) =>
        checkServerIdentity(logicalHostname, certificate),
    });

    try {
      await once(tlsSocket, "secureConnect", { signal });
    } catch (error) {
      tlsSocket.destroy();
      throw error;
    }

    return tlsSocket;
  }

  private requestResponse(
    socket: Socket | TLSSocket,
    url: URL,
    signal: AbortSignal,
  ): Promise<IncomingMessage> {
    if (signal.aborted) {
      return Promise.reject(signal.reason);
    }

    const headerBudget: HeaderBudget = { fields: 0, bytes: 0 };
    const agent = new PinnedSocketAgent(socket);

    return new Promise<IncomingMessage>((resolve, reject) => {
      let settled = false;
      let informationalError: ProtectedTransportError | undefined;
      const request = makeHttpRequest({
        hostname: url.hostname,
        port: url.protocol === "https:" ? 443 : 80,
        method: "GET",
        path: `${url.pathname}${url.search}`,
        agent,
        setHost: false,
        insecureHTTPParser: false,
        joinDuplicateHeaders: false,
        maxHeaderSize: this.config.limits.http.headerBytes,
        headers: {
          Host: url.host,
          "User-Agent": this.config.userAgent,
          Accept: "text/html,application/xhtml+xml,*/*;q=0.1",
          "Accept-Encoding": "gzip, deflate, br",
          Connection: "close",
        },
      });
      request.maxHeadersCount = this.config.limits.http.headerFields + 1;

      const settleReject = (error: unknown): void => {
        if (settled) {
          return;
        }

        settled = true;
        signal.removeEventListener("abort", onAbort);
        reject(error);
      };
      const settleResolve = (response: IncomingMessage): void => {
        if (settled) {
          response.destroy();
          return;
        }

        settled = true;
        signal.removeEventListener("abort", onAbort);
        resolve(response);
      };
      const onAbort = (): void => {
        const error = abortError(signal.reason);
        settleReject(error);
        request.destroy(error);
      };
      signal.addEventListener("abort", onAbort, { once: true });

      request.on("information", () => {
        informationalError ??= transportError(
          "HTTP_RESPONSE_LIMIT_EXCEEDED",
          "http",
          false,
        );
        settleReject(informationalError);
        request.destroy(informationalError);
      });

      request.once("response", (response) => {
        if (informationalError !== undefined) {
          response.destroy();
          settleReject(informationalError);
          return;
        }

        try {
          consumeHeaders(
            headerBudget,
            response.rawHeaders,
            this.config,
            {
              httpVersion: response.httpVersion,
              statusCode: response.statusCode ?? 0,
              statusMessage: response.statusMessage ?? "",
            },
          );
        } catch (error) {
          response.destroy();
          settleReject(error);
          return;
        }

        settleResolve(response);
      });
      request.once("upgrade", (_response, upgradedSocket) => {
        upgradedSocket.destroy();
        settleReject(transportError("HTTP_REQUEST_FAILED", "http", false));
      });
      request.once("error", (error) => {
        settleReject(error);
      });
      request.end();
    });
  }

  private redirectTarget(
    currentUrl: string,
    statusCode: number,
    rawHeaders: readonly string[],
  ): string | null {
    if (!isRedirect(statusCode)) {
      return null;
    }

    const locations = rawHeaderValues(rawHeaders, "location");

    if (locations.length === 0) {
      return null;
    }

    if (locations.length !== 1) {
      throw transportError("TARGET_REDIRECT_INVALID", "target", false);
    }

    const location = locations[0];

    if (location === undefined) {
      throw transportError("TARGET_REDIRECT_INVALID", "target", false);
    }

    return resolveRedirectTarget(
      currentUrl,
      location,
      this.config.limits.url.codeUnits,
    );
  }

  private async readBody(
    response: IncomingMessage,
    purpose: BodyPurpose,
    signal: AbortSignal,
  ): Promise<Uint8Array> {
    const limits = bodyLimits(this.config, purpose);
    let compressedBytes = 0;
    let decompressedBytes = 0;
    const domainLimit =
      this.config.limits.http.staticDecompressedBytesPerDomain;

    if (this.staticDecompressedBytes >= domainLimit) {
      response.destroy();
      throw transportError("HTTP_RESPONSE_LIMIT_EXCEEDED", "http", false);
    }

    const lengthValues = rawHeaderValues(response.rawHeaders, "content-length");

    if (lengthValues.length > 1) {
      response.destroy();
      throw transportError("HTTP_RESPONSE_LIMIT_EXCEEDED", "http", false);
    }

    const lengthValue = lengthValues[0];

    if (lengthValue !== undefined) {
      if (!/^\d+$/.test(lengthValue)) {
        response.destroy();
        throw transportError("HTTP_RESPONSE_LIMIT_EXCEEDED", "http", false);
      }

      const declaredLength = Number(lengthValue);

      if (!Number.isSafeInteger(declaredLength) || declaredLength > limits.compressedBytes) {
        response.destroy();
        throw transportError("HTTP_RESPONSE_LIMIT_EXCEEDED", "http", false);
      }
    }

    const encoding = contentEncoding(response.headers);
    const decoder = decoderFor(encoding);
    const bodyBuffer = Buffer.allocUnsafe(
      Math.min(
        limits.decompressedBytes,
        domainLimit - this.staticDecompressedBytes,
      ),
    );
    let decoderFailure: unknown;

    decoder?.once("error", (error) => {
      decoderFailure = error;
    });

    const counter = new Transform({
      transform: (chunk: Buffer, _encoding, callback) => {
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        compressedBytes += bytes.length;
        this.staticTransferredBytes += bytes.length;

        if (compressedBytes > limits.compressedBytes) {
          callback(
            transportError("HTTP_RESPONSE_LIMIT_EXCEEDED", "http", false),
          );
          return;
        }

        callback(null, bytes);
      },
    });
    const collector = new Writable({
      write: (chunk: Buffer, _encoding, callback) => {
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        const nextDomainBytes = this.staticDecompressedBytes + bytes.length;
        this.staticDecompressedBytes = Math.min(nextDomainBytes, domainLimit);

        if (
          decompressedBytes + bytes.length > limits.decompressedBytes ||
          nextDomainBytes > domainLimit
        ) {
          callback(
            transportError("HTTP_RESPONSE_LIMIT_EXCEEDED", "http", false),
          );
          return;
        }

        bytes.copy(bodyBuffer, decompressedBytes);
        decompressedBytes += bytes.length;
        callback();
      },
    });

    try {
      if (decoder === undefined) {
        await pipeline(response, counter, collector, { signal });
      } else {
        await pipeline(response, counter, decoder, collector, { signal });
      }

      if (response.rawTrailers.length > 0) {
        throw transportError("HTTP_RESPONSE_LIMIT_EXCEEDED", "http", false);
      }
    } catch (error) {
      response.destroy();

      if (error instanceof ProtectedTransportError) {
        throw error;
      }

      if (signal.aborted) {
        throw abortError(signal.reason);
      }

      if (!response.complete) {
        throw transportError("HTTP_REQUEST_FAILED", "http", true);
      }

      if (
        decoder !== undefined &&
        !isTransientNetworkError(error) &&
        (error === decoderFailure || errorCode(error)?.startsWith("Z_") === true)
      ) {
        throw transportError("HTTP_DECOMPRESSION_FAILED", "http", false);
      }

      throw error;
    }

    return new Uint8Array(bodyBuffer.subarray(0, decompressedBytes));
  }

  private domainTimedOut(): boolean {
    const reason = this.timeoutController.signal.reason;
    return (
      reason instanceof AbortMarker && reason.kind === "domain-timeout"
    );
  }
}

export function createProtectedHttpTransport(
  config: ScanConfig,
): ProtectedHttpTransport {
  return new ProtectedHttpTransportImpl(config);
}

export const TRANSPORT_ERROR_CODES = Object.freeze(
  Object.keys(TRANSPORT_MESSAGES) as readonly TransportErrorCode[],
) satisfies readonly ErrorCode[];
