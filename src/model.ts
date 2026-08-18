import { readFileSync } from "node:fs";
import { isIP } from "node:net";

import { Ajv2020, type AnySchemaObject } from "ajv/dist/2020.js";

import { computeConfigDigest, type ScanConfig } from "./config.ts";
import { isPublicIpAddress, normalizeHostname } from "./network-policy.ts";

export const PAGE_IDS = ["p1", "p2", "p3"] as const;
export type PageId = (typeof PAGE_IDS)[number];

export const EVIDENCE_SOURCES = [
  "url",
  "header",
  "cookie",
  "html",
  "text",
  "css",
  "meta",
  "script_url",
  "script_content",
  "dom",
  "javascript",
  "network_url",
  "network_hostname",
  "dns_record",
  "tls_issuer",
  "robots",
  "probe",
] as const;
export type EvidenceSource = (typeof EVIDENCE_SOURCES)[number];

export const DNS_RECORD_TYPES = [
  "A",
  "AAAA",
  "CAA",
  "CNAME",
  "MX",
  "NS",
  "PTR",
  "SOA",
  "SRV",
  "TXT",
] as const;
export type DnsRecordType = (typeof DNS_RECORD_TYPES)[number];

export const ERROR_STAGES = [
  "target",
  "robots",
  "http",
  "dns",
  "tls",
  "browser",
  "detect",
] as const;
export type ErrorStage = (typeof ERROR_STAGES)[number];

export const ERROR_CODES = [
  "TARGET_NOT_FOUND",
  "TARGET_ACCESS_DENIED",
  "TARGET_REDIRECT_INVALID",
  "TARGET_REDIRECT_LIMIT_EXCEEDED",
  "ROBOTS_DISALLOWED",
  "ROBOTS_UNAVAILABLE",
  "ROBOTS_LIMIT_EXCEEDED",
  "HTTP_REQUEST_FAILED",
  "HTTP_TIMEOUT",
  "HTTP_LIMIT_EXCEEDED",
  "HTTP_RESPONSE_LIMIT_EXCEEDED",
  "HTTP_DECOMPRESSION_FAILED",
  "UNSUPPORTED_CONTENT_TYPE",
  "DNS_LOOKUP_FAILED",
  "DNS_NO_ADDRESS",
  "DNS_LIMIT_EXCEEDED",
  "TLS_CONNECTION_FAILED",
  "TLS_CERTIFICATE_INVALID",
  "TLS_TIMEOUT",
  "TLS_LIMIT_EXCEEDED",
  "BROWSER_UNAVAILABLE",
  "BROWSER_NAVIGATION_FAILED",
  "BROWSER_TIMEOUT",
  "BROWSER_LIMIT_EXCEEDED",
  "BROWSER_PROXY_FAILED",
  "SSRF_NON_PUBLIC_ADDRESS",
  "SSRF_MIXED_ADDRESSES",
  "SSRF_REMOTE_ADDRESS_MISMATCH",
  "DOMAIN_DEADLINE_EXCEEDED",
  "RESULT_LIMIT_EXCEEDED",
  "REGEX_RULE_TIMEOUT",
  "REGEX_DOMAIN_BUDGET_EXCEEDED",
  "REGEX_EXECUTION_LIMIT",
  "REGEX_WORKER_CRASH",
  "REGEX_WORKER_RESTART_FAILED",
  "DETECTOR_UNAVAILABLE",
] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];

export type Collector = "http" | "browser" | "dns" | "tls";
export type PageRole = "entry" | "detail" | "listing" | "content";
export type DomainStatus = "success" | "partial" | "failed";
export type DetectionType = "direct" | "inferred";
export type MatchKind = "presence" | "value" | "redacted";
export type SafeVersion = string | null;

export interface EvidenceMatch {
  readonly kind: MatchKind;
  readonly value: string | null;
  readonly truncated: boolean;
}

export interface Category {
  readonly id: number;
  readonly name: string;
}

export interface Inference {
  readonly technology: string;
  readonly ruleId: string;
  readonly confidence: number;
  readonly version: SafeVersion;
}

export interface Evidence {
  readonly collector: Collector;
  readonly source: EvidenceSource;
  readonly pageId: PageId | null;
  readonly key: string | null;
  readonly match: EvidenceMatch;
  readonly ruleId: string;
  readonly pattern: string | null;
  readonly confidence: number;
  readonly version: SafeVersion;
}

export interface Technology {
  readonly name: string;
  readonly categories: readonly Category[];
  readonly version: SafeVersion;
  readonly confidence: number;
  readonly type: DetectionType;
  readonly pageIds: readonly PageId[];
  readonly evidence: readonly Evidence[];
  readonly inferredFrom: readonly Inference[];
}

export type PageCollectors =
  | readonly []
  | readonly ["http"]
  | readonly ["http", "browser"];

export interface PageRecord {
  readonly id: PageId;
  readonly role: PageRole;
  readonly url: string;
  readonly httpStatus: number | null;
  readonly collectors: PageCollectors;
}

export interface ScanError {
  readonly stage: ErrorStage;
  readonly code: ErrorCode;
  readonly pageId: PageId | null;
  readonly retryable: boolean;
  readonly message: string;
  readonly ruleId: string | null;
  readonly signal: EvidenceSource | null;
  readonly limit: string | null;
  readonly catalogRevision: string | null;
}

export interface HttpHeaderObservation {
  readonly name: string;
  readonly value: string;
}

export interface HttpCookieObservation {
  readonly name: string;
  readonly value: string;
}

export interface HttpRedirectObservation {
  readonly fromUrl: string;
  readonly statusCode: 301 | 302 | 303 | 307 | 308;
  readonly toUrl: string;
}

export interface HttpMetadataObservation {
  readonly key: string;
  readonly value: string;
}

export type HttpResourceKind =
  | "script"
  | "stylesheet"
  | "image"
  | "iframe"
  | "link";

export interface HttpResourceObservation {
  readonly kind: HttpResourceKind;
  readonly url: string;
}

export interface HttpRobotsObservation {
  readonly ownerOrigin: string;
  readonly fetchedUrl: string;
  readonly text: string;
}

export interface HttpProbeObservation {
  readonly path: string;
  readonly body: string;
}

export interface HttpProbeResult {
  readonly observations: readonly HttpProbeObservation[];
  readonly robots: readonly HttpRobotsObservation[];
  readonly errors: readonly ScanError[];
  readonly completed: boolean;
}

export interface HttpResponseObservations {
  readonly finalNetworkUrl: string;
  readonly statusCode: number;
  readonly redirects: readonly HttpRedirectObservation[];
  readonly headers: readonly HttpHeaderObservation[];
  readonly cookies: readonly HttpCookieObservation[];
  readonly cookiesTruncated: boolean;
  readonly tlsIssuer: string | null;
  readonly tlsHandshakeMs: number | null;
}

export interface DnsRecordObservation {
  readonly type: DnsRecordType;
  readonly value: string;
}

export interface InfrastructureObservations {
  readonly dnsRecords: readonly DnsRecordObservation[];
  readonly tlsIssuer: string | null;
}

export interface InfrastructureResult {
  readonly observations: InfrastructureObservations;
  readonly errors: readonly ScanError[];
  readonly dnsMs: number | null;
  readonly tlsMs: number | null;
  readonly completed: boolean;
}

export interface HttpPageObservations {
  readonly pageId: PageId;
  readonly response: HttpResponseObservations;
  readonly html: string;
  readonly text: string;
  readonly textTruncated: boolean;
  readonly metadata: readonly HttpMetadataObservation[];
  readonly metadataTruncated: boolean;
  readonly resources: readonly HttpResourceObservation[];
  readonly navigationLinks: readonly string[];
  readonly urlsTruncated: boolean;
  readonly collectionState: "complete" | "truncated" | "failed";
}

export type HttpPageResult =
  | {
      readonly kind: "html";
      readonly page: HttpPageObservations;
      readonly robots: readonly HttpRobotsObservation[];
      readonly errors: readonly ScanError[];
    }
  | {
      readonly kind: "non-html";
      readonly pageId: PageId;
      readonly requestedUrl: string;
      readonly response: HttpResponseObservations;
      readonly robots: readonly HttpRobotsObservation[];
      readonly errors: readonly ScanError[];
    }
  | {
      readonly kind: "failed";
      readonly pageId: PageId;
      readonly requestedUrl: string;
      readonly response: HttpResponseObservations | null;
      readonly robots: readonly HttpRobotsObservation[];
      readonly errors: readonly [ScanError];
    }
  | {
      readonly kind: "skipped";
      readonly pageId: PageId;
      readonly requestedUrl: string;
      readonly robots: readonly HttpRobotsObservation[];
      readonly errors: readonly [];
    };

export type HttpEntryResult =
  | {
      readonly kind: "html";
      readonly page: HttpPageObservations;
      readonly robots: readonly HttpRobotsObservation[];
      readonly errors: readonly ScanError[];
    }
  | {
      readonly kind: "non-html";
      readonly response: HttpResponseObservations;
      readonly robots: readonly HttpRobotsObservation[];
      readonly errors: readonly ScanError[];
    }
  | {
      readonly kind: "failed";
      readonly response: HttpResponseObservations | null;
      readonly robots: readonly HttpRobotsObservation[];
      readonly errors: readonly [ScanError];
    };

export type BrowserFact =
  | {
      readonly kind: "presence";
    }
  | {
      readonly kind: "value";
      readonly value: string;
    };

export interface CatalogFactDemand {
  readonly presence: boolean;
  readonly value: boolean;
}

export type CatalogDomFactKind =
  | "exists"
  | "text"
  | "attribute"
  | "property";

export interface CatalogDomFact {
  readonly kind: CatalogDomFactKind;
  readonly name: string | null;
  readonly locator: string;
  readonly demand: CatalogFactDemand;
}

export interface CatalogDomInspection {
  readonly selector: string;
  readonly facts: readonly CatalogDomFact[];
}

export interface CatalogJavascriptInspection {
  readonly path: string;
  readonly segments: readonly string[];
  readonly demand: CatalogFactDemand;
}

export interface CatalogInspectionPlan {
  readonly dom: readonly CatalogDomInspection[];
  readonly javascript: readonly CatalogJavascriptInspection[];
  readonly probePaths: readonly string[];
  readonly dnsRecordTypes: readonly DnsRecordType[];
  readonly tlsIssuer: boolean;
}

export interface BrowserDomObservation {
  readonly pageId: PageId;
  readonly locator: string;
  readonly fact: BrowserFact;
}

export interface BrowserJavascriptObservation {
  readonly pageId: PageId;
  readonly path: string;
  readonly fact: BrowserFact;
}

export interface BrowserScriptBodyObservation {
  readonly pageId: PageId;
  readonly url: string;
  readonly content: string;
}

export interface BrowserPageObservations {
  readonly pageId: PageId;
  readonly finalUrl: string;
  readonly dom: readonly BrowserDomObservation[];
  readonly javascript: readonly BrowserJavascriptObservation[];
  readonly cookies: readonly HttpCookieObservation[];
  readonly networkUrls: readonly string[];
  readonly networkHostnames: readonly string[];
  readonly scriptUrls: readonly string[];
  readonly scriptBodies: readonly BrowserScriptBodyObservation[];
  readonly navigationLinks: readonly string[];
  readonly truncated: boolean;
}

export interface Timings {
  readonly totalMs: number;
  readonly targetMs: number | null;
  readonly robotsMs: number | null;
  readonly httpMs: number | null;
  readonly dnsMs: number | null;
  readonly tlsMs: number | null;
  readonly browserMs: number | null;
  readonly detectMs: number | null;
}

export interface Usage {
  readonly httpRequests: number;
  readonly browserRequests: number;
  readonly retries: number;
  readonly pagesVisited: number;
  readonly probesIssued: number;
  readonly scriptBodiesInspected: number;
  readonly staticTransferredBytes: number;
  readonly browserTransferredBytes: number;
}

export interface RuntimeProvenance {
  readonly node: string;
  readonly playwright: string;
  readonly chromiumRevision: string;
}

export interface CatalogProvenance {
  readonly source: string;
  readonly revision: string;
  readonly digest: string;
}

export interface Provenance {
  readonly scannerVersion: string;
  readonly runtime: RuntimeProvenance;
  readonly catalog: CatalogProvenance;
  readonly configDigest: string;
}

export interface DomainResult {
  readonly schemaVersion: 1;
  readonly runId: string;
  readonly domain: string;
  readonly scannedAt: string;
  readonly status: DomainStatus;
  readonly finalUrl: string | null;
  readonly scanMode: "full";
  readonly pages: readonly PageRecord[];
  readonly technologies: readonly Technology[];
  readonly errors: readonly ScanError[];
  readonly timings: Timings;
  readonly usage: Usage;
  readonly provenance: Provenance;
}

export interface DomainResultValidationContext {
  readonly scanConfig: ScanConfig;
  readonly expectedConfigDigest: string;
  readonly signalAdmitted: boolean;
}

export interface SanitizationLimits {
  readonly urlCodeUnits: number;
  readonly safePathSegmentCodeUnits: number;
  readonly hexTokenMinCodeUnits: number;
  readonly base64UrlTokenMinCodeUnits: number;
}

export interface EvidenceMatchInput {
  readonly source: EvidenceSource;
  readonly key: string | null;
  readonly observedValue: string;
  readonly matchedValue: string;
  readonly scanConfig: ScanConfig;
}

export interface EvidenceVersionInput {
  readonly version: string | null;
  readonly source: EvidenceSource;
  readonly observedValue: string;
  readonly matchedValue: string;
  readonly matchIndex: number;
  readonly matchLength: number;
  readonly scanConfig: ScanConfig;
}

export class DomainResultValidationError extends Error {
  readonly code = "DOMAIN_RESULT_INVALID";
  readonly issues: readonly string[];

  constructor(issues: readonly string[]) {
    super(`DomainResult failed validation: ${issues.join("; ")}`);
    this.name = "DomainResultValidationError";
    this.issues = issues;
  }
}

const resultSchema = JSON.parse(
  readFileSync(
    new URL("../schemas/domain-result.v1.schema.json", import.meta.url),
    "utf8",
  ),
) as AnySchemaObject;

const ajv = new Ajv2020({
  allErrors: false,
  coerceTypes: false,
  ownProperties: true,
  removeAdditional: false,
  strict: true,
  useDefaults: false,
  validateFormats: false,
});
const validateWireResult = ajv.compile(resultSchema);

const errorCodeSet = new Set<string>(ERROR_CODES);
const sensitiveWords = new Set<string>([
  "authorization",
  "cookie",
  "credential",
  "password",
  "secret",
  "signature",
  "session",
  "token",
  "apikey",
]);
const sensitiveHeaderWords = new Set<string>([
  ...sensitiveWords,
  "auth",
  "authenticate",
  "authentication",
  "key",
  "nonce",
]);
const credentialSchemePattern =
  /(?:^|[^A-Za-z0-9_-])(?:basic|bearer|digest|negotiate|ntlm|aws4-hmac-sha256)[\t ]+/iu;
const sensitivePathMarkers = new Set([
  "auth",
  "code",
  "key",
  "password",
  "secret",
  "session",
  "signature",
  "token",
]);
const defaultSanitizationLimits: SanitizationLimits = Object.freeze({
  urlCodeUnits: 2_048,
  safePathSegmentCodeUnits: 64,
  hexTokenMinCodeUnits: 16,
  base64UrlTokenMinCodeUnits: 24,
});
const pageRank = new Map<PageId, number>(PAGE_IDS.map((id, index) => [id, index]));
const collectorRank = new Map<Collector, number>(
  (["http", "browser", "dns", "tls"] as const).map((item, index) => [
    item,
    index,
  ]),
);
const sourceRank = new Map<EvidenceSource, number>(
  EVIDENCE_SOURCES.map((item, index) => [item, index]),
);
const stageRank = new Map<ErrorStage, number>(
  ERROR_STAGES.map((item, index) => [item, index]),
);
const networkErrorStages = [
  "target",
  "robots",
  "http",
  "dns",
  "tls",
  "browser",
] as const;
const errorCodeStages = {
  TARGET_NOT_FOUND: ["target"],
  TARGET_ACCESS_DENIED: ["target"],
  TARGET_REDIRECT_INVALID: ["target"],
  TARGET_REDIRECT_LIMIT_EXCEEDED: ["target"],
  ROBOTS_DISALLOWED: ["robots"],
  ROBOTS_UNAVAILABLE: ["robots"],
  ROBOTS_LIMIT_EXCEEDED: ["robots"],
  HTTP_REQUEST_FAILED: ["http"],
  HTTP_TIMEOUT: ["http"],
  HTTP_LIMIT_EXCEEDED: ["http"],
  HTTP_RESPONSE_LIMIT_EXCEEDED: ["http"],
  HTTP_DECOMPRESSION_FAILED: ["http"],
  UNSUPPORTED_CONTENT_TYPE: ["http"],
  DNS_LOOKUP_FAILED: ["dns"],
  DNS_NO_ADDRESS: ["dns"],
  DNS_LIMIT_EXCEEDED: ["dns"],
  TLS_CONNECTION_FAILED: ["tls"],
  TLS_CERTIFICATE_INVALID: ["tls"],
  TLS_TIMEOUT: ["tls"],
  TLS_LIMIT_EXCEEDED: ["tls"],
  BROWSER_UNAVAILABLE: ["browser"],
  BROWSER_NAVIGATION_FAILED: ["browser"],
  BROWSER_TIMEOUT: ["browser"],
  BROWSER_LIMIT_EXCEEDED: ["browser"],
  BROWSER_PROXY_FAILED: ["browser"],
  SSRF_NON_PUBLIC_ADDRESS: networkErrorStages,
  SSRF_MIXED_ADDRESSES: networkErrorStages,
  SSRF_REMOTE_ADDRESS_MISMATCH: networkErrorStages,
  DOMAIN_DEADLINE_EXCEEDED: ERROR_STAGES,
  RESULT_LIMIT_EXCEEDED: ["detect"],
  REGEX_RULE_TIMEOUT: ["detect"],
  REGEX_DOMAIN_BUDGET_EXCEEDED: ["detect"],
  REGEX_EXECUTION_LIMIT: ["detect"],
  REGEX_WORKER_CRASH: ["detect"],
  REGEX_WORKER_RESTART_FAILED: ["detect"],
  DETECTOR_UNAVAILABLE: ["detect"],
} as const satisfies Record<ErrorCode, readonly ErrorStage[]>;
const stageTimingKeys = {
  target: "targetMs",
  robots: "robotsMs",
  http: "httpMs",
  dns: "dnsMs",
  tls: "tlsMs",
  browser: "browserMs",
  detect: "detectMs",
} as const satisfies Record<ErrorStage, keyof Timings>;
const configDigestCache = new WeakMap<object, string>();

function compareString(left: string, right: string): number {
  if (left < right) {
    return -1;
  }

  if (left > right) {
    return 1;
  }

  return 0;
}

function compareNullableString(left: string | null, right: string | null): number {
  if (left === null) {
    return right === null ? 0 : -1;
  }

  return right === null ? 1 : compareString(left, right);
}

function compareNumber(left: number, right: number): number {
  return left - right;
}

function hasOnlyUnicodeScalars(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);

    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);

      if (next < 0xdc00 || next > 0xdfff) {
        return false;
      }

      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }

  return true;
}

function visitStrings(value: unknown, path: string, issues: string[]): void {
  if (typeof value === "string") {
    if (!hasOnlyUnicodeScalars(value)) {
      issues.push(`${path} contains an unpaired surrogate`);
    }

    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => visitStrings(item, `${path}[${index}]`, issues));
    return;
  }

  if (value !== null && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      visitStrings(child, `${path}.${key}`, issues);
    }
  }
}

function containsOpaqueToken(
  value: string,
  limits: SanitizationLimits = defaultSanitizationLimits,
): boolean {
  function hasRun(
    minimum: number,
    matches: (character: string) => boolean,
  ): boolean {
    let run = 0;

    for (const character of value) {
      run = matches(character) ? run + 1 : 0;

      if (run >= minimum) {
        return true;
      }
    }

    return false;
  }

  return hasRun(
    limits.hexTokenMinCodeUnits,
    (character) => /[0-9a-f]/i.test(character),
  ) || hasRun(
    limits.base64UrlTokenMinCodeUnits,
    (character) => /[A-Za-z0-9_-]/.test(character),
  );
}

function containsSensitiveMarker(
  value: string,
  markers: ReadonlySet<string> = sensitiveWords,
): boolean {
  const tokens = value.toLowerCase().split(/[^a-z0-9]+/u).filter(Boolean);

  return tokens.some((token) => markers.has(token))
    || tokens.some(
      (token, index) => token === "api" && tokens[index + 1] === "key",
    );
}

function isSensitiveToken(
  value: string,
  limits: SanitizationLimits = defaultSanitizationLimits,
): boolean {
  return containsSensitiveMarker(value)
    || containsOpaqueToken(value, limits);
}

function shouldRedactPublicKey(
  value: string,
  limits: SanitizationLimits,
  markers: ReadonlySet<string> = sensitiveWords,
): boolean {
  return !hasOnlyUnicodeScalars(value)
    || value.length > limits.safePathSegmentCodeUnits
    || containsSensitiveMarker(value, markers)
    || containsOpaqueToken(value, limits);
}

function sanitizePath(pathname: string, limits: SanitizationLimits): string {
  const segments = pathname.split("/");
  const decoded = segments.map((segment) => {
    try {
      return decodeURIComponent(segment);
    } catch {
      return null;
    }
  });
  const unsafe = decoded.map((segment) => {
    if (segment === "" || segment === "[redacted]") {
      return false;
    }

    if (
      segment === null
      || segment.length > limits.safePathSegmentCodeUnits
      || !/^[A-Za-z0-9._~-]+$/.test(segment)
    ) {
      return true;
    }

    return isSensitiveToken(segment, limits);
  });

  decoded.forEach((segment, index) => {
    if (segment !== null && sensitivePathMarkers.has(segment.toLowerCase())) {
      unsafe[index] = true;

      if (index > 0) {
        unsafe[index - 1] = true;
      }

      if (index + 1 < unsafe.length) {
        unsafe[index + 1] = true;
      }
    }
  });

  return decoded
    .map((segment, index) => {
      if (segment === "") {
        return "";
      }

      if (segment === "[redacted]" || unsafe[index]) {
        return "%5Bredacted%5D";
      }

      return segment;
    })
    .join("/");
}

function isSafeProbePath(value: string, maximumCodeUnits: number): boolean {
  if (
    value.length === 0
    || value.length > maximumCodeUnits
    || !value.startsWith("/")
    || value.startsWith("//")
    || value.includes("\\")
    || value.includes("?")
    || value.includes("#")
  ) {
    return false;
  }

  try {
    const resolved = new URL(value, "https://catalog-probe.invalid/");
    return resolved.origin === "https://catalog-probe.invalid"
      && resolved.pathname === value
      && resolved.search === ""
      && resolved.hash === "";
  } catch {
    return false;
  }
}

export function sanitizeUrl(
  value: string,
  limits: SanitizationLimits = defaultSanitizationLimits,
): string {
  if (value.length > limits.urlCodeUnits) {
    throw new TypeError("URL exceeds the configured code-unit limit");
  }

  const url = new URL(value);

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new TypeError("Only HTTP(S) URLs can be sanitized");
  }

  url.username = "";
  url.password = "";
  url.hash = "";
  url.pathname = sanitizePath(url.pathname, limits);

  if (url.search !== "") {
    const keys = [...url.searchParams.keys()];

    url.search = "";
    for (const key of keys) {
      const sanitizedKey = shouldRedactPublicKey(key, limits)
        ? "[redacted]"
        : key;
      url.searchParams.append(sanitizedKey, "[redacted]");
    }
  }

  const sanitized = url.href;

  if (sanitized.length > limits.urlCodeUnits) {
    throw new TypeError("Sanitized URL exceeds the configured code-unit limit");
  }

  return sanitized;
}

export function sanitizeEvidenceKey(
  source: EvidenceSource,
  key: string | null,
  scanConfig: ScanConfig,
): string | null {
  if (
    key === null
    || (source !== "cookie" && source !== "header" && source !== "meta")
  ) {
    return key;
  }

  return shouldRedactPublicKey(
      key,
      sanitizationLimits(scanConfig),
      source === "header" ? sensitiveHeaderWords : sensitiveWords,
    )
    ? null
    : key;
}

function truncateCodePoints(value: string, maximum: number): {
  readonly value: string;
  readonly truncated: boolean;
} {
  const points = [...value];
  if (points.length <= maximum) {
    return { value, truncated: false };
  }
  return { value: points.slice(0, maximum).join(""), truncated: true };
}

export function createEvidenceValueMatch(input: EvidenceMatchInput): EvidenceMatch {
  const limits = sanitizationLimits(input.scanConfig);
  const redact = (): EvidenceMatch => ({
    kind: "redacted",
    value: null,
    truncated: false,
  });
  let candidate: string;

  if (
    input.source === "url"
    || input.source === "script_url"
    || input.source === "network_url"
  ) {
    try {
      candidate = sanitizeUrl(input.observedValue, limits);
    } catch {
      return redact();
    }

    if ([...candidate].length > input.scanConfig.limits.evidence.matchCodePoints) {
      return redact();
    }
    return { kind: "value", value: candidate, truncated: false };
  }

  if (input.source === "header") {
    const key = input.key?.toLowerCase() ?? "";
    if (
      containsSensitiveMarker(key, sensitiveHeaderWords)
      || credentialSchemePattern.test(input.observedValue)
      || isSensitiveToken(input.observedValue, limits)
    ) {
      return redact();
    }
    candidate = input.matchedValue;
  } else if (input.source === "meta") {
    if (
      (input.key !== "generator" && input.key !== "application-name")
      || credentialSchemePattern.test(input.observedValue)
      || isSensitiveToken(input.observedValue, limits)
    ) {
      return redact();
    }
    candidate = input.matchedValue;
  } else if (input.source === "network_hostname") {
    candidate = input.observedValue;
  } else if (input.source === "dns_record") {
    if (
      (input.key === "A" && isCanonicalPublicIpAddress(input.observedValue, 4))
      || (input.key === "AAAA"
        && isCanonicalPublicIpAddress(input.observedValue, 6))
      || ((input.key === "CNAME"
        || input.key === "MX"
        || input.key === "NS"
        || input.key === "PTR"
        || input.key === "SRV")
        && isCanonicalPublicHostname(input.observedValue))
    ) {
      candidate = input.observedValue;
      if ([...candidate].length > input.scanConfig.limits.evidence.matchCodePoints) {
        return redact();
      }
    } else {
      return redact();
    }
  } else if (input.source === "tls_issuer") {
    if (isSensitiveToken(input.observedValue, limits)) {
      return redact();
    }
    candidate = input.matchedValue;
  } else {
    return redact();
  }

  if (candidate === "" || !hasOnlyUnicodeScalars(candidate)) {
    return redact();
  }
  const bounded = truncateCodePoints(
    candidate,
    input.scanConfig.limits.evidence.matchCodePoints,
  );
  return {
    kind: "value",
    value: bounded.value,
    truncated: bounded.truncated,
  };
}

export function createEvidenceVersion(input: EvidenceVersionInput): SafeVersion {
  if (
    input.version === null
    || !Number.isSafeInteger(input.matchIndex)
    || !Number.isSafeInteger(input.matchLength)
    || input.matchIndex < 0
    || input.matchLength < 0
    || input.matchIndex + input.matchLength > input.observedValue.length
    || input.observedValue.slice(
      input.matchIndex,
      input.matchIndex + input.matchLength,
    ) !== input.matchedValue
    || input.version.length > input.scanConfig.limits.evidence.versionCodeUnits
    || !/^[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}$/u.test(input.version)
  ) {
    return null;
  }
  const limits = sanitizationLimits(input.scanConfig);
  if (
    input.source === "url"
    || input.source === "script_url"
    || input.source === "network_url"
  ) {
    let parsed: URL;
    let sanitized: URL;
    try {
      parsed = new URL(input.observedValue);
      sanitized = new URL(sanitizeUrl(input.observedValue, limits));
    } catch {
      return null;
    }
    if (
      parsed.username !== ""
      || parsed.password !== ""
      || parsed.pathname !== sanitized.pathname
      || input.observedValue.includes("?")
      || input.observedValue.includes("#")
    ) {
      return null;
    }
  }
  if (
    isSensitiveToken(input.version, limits)
    || credentialSchemePattern.test(input.matchedValue)
    || containsSensitiveMarker(input.matchedValue)
    || containsOpaqueToken(input.matchedValue, limits)
  ) {
    return null;
  }
  return input.version;
}

function isSanitizedCanonicalUrl(
  value: string,
  limits: SanitizationLimits = defaultSanitizationLimits,
): boolean {
  try {
    const url = new URL(value);

    return sanitizeUrl(value, limits) === value
      && isAllowedUrlAuthority(url);
  } catch {
    return false;
  }
}

function isAllowedUrlAuthority(url: URL): boolean {
  if (url.port !== "") {
    return false;
  }

  const hostname = url.hostname;

  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    return isCanonicalPublicIpAddress(hostname.slice(1, -1), 6);
  }

  if (isIP(hostname) === 4) {
    return isCanonicalPublicIpAddress(hostname, 4);
  }

  return isCanonicalPublicHostname(hostname);
}

function isCanonicalPublicHostname(
  value: string,
  maximumCodeUnits = 2_048,
): boolean {
  if (isIP(value) !== 0) {
    return false;
  }

  try {
    return normalizeHostname(value, maximumCodeUnits) === value;
  } catch {
    return false;
  }
}

function isCanonicalPublicIpAddress(value: string, family: 4 | 6): boolean {
  if (isIP(value) !== family || !isPublicIpAddress(value)) {
    return false;
  }

  try {
    const serialized = family === 4
      ? new URL(`http://${value}/`).hostname
      : new URL(`http://[${value}]/`).hostname.slice(1, -1);

    return serialized === value;
  } catch {
    return false;
  }
}

function containsUnsanitizedUrl(
  value: string,
  limits: SanitizationLimits,
): boolean {
  for (const match of value.matchAll(/https?:\/\/[^\s<>"']+/giu)) {
    const url = match[0];

    if (!isSanitizedCanonicalUrl(url, limits)) {
      return true;
    }
  }

  return false;
}

function isDeeplyFrozen(value: unknown): boolean {
  if (typeof value !== "object" || value === null) {
    return true;
  }

  if (!Object.isFrozen(value)) {
    return false;
  }

  return Object.values(value).every(isDeeplyFrozen);
}

function validatedConfigDigest(config: ScanConfig): string {
  const cached = configDigestCache.get(config);

  if (cached !== undefined) {
    return cached;
  }

  const digest = computeConfigDigest(config);

  if (isDeeplyFrozen(config)) {
    configDigestCache.set(config, digest);
  }

  return digest;
}

function assertSorted<T>(
  values: readonly T[],
  compare: (left: T, right: T) => number,
  path: string,
  issues: string[],
): void {
  for (let index = 1; index < values.length; index += 1) {
    const previous = values[index - 1];
    const current = values[index];

    if (previous !== undefined && current !== undefined && compare(previous, current) > 0) {
      issues.push(`${path} is not in canonical order`);
      return;
    }
  }
}

function assertUnique<T>(
  values: readonly T[],
  keyOf: (value: T) => string,
  path: string,
  issues: string[],
): void {
  const seen = new Set<string>();

  for (const value of values) {
    const key = keyOf(value);

    if (seen.has(key)) {
      issues.push(`${path} contains a duplicate`);
      return;
    }

    seen.add(key);
  }
}

function compareCategory(left: Category, right: Category): number {
  return compareNumber(left.id, right.id) || compareString(left.name, right.name);
}

function evidenceIdentity(evidence: Evidence): string {
  return JSON.stringify([
    evidence.ruleId,
    evidence.collector,
    evidence.source,
    evidence.pageId,
    evidence.key,
    evidence.match.kind,
    evidence.match.value,
    evidence.version,
  ]);
}

function compareEvidence(left: Evidence, right: Evidence): number {
  return compareNumber(
    collectorRank.get(left.collector) ?? Number.MAX_SAFE_INTEGER,
    collectorRank.get(right.collector) ?? Number.MAX_SAFE_INTEGER,
  )
    || compareNumber(
      sourceRank.get(left.source) ?? Number.MAX_SAFE_INTEGER,
      sourceRank.get(right.source) ?? Number.MAX_SAFE_INTEGER,
    )
    || compareNullableString(left.pageId, right.pageId)
    || compareNullableString(left.key, right.key)
    || compareString(left.ruleId, right.ruleId)
    || compareString(left.match.kind, right.match.kind)
    || compareNullableString(left.match.value, right.match.value)
    || compareNullableString(left.version, right.version);
}

function compareInference(left: Inference, right: Inference): number {
  return compareString(left.technology, right.technology)
    || compareString(left.ruleId, right.ruleId);
}

function compareError(left: ScanError, right: ScanError): number {
  return compareNumber(
    stageRank.get(left.stage) ?? Number.MAX_SAFE_INTEGER,
    stageRank.get(right.stage) ?? Number.MAX_SAFE_INTEGER,
  )
    || compareString(left.code, right.code)
    || compareNullableString(left.pageId, right.pageId)
    || compareNullableString(left.ruleId, right.ruleId)
    || compareString(left.message, right.message);
}

function calculateDirectConfidence(evidence: readonly Evidence[]): number {
  const rules = new Map<string, number>();

  for (const item of evidence) {
    const previous = rules.get(item.ruleId);

    if (previous === undefined || item.confidence > previous) {
      rules.set(item.ruleId, item.confidence);
    }
  }

  let total = 0;
  for (const confidence of rules.values()) {
    total += confidence;
  }

  return Math.min(100, total);
}

function calculateDirectVersion(evidence: readonly Evidence[]): SafeVersion {
  const scores = new Map<string, Map<string, number>>();

  for (const item of evidence) {
    if (item.version === null) {
      continue;
    }

    const rules = scores.get(item.version) ?? new Map<string, number>();
    const previous = rules.get(item.ruleId);

    if (previous === undefined || item.confidence > previous) {
      rules.set(item.ruleId, item.confidence);
    }

    scores.set(item.version, rules);
  }

  let bestScore = -1;
  const winners: string[] = [];

  for (const [version, rules] of scores) {
    let score = 0;
    for (const confidence of rules.values()) {
      score += confidence;
    }

    if (score > bestScore) {
      bestScore = score;
      winners.length = 0;
      winners.push(version);
    } else if (score === bestScore) {
      winners.push(version);
    }
  }

  return winners.length === 1 ? winners[0] ?? null : null;
}

function calculateInferredVersion(technology: Technology): SafeVersion {
  const versions = new Set(
    technology.inferredFrom
      .filter((item) => item.confidence === technology.confidence)
      .map((item) => item.version)
      .filter((version): version is string => version !== null),
  );

  return versions.size === 1 ? [...versions][0] ?? null : null;
}

function sanitizationLimits(config: ScanConfig): SanitizationLimits {
  return {
    urlCodeUnits: config.limits.url.codeUnits,
    safePathSegmentCodeUnits: config.limits.evidence.safePathSegmentCodeUnits,
    hexTokenMinCodeUnits: config.limits.evidence.hexTokenMinCodeUnits,
    base64UrlTokenMinCodeUnits:
      config.limits.evidence.base64UrlTokenMinCodeUnits,
  };
}

function validateEvidenceValue(
  evidence: Evidence,
  path: string,
  config: ScanConfig,
  issues: string[],
): void {
  if (sanitizeEvidenceKey(evidence.source, evidence.key, config) !== evidence.key) {
    issues.push(`${path}.key exposes a sensitive or opaque locator`);
  }

  if (
    evidence.source === "probe"
    && (
      evidence.key === null
      || !isSafeProbePath(evidence.key, config.limits.url.codeUnits)
    )
  ) {
    issues.push(`${path}.key is not a safe catalog probe path`);
  }

  const value = evidence.match.value;

  if (evidence.match.kind !== "value" || value === null) {
    return;
  }

  if (
    [...value].length > config.limits.evidence.matchCodePoints
    || (evidence.match.truncated
      && [...value].length !== config.limits.evidence.matchCodePoints)
  ) {
    issues.push(`${path}.match.value violates the configured code-point limit`);
  }

  if ((evidence.source === "url"
      || evidence.source === "script_url"
      || evidence.source === "network_url")
    && !isSanitizedCanonicalUrl(value, sanitizationLimits(config))) {
    issues.push(`${path}.match.value is not a canonical sanitized URL`);
  }

  if (
    evidence.source === "network_hostname"
    && !isCanonicalPublicHostname(value)
  ) {
    issues.push(`${path}.match.value is not a canonical public hostname`);
  }

  if (evidence.source === "header") {
    const key = evidence.key?.toLowerCase() ?? "";

    if (
      containsSensitiveMarker(key, sensitiveHeaderWords)
      || credentialSchemePattern.test(value)
      || isSensitiveToken(value, sanitizationLimits(config))
    ) {
      issues.push(`${path}.match.value exposes a sensitive header or token`);
    }
  }

  if (
    evidence.source === "meta"
    && (
      credentialSchemePattern.test(value)
      || isSensitiveToken(value, sanitizationLimits(config))
    )
  ) {
    issues.push(`${path}.match.value exposes a sensitive metadata token`);
  }

  if (evidence.source === "dns_record") {
    if (evidence.key === "A" && !isCanonicalPublicIpAddress(value, 4)) {
      issues.push(`${path}.match.value is not a canonical public IPv4 address`);
    }

    if (evidence.key === "AAAA" && !isCanonicalPublicIpAddress(value, 6)) {
      issues.push(`${path}.match.value is not a canonical public IPv6 address`);
    }

    if (
      evidence.key !== "A"
      && evidence.key !== "AAAA"
      && !isCanonicalPublicHostname(value)
    ) {
      issues.push(`${path}.match.value is not a canonical public DNS hostname`);
    }
  }
}

function validateTechnology(
  technology: Technology,
  index: number,
  pageIds: ReadonlySet<PageId>,
  technologyByName: ReadonlyMap<string, Technology>,
  config: ScanConfig,
  issues: string[],
): void {
  const path = `$.technologies[${index}]`;

  if (technology.confidence < 1) {
    issues.push(`${path}.confidence must be at least 1`);
  }

  assertSorted(technology.categories, compareCategory, `${path}.categories`, issues);
  assertUnique(
    technology.categories,
    (category) => String(category.id),
    `${path}.categories`,
    issues,
  );
  assertSorted(
    technology.pageIds,
    (left, right) => compareNumber(pageRank.get(left) ?? 99, pageRank.get(right) ?? 99),
    `${path}.pageIds`,
    issues,
  );
  assertSorted(technology.evidence, compareEvidence, `${path}.evidence`, issues);
  assertUnique(technology.evidence, evidenceIdentity, `${path}.evidence`, issues);
  assertSorted(technology.inferredFrom, compareInference, `${path}.inferredFrom`, issues);
  assertUnique(
    technology.inferredFrom,
    (inference) => `${inference.technology}\u0000${inference.ruleId}`,
    `${path}.inferredFrom`,
    issues,
  );

  for (const pageId of technology.pageIds) {
    if (!pageIds.has(pageId)) {
      issues.push(`${path}.pageIds references a missing page`);
    }
  }

  technology.evidence.forEach((evidence, evidenceIndex) => {
    if (evidence.pageId !== null && !pageIds.has(evidence.pageId)) {
      issues.push(`${path}.evidence[${evidenceIndex}].pageId references a missing page`);
    }

    validateEvidenceValue(
      evidence,
      `${path}.evidence[${evidenceIndex}]`,
      config,
      issues,
    );
    if (
      evidence.version !== null
      && isSensitiveToken(evidence.version, sanitizationLimits(config))
    ) {
      issues.push(`${path}.evidence[${evidenceIndex}].version may expose a token`);
    }
  });

  const directRuleMetadata = new Map<string, string>();
  technology.evidence.forEach((evidence) => {
    const signature = JSON.stringify([
      evidence.source,
      evidence.source === "cookie" ? null : evidence.key,
      evidence.pattern,
      evidence.confidence,
    ]);
    const previous = directRuleMetadata.get(evidence.ruleId);

    if (previous !== undefined && previous !== signature) {
      issues.push(`${path}.evidence disagrees about immutable rule metadata`);
    }

    directRuleMetadata.set(evidence.ruleId, signature);
  });

  if (technology.type === "direct") {
    const evidencePages = PAGE_IDS.filter((pageId) =>
      technology.evidence.some((evidence) => evidence.pageId === pageId)
    );

    if (JSON.stringify(evidencePages) !== JSON.stringify(technology.pageIds)) {
      issues.push(`${path}.pageIds does not match its evidence page references`);
    }

    if (calculateDirectConfidence(technology.evidence) !== technology.confidence) {
      issues.push(`${path}.confidence does not match unique direct rules`);
    }

    if (calculateDirectVersion(technology.evidence) !== technology.version) {
      issues.push(`${path}.version does not match direct evidence support`);
    }
  } else {
    const inferredConfidence = Math.max(
      0,
      ...technology.inferredFrom.map((inference) => inference.confidence),
    );

    if (technology.confidence !== inferredConfidence) {
      issues.push(`${path}.confidence does not match its winning inferences`);
    }

    if (calculateInferredVersion(technology) !== technology.version) {
      issues.push(`${path}.version does not match its winning inferences`);
    }

    for (const inference of technology.inferredFrom) {
      const parent = technologyByName.get(inference.technology);

      if (inference.confidence !== technology.confidence) {
        issues.push(`${path}.inferredFrom contains a non-winning confidence`);
      } else if (parent === undefined) {
        issues.push(`${path}.inferredFrom references a missing technology`);
      } else if (inference.confidence > parent.confidence) {
        issues.push(`${path}.inferredFrom confidence exceeds its parent`);
      }
    }
  }
}

function validateInferenceGraph(
  technologies: readonly Technology[],
  issues: string[],
): void {
  const byName = new Map(technologies.map((technology) => [technology.name, technology]));
  const depths = new Map<string, number>();
  const unresolvedParents = new Map<string, number>();
  const parentNamesByChild = new Map<string, readonly string[]>();
  const childrenByParent = new Map<string, string[]>();
  const queue: string[] = [];

  for (const technology of technologies) {
    if (technology.type === "direct") {
      depths.set(technology.name, 0);
      queue.push(technology.name);
      continue;
    }

    const parentNames = [...new Set(
      technology.inferredFrom.map((inference) => inference.technology),
    )];
    if (
      parentNames.length === 0
      || parentNames.some((parentName) => !byName.has(parentName))
    ) {
      issues.push("$.technologies contains cyclic or rootless inference provenance");
      return;
    }

    parentNamesByChild.set(technology.name, parentNames);
    unresolvedParents.set(technology.name, parentNames.length);
    for (const parentName of parentNames) {
      const children = childrenByParent.get(parentName) ?? [];
      children.push(technology.name);
      childrenByParent.set(parentName, children);
    }
  }

  for (let queueIndex = 0; queueIndex < queue.length; queueIndex += 1) {
    const parentName = queue[queueIndex]!;
    for (const childName of childrenByParent.get(parentName) ?? []) {
      const remaining = (unresolvedParents.get(childName) ?? 0) - 1;
      unresolvedParents.set(childName, remaining);
      if (remaining !== 0) {
        continue;
      }

      const parentDepths = (parentNamesByChild.get(childName) ?? []).map(
        (name) => depths.get(name),
      );
      if (
        parentDepths.some((depth) => depth === undefined)
        || new Set(parentDepths).size !== 1
      ) {
        issues.push(
          `$.technologies inference parents for ${childName} have different depths`,
        );
        return;
      }

      depths.set(childName, parentDepths[0]! + 1);
      queue.push(childName);
    }
  }

  if (depths.size !== technologies.length) {
    issues.push("$.technologies contains cyclic or rootless inference provenance");
  }
}

function validateConfiguredLimits(
  result: DomainResult,
  config: ScanConfig,
  issues: string[],
): void {
  const output = config.limits.output;
  let evidenceCount = 0;
  let inferenceCount = 0;

  if (result.pages.length > config.limits.pages.topLevelPerDomain) {
    issues.push("$.pages exceeds the configured per-domain limit");
  }

  if (result.technologies.length > output.technologiesPerDomain) {
    issues.push("$.technologies exceeds the configured per-domain limit");
  }

  if (result.errors.length > output.errorsPerDomain) {
    issues.push("$.errors exceeds the configured per-domain limit");
  }

  result.technologies.forEach((technology, index) => {
    const path = `$.technologies[${index}]`;

    if (
      [...technology.name].length
      > config.limits.detector.technologyNameCodePoints
    ) {
      issues.push(`${path}.name exceeds the configured code-point limit`);
    }

    if (
      technology.categories.length
      > config.limits.detector.categoriesPerTechnology
    ) {
      issues.push(`${path}.categories exceeds the configured limit`);
    }

    for (const category of technology.categories) {
      if (
        [...category.name].length
        > config.limits.detector.categoryNameCodePoints
      ) {
        issues.push(`${path}.categories contains an over-limit name`);
        break;
      }
    }

    if (technology.evidence.length > output.evidencePerTechnology) {
      issues.push(`${path}.evidence exceeds the configured limit`);
    }

    if (technology.inferredFrom.length > output.inferencesPerTechnology) {
      issues.push(`${path}.inferredFrom exceeds the configured limit`);
    }

    evidenceCount += technology.evidence.length;
    inferenceCount += technology.inferredFrom.length;

    if (
      technology.version !== null
      && technology.version.length > config.limits.evidence.versionCodeUnits
    ) {
      issues.push(`${path}.version exceeds the configured code-unit limit`);
    }

    technology.evidence.forEach((evidence, evidenceIndex) => {
      if (
        evidence.pattern !== null
        && evidence.pattern.length
          > config.limits.detector.patternSourceCodeUnits
      ) {
        issues.push(
          `${path}.evidence[${evidenceIndex}].pattern exceeds the configured limit`,
        );
      }

      if (
        evidence.version !== null
        && evidence.version.length > config.limits.evidence.versionCodeUnits
      ) {
        issues.push(
          `${path}.evidence[${evidenceIndex}].version exceeds the configured limit`,
        );
      }
    });

    technology.inferredFrom.forEach((inference, inferenceIndex) => {
      if (
        inference.version !== null
        && inference.version.length > config.limits.evidence.versionCodeUnits
      ) {
        issues.push(
          `${path}.inferredFrom[${inferenceIndex}].version exceeds the configured limit`,
        );
      }
    });
  });

  if (evidenceCount > output.evidencePerDomain) {
    issues.push("$.technologies contains too much evidence for this configuration");
  }

  if (inferenceCount > output.inferencesPerDomain) {
    issues.push("$.technologies contains too many inferences for this configuration");
  }

  if (result.usage.httpRequests > config.limits.http.transactionsPerDomain) {
    issues.push("$.usage.httpRequests exceeds the configured limit");
  }

  if (result.usage.browserRequests > config.limits.browser.requestsPerDomain) {
    issues.push("$.usage.browserRequests exceeds the configured limit");
  }

  const initialHttpRequests =
    result.usage.httpRequests - result.usage.retries;
  const retryCapacity =
    initialHttpRequests * config.limits.http.transientRetriesPerRequest;

  if (initialHttpRequests < 0 || result.usage.retries > retryCapacity) {
    issues.push("$.usage.retries is inconsistent with HTTP transactions");
  }

  if (
    result.usage.staticTransferredBytes > 0
    && result.usage.httpRequests === 0
  ) {
    issues.push("$.usage.staticTransferredBytes requires an HTTP request");
  }

  if (
    result.usage.browserTransferredBytes > 0
    && result.usage.browserRequests === 0
  ) {
    issues.push("$.usage.browserTransferredBytes requires a browser request");
  }

  if (
    result.usage.browserRequests > 0
    && result.timings.browserMs === null
  ) {
    issues.push("$.timings.browserMs is null despite browser requests");
  }

  const httpPages = result.pages.filter((page) =>
    page.collectors.some((collector) => collector === "http")
  ).length;
  const browserPages = result.pages.filter((page) =>
    page.collectors.some((collector) => collector === "browser")
  ).length;

  if (httpPages > result.usage.httpRequests) {
    issues.push("$.usage.httpRequests is lower than collected HTTP pages");
  }

  if (browserPages > result.usage.browserRequests) {
    issues.push("$.usage.browserRequests is lower than collected browser pages");
  }

  if (result.usage.probesIssued > config.limits.pages.catalogProbesPerDomain) {
    issues.push("$.usage.probesIssued exceeds the configured limit");
  }

  if (result.usage.probesIssued > result.usage.httpRequests) {
    issues.push("$.usage.probesIssued exceeds $.usage.httpRequests");
  }

  if (result.usage.probesIssued > 0 && result.timings.httpMs === null) {
    issues.push("$.timings.httpMs is null despite catalog probe requests");
  }

  const probeEvidenceKeys = new Set(
    result.technologies.flatMap((technology) =>
      technology.evidence
        .filter((evidence) => evidence.source === "probe")
        .map((evidence) => evidence.key),
    ),
  );
  if (probeEvidenceKeys.size > result.usage.probesIssued) {
    issues.push("$.usage.probesIssued is lower than evidenced catalog probes");
  }

  if (
    result.usage.scriptBodiesInspected > config.limits.scripts.bodiesPerDomain
  ) {
    issues.push("$.usage.scriptBodiesInspected exceeds the configured limit");
  }

  if (
    result.usage.browserTransferredBytes
    > config.limits.browser.transferBytesPerDomain
  ) {
    issues.push("$.usage.browserTransferredBytes exceeds the configured limit");
  }

  const recordBytes = Buffer.byteLength(`${JSON.stringify(result)}\n`, "utf8");
  if (recordBytes > output.jsonlRecordBytes) {
    issues.push("$ exceeds the configured JSONL record byte limit");
  }
}

function validateSemantics(
  result: DomainResult,
  context: DomainResultValidationContext,
): readonly string[] {
  const issues: string[] = [];
  const config = context.scanConfig;
  const urlLimits = sanitizationLimits(config);
  const configDigest = validatedConfigDigest(config);

  visitStrings(result, "$", issues);

  if (
    !isCanonicalPublicHostname(
      result.domain,
      config.limits.hostname.inputCodeUnits,
    )
  ) {
    issues.push("$.domain is not the canonical validated input hostname");
  }

  if (new Date(result.scannedAt).toISOString() !== result.scannedAt) {
    issues.push("$.scannedAt is not a real canonical UTC timestamp");
  }

  if (
    result.finalUrl !== null
    && !isSanitizedCanonicalUrl(result.finalUrl, urlLimits)
  ) {
    issues.push("$.finalUrl is not a canonical sanitized URL");
  }

  if (context.expectedConfigDigest !== configDigest) {
    issues.push("validation context digest does not match scanConfig");
  }

  if (result.provenance.configDigest !== configDigest) {
    issues.push("$.provenance.configDigest does not match the validated configuration");
  }

  if (result.usage.pagesVisited !== result.pages.length) {
    issues.push("$.usage.pagesVisited does not match $.pages.length");
  }

  const pageIds = new Set(result.pages.map((page) => page.id));
  const pageUrls = new Set<string>();
  let finalOrigin: string | null = null;

  if (result.finalUrl !== null) {
    try {
      finalOrigin = new URL(result.finalUrl).origin;
    } catch {
      // The canonical URL issue above is the authoritative diagnostic.
    }
  }

  result.pages.forEach((page, index) => {
    if (!isSanitizedCanonicalUrl(page.url, urlLimits)) {
      issues.push(`$.pages[${index}].url is not a canonical sanitized URL`);
    }

    if (pageUrls.has(page.url)) {
      issues.push("$.pages contains a duplicate URL");
    }
    pageUrls.add(page.url);

    if (index > 0) {
      try {
        const pageUrl = new URL(page.url);

        if (pageUrl.origin !== finalOrigin) {
          issues.push(`$.pages[${index}].url is not on the final origin`);
        }

        if (pageUrl.search !== "") {
          issues.push(`$.pages[${index}].url contains a query string`);
        }
      } catch {
        // The canonical URL issue above is the authoritative diagnostic.
      }
    }
  });

  if (result.pages.length > 0 && result.pages[0]?.url !== result.finalUrl) {
    issues.push("$.pages[0].url does not match $.finalUrl");
  }

  if (result.status === "success") {
    if (result.finalUrl === null || result.pages.length === 0) {
      issues.push("$.status success requires a collected entry page");
    }

    if (
      result.pages.some(
        (page) =>
          page.httpStatus === null
          || page.httpStatus < 200
          || page.httpStatus > 299
          || page.collectors.length !== 2
          || page.collectors[0] !== "http"
          || page.collectors[1] !== "browser",
      )
    ) {
      issues.push("$.status success requires full HTTP/browser page collection");
    }

    const requiredTimings = [
      "targetMs",
      "robotsMs",
      "httpMs",
      "browserMs",
      "detectMs",
    ] as const;

    if (requiredTimings.some((key) => result.timings[key] === null)) {
      issues.push("$.status success requires all mandatory stage timings");
    }
  }

  const stageTimings = [
    result.timings.targetMs,
    result.timings.robotsMs,
    result.timings.httpMs,
    result.timings.dnsMs,
    result.timings.tlsMs,
    result.timings.browserMs,
    result.timings.detectMs,
  ];

  if (stageTimings.some((timing) => timing !== null && timing > result.timings.totalMs)) {
    issues.push("$.timings contains a stage longer than totalMs");
  }

  if (result.technologies.length > 0 && result.timings.detectMs === null) {
    issues.push("$.timings.detectMs is null despite emitted detections");
  }

  if (
    result.pages.some((page) =>
      page.collectors.some((collector) => collector === "http")
    )
    && result.timings.httpMs === null
  ) {
    issues.push("$.timings.httpMs is null despite an HTTP page collector");
  }

  if (
    result.pages.some((page) =>
      page.collectors.some((collector) => collector === "browser")
    )
    && result.timings.browserMs === null
  ) {
    issues.push("$.timings.browserMs is null despite a browser page collector");
  }

  const evidence = result.technologies.flatMap((technology) => technology.evidence);

  if (
    evidence.some((item) => item.collector === "dns")
    && result.timings.dnsMs === null
  ) {
    issues.push("$.timings.dnsMs is null despite DNS evidence");
  }

  if (
    evidence.some((item) => item.collector === "tls")
    && result.timings.tlsMs === null
  ) {
    issues.push("$.timings.tlsMs is null despite TLS evidence");
  }

  assertSorted(
    result.pages.slice(1),
    (left, right) => compareString(left.url, right.url),
    "$.pages[1..]",
    issues,
  );
  assertSorted(
    result.technologies,
    (left, right) => compareString(left.name, right.name),
    "$.technologies",
    issues,
  );
  assertUnique(
    result.technologies,
    (technology) => technology.name,
    "$.technologies",
    issues,
  );
  assertSorted(result.errors, compareError, "$.errors", issues);
  assertUnique(
    result.errors,
    (error) => JSON.stringify([
      error.stage,
      error.code,
      error.pageId,
      error.ruleId,
      error.message,
    ]),
    "$.errors",
    issues,
  );

  const technologyByName = new Map(
    result.technologies.map((technology) => [technology.name, technology]),
  );
  const categoryNames = new Map<number, string>();

  result.technologies.forEach((technology) => {
    technology.categories.forEach((category) => {
      const previous = categoryNames.get(category.id);

      if (previous !== undefined && previous !== category.name) {
        issues.push("$.technologies assigns multiple names to one category ID");
      }

      categoryNames.set(category.id, category.name);
    });
  });
  result.technologies.forEach((technology, index) =>
    validateTechnology(
      technology,
      index,
      pageIds,
      technologyByName,
      config,
      issues,
    )
  );
  validateInferenceGraph(result.technologies, issues);

  result.errors.forEach((error, index) => {
    if (!errorCodeSet.has(error.code)) {
      issues.push(`$.errors[${index}].code is not registered`);
    }

    if (error.pageId !== null && !pageIds.has(error.pageId)) {
      issues.push(`$.errors[${index}].pageId references a missing page`);
    }

    if (errorCodeSet.has(error.code)) {
      const allowedStages = errorCodeStages[error.code] as readonly ErrorStage[];

      if (!allowedStages.includes(error.stage)) {
        issues.push(`$.errors[${index}].code is incompatible with its stage`);
      }
    }

    if (result.timings[stageTimingKeys[error.stage]] === null) {
      issues.push(`$.timings.${stageTimingKeys[error.stage]} is null despite an error`);
    }

    if (error.catalogRevision !== null
      && error.catalogRevision !== result.provenance.catalog.revision) {
      issues.push(`$.errors[${index}].catalogRevision does not match provenance`);
    }

    if (
      isSensitiveToken(error.message, urlLimits)
      || containsUnsanitizedUrl(error.message, urlLimits)
    ) {
      issues.push(`$.errors[${index}].message may expose unsanitized data`);
    }
  });

  if (typeof context.signalAdmitted !== "boolean") {
    issues.push("validation context must declare signalAdmitted");
  } else if (result.status === "success" && !context.signalAdmitted) {
    issues.push("$.status success requires an admitted signal");
  } else if (context.signalAdmitted && result.status === "failed") {
    issues.push("$.status is failed even though a signal was admitted");
  } else if (!context.signalAdmitted && result.status === "partial") {
    issues.push("$.status is partial even though no signal was admitted");
  } else if (
    !context.signalAdmitted
    && (result.finalUrl !== null || result.pages.length > 0)
  ) {
    issues.push("a no-signal result cannot contain a final URL or page");
  }

  validateConfiguredLimits(result, config, issues);

  return issues;
}

export function validateDomainResult(
  value: unknown,
  context: DomainResultValidationContext,
): DomainResult {
  if (!validateWireResult(value)) {
    const issue = validateWireResult.errors?.[0];
    const path = issue?.instancePath === "" ? "$" : `$${issue?.instancePath ?? ""}`;

    throw new DomainResultValidationError([
      `${path} violates the DomainResult v1 wire schema`,
    ]);
  }

  const result = value as DomainResult;
  const issues = validateSemantics(result, context);

  if (issues.length > 0) {
    throw new DomainResultValidationError(issues);
  }

  return result;
}
