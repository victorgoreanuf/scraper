import { once } from "node:events";
import { setImmediate as yieldToEventLoop, setTimeout as delay } from "node:timers/promises";

import { decodeStream, type CheerioAPI } from "cheerio";

import type { ScanConfig } from "../config.ts";
import {
  type ErrorCode,
  type ErrorStage,
  type HttpCookieObservation,
  type HttpEntryResult,
  type HttpHeaderObservation,
  type HttpMetadataObservation,
  type HttpPageObservations,
  type HttpRedirectObservation,
  type HttpResourceKind,
  type HttpResourceObservation,
  type HttpResponseObservations,
  type HttpRobotsObservation,
  type ScanError,
} from "../model.ts";
import { createTargetCandidates, TargetPolicyError } from "../network-policy.ts";
import {
  type RobotsCheck,
  RobotsPolicyError,
  type RobotsPolicyService,
} from "./robots.ts";
import {
  ProtectedTransportError,
  type ProtectedTransportHeader,
  type ProtectedTransportResponse,
  type ProtectedTransportResponseHead,
  type ProtectedTransportSession,
  resolveRedirectTarget,
} from "./transport.ts";

const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);
const DENIAL_STATUS_CODES = new Set([401, 403, 407, 451]);
const RETRY_STATUS_CODES = new Set([408, 425, 429]);
const HTML_MEDIA_TYPES = new Set(["text/html", "application/xhtml+xml"]);
const MIME_TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const COOKIE_NAME = MIME_TOKEN;
const COOKIE_VALUE = /^[\u0021\u0023-\u002b\u002d-\u003a\u003c-\u005b\u005d-\u007e]*$/u;
const RETRY_BACKOFF_MS = 100;
const DECODE_CHUNK_BYTES = 65_536;

const LOCAL_MESSAGES = {
  TARGET_NOT_FOUND: "No target candidate returned a usable response.",
  TARGET_ACCESS_DENIED: "The target explicitly denied automated access.",
  TARGET_REDIRECT_INVALID: "The target returned an invalid redirect.",
  TARGET_REDIRECT_LIMIT_EXCEEDED: "The target redirect chain exceeded its limit.",
  ROBOTS_DISALLOWED: "The robots policy disallowed the target path.",
  ROBOTS_UNAVAILABLE: "The robots policy is unavailable.",
  HTTP_REQUEST_FAILED: "The static HTML response could not be parsed safely.",
  HTTP_RESPONSE_LIMIT_EXCEEDED: "Static response observations exceeded a safety limit.",
  UNSUPPORTED_CONTENT_TYPE: "The selected target did not return supported HTML content.",
  DOMAIN_DEADLINE_EXCEEDED: "The active domain deadline was exceeded.",
} as const;

export interface CollectHttpEntryOptions {
  readonly config: ScanConfig;
  readonly session: ProtectedTransportSession;
  readonly robots: RobotsPolicyService;
}

interface ParsedMediaType {
  readonly essence: string;
  readonly charset: string | null;
}

interface CookieExtraction {
  readonly cookies: readonly HttpCookieObservation[];
  readonly truncated: boolean;
}

interface DecodedDocument {
  readonly $: CheerioAPI;
  readonly html: string;
}

interface ExtractedDocument {
  readonly metadata: readonly HttpMetadataObservation[];
  readonly metadataTruncated: boolean;
  readonly resources: readonly HttpResourceObservation[];
  readonly navigationLinks: readonly string[];
  readonly urlsTruncated: boolean;
  readonly text: string;
  readonly textTruncated: boolean;
}

class HtmlDecodeError extends Error {
  readonly partialHtml: string;

  constructor(partialHtml: string, cause: unknown) {
    super(LOCAL_MESSAGES.HTTP_REQUEST_FAILED, { cause });
    this.name = "HtmlDecodeError";
    this.partialHtml = partialHtml;
  }
}

function scanError(
  stage: ErrorStage,
  code: ErrorCode,
  retryable: boolean,
  message: string,
  pageId: "p1" | null = null,
): ScanError {
  return Object.freeze({
    stage,
    code,
    pageId,
    retryable,
    message,
    ruleId: null,
    signal: null,
    limit: null,
    catalogRevision: null,
  });
}

function localError(
  stage: ErrorStage,
  code: keyof typeof LOCAL_MESSAGES,
  retryable = false,
  pageId: "p1" | null = null,
): ScanError {
  return scanError(stage, code, retryable, LOCAL_MESSAGES[code], pageId);
}

function observedError(
  error: ProtectedTransportError | RobotsPolicyError,
  pageId: "p1" | null = null,
): ScanError {
  return scanError(
    error.stage,
    error.code,
    error.retryable,
    error.message,
    pageId,
  );
}

function deadlineError(
  stage: ErrorStage,
  pageId: "p1" | null = null,
): ScanError {
  return localError(stage, "DOMAIN_DEADLINE_EXCEEDED", true, pageId);
}

function failedResult(
  robots: readonly HttpRobotsObservation[],
  error: ScanError,
  response: HttpResponseObservations | null = null,
): HttpEntryResult {
  return Object.freeze({
    kind: "failed" as const,
    response,
    robots: Object.freeze([...robots]),
    errors: Object.freeze([error]) as readonly [ScanError],
  });
}

function trimAsciiWhitespace(value: string): string {
  return value.replace(/^[\u0009\u000a\u000c\u000d\u0020]+|[\u0009\u000a\u000c\u000d\u0020]+$/gu, "");
}

function asciiLowercase(value: string): string {
  return value.replace(/[A-Z]/gu, (character) =>
    String.fromCharCode(character.charCodeAt(0) + 0x20),
  );
}

function splitMimeSegments(value: string): readonly string[] | null {
  const segments: string[] = [];
  let start = 0;
  let quoted = false;
  let escaped = false;

  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    const code = value.charCodeAt(index);

    if ((code < 0x20 && code !== 0x09) || code === 0x7f) {
      return null;
    }

    if (escaped) {
      escaped = false;
      continue;
    }

    if (quoted && character === "\\") {
      escaped = true;
      continue;
    }

    if (character === '"') {
      quoted = !quoted;
      continue;
    }

    if (!quoted && character === ";") {
      segments.push(value.slice(start, index));
      start = index + 1;
    }
  }

  if (quoted || escaped) {
    return null;
  }

  segments.push(value.slice(start));
  return segments;
}

function parseQuotedParameter(value: string): string | null {
  if (value.length < 2 || value[0] !== '"' || value.at(-1) !== '"') {
    return null;
  }

  let parsed = "";

  for (let index = 1; index < value.length - 1; index += 1) {
    const character = value[index];
    const code = value.charCodeAt(index);

    if (character === '"') {
      return null;
    }

    if (character === "\\") {
      const escaped = value[index + 1];

      if (escaped === undefined || index + 1 >= value.length - 1) {
        return null;
      }

      const escapedCode = escaped.charCodeAt(0);

      if ((escapedCode < 0x20 && escapedCode !== 0x09) || escapedCode === 0x7f) {
        return null;
      }

      parsed += escaped;
      index += 1;
      continue;
    }

    if ((code < 0x20 && code !== 0x09) || code === 0x7f) {
      return null;
    }

    parsed += character;
  }

  return parsed;
}

function parseMediaType(value: string): ParsedMediaType | null {
  const segments = splitMimeSegments(value);

  if (segments === null || segments.length === 0) {
    return null;
  }

  const essenceValue = trimAsciiWhitespace(segments[0] ?? "");
  const slash = essenceValue.indexOf("/");

  if (
    slash <= 0
    || slash !== essenceValue.lastIndexOf("/")
    || !MIME_TOKEN.test(essenceValue.slice(0, slash))
    || !MIME_TOKEN.test(essenceValue.slice(slash + 1))
  ) {
    return null;
  }

  let charset: string | null = null;

  for (const rawSegment of segments.slice(1)) {
    const segment = trimAsciiWhitespace(rawSegment);
    const separator = segment.indexOf("=");

    if (separator <= 0) {
      return null;
    }

    const name = trimAsciiWhitespace(segment.slice(0, separator));
    const rawParameterValue = trimAsciiWhitespace(segment.slice(separator + 1));

    if (!MIME_TOKEN.test(name) || rawParameterValue.length === 0) {
      return null;
    }

    const parameterValue = rawParameterValue.startsWith('"')
      ? parseQuotedParameter(rawParameterValue)
      : MIME_TOKEN.test(rawParameterValue)
        ? rawParameterValue
        : null;

    if (parameterValue === null) {
      return null;
    }

    if (charset === null && name.toLowerCase() === "charset") {
      charset = parameterValue;
    }
  }

  return Object.freeze({
    essence: essenceValue.toLowerCase(),
    charset,
  });
}

function headerValues(
  headers: readonly ProtectedTransportHeader[],
  name: string,
): readonly string[] {
  const values: string[] = [];

  for (const header of headers) {
    if (header.name === name) {
      values.push(header.value);
    }
  }

  return values;
}

function mediaTypeFor(
  headers: readonly ProtectedTransportHeader[],
): ParsedMediaType | null {
  const values = headerValues(headers, "content-type");
  return values.length === 1 ? parseMediaType(values[0] ?? "") : null;
}

function admitsHtmlBody(head: ProtectedTransportResponseHead): boolean {
  const mediaType = mediaTypeFor(head.headers);
  return mediaType !== null && HTML_MEDIA_TYPES.has(mediaType.essence);
}

function parseCookiePair(value: string): HttpCookieObservation | null {
  const semicolon = value.indexOf(";");
  const pair = trimAsciiWhitespace(
    semicolon < 0 ? value : value.slice(0, semicolon),
  );
  const separator = pair.indexOf("=");

  if (separator <= 0) {
    return null;
  }

  const name = pair.slice(0, separator);
  let cookieValue = pair.slice(separator + 1);

  if (!COOKIE_NAME.test(name)) {
    return null;
  }

  if (cookieValue.startsWith('"') || cookieValue.endsWith('"')) {
    if (
      cookieValue.length < 2
      || cookieValue[0] !== '"'
      || cookieValue.at(-1) !== '"'
    ) {
      return null;
    }

    cookieValue = cookieValue.slice(1, -1);
  }

  if (!COOKIE_VALUE.test(cookieValue)) {
    return null;
  }

  return Object.freeze({ name, value: cookieValue });
}

function extractCookies(
  headers: readonly ProtectedTransportHeader[],
  config: ScanConfig,
): CookieExtraction {
  const cookies: HttpCookieObservation[] = [];
  let bytes = 0;
  let truncated = false;

  for (const header of headers) {
    if (header.name !== "set-cookie") {
      continue;
    }

    const cookie = parseCookiePair(header.value);

    if (cookie === null || truncated) {
      continue;
    }

    const valueBytes = Buffer.byteLength(cookie.value, "utf8");
    const pairBytes = Buffer.byteLength(cookie.name, "utf8") + valueBytes;

    if (
      cookies.length >= config.limits.cookies.perDomain
      || cookie.name.length > config.limits.cookies.nameCodeUnits
      || valueBytes > config.limits.cookies.valueBytes
      || bytes > config.limits.cookies.totalBytesPerDomain - pairBytes
    ) {
      truncated = true;
      continue;
    }

    cookies.push(cookie);
    bytes += pairBytes;
  }

  return Object.freeze({
    cookies: Object.freeze(cookies),
    truncated,
  });
}

function responseObservations(
  response: Pick<ProtectedTransportResponse, "url" | "statusCode" | "headers">,
  redirects: readonly HttpRedirectObservation[],
  config: ScanConfig,
): HttpResponseObservations {
  const headers: HttpHeaderObservation[] = response.headers.map((header) =>
    Object.freeze({ name: header.name, value: header.value }),
  );
  const cookies = extractCookies(response.headers, config);

  return Object.freeze({
    finalNetworkUrl: response.url,
    statusCode: response.statusCode,
    redirects: Object.freeze([...redirects]),
    headers: Object.freeze(headers),
    cookies: cookies.cookies,
    cookiesTruncated: cookies.truncated,
  });
}

function recordRobotsObservation(
  check: RobotsCheck,
  observations: HttpRobotsObservation[],
  seen: Set<string>,
): void {
  if (check.robotsText === null) {
    return;
  }

  const key = `${check.ownerOrigin}\0${check.fetchedUrl}`;

  if (seen.has(key)) {
    return;
  }

  seen.add(key);
  observations.push(Object.freeze({
    ownerOrigin: check.ownerOrigin,
    fetchedUrl: check.fetchedUrl,
    text: check.robotsText,
  }));
}

function retryAfterMilliseconds(
  response: ProtectedTransportResponse,
  config: ScanConfig,
): number {
  const cap = config.limits.timeMs.retryAfterCap;
  const values = headerValues(response.headers, "retry-after");
  let parsed: number | null = null;

  if (values.length === 1) {
    const value = values[0] ?? "";

    if (/^\d+$/u.test(value)) {
      const seconds = Number(value);

      if (Number.isSafeInteger(seconds)) {
        parsed = seconds > Math.ceil(cap / 1_000)
          ? cap
          : seconds * 1_000;
      }
    } else if (
      /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/u.test(value)
    ) {
      const timestamp = Date.parse(value);

      if (Number.isFinite(timestamp) && new Date(timestamp).toUTCString() === value) {
        parsed = Math.max(0, timestamp - Date.now());
      }
    }
  }

  const desired = Math.max(RETRY_BACKOFF_MS, parsed ?? RETRY_BACKOFF_MS);
  return Math.min(cap, desired);
}

async function waitBeforeRetry(
  milliseconds: number,
  signal: AbortSignal,
): Promise<void> {
  signal.throwIfAborted();

  if (milliseconds === 0) {
    return;
  }

  await delay(milliseconds, undefined, { signal });
}

function shouldRetryStatus(statusCode: number): boolean {
  return RETRY_STATUS_CODES.has(statusCode)
    || (statusCode >= 500 && statusCode <= 599);
}

function isRedirectStatus(
  statusCode: number,
): statusCode is 301 | 302 | 303 | 307 | 308 {
  return REDIRECT_STATUS_CODES.has(statusCode);
}

function abortReason(signal: AbortSignal): Error {
  return signal.reason instanceof Error
    ? signal.reason
    : new DOMException("The operation was aborted.", "AbortError");
}

async function decodeHtml(
  body: Uint8Array,
  mediaType: ParsedMediaType,
  finalUrl: string,
  signal: AbortSignal,
): Promise<DecodedDocument> {
  const chunks: string[] = [];
  let resolveDocument: ((value: CheerioAPI) => void) | undefined;
  let rejectDocument: ((reason?: unknown) => void) | undefined;
  const document = new Promise<CheerioAPI>((resolve, reject) => {
    resolveDocument = resolve;
    rejectDocument = reject;
  });
  const encoding = mediaType.charset === null
    ? {}
    : { transportLayerEncodingLabel: mediaType.charset };
  const stream = decodeStream(
    {
      baseURI: finalUrl,
      encoding,
      xmlMode: mediaType.essence === "application/xhtml+xml",
    },
    (error, $) => {
      if (error === null || error === undefined) {
        resolveDocument?.($);
      } else {
        rejectDocument?.(error);
      }
    },
  );

  // ponytail: Cheerio 1.2 returns its pinned DecodeStream Transform even though
  // the public type is Writable; the regression test guards decoded data events.
  stream.on("data", (chunk: unknown) => {
    chunks.push(Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk));
  });
  stream.once("error", (error) => rejectDocument?.(error));

  const onAbort = (): void => {
    stream.destroy(abortReason(signal));
  };
  signal.addEventListener("abort", onAbort, { once: true });

  try {
    for (let offset = 0; offset < body.byteLength; offset += DECODE_CHUNK_BYTES) {
      signal.throwIfAborted();
      const end = Math.min(body.byteLength, offset + DECODE_CHUNK_BYTES);
      const chunk = Buffer.from(body.subarray(offset, end));

      if (!stream.write(chunk)) {
        await once(stream, "drain", { signal });
      }

      await yieldToEventLoop(undefined, { signal });
    }

    signal.throwIfAborted();
    stream.end();
    const $ = await document;
    signal.throwIfAborted();

    return Object.freeze({ $, html: chunks.join("") });
  } catch (error) {
    stream.destroy(error instanceof Error ? error : undefined);
    void document.catch(() => undefined);
    throw new HtmlDecodeError(chunks.join(""), error);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

function extractMetadata(
  $: CheerioAPI,
  maximum: number,
  signal: AbortSignal,
): { readonly metadata: readonly HttpMetadataObservation[]; readonly truncated: boolean } {
  const metadata: HttpMetadataObservation[] = [];
  const seen = new Set<string>();
  let truncated = false;

  $("meta").each((_index, element) => {
    const node = $(element);
    const rawName = node.attr("name");
    const normalizedName = rawName === undefined
      ? ""
      : asciiLowercase(trimAsciiWhitespace(rawName));
    const rawProperty = node.attr("property");
    const key = normalizedName.length > 0
      ? normalizedName
      : rawProperty === undefined
        ? ""
        : asciiLowercase(trimAsciiWhitespace(rawProperty));
    const value = node.attr("content");

    if (key.length === 0 || value === undefined) {
      return undefined;
    }

    const identity = `${key}\0${value}`;

    if (seen.has(identity)) {
      return undefined;
    }

    if (metadata.length >= maximum) {
      truncated = true;
      return false;
    }

    seen.add(identity);
    metadata.push(Object.freeze({ key, value }));
    return undefined;
  });

  signal.throwIfAborted();
  return Object.freeze({ metadata: Object.freeze(metadata), truncated });
}

function observedUrl(
  baseUrl: string,
  rawValue: string | undefined,
  config: ScanConfig,
): string | null {
  if (rawValue === undefined) {
    return null;
  }

  const value = trimAsciiWhitespace(rawValue);

  if (value.length === 0 || value.length > config.limits.url.codeUnits) {
    return null;
  }

  try {
    return resolveRedirectTarget(baseUrl, value, config.limits.url.codeUnits);
  } catch {
    return null;
  }
}

function documentBaseUrl(
  $: CheerioAPI,
  finalUrl: string,
  config: ScanConfig,
): string {
  let baseUrl = finalUrl;

  $("base[href]").each((_index, element) => {
    const resolved = observedUrl(finalUrl, $(element).attr("href"), config);

    if (resolved !== null) {
      baseUrl = resolved;
      return false;
    }

    return undefined;
  });

  return baseUrl;
}

function resourceKind(
  tagName: string,
  rel: string | undefined,
): HttpResourceKind | null {
  if (tagName === "script") {
    return "script";
  }

  if (tagName === "img") {
    return "image";
  }

  if (tagName === "iframe") {
    return "iframe";
  }

  if (tagName === "link") {
    const tokens = (rel ?? "")
      .split(/[\u0009\u000a\u000c\u000d\u0020]+/u)
      .filter((token) => token.length > 0)
      .map((token) => token.toLowerCase());
    return tokens.includes("stylesheet") ? "stylesheet" : "link";
  }

  return null;
}

function extractUrls(
  $: CheerioAPI,
  finalUrl: string,
  config: ScanConfig,
  signal: AbortSignal,
): {
  readonly resources: readonly HttpResourceObservation[];
  readonly navigationLinks: readonly string[];
  readonly truncated: boolean;
} {
  const baseUrl = documentBaseUrl($, finalUrl, config);
  const resources: HttpResourceObservation[] = [];
  const navigationLinks: string[] = [];
  const seen = new Set<string>();
  let accepted = 0;
  let truncated = false;

  $("script[src],link[href],img[src],iframe[src],a[href]").each(
    (_index, element) => {
      const node = $(element);
      const tagName = element.tagName.toLowerCase();
      const isNavigation = tagName === "a";
      const attribute = isNavigation ? "href" : tagName === "link" ? "href" : "src";
      const url = observedUrl(baseUrl, node.attr(attribute), config);

      if (url === null) {
        return undefined;
      }

      const kind = isNavigation ? null : resourceKind(tagName, node.attr("rel"));

      if (!isNavigation && kind === null) {
        return undefined;
      }

      const identity = `${kind ?? "navigation"}\0${url}`;

      if (seen.has(identity)) {
        return undefined;
      }

      if (accepted >= config.limits.pages.extractedUrlsPerPage) {
        truncated = true;
        return false;
      }

      seen.add(identity);
      accepted += 1;

      if (isNavigation) {
        navigationLinks.push(url);
      } else if (kind !== null) {
        resources.push(Object.freeze({ kind, url }));
      }

      return undefined;
    },
  );

  signal.throwIfAborted();
  return Object.freeze({
    resources: Object.freeze(resources),
    navigationLinks: Object.freeze(navigationLinks),
    truncated,
  });
}

function truncateUtf8(
  value: string,
  maximumBytes: number,
): { readonly value: string; readonly truncated: boolean } {
  const bytes = Buffer.from(value, "utf8");

  if (bytes.length <= maximumBytes) {
    return { value, truncated: false };
  }

  let end = maximumBytes;

  if ((bytes[end] ?? 0) >> 6 === 0b10) {
    while (end > 0 && (bytes[end] ?? 0) >> 6 === 0b10) {
      end -= 1;
    }
  }

  return {
    value: bytes.toString("utf8", 0, end),
    truncated: true,
  };
}

function extractDocument(
  $: CheerioAPI,
  finalUrl: string,
  config: ScanConfig,
  signal: AbortSignal,
): ExtractedDocument {
  signal.throwIfAborted();
  $("template").remove();
  const metadata = extractMetadata(
    $,
    config.limits.pages.metadataPerPage,
    signal,
  );
  const urls = extractUrls($, finalUrl, config, signal);
  $("script,style,noscript").remove();
  const normalizedText = $("body")
    .text()
    .replace(/[\u0009\u000a\u000c\u000d\u0020]+/gu, " ")
    .replace(/^ | $/gu, "");
  const text = truncateUtf8(
    normalizedText,
    config.limits.pages.visibleTextBytesPerPage,
  );
  signal.throwIfAborted();

  return Object.freeze({
    metadata: metadata.metadata,
    metadataTruncated: metadata.truncated,
    resources: urls.resources,
    navigationLinks: urls.navigationLinks,
    urlsTruncated: urls.truncated,
    text: text.value,
    textTruncated: text.truncated,
  });
}

function incompletePage(
  response: HttpResponseObservations,
  html: string,
): HttpPageObservations {
  return Object.freeze({
    pageId: "p1" as const,
    response,
    html,
    text: "",
    textTruncated: false,
    metadata: Object.freeze([]),
    metadataTruncated: false,
    resources: Object.freeze([]),
    navigationLinks: Object.freeze([]),
    urlsTruncated: false,
    collectionState: "failed" as const,
  });
}

function htmlResult(
  page: HttpPageObservations,
  robots: readonly HttpRobotsObservation[],
  errors: readonly ScanError[],
): HttpEntryResult {
  return Object.freeze({
    kind: "html" as const,
    page,
    robots: Object.freeze([...robots]),
    errors: Object.freeze([...errors]),
  });
}

function htmlHeadResponse(
  head: ProtectedTransportResponseHead,
  redirects: readonly HttpRedirectObservation[],
  config: ScanConfig,
): HttpResponseObservations {
  return responseObservations(
    { url: head.url, statusCode: head.statusCode, headers: head.headers },
    redirects,
    config,
  );
}

function errorForCaught(
  error: unknown,
  stage: ErrorStage,
  signal: AbortSignal,
  pageId: "p1" | null = null,
): ScanError {
  if (error instanceof ProtectedTransportError || error instanceof RobotsPolicyError) {
    return observedError(error, pageId);
  }

  if (signal.aborted) {
    return deadlineError(stage, pageId);
  }

  if (stage === "robots") {
    return localError("robots", "ROBOTS_UNAVAILABLE");
  }

  return localError(stage, "HTTP_REQUEST_FAILED");
}

export async function collectHttpEntry(
  domain: string,
  options: CollectHttpEntryOptions,
): Promise<HttpEntryResult> {
  const { config, session, robots } = options;
  const signal = session.getSignal();
  let candidates: readonly string[];

  if (signal.aborted) {
    return failedResult([], deadlineError("target"));
  }

  try {
    candidates = createTargetCandidates(domain).slice(
      0,
      config.limits.target.candidates,
    );
  } catch (error) {
    if (error instanceof TargetPolicyError) {
      return failedResult([], localError("target", "TARGET_NOT_FOUND"));
    }

    throw error;
  }

  for (const candidate of candidates) {
    const candidateRobots: HttpRobotsObservation[] = [];
    const seenRobots = new Set<string>();
    const redirects: HttpRedirectObservation[] = [];
    const seenUrls = new Set<string>([candidate]);
    let currentUrl = candidate;
    let softFailure = false;

    while (true) {
      let response: ProtectedTransportResponse | undefined;
      let acceptedHead: ProtectedTransportResponseHead | null = null;

      for (
        let retry = 0;
        retry <= config.limits.http.transientRetriesPerRequest;
        retry += 1
      ) {
        let robotsCheck: RobotsCheck;

        try {
          robotsCheck = await robots.check(session, currentUrl);
        } catch (error) {
          return failedResult(
            candidateRobots,
            errorForCaught(error, "robots", signal),
          );
        }

        recordRobotsObservation(robotsCheck, candidateRobots, seenRobots);

        if (!robotsCheck.allowed) {
          return failedResult(
            candidateRobots,
            localError("robots", "ROBOTS_DISALLOWED"),
          );
        }

        try {
          acceptedHead = null;
          response = await session.requestHop({
            url: currentUrl,
            purpose: "page",
            isRetry: retry > 0,
            acceptBody: (head) => {
              acceptedHead = head;
              return admitsHtmlBody(head);
            },
          });
        } catch (error) {
          if (
            error instanceof ProtectedTransportError
            && error.retryable
            && error.code !== "DOMAIN_DEADLINE_EXCEEDED"
            && retry < config.limits.http.transientRetriesPerRequest
          ) {
            try {
              await waitBeforeRetry(RETRY_BACKOFF_MS, signal);
            } catch {
              return failedResult(candidateRobots, deadlineError("http"));
            }

            continue;
          }

          const failedHead = acceptedHead as ProtectedTransportResponseHead | null;

          if (
            failedHead !== null
            && failedHead.statusCode >= 200
            && failedHead.statusCode <= 299
            && admitsHtmlBody(failedHead)
          ) {
            const headResponse = htmlHeadResponse(
              failedHead,
              redirects,
              config,
            );
            const failure = errorForCaught(error, "http", signal, "p1");
            const errors = headResponse.cookiesTruncated
              && failure.code !== "HTTP_RESPONSE_LIMIT_EXCEEDED"
              ? [
                  localError("http", "HTTP_RESPONSE_LIMIT_EXCEEDED", false, "p1"),
                  failure,
                ]
              : [failure];
            return htmlResult(
              incompletePage(headResponse, ""),
              candidateRobots,
              errors,
            );
          }

          if (
            error instanceof ProtectedTransportError
            && error.retryable
            && error.code !== "DOMAIN_DEADLINE_EXCEEDED"
          ) {
            softFailure = true;
            break;
          }

          return failedResult(
            candidateRobots,
            errorForCaught(error, "http", signal),
          );
        }

        if (shouldRetryStatus(response.statusCode)) {
          if (retry < config.limits.http.transientRetriesPerRequest) {
            const milliseconds = response.statusCode === 429
              ? retryAfterMilliseconds(response, config)
              : RETRY_BACKOFF_MS;

            try {
              await waitBeforeRetry(milliseconds, signal);
            } catch {
              return failedResult(candidateRobots, deadlineError("http"));
            }

            continue;
          }

          if (response.statusCode === 429) {
            return failedResult(
              candidateRobots,
              localError("target", "TARGET_ACCESS_DENIED"),
            );
          }

          softFailure = true;
        }

        break;
      }

      if (softFailure || response === undefined) {
        break;
      }

      if (isRedirectStatus(response.statusCode)) {
        const nextUrl = response.redirectUrl;

        if (nextUrl === null) {
          return failedResult(
            candidateRobots,
            localError("target", "TARGET_REDIRECT_INVALID"),
          );
        }

        if (
          redirects.length >= config.limits.target.redirectsPerChain
          || seenUrls.has(nextUrl)
        ) {
          return failedResult(
            candidateRobots,
            localError("target", "TARGET_REDIRECT_LIMIT_EXCEEDED"),
          );
        }

        redirects.push(Object.freeze({
          fromUrl: response.url,
          statusCode: response.statusCode,
          toUrl: nextUrl,
        }));
        seenUrls.add(nextUrl);
        currentUrl = nextUrl;
        continue;
      }

      if (response.statusCode >= 300 && response.statusCode <= 399) {
        return failedResult(
          candidateRobots,
          localError("target", "TARGET_REDIRECT_INVALID"),
        );
      }

      if (DENIAL_STATUS_CODES.has(response.statusCode)) {
        return failedResult(
          candidateRobots,
          localError("target", "TARGET_ACCESS_DENIED"),
        );
      }

      if (response.statusCode >= 400 && response.statusCode <= 499) {
        softFailure = true;
        break;
      }

      if (response.statusCode < 200 || response.statusCode > 299) {
        softFailure = true;
        break;
      }

      const observedResponse = responseObservations(response, redirects, config);
      const mediaType = mediaTypeFor(response.headers);
      const extractionErrors: ScanError[] = [];

      if (
        response.statusCode === 204
        || response.statusCode === 205
        || mediaType === null
        || !HTML_MEDIA_TYPES.has(mediaType.essence)
      ) {
        if (observedResponse.cookiesTruncated) {
          extractionErrors.push(
            localError("http", "HTTP_RESPONSE_LIMIT_EXCEEDED"),
          );
        }

        extractionErrors.push(localError("http", "UNSUPPORTED_CONTENT_TYPE"));
        return Object.freeze({
          kind: "non-html" as const,
          response: observedResponse,
          robots: Object.freeze([...candidateRobots]),
          errors: Object.freeze(extractionErrors),
        });
      }

      if (observedResponse.cookiesTruncated) {
        extractionErrors.push(
          localError("http", "HTTP_RESPONSE_LIMIT_EXCEEDED", false, "p1"),
        );
      }

      let decoded: DecodedDocument;

      try {
        decoded = await decodeHtml(
          response.body,
          mediaType,
          response.url,
          signal,
        );
      } catch (error) {
        const partialHtml = error instanceof HtmlDecodeError ? error.partialHtml : "";
        return htmlResult(
          incompletePage(observedResponse, partialHtml),
          candidateRobots,
          [
            ...extractionErrors,
            errorForCaught(error, "http", signal, "p1"),
          ],
        );
      }

      let extracted: ExtractedDocument;

      try {
        extracted = extractDocument(
          decoded.$,
          response.url,
          config,
          signal,
        );
      } catch (error) {
        return htmlResult(
          incompletePage(observedResponse, decoded.html),
          candidateRobots,
          [
            ...extractionErrors,
            errorForCaught(error, "http", signal, "p1"),
          ],
        );
      }

      const truncated =
        observedResponse.cookiesTruncated
        || extracted.metadataTruncated
        || extracted.urlsTruncated
        || extracted.textTruncated;

      if (
        truncated
        && !extractionErrors.some((error) => error.code === "HTTP_RESPONSE_LIMIT_EXCEEDED")
      ) {
        extractionErrors.push(
          localError("http", "HTTP_RESPONSE_LIMIT_EXCEEDED", false, "p1"),
        );
      }

      const page: HttpPageObservations = Object.freeze({
        pageId: "p1" as const,
        response: observedResponse,
        html: decoded.html,
        text: extracted.text,
        textTruncated: extracted.textTruncated,
        metadata: extracted.metadata,
        metadataTruncated: extracted.metadataTruncated,
        resources: extracted.resources,
        navigationLinks: extracted.navigationLinks,
        urlsTruncated: extracted.urlsTruncated,
        collectionState: truncated ? "truncated" as const : "complete" as const,
      });

      return htmlResult(page, candidateRobots, extractionErrors);
    }

    if (!softFailure) {
      break;
    }
  }

  return failedResult([], localError("target", "TARGET_NOT_FOUND"));
}
