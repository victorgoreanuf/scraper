import { createRequire } from "node:module";

import type { ScanConfig } from "../config.ts";
import {
  resolveRedirectTarget,
  type ProtectedTransportSession,
} from "./transport.ts";

const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);
const DENIAL_STATUS_CODES = new Set([401, 403, 407, 451]);
const TRANSIENT_STATUS_CODES = new Set([408, 425, 429]);

const ROBOTS_MESSAGES = {
  ROBOTS_UNAVAILABLE: "The robots policy is unavailable.",
  ROBOTS_LIMIT_EXCEEDED: "The robots policy exceeded a safety limit.",
} as const;

interface ParsedRobotsPolicy {
  isAllowed(url: string, userAgent?: string): boolean | undefined;
}

const require = createRequire(import.meta.url);
const robotsParser = require("robots-parser") as (
  url: string,
  contents: string,
) => ParsedRobotsPolicy;

export type RobotsPolicyErrorCode = keyof typeof ROBOTS_MESSAGES;

export interface RobotsCheck {
  readonly allowed: boolean;
  readonly robotsText: string | null;
  readonly ownerOrigin: string;
  readonly fetchedUrl: string;
}

export interface RobotsPolicyService {
  check(
    session: ProtectedTransportSession,
    url: string,
  ): Promise<RobotsCheck>;
  allowsCached(url: string): boolean;
  clear(): void;
}

export interface RobotsPolicyServiceOptions {
  readonly now?: () => number;
}

export class RobotsPolicyError extends Error {
  readonly code: RobotsPolicyErrorCode;
  readonly stage = "robots" as const;
  readonly retryable: boolean;

  constructor(code: RobotsPolicyErrorCode, retryable: boolean) {
    super(ROBOTS_MESSAGES[code]);
    this.name = "RobotsPolicyError";
    this.code = code;
    this.retryable = retryable;
  }
}

interface RobotsRule {
  readonly directive: "allow" | "disallow";
  readonly pattern: string;
}

interface RobotsGroup {
  readonly userAgents: readonly string[];
  readonly rules: readonly RobotsRule[];
}

interface ParsedRobotsText {
  readonly parserText: string;
  readonly relevantRules: readonly RobotsRule[];
}

interface CachedRobotsPolicy {
  readonly ownerOrigin: string;
  readonly fetchedUrl: string;
  readonly robotsText: string | null;
  readonly parser: ParsedRobotsPolicy | null;
  readonly relevantRules: readonly RobotsRule[];
}

interface RobotsCacheEntry {
  readonly promise: Promise<CachedRobotsPolicy>;
  readonly expiresAt: number;
  readonly policy: CachedRobotsPolicy | null;
}

function robotsError(
  code: RobotsPolicyErrorCode,
  retryable: boolean,
): RobotsPolicyError {
  return new RobotsPolicyError(code, retryable);
}

function splitRobotsLines(text: string): readonly string[] {
  if (text.length === 0) {
    return [];
  }

  const lines = text.split(/\r\n|\r|\n/u);

  if (
    lines.at(-1) === ""
    && (text.endsWith("\n") || text.endsWith("\r"))
  ) {
    lines.pop();
  }

  return lines;
}

function hasForbiddenControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);

    if (
      (code <= 0x1f && code !== 0x09)
      || (code >= 0x7f && code <= 0x9f)
    ) {
      return true;
    }
  }

  return false;
}

function normalizePercentEncoding(value: string): string {
  let encoded: string;

  try {
    encoded = encodeURI(value).replaceAll("%25", "%");
  } catch {
    throw robotsError("ROBOTS_UNAVAILABLE", false);
  }

  return encoded.replace(/%[0-9a-fA-F]{2}/gu, (escape) => {
    const code = Number.parseInt(escape.slice(1), 16);
    const character = String.fromCharCode(code);

    if (/^[A-Za-z0-9._~-]$/u.test(character)) {
      return character;
    }

    return `%${escape.slice(1).toUpperCase()}`;
  });
}

function normalizeUserAgent(value: string): string | null {
  if (!/^(?:\*|[A-Za-z_-]+)$/u.test(value)) {
    return null;
  }

  return value.toLowerCase();
}

function isValidRuleValue(value: string): boolean {
  return (
    value.length === 0
    || (
      (value.startsWith("/") || value.startsWith("*"))
      && !/[\u0009\u0020]/u.test(value)
    )
  );
}

function parseRobotsText(
  text: string,
  config: ScanConfig,
): ParsedRobotsText {
  const lines = splitRobotsLines(text);

  if (lines.length > config.limits.robots.lines) {
    throw robotsError("ROBOTS_LIMIT_EXCEEDED", false);
  }

  const productToken = config.security.robots.productToken.toLowerCase();
  const groups: RobotsGroup[] = [];
  const exactRules: RobotsRule[] = [];
  const wildcardRules: RobotsRule[] = [];
  let currentUserAgents: string[] = [];
  let currentRules: RobotsRule[] = [];
  let exactGroupDefined = false;
  let wildcardGroupDefined = false;
  let ruleAssociations = 0;

  function finalizeGroup(): void {
    if (currentUserAgents.length === 0) {
      currentRules = [];
      return;
    }

    const associationCount = currentUserAgents.length
      * Math.max(currentRules.length, 1);

    if (
      !Number.isSafeInteger(associationCount)
      || ruleAssociations > config.limits.robots.rules - associationCount
    ) {
      throw robotsError("ROBOTS_LIMIT_EXCEEDED", false);
    }

    ruleAssociations += associationCount;
    const frozenAgents = Object.freeze([...currentUserAgents]);
    const frozenRules = Object.freeze([...currentRules]);
    groups.push(Object.freeze({
      userAgents: frozenAgents,
      rules: frozenRules,
    }));

    for (const userAgent of frozenAgents) {
      const selectedRules = userAgent === productToken
        ? exactRules
        : userAgent === "*"
          ? wildcardRules
          : null;

      if (selectedRules === null) {
        continue;
      }

      if (userAgent === productToken) {
        exactGroupDefined = true;
      } else {
        wildcardGroupDefined = true;
      }

      for (const rule of frozenRules) {
        if (rule.pattern.length > 0) {
          selectedRules.push(rule);
        }
      }
    }

    currentUserAgents = [];
    currentRules = [];
  }

  for (const originalLine of lines) {
    const commentIndex = originalLine.indexOf("#");
    const uncommented = (
      commentIndex < 0 ? originalLine : originalLine.slice(0, commentIndex)
    ).trim();

    if (uncommented.length === 0 || hasForbiddenControl(uncommented)) {
      continue;
    }

    const separator = uncommented.indexOf(":");

    if (separator < 0) {
      continue;
    }

    const name = uncommented.slice(0, separator).trim().toLowerCase();
    const value = uncommented.slice(separator + 1).trim();

    if (name.length === 0) {
      continue;
    }

    if (name === "user-agent") {
      const userAgent = normalizeUserAgent(value);

      if (userAgent === null) {
        continue;
      }

      if (currentRules.length > 0) {
        finalizeGroup();
      }

      currentUserAgents.push(userAgent);
      continue;
    }

    if (name !== "allow" && name !== "disallow") {
      continue;
    }

    if (currentUserAgents.length === 0 || !isValidRuleValue(value)) {
      continue;
    }

    const pattern = value.length === 0 ? "" : normalizePercentEncoding(value);

    if (pattern.length > config.limits.robots.ruleCodeUnits) {
      throw robotsError("ROBOTS_LIMIT_EXCEEDED", false);
    }

    currentRules.push(Object.freeze({ directive: name, pattern }));
  }

  finalizeGroup();

  const parserLines: string[] = [];

  for (const group of groups) {
    for (const userAgent of group.userAgents) {
      parserLines.push(`User-agent: ${userAgent}`);
    }

    const rules = group.rules.length === 0
      ? [Object.freeze({ directive: "disallow" as const, pattern: "" })]
      : group.rules;

    for (const rule of rules) {
      parserLines.push(
        `${rule.directive === "allow" ? "Allow" : "Disallow"}: ${rule.pattern}`,
      );
    }
  }

  const relevantRules = exactGroupDefined
    ? exactRules
    : wildcardGroupDefined
      ? wildcardRules
      : [];

  return Object.freeze({
    parserText: parserLines.join("\n"),
    relevantRules: Object.freeze(relevantRules),
  });
}

function decodeRobotsBody(body: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    throw robotsError("ROBOTS_UNAVAILABLE", false);
  }
}

function isNoRulesStatus(statusCode: number): boolean {
  return (
    statusCode >= 400
    && statusCode <= 499
    && !DENIAL_STATUS_CODES.has(statusCode)
    && !TRANSIENT_STATUS_CODES.has(statusCode)
  );
}

function unavailableForStatus(statusCode: number): RobotsPolicyError {
  return robotsError(
    "ROBOTS_UNAVAILABLE",
    TRANSIENT_STATUS_CODES.has(statusCode)
      || (statusCode >= 500 && statusCode <= 599),
  );
}

function matchingUrlAndPath(targetUrl: string): {
  readonly matchingUrl: string;
  readonly path: string;
} {
  const target = new URL(targetUrl);
  const path = normalizePercentEncoding(`${target.pathname}${target.search}`);

  return {
    matchingUrl: `${target.origin}${path}`,
    path,
  };
}

function enforceMatchingWork(
  rules: readonly RobotsRule[],
  path: string,
  maximumStates: number,
): void {
  const pathStates = path.length + 1;
  let states = 0;

  for (const rule of rules) {
    const patternStates = rule.pattern.length * pathStates;

    if (
      !Number.isSafeInteger(patternStates)
      || states > maximumStates - patternStates
    ) {
      throw robotsError("ROBOTS_LIMIT_EXCEEDED", false);
    }

    states += patternStates;
  }
}

function evaluatePolicy(
  policy: CachedRobotsPolicy,
  canonicalUrl: string,
  config: ScanConfig,
): boolean {
  const normalized = matchingUrlAndPath(canonicalUrl);
  enforceMatchingWork(
    policy.relevantRules,
    normalized.path,
    config.limits.robots.matchingStatesPerUrl,
  );

  if (policy.parser === null) {
    return true;
  }

  try {
    const result = policy.parser.isAllowed(
      normalized.matchingUrl,
      config.security.robots.productToken,
    );

    if (result === undefined) {
      throw robotsError("ROBOTS_UNAVAILABLE", false);
    }

    return result;
  } catch (error) {
    if (error instanceof RobotsPolicyError) {
      throw error;
    }

    throw robotsError("ROBOTS_UNAVAILABLE", false);
  }
}

async function fetchRobotsPolicy(
  config: ScanConfig,
  session: ProtectedTransportSession,
  ownerOrigin: string,
): Promise<CachedRobotsPolicy> {
  const ownerRobotsUrl = new URL("/robots.txt", `${ownerOrigin}/`).href;
  const seen = new Set<string>([ownerRobotsUrl]);
  let currentUrl = ownerRobotsUrl;
  let followedRedirects = 0;

  while (true) {
    const response = await session.requestHop({
      url: currentUrl,
      purpose: "robots",
    });

    if (REDIRECT_STATUS_CODES.has(response.statusCode)) {
      const nextUrl = response.redirectUrl;

      if (nextUrl === null) {
        throw robotsError("ROBOTS_UNAVAILABLE", false);
      }

      if (
        followedRedirects >= config.limits.robots.redirects
        || seen.has(nextUrl)
      ) {
        throw robotsError("ROBOTS_LIMIT_EXCEEDED", false);
      }

      followedRedirects += 1;
      seen.add(nextUrl);
      currentUrl = nextUrl;
      continue;
    }

    if (response.statusCode >= 200 && response.statusCode <= 299) {
      const robotsText = decodeRobotsBody(response.body);
      const parsed = parseRobotsText(robotsText, config);
      let parser: ParsedRobotsPolicy;

      try {
        parser = robotsParser(ownerRobotsUrl, parsed.parserText);
      } catch {
        throw robotsError("ROBOTS_UNAVAILABLE", false);
      }

      return Object.freeze({
        ownerOrigin,
        fetchedUrl: currentUrl,
        robotsText,
        parser,
        relevantRules: parsed.relevantRules,
      });
    }

    if (isNoRulesStatus(response.statusCode)) {
      return Object.freeze({
        ownerOrigin,
        fetchedUrl: currentUrl,
        robotsText: null,
        parser: null,
        relevantRules: Object.freeze([]),
      });
    }

    throw unavailableForStatus(response.statusCode);
  }
}

function currentTime(now: () => number): number {
  const value = now();

  if (!Number.isFinite(value)) {
    throw new TypeError("The robots cache clock returned an invalid value.");
  }

  return value;
}

export function createRobotsPolicyService(
  config: ScanConfig,
  options: RobotsPolicyServiceOptions = {},
): RobotsPolicyService {
  const now = options.now ?? (() => performance.now());
  const cache = new Map<string, RobotsCacheEntry>();

  async function policyFor(
    session: ProtectedTransportSession,
    ownerOrigin: string,
  ): Promise<CachedRobotsPolicy> {
    const key = `${ownerOrigin}\0${config.security.robots.productToken}`;
    const time = currentTime(now);
    const existing = cache.get(key);

    if (existing !== undefined && existing.expiresAt > time) {
      return existing.promise;
    }

    if (existing !== undefined) {
      cache.delete(key);
    }

    const promise = fetchRobotsPolicy(config, session, ownerOrigin);
    const pendingEntry: RobotsCacheEntry = {
      promise,
      expiresAt: Number.POSITIVE_INFINITY,
      policy: null,
    };
    cache.set(key, pendingEntry);

    try {
      const policy = await promise;

      if (cache.get(key) === pendingEntry) {
        cache.set(key, {
          promise: Promise.resolve(policy),
          expiresAt: currentTime(now) + config.limits.timeMs.robotsCache,
          policy,
        });
      }

      return policy;
    } catch (error) {
      if (cache.get(key) === pendingEntry) {
        cache.delete(key);
      }

      throw error;
    }
  }

  return Object.freeze({
    async check(
      session: ProtectedTransportSession,
      url: string,
    ): Promise<RobotsCheck> {
      const canonicalUrl = resolveRedirectTarget(
        url,
        url,
        config.limits.url.codeUnits,
      );
      const target = new URL(canonicalUrl);
      const policy = await policyFor(session, target.origin);
      const allowed = evaluatePolicy(policy, canonicalUrl, config);

      return Object.freeze({
        allowed,
        robotsText: policy.robotsText,
        ownerOrigin: policy.ownerOrigin,
        fetchedUrl: policy.fetchedUrl,
      });
    },

    allowsCached(url: string): boolean {
      try {
        const canonicalUrl = resolveRedirectTarget(
          url,
          url,
          config.limits.url.codeUnits,
        );
        const target = new URL(canonicalUrl);
        const key = `${target.origin}\0${config.security.robots.productToken}`;
        const entry = cache.get(key);
        const time = currentTime(now);

        if (
          entry === undefined
          || entry.policy === null
          || entry.expiresAt <= time
        ) {
          if (entry !== undefined && entry.expiresAt <= time) {
            cache.delete(key);
          }
          return false;
        }

        return evaluatePolicy(entry.policy, canonicalUrl, config);
      } catch {
        return false;
      }
    },

    clear(): void {
      cache.clear();
    },
  });
}

export const ROBOTS_POLICY_ERROR_CODES = Object.freeze(
  Object.keys(ROBOTS_MESSAGES) as RobotsPolicyErrorCode[],
);
