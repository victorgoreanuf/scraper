import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  opendirSync,
  readFileSync,
  readSync,
  type Dir,
  type Dirent,
} from "node:fs";
import { fileURLToPath } from "node:url";

import { Ajv2020, type AnySchemaObject } from "ajv/dist/2020.js";
import { load as loadHtml } from "cheerio";

import type { ScanConfig } from "../config.ts";
import { DNS_RECORD_TYPES } from "../model.ts";
import type {
  CatalogDomFactKind,
  CatalogInspectionPlan,
  Category,
  DnsRecordType,
  EvidenceSource,
} from "../model.ts";

export type {
  CatalogDomFact,
  CatalogDomFactKind,
  CatalogDomInspection,
  CatalogInspectionPlan,
  CatalogJavascriptInspection,
} from "../model.ts";

export const CATALOG_SOURCE = "enthec/webappanalyzer";
export const CATALOG_REVISION =
  "5e7c47b1d441ded0bd476b252261e87634349f96";
export const UPSTREAM_RULE_NAMESPACE = "enthec/webappanalyzer:rule-v1";
export const CUSTOM_RULE_NAMESPACE =
  "website-technologies-scraper/custom:rule-v1";
export const CATALOG_CORRECTIONS_SCHEMA =
  "website-technologies-scraper/catalog-corrections-v1";
export const CATALOG_CORRECTIONS_REVISION = "2026-08-20.1";
export const PINNED_UPSTREAM_DIGEST =
  "sha256:cdcccc905a14bbc7ad35a7ea6de636a2e6e51280c6ebbe5ba14f5e55aac18c8f";

const fixedSchemaUrl = new URL(
  "../../fingerprints/upstream/webappanalyzer/schema.json",
  import.meta.url,
);
const fixedSchemaBytes = readFileSync(fixedSchemaUrl);
const fixedSchemaHash = createHash("sha256").update(fixedSchemaBytes).digest("hex");

if (
  fixedSchemaHash
  !== "4dad6720aab3ad69e0727d7aee64d67f334fc5910ff942ca25067e6ae819441e"
) {
  throw new Error("The reviewed WebAppAnalyzer schema bytes do not match the pin");
}

const fixedSchema = JSON.parse(fixedSchemaBytes.toString("utf8")) as AnySchemaObject;
const catalogAjv = new Ajv2020({
  allErrors: false,
  coerceTypes: false,
  ownProperties: true,
  removeAdditional: false,
  strict: true,
  // The immutable upstream schema omits type: object around one required block.
  strictTypes: false,
  useDefaults: false,
  validateFormats: false,
});
const validateTechnologyDocument = catalogAjv.compile(fixedSchema);

const upstreamTechnologyFiles = [
  "_.json",
  ..."abcdefghijklmnopqrstuvwxyz".split("").map((letter) => `${letter}.json`),
] as const;
const expectedUpstreamRootEntries = [
  "categories.json",
  "schema.json",
  "technologies",
] as const;
const ruleSignals: readonly EvidenceSource[] = [
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
  "dns_record",
  "tls_issuer",
  "robots",
  "probe",
];
const signalRank = new Map(ruleSignals.map((signal, index) => [signal, index]));
const supportedDnsTypes = new Set<string>(DNS_RECORD_TYPES);

export type CatalogErrorCode =
  | "CATALOG_IO_FAILED"
  | "CATALOG_INVALID"
  | "CATALOG_LIMIT_EXCEEDED";

export class FingerprintCatalogError extends Error {
  readonly code: CatalogErrorCode;

  constructor(code: CatalogErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "FingerprintCatalogError";
    this.code = code;
  }
}

export type CatalogFileKind =
  | "schema"
  | "categories"
  | "technologies"
  | "corrections";

export interface CatalogInputFile {
  readonly kind: CatalogFileKind;
  readonly namespace: string;
  readonly relativePath: string;
  readonly bytes: Uint8Array;
}

export interface CatalogCompilationInput {
  readonly source: string;
  readonly revision: string;
  readonly files: readonly CatalogInputFile[];
}

export interface CompiledFingerprintRule {
  readonly ruleId: string;
  readonly namespace: string;
  readonly technology: string;
  readonly source: EvidenceSource;
  readonly locator: string | null;
  readonly locatorPattern: string | null;
  readonly original: string;
  readonly pattern: string | null;
  readonly matchMode: "presence" | "literal" | "regex";
  readonly confidence: number;
  readonly versionTemplate: string | null;
}

export interface CompiledImplication {
  readonly technology: string;
  readonly ruleId: string;
  readonly confidence: number;
  readonly version: string | null;
}

export interface CompiledTechnologyDefinition {
  readonly name: string;
  readonly categories: readonly Category[];
  readonly requires: readonly string[];
  readonly requiresCategory: readonly number[];
  readonly implies: readonly CompiledImplication[];
  readonly excludes: readonly string[];
}

export interface CatalogKeyedRuleIndex {
  readonly locator: string;
  readonly ruleOrdinals: readonly number[];
}

export interface CatalogSignalIndex {
  readonly source: EvidenceSource;
  readonly unkeyedRuleOrdinals: readonly number[];
  readonly keyed: readonly CatalogKeyedRuleIndex[];
  readonly patternLocatorRuleOrdinals: readonly number[];
}

export interface CompiledFingerprintCatalog {
  readonly source: string;
  readonly revision: string;
  readonly digest: string;
  readonly categories: readonly Category[];
  readonly technologies: readonly CompiledTechnologyDefinition[];
  readonly rules: readonly CompiledFingerprintRule[];
  readonly indexes: readonly CatalogSignalIndex[];
  readonly inspectionPlan: CatalogInspectionPlan;
  readonly declarationCount: number;
  readonly relationshipCount: number;
  readonly regexSourceCount: number;
  readonly regexSourceCodeUnits: number;
}

interface TaggedRule {
  readonly pattern: string;
  readonly confidence: number;
  readonly versionTemplate: string | null;
}

interface DraftTechnology {
  readonly namespace: string;
  readonly name: string;
  readonly value: Record<string, unknown>;
}

interface ParsedCatalogInputFile extends CatalogInputFile {
  readonly value: unknown;
}

interface CatalogRuleReplacement {
  readonly targetRuleId: string;
  readonly technology: string;
  readonly source: EvidenceSource;
  readonly locator: string | null;
  readonly original: string;
}

interface CatalogCorrections {
  readonly dropTechnologies: ReadonlySet<string>;
  readonly dropRules: ReadonlySet<string>;
  readonly replaceRules: ReadonlyMap<string, CatalogRuleReplacement>;
}

interface MutableFactDemand {
  presence: boolean;
  value: boolean;
}

interface MutableDomFact {
  readonly kind: CatalogDomFactKind;
  readonly name: string | null;
  readonly locator: string;
  readonly demand: MutableFactDemand;
}

const EVIDENCE_KEY_CODE_UNITS = 2_048;
const domFactRank = new Map<CatalogDomFactKind, number>([
  ["exists", 0],
  ["text", 1],
  ["attribute", 2],
  ["property", 3],
]);

function compareString(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function addRuleDemand(
  demand: MutableFactDemand,
  matchMode: CompiledFingerprintRule["matchMode"],
): void {
  if (matchMode === "presence") {
    demand.presence = true;
  } else {
    demand.value = true;
  }
}

function createInspectionPlan(
  rules: readonly CompiledFingerprintRule[],
  probePaths: ReadonlySet<string>,
): CatalogInspectionPlan {
  const domBySelector = new Map<string, Map<string, MutableDomFact>>();
  const javascriptByPath = new Map<string, MutableFactDemand>();
  const dnsRecordTypes = new Set<DnsRecordType>();
  let tlsIssuer = false;

  for (const rule of rules) {
    if (rule.source === "dom") {
      const locator = rule.locator;
      if (locator === null) {
        throw new FingerprintCatalogError(
          "CATALOG_INVALID",
          "Compiled DOM rule is missing its locator",
        );
      }
      const [selector, rawKind, name] = JSON.parse(locator) as [
        string,
        "exists" | "text" | "attributes" | "properties",
        string | null,
      ];
      const kind: CatalogDomFactKind = rawKind === "attributes"
        ? "attribute"
        : rawKind === "properties"
          ? "property"
          : rawKind;
      const facts = domBySelector.get(selector) ?? new Map<string, MutableDomFact>();
      const fact = facts.get(locator) ?? {
        kind,
        name,
        locator,
        demand: { presence: false, value: false },
      };
      addRuleDemand(fact.demand, rule.matchMode);
      facts.set(locator, fact);
      domBySelector.set(selector, facts);
      continue;
    }

    if (rule.source === "javascript") {
      const path = rule.locator;
      if (path === null) {
        throw new FingerprintCatalogError(
          "CATALOG_INVALID",
          "Compiled JavaScript rule is missing its path",
        );
      }
      const demand = javascriptByPath.get(path) ?? {
        presence: false,
        value: false,
      };
      addRuleDemand(demand, rule.matchMode);
      javascriptByPath.set(path, demand);
      continue;
    }

    if (rule.source === "dns_record") {
      if (rule.locator === null || !supportedDnsTypes.has(rule.locator)) {
        throw new FingerprintCatalogError(
          "CATALOG_INVALID",
          "Compiled DNS rule is missing a supported record type",
        );
      }
      dnsRecordTypes.add(rule.locator as DnsRecordType);
      continue;
    }

    if (rule.source === "tls_issuer") {
      tlsIssuer = true;
    }
  }

  return {
    dom: [...domBySelector]
      .sort(([left], [right]) => compareString(left, right))
      .map(([selector, facts]) => ({
        selector,
        facts: [...facts.values()]
          .sort((left, right) =>
            (domFactRank.get(left.kind) ?? Number.MAX_SAFE_INTEGER)
              - (domFactRank.get(right.kind) ?? Number.MAX_SAFE_INTEGER)
            || compareString(left.name ?? "", right.name ?? "")
            || compareString(left.locator, right.locator))
          .map((fact) => ({
            kind: fact.kind,
            name: fact.name,
            locator: fact.locator,
            demand: {
              presence: fact.demand.presence,
              value: fact.demand.value,
            },
          })),
      })),
    javascript: [...javascriptByPath]
      .sort(([left], [right]) => compareString(left, right))
      .map(([path, demand]) => ({
        path,
        segments: (path.startsWith(".") ? path.slice(1) : path).split("."),
        demand: {
          presence: demand.presence,
          value: demand.value,
        },
      })),
    probePaths: [...probePaths].sort(compareString),
    dnsRecordTypes: DNS_RECORD_TYPES.filter((type) => dnsRecordTypes.has(type)),
    tlsIssuer,
  };
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

function assertBoundedString(
  value: unknown,
  label: string,
  maximumCodeUnits: number,
  allowEmpty = false,
): asserts value is string {
  if (
    typeof value !== "string"
    || (!allowEmpty && value.trim() === "")
    || value.length > maximumCodeUnits
    || !hasOnlyUnicodeScalars(value)
    || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)
  ) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      `${label} is not a bounded valid string`,
    );
  }
}

function assertNoAsciiControl(value: string, label: string): void {
  if (/[\u0000-\u001f\u007f]/u.test(value)) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      `${label} must not contain control characters`,
    );
  }
}

function assertRecord(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (
    typeof value !== "object"
    || value === null
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new FingerprintCatalogError("CATALOG_INVALID", `${label} must be an object`);
  }
}

function assertStringArray(value: unknown, label: string): asserts value is string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      `${label} must be an array of strings`,
    );
  }
}

function sha256Tuple(values: readonly unknown[]): string {
  const digest = createHash("sha256")
    .update(JSON.stringify(values), "utf8")
    .digest("hex");
  return `sha256:${digest}`;
}

function lengthPrefix(length: number): Buffer {
  const value = Buffer.allocUnsafe(8);
  value.writeBigUInt64BE(BigInt(length));
  return value;
}

export function computeCatalogDigest(files: readonly CatalogInputFile[]): string {
  const hash = createHash("sha256");
  const ordered = [...files].sort((left, right) =>
    Buffer.compare(
      Buffer.from(left.relativePath, "utf8"),
      Buffer.from(right.relativePath, "utf8"),
    ));

  for (const file of ordered) {
    const path = Buffer.from(file.relativePath, "utf8");
    const bytes = Buffer.from(file.bytes);
    hash.update(lengthPrefix(path.length));
    hash.update(path);
    hash.update(lengthPrefix(bytes.length));
    hash.update(bytes);
  }

  return `sha256:${hash.digest("hex")}`;
}

function parseJsonString(text: string, start: number): { value: string; end: number } {
  let index = start + 1;

  while (index < text.length) {
    const character = text[index];
    if (character === '"') {
      const raw = text.slice(start, index + 1);
      return { value: JSON.parse(raw) as string, end: index + 1 };
    }

    if (character === "\\") {
      index += 1;
      if (text[index] === "u") {
        index += 4;
      }
    }

    index += 1;
  }

  throw new FingerprintCatalogError("CATALOG_INVALID", "JSON string is unterminated");
}

// ponytail: native JSON.parse cannot detect duplicate members, so this small
// structural scan closes that deterministic-input gap without another package.
function assertJsonStructure(
  text: string,
  relativePath: string,
  maximumDepth: number,
): void {
  let index = 0;

  function skipWhitespace(): void {
    while (/[\u0009\u000a\u000d\u0020]/u.test(text[index] ?? "")) {
      index += 1;
    }
  }

  function fail(message: string): never {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      `${relativePath} ${message} near offset ${index}`,
    );
  }

  function parseValue(depth: number): void {
    if (depth > maximumDepth) {
      throw new FingerprintCatalogError(
        "CATALOG_LIMIT_EXCEEDED",
        `${relativePath} exceeds the configured JSON depth`,
      );
    }

    skipWhitespace();
    const character = text[index];

    if (character === "{") {
      parseObject(depth + 1);
      return;
    }

    if (character === "[") {
      parseArray(depth + 1);
      return;
    }

    if (character === '"') {
      index = parseJsonString(text, index).end;
      return;
    }

    const remainder = text.slice(index);
    const scalar = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u.exec(
      remainder,
    );
    if (scalar === null) {
      fail("contains invalid JSON");
    }
    index += scalar[0].length;
  }

  function parseObject(depth: number): void {
    index += 1;
    const keys = new Set<string>();
    skipWhitespace();
    if (text[index] === "}") {
      index += 1;
      return;
    }

    while (index < text.length) {
      skipWhitespace();
      if (text[index] !== '"') {
        fail("contains a non-string object key");
      }
      const parsed = parseJsonString(text, index);
      if (keys.has(parsed.value)) {
        throw new FingerprintCatalogError(
          "CATALOG_INVALID",
          `${relativePath} contains duplicate JSON member ${JSON.stringify(parsed.value)}`,
        );
      }
      keys.add(parsed.value);
      index = parsed.end;
      skipWhitespace();
      if (text[index] !== ":") {
        fail("is missing an object colon");
      }
      index += 1;
      parseValue(depth);
      skipWhitespace();
      if (text[index] === "}") {
        index += 1;
        return;
      }
      if (text[index] !== ",") {
        fail("is missing an object comma");
      }
      index += 1;
    }

    fail("contains an unterminated object");
  }

  function parseArray(depth: number): void {
    index += 1;
    skipWhitespace();
    if (text[index] === "]") {
      index += 1;
      return;
    }

    while (index < text.length) {
      parseValue(depth);
      skipWhitespace();
      if (text[index] === "]") {
        index += 1;
        return;
      }
      if (text[index] !== ",") {
        fail("is missing an array comma");
      }
      index += 1;
    }

    fail("contains an unterminated array");
  }

  parseValue(0);
  skipWhitespace();
  if (index !== text.length) {
    fail("contains trailing JSON data");
  }
}

function parseCatalogJson(
  bytes: Uint8Array,
  relativePath: string,
  maximumDepth: number,
): unknown {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      `${relativePath} is not valid UTF-8`,
      { cause: error },
    );
  }

  assertJsonStructure(text, relativePath, maximumDepth);
  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      `${relativePath} is not valid JSON`,
      { cause: error },
    );
  }
}

function parseTags(
  pattern: string,
  tagSegments: readonly string[],
  label: string,
  confidenceMinimum: number,
): TaggedRule {
  let confidence = 100;
  let versionTemplate: string | null = null;
  const seen = new Set<string>();

  for (const segment of tagSegments) {
    const separator = segment.indexOf(":");
    if (separator <= 0) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `${label} contains a malformed rule tag`,
      );
    }
    const name = segment.slice(0, separator);
    const value = segment.slice(separator + 1);
    if (seen.has(name) || (name !== "confidence" && name !== "version")) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `${label} contains a duplicate or unsupported ${name} tag`,
      );
    }
    seen.add(name);

    if (name === "confidence") {
      if (!/^(?:0|[1-9]\d{0,2})$/u.test(value)) {
        throw new FingerprintCatalogError(
          "CATALOG_INVALID",
          `${label} contains malformed confidence`,
        );
      }
      confidence = Number(value);
      if (confidence < confidenceMinimum || confidence > 100) {
        throw new FingerprintCatalogError(
          "CATALOG_INVALID",
          `${label} confidence is outside the accepted range`,
        );
      }
    } else {
      assertBoundedString(value, `${label} version template`, 256);
      validateVersionTemplate(value, label);
      versionTemplate = value;
    }
  }

  return { pattern, confidence, versionTemplate };
}

function parseTaggedRule(
  original: string,
  label: string,
  confidenceMinimum = 0,
): TaggedRule {
  const [pattern = "", ...tagSegments] = original.split("\\;");
  return parseTags(pattern, tagSegments, label, confidenceMinimum);
}

function parseSelectorRule(original: string, label: string): TaggedRule {
  const delimiter = original.indexOf("\\;");
  if (delimiter === -1) {
    return { pattern: original, confidence: 100, versionTemplate: null };
  }

  return parseTags(
    original.slice(0, delimiter),
    original.slice(delimiter + 2).split("\\;"),
    label,
    0,
  );
}

function validateVersionTemplate(value: string, label: string): void {
  let index = 0;
  while (index < value.length) {
    if (value[index] === "\\") {
      index += 1;
      if (!/[1-9]/u.test(value[index] ?? "")) {
        throw new FingerprintCatalogError(
          "CATALOG_INVALID",
          `${label} contains an unsupported version backreference`,
        );
      }
      while (/\d/u.test(value[index] ?? "")) {
        index += 1;
      }
      continue;
    }
    index += 1;
  }

  if (value.includes("?") && !/^\\[1-9]\d*\?[^:]*:[^:]*$/u.test(value)) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      `${label} contains an unsupported version conditional`,
    );
  }
}

function validateSelector(selector: string, label: string, config: ScanConfig): void {
  assertBoundedString(
    selector,
    label,
    config.limits.inspection.domSelectorCodeUnits,
  );
  try {
    loadHtml("<html></html>")(selector);
  } catch {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      `${label} is not a supported CSS selector`,
    );
  }
}

function normalizeCookieLocator(locator: string): string {
  const source = locator.startsWith("(?i)") ? locator.slice(4) : locator;
  return `^(?:${source})$`;
}

function normalizeLocator(source: EvidenceSource, locator: string): string {
  if (source === "header" || source === "meta") {
    return locator.trim().toLowerCase();
  }
  if (source === "dns_record") {
    return locator.toUpperCase();
  }
  return locator;
}

function assertExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort(compareString);
  const wanted = [...expected].sort(compareString);
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      `${label} does not have the exact supported shape`,
    );
  }
}

function assertRuleId(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(value)) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      `${label} is not a complete lowercase SHA-256 rule id`,
    );
  }
}

function parseCatalogCorrections(
  file: ParsedCatalogInputFile | undefined,
  config: ScanConfig,
): CatalogCorrections {
  if (file === undefined) {
    return {
      dropTechnologies: new Set<string>(),
      dropRules: new Set<string>(),
      replaceRules: new Map<string, CatalogRuleReplacement>(),
    };
  }

  assertRecord(file.value, "Catalog correction ledger");
  assertExactKeys(
    file.value,
    [
      "schema",
      "revision",
      "appliesTo",
      "dropTechnologies",
      "dropRules",
      "replaceRules",
    ],
    "Catalog correction ledger",
  );
  if (
    file.value.schema !== CATALOG_CORRECTIONS_SCHEMA
    || file.value.revision !== CATALOG_CORRECTIONS_REVISION
  ) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      "Catalog correction ledger schema does not match the fixed revision",
    );
  }

  const appliesTo = file.value.appliesTo;
  assertRecord(appliesTo, "Catalog correction ledger appliesTo");
  assertExactKeys(
    appliesTo,
    ["source", "revision", "digest"],
    "Catalog correction ledger appliesTo",
  );
  if (
    appliesTo.source !== CATALOG_SOURCE
    || appliesTo.revision !== CATALOG_REVISION
    || appliesTo.digest !== PINNED_UPSTREAM_DIGEST
  ) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      "Catalog correction ledger does not target the pinned upstream revision",
    );
  }

  const rawDropTechnologies = file.value.dropTechnologies;
  const rawDropRules = file.value.dropRules;
  const rawReplaceRules = file.value.replaceRules;
  if (
    !Array.isArray(rawDropTechnologies)
    || !Array.isArray(rawDropRules)
    || !Array.isArray(rawReplaceRules)
  ) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      "Catalog correction operations must be arrays",
    );
  }
  if (
    rawDropTechnologies.length > config.limits.detector.technologiesPerCatalog
    || rawDropRules.length + rawReplaceRules.length
      > config.limits.detector.patternsPerCatalog
  ) {
    throw new FingerprintCatalogError(
      "CATALOG_LIMIT_EXCEEDED",
      "Catalog correction ledger exceeds the effective catalog limits",
    );
  }

  const dropTechnologies = new Set<string>();
  for (const name of rawDropTechnologies) {
    assertBoundedString(
      name,
      "Catalog correction technology",
      config.limits.detector.technologyNameCodePoints * 2,
    );
    assertNoAsciiControl(name, "Catalog correction technology");
    if (dropTechnologies.has(name)) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `Catalog correction ledger drops ${name} more than once`,
      );
    }
    dropTechnologies.add(name);
  }

  const correctedRuleIds = new Set<string>();
  const dropRules = new Set<string>();
  for (const targetRuleId of rawDropRules) {
    assertRuleId(targetRuleId, "Catalog correction dropRules target");
    if (correctedRuleIds.has(targetRuleId)) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `Catalog correction ledger targets ${targetRuleId} more than once`,
      );
    }
    correctedRuleIds.add(targetRuleId);
    dropRules.add(targetRuleId);
  }

  const replacementIds = new Set<string>();
  const replaceRules = new Map<string, CatalogRuleReplacement>();
  for (const [index, rawReplacement] of rawReplaceRules.entries()) {
    assertRecord(rawReplacement, `Catalog correction replacement ${index}`);
    assertExactKeys(
      rawReplacement,
      ["targetRuleId", "technology", "source", "locator", "original"],
      `Catalog correction replacement ${index}`,
    );
    const { targetRuleId, technology, source, locator, original } = rawReplacement;
    assertRuleId(targetRuleId, `Catalog correction replacement ${index} target`);
    assertBoundedString(
      technology,
      `Catalog correction replacement ${index} technology`,
      config.limits.detector.technologyNameCodePoints * 2,
    );
    if (typeof source !== "string" || !ruleSignals.includes(source as EvidenceSource)) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `Catalog correction replacement ${index} has an unsupported signal`,
      );
    }
    if (locator !== null) {
      assertBoundedString(
        locator,
        `Catalog correction replacement ${index} locator`,
        config.limits.detector.patternSourceCodeUnits,
      );
      if (normalizeLocator(source as EvidenceSource, locator) !== locator) {
        throw new FingerprintCatalogError(
          "CATALOG_INVALID",
          `Catalog correction replacement ${index} locator is not normalized`,
        );
      }
    }
    assertBoundedString(
      original,
      `Catalog correction replacement ${index} original`,
      2_304,
      true,
    );
    if (correctedRuleIds.has(targetRuleId)) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `Catalog correction ledger targets ${targetRuleId} more than once`,
      );
    }
    correctedRuleIds.add(targetRuleId);
    const replacementId = sha256Tuple([
      CUSTOM_RULE_NAMESPACE,
      technology,
      source,
      locator,
      original,
    ]);
    if (replacementIds.has(replacementId)) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        "Catalog correction ledger contains duplicate replacement rules",
      );
    }
    replacementIds.add(replacementId);
    replaceRules.set(targetRuleId, {
      targetRuleId,
      technology,
      source: source as EvidenceSource,
      locator,
      original,
    });
  }

  return { dropTechnologies, dropRules, replaceRules };
}

function deepFreeze(value: unknown): void {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) {
    return;
  }
  for (const child of Object.values(value)) {
    deepFreeze(child);
  }
  Object.freeze(value);
}

function readRegularFile(
  url: URL,
  relativePath: string,
  config: ScanConfig,
): Uint8Array {
  let descriptor: number | undefined;
  try {
    const pathStat = lstatSync(url);
    if (!pathStat.isFile() || pathStat.isSymbolicLink()) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `${relativePath} must be a regular non-symlink file`,
      );
    }
    if (pathStat.size > config.limits.detector.catalogFileBytes) {
      throw new FingerprintCatalogError(
        "CATALOG_LIMIT_EXCEEDED",
        `${relativePath} exceeds the configured catalog file byte limit`,
      );
    }

    descriptor = openSync(url, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = fstatSync(descriptor, { bigint: true });
    if (!before.isFile()) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `${relativePath} must be a regular non-symlink file`,
      );
    }
    if (before.size > BigInt(config.limits.detector.catalogFileBytes)) {
      throw new FingerprintCatalogError(
        "CATALOG_LIMIT_EXCEEDED",
        `${relativePath} exceeds the configured catalog file byte limit`,
      );
    }

    const buffer = Buffer.allocUnsafe(config.limits.detector.catalogFileBytes + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const count = readSync(
        descriptor,
        buffer,
        offset,
        buffer.length - offset,
        null,
      );
      if (count === 0) {
        break;
      }
      offset += count;
    }
    if (offset > config.limits.detector.catalogFileBytes) {
      throw new FingerprintCatalogError(
        "CATALOG_LIMIT_EXCEEDED",
        `${relativePath} exceeds the configured catalog file byte limit`,
      );
    }

    const after = fstatSync(descriptor, { bigint: true });
    if (
      before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs
      || before.ctimeNs !== after.ctimeNs
      || after.size !== BigInt(offset)
    ) {
      throw new FingerprintCatalogError(
        "CATALOG_IO_FAILED",
        `${relativePath} changed while it was being read`,
      );
    }

    return Buffer.from(buffer.subarray(0, offset));
  } catch (error) {
    if (error instanceof FingerprintCatalogError) {
      throw error;
    }
    throw new FingerprintCatalogError(
      "CATALOG_IO_FAILED",
      `Cannot read ${relativePath}`,
      { cause: error },
    );
  } finally {
    if (descriptor !== undefined) {
      closeSync(descriptor);
    }
  }
}

function readCatalogDirectory(
  url: URL,
  label: string,
  maximumEntries: number,
): Dirent[] {
  let directory: Dir | undefined;
  try {
    let directoryPath = fileURLToPath(url);
    while (
      directoryPath.length > 1
      && /[\\/]$/u.test(directoryPath)
      && !/^[A-Za-z]:[\\/]$/u.test(directoryPath)
    ) {
      directoryPath = directoryPath.slice(0, -1);
    }
    const stat = lstatSync(directoryPath);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `${label} must be a regular non-symlink directory`,
      );
    }
    directory = opendirSync(directoryPath);
    const entries: Dirent[] = [];
    while (true) {
      const entry = directory.readSync();
      if (entry === null) {
        break;
      }
      entries.push(entry);
      if (entries.length > maximumEntries) {
        throw new FingerprintCatalogError(
          "CATALOG_LIMIT_EXCEEDED",
          `${label} exceeds its entry-count limit`,
        );
      }
    }
    return entries.sort((left, right) => compareString(left.name, right.name));
  } catch (error) {
    if (error instanceof FingerprintCatalogError) {
      throw error;
    }
    throw new FingerprintCatalogError(
      "CATALOG_IO_FAILED",
      `Cannot read ${label}`,
      { cause: error },
    );
  } finally {
    directory?.closeSync();
  }
}

function readDirectoryEntries(
  url: URL,
  label: string,
  maximumEntries: number,
): string[] {
  return readCatalogDirectory(url, label, maximumEntries)
    .map((entry) => entry.name);
}

function readDirectoryEntriesWithTypes(
  url: URL,
  label: string,
  maximumEntries: number,
): Dirent[] {
  return readCatalogDirectory(url, label, maximumEntries);
}

function assertExactDirectoryEntries(url: URL, expected: readonly string[], label: string): void {
  const actual = readDirectoryEntries(url, label, expected.length + 1);
  const wanted = [...expected].sort(compareString);
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      `${label} has missing or unexpected entries`,
    );
  }
}

export function loadFingerprintCatalog(
  config: ScanConfig,
  rootUrl = new URL("../../fingerprints/", import.meta.url),
): CompiledFingerprintCatalog {
  if (
    rootUrl.protocol !== "file:"
    || rootUrl.search !== ""
    || rootUrl.hash !== ""
    || !rootUrl.pathname.endsWith("/")
  ) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      "Catalog root must be an absolute file directory URL",
    );
  }

  const rootEntries = readDirectoryEntries(
    rootUrl,
    "Fingerprint catalog directory",
    3,
  );
  const hasCustom = rootEntries.includes("custom");
  const expectedRootEntries = hasCustom ? ["custom", "upstream"] : ["upstream"];
  if (JSON.stringify(rootEntries) !== JSON.stringify(expectedRootEntries)) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      "Fingerprint catalog directory has missing or unexpected entries",
    );
  }

  const upstreamContainer = new URL("upstream/", rootUrl);
  const upstreamRoot = new URL("upstream/webappanalyzer/", rootUrl);
  const upstreamTechnologies = new URL("technologies/", upstreamRoot);

  assertExactDirectoryEntries(
    upstreamContainer,
    ["webappanalyzer"],
    "Upstream catalog directory",
  );
  assertExactDirectoryEntries(
    upstreamRoot,
    expectedUpstreamRootEntries,
    "Pinned upstream catalog directory",
  );
  assertExactDirectoryEntries(
    upstreamTechnologies,
    upstreamTechnologyFiles,
    "Pinned upstream technology directory",
  );

  const files: CatalogInputFile[] = [];
  let loadedBytes = 0;
  const append = (
    kind: CatalogFileKind,
    namespace: string,
    relativePath: string,
    url: URL,
  ): void => {
    if (files.length >= config.limits.detector.catalogFiles) {
      throw new FingerprintCatalogError(
        "CATALOG_LIMIT_EXCEEDED",
        "Catalog exceeds the configured file-count limit",
      );
    }
    const bytes = readRegularFile(url, relativePath, config);
    loadedBytes += bytes.byteLength;
    if (loadedBytes > config.limits.detector.catalogBytes) {
      throw new FingerprintCatalogError(
        "CATALOG_LIMIT_EXCEEDED",
        "Catalog exceeds the configured total byte limit",
      );
    }
    files.push({
      kind,
      namespace,
      relativePath,
      bytes,
    });
  };

  append(
    "schema",
    UPSTREAM_RULE_NAMESPACE,
    "upstream/webappanalyzer/schema.json",
    new URL("schema.json", upstreamRoot),
  );
  append(
    "categories",
    UPSTREAM_RULE_NAMESPACE,
    "upstream/webappanalyzer/categories.json",
    new URL("categories.json", upstreamRoot),
  );
  for (const filename of upstreamTechnologyFiles) {
    append(
      "technologies",
      UPSTREAM_RULE_NAMESPACE,
      `upstream/webappanalyzer/technologies/${filename}`,
      new URL(filename, upstreamTechnologies),
    );
  }

  const customRoot = new URL("custom/", rootUrl);
  if (hasCustom) {
    const customEntries = readDirectoryEntriesWithTypes(
      customRoot,
      "Custom catalog directory",
      3,
    );
    const correctionEntry = customEntries.find(
      (entry) => entry.name === "corrections.v1.json",
    );
    const technologyEntry = customEntries.find(
      (entry) => entry.name === "technologies",
    );
    if (
      customEntries.length === 0
      || customEntries.some((entry) =>
        entry.name !== "corrections.v1.json" && entry.name !== "technologies")
      || (correctionEntry !== undefined
        && (!correctionEntry.isFile() || correctionEntry.isSymbolicLink()))
      || (technologyEntry !== undefined
        && (!technologyEntry.isDirectory() || technologyEntry.isSymbolicLink()))
    ) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        "Custom catalog directory has an unsupported entry",
      );
    }
    if (correctionEntry !== undefined) {
      append(
        "corrections",
        CUSTOM_RULE_NAMESPACE,
        "custom/corrections.v1.json",
        new URL("corrections.v1.json", customRoot),
      );
    }
    if (technologyEntry !== undefined) {
      const customTechnologies = new URL("technologies/", customRoot);
      const technologyFiles = readDirectoryEntriesWithTypes(
        customTechnologies,
        "Custom technology directory",
        config.limits.detector.catalogFiles - files.length,
      );
      for (const entry of technologyFiles) {
        if (
          !entry.isFile()
          || entry.isSymbolicLink()
          || !/^[A-Za-z0-9][A-Za-z0-9._-]*\.json$/u.test(entry.name)
        ) {
          throw new FingerprintCatalogError(
            "CATALOG_INVALID",
            "Custom catalog contains an entry that is not an allowed JSON file",
          );
        }
        append(
          "technologies",
          CUSTOM_RULE_NAMESPACE,
          `custom/technologies/${entry.name}`,
          new URL(entry.name, customTechnologies),
        );
      }
    }
  }

  if (files.length > config.limits.detector.catalogFiles) {
    throw new FingerprintCatalogError(
      "CATALOG_LIMIT_EXCEEDED",
      "Catalog exceeds the configured file-count limit",
    );
  }
  const totalBytes = files.reduce((total, file) => total + file.bytes.byteLength, 0);
  if (totalBytes > config.limits.detector.catalogBytes) {
    throw new FingerprintCatalogError(
      "CATALOG_LIMIT_EXCEEDED",
      "Catalog exceeds the configured total byte limit",
    );
  }

  const upstreamDigest = computeCatalogDigest(
    files.filter((file) => file.namespace === UPSTREAM_RULE_NAMESPACE),
  );
  if (upstreamDigest !== PINNED_UPSTREAM_DIGEST) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      "Vendored upstream catalog bytes do not match the pinned snapshot",
    );
  }

  return compileFingerprintCatalog({
    source: CATALOG_SOURCE,
    revision: CATALOG_REVISION,
    files,
  }, config);
}

export function compileFingerprintCatalog(
  input: CatalogCompilationInput,
  config: ScanConfig,
): CompiledFingerprintCatalog {
  assertBoundedString(input.source, "Catalog source", 256);
  assertNoAsciiControl(input.source, "Catalog source");
  assertBoundedString(input.revision, "Catalog revision", 256);
  assertNoAsciiControl(input.revision, "Catalog revision");
  if (input.source !== CATALOG_SOURCE || input.revision !== CATALOG_REVISION) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      "Catalog source or revision does not match the fixed provenance",
    );
  }
  if (input.files.length === 0 || input.files.length > config.limits.detector.catalogFiles) {
    throw new FingerprintCatalogError(
      "CATALOG_LIMIT_EXCEEDED",
      "Catalog file count is outside the configured limit",
    );
  }

  const paths = new Set<string>();
  const parsedFiles: ParsedCatalogInputFile[] = [];
  let totalBytes = 0;
  for (const file of input.files) {
    if (
      file.kind !== "schema"
      && file.kind !== "categories"
      && file.kind !== "technologies"
      && file.kind !== "corrections"
    ) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        "Catalog contains an unsupported file kind",
      );
    }
    if (!(file.bytes instanceof Uint8Array)) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        "Catalog file bytes must be a byte array",
      );
    }
    assertBoundedString(file.relativePath, "Catalog relative path", 1_024);
    assertNoAsciiControl(file.relativePath, "Catalog relative path");
    assertBoundedString(file.namespace, "Catalog namespace", 256);
    assertNoAsciiControl(file.namespace, "Catalog namespace");
    const pathSegments = file.relativePath.split("/");
    if (
      file.relativePath.includes("\\")
      || file.relativePath.startsWith("/")
      || pathSegments.some((segment) => segment === "" || segment === "." || segment === "..")
    ) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `Catalog path ${file.relativePath} is not relative POSIX form`,
      );
    }
    if (
      (file.kind === "schema"
        && (
          file.namespace !== UPSTREAM_RULE_NAMESPACE
          || file.relativePath !== "upstream/webappanalyzer/schema.json"
        ))
      || (file.kind === "categories"
        && (
          file.namespace !== UPSTREAM_RULE_NAMESPACE
          || file.relativePath !== "upstream/webappanalyzer/categories.json"
        ))
      || (file.kind === "technologies"
        && !(
          (file.namespace === UPSTREAM_RULE_NAMESPACE
            && /^upstream\/webappanalyzer\/technologies\/(?:_|[a-z])\.json$/u.test(
              file.relativePath,
            ))
          || (file.namespace === CUSTOM_RULE_NAMESPACE
            && /^custom\/technologies\/[A-Za-z0-9][A-Za-z0-9._-]*\.json$/u.test(
              file.relativePath,
            ))
        ))
      || (file.kind === "corrections"
        && (
          file.namespace !== CUSTOM_RULE_NAMESPACE
          || file.relativePath !== "custom/corrections.v1.json"
        ))
    ) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        "Catalog file path, kind, or namespace is not allowed",
      );
    }
    if (paths.has(file.relativePath)) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `Catalog contains duplicate path ${file.relativePath}`,
      );
    }
    paths.add(file.relativePath);
    if (file.bytes.byteLength > config.limits.detector.catalogFileBytes) {
      throw new FingerprintCatalogError(
        "CATALOG_LIMIT_EXCEEDED",
        `${file.relativePath} exceeds the configured file byte limit`,
      );
    }
    totalBytes += file.bytes.byteLength;
    if (totalBytes > config.limits.detector.catalogBytes) {
      throw new FingerprintCatalogError(
        "CATALOG_LIMIT_EXCEEDED",
        "Catalog exceeds the configured total byte limit",
      );
    }
    const bytes = Buffer.from(file.bytes);
    parsedFiles.push({
      kind: file.kind,
      namespace: file.namespace,
      relativePath: file.relativePath,
      bytes,
      value: parseCatalogJson(
        bytes,
        file.relativePath,
        config.limits.detector.catalogJsonDepth,
      ),
    });
  }
  const categoryFiles = parsedFiles.filter((file) => file.kind === "categories");
  const schemaFiles = parsedFiles.filter((file) => file.kind === "schema");
  const technologyFiles = parsedFiles.filter((file) => file.kind === "technologies");
  const correctionFiles = parsedFiles.filter((file) => file.kind === "corrections");
  if (categoryFiles.length !== 1 || schemaFiles.length !== 1 || technologyFiles.length === 0) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      "Catalog requires one schema, one category file, and technology files",
    );
  }
  if (correctionFiles.length > 1) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      "Catalog accepts at most one fixed correction ledger",
    );
  }
  if (!Buffer.from(schemaFiles[0]?.bytes ?? []).equals(fixedSchemaBytes)) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      "Catalog schema bytes do not match the fixed reviewed schema",
    );
  }
  if (
    correctionFiles.length === 1
    && computeCatalogDigest(
      parsedFiles.filter((file) => file.namespace === UPSTREAM_RULE_NAMESPACE),
    ) !== PINNED_UPSTREAM_DIGEST
  ) {
    throw new FingerprintCatalogError(
      "CATALOG_INVALID",
      "Catalog corrections require the exact pinned upstream bytes",
    );
  }
  const corrections = parseCatalogCorrections(correctionFiles[0], config);

  const categoryValue = categoryFiles[0]?.value;
  assertRecord(categoryValue, "Category catalog");
  const categories: Category[] = [];
  const categoryById = new Map<number, Category>();
  for (const [rawId, rawCategory] of Object.entries(categoryValue)) {
    if (!/^[1-9]\d*$/u.test(rawId)) {
      throw new FingerprintCatalogError("CATALOG_INVALID", "Category id is invalid");
    }
    const id = Number(rawId);
    if (!Number.isSafeInteger(id) || id > 1_000_000) {
      throw new FingerprintCatalogError("CATALOG_INVALID", "Category id is invalid");
    }
    assertRecord(rawCategory, `Category ${rawId}`);
    const allowed = new Set(["groups", "name", "priority"]);
    if (
      Object.keys(rawCategory).some((key) => !allowed.has(key))
      || Object.keys(rawCategory).length !== allowed.size
    ) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `Category ${rawId} does not have the exact supported shape`,
      );
    }
    const name = rawCategory.name;
    assertBoundedString(
      name,
      `Category ${rawId} name`,
      config.limits.detector.categoryNameCodePoints * 2,
    );
    assertNoAsciiControl(name, `Category ${rawId} name`);
    if ([...name].length > config.limits.detector.categoryNameCodePoints) {
      throw new FingerprintCatalogError(
        "CATALOG_LIMIT_EXCEEDED",
        `Category ${rawId} name exceeds the code-point limit`,
      );
    }
    const groups = rawCategory.groups;
    if (!Array.isArray(groups)) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `Category ${rawId} groups must be an array`,
      );
    }
    const groupIds = new Set<number>();
    for (const groupId of groups) {
      if (
        !Number.isSafeInteger(groupId)
        || (groupId as number) < 1
        || (groupId as number) > 1_000_000
        || groupIds.has(groupId as number)
      ) {
        throw new FingerprintCatalogError(
          "CATALOG_INVALID",
          `Category ${rawId} contains an invalid or duplicate group`,
        );
      }
      groupIds.add(groupId as number);
    }
    if (
      !Number.isSafeInteger(rawCategory.priority)
      || (rawCategory.priority as number) < 1
      || (rawCategory.priority as number) > 1_000_000
    ) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `Category ${rawId} priority is invalid`,
      );
    }
    const category = { id, name };
    categories.push(category);
    categoryById.set(id, category);
  }
  if (categories.length > config.limits.detector.categoriesPerCatalog) {
    throw new FingerprintCatalogError(
      "CATALOG_LIMIT_EXCEEDED",
      "Catalog exceeds the category-count limit",
    );
  }
  categories.sort((left, right) => left.id - right.id || compareString(left.name, right.name));

  const allDrafts: DraftTechnology[] = [];
  const declaredTechnologyNames = new Set<string>();
  for (const file of technologyFiles) {
    if (!validateTechnologyDocument(file.value)) {
      const issue = validateTechnologyDocument.errors?.[0];
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `${file.relativePath} fails the pinned schema (${issue?.keyword ?? "invalid"})`,
      );
    }
    assertRecord(file.value, file.relativePath);
    for (const [name, value] of Object.entries(file.value)) {
      assertBoundedString(
        name,
        `Technology name in ${file.relativePath}`,
        config.limits.detector.technologyNameCodePoints * 2,
      );
      assertNoAsciiControl(name, `Technology name in ${file.relativePath}`);
      if ([...name].length > config.limits.detector.technologyNameCodePoints) {
        throw new FingerprintCatalogError(
          "CATALOG_LIMIT_EXCEEDED",
          `Technology ${name} exceeds the name limit`,
        );
      }
      if (declaredTechnologyNames.has(name)) {
        throw new FingerprintCatalogError(
          "CATALOG_INVALID",
          `Technology ${name} is declared more than once`,
        );
      }
      declaredTechnologyNames.add(name);
      assertRecord(value, `Technology ${name}`);
      allDrafts.push({ namespace: file.namespace, name, value });
    }
  }
  for (const name of corrections.dropTechnologies) {
    const target = allDrafts.find((draft) => draft.name === name);
    if (target === undefined || target.namespace !== UPSTREAM_RULE_NAMESPACE) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `Catalog correction technology target ${name} is missing or is not upstream`,
      );
    }
  }
  const drafts = allDrafts.filter(
    (draft) => !corrections.dropTechnologies.has(draft.name),
  );
  if (drafts.length > config.limits.detector.technologiesPerCatalog) {
    throw new FingerprintCatalogError(
      "CATALOG_LIMIT_EXCEEDED",
      "Effective catalog exceeds the technology-count limit",
    );
  }
  const seenTechnologyNames = new Set(drafts.map((draft) => draft.name));
  drafts.sort((left, right) => compareString(left.name, right.name));

  const rulesById = new Map<string, CompiledFingerprintRule>();
  const technologyDefinitions: CompiledTechnologyDefinition[] = [];
  let declarationCount = 0;
  let relationshipCount = 0;
  let regexSourceCount = 0;
  let regexSourceCodeUnits = 0;
  const correctedTargetCounts = new Map<string, number>([
    ...[...corrections.dropRules].map((ruleId) => [ruleId, 0] as const),
    ...[...corrections.replaceRules.keys()].map((ruleId) => [ruleId, 0] as const),
  ]);

  const accountRegex = (source: string, label: string): void => {
    if (source === "") {
      return;
    }
    if (source.length > config.limits.detector.patternSourceCodeUnits) {
      throw new FingerprintCatalogError(
        "CATALOG_LIMIT_EXCEEDED",
        `${label} exceeds the pattern-source limit`,
      );
    }
    regexSourceCount += 1;
    regexSourceCodeUnits += source.length;
    if (
      regexSourceCount > config.limits.detector.patternsPerCatalog
      || regexSourceCodeUnits > config.limits.detector.totalPatternSourceCodeUnits
    ) {
      throw new FingerprintCatalogError(
        "CATALOG_LIMIT_EXCEEDED",
        "Catalog exceeds the regex count or total-source limit",
      );
    }
  };

  const addRule = (
    draft: DraftTechnology,
    source: EvidenceSource,
    locatorInput: string | null,
    original: string,
    parsedOverride?: TaggedRule,
    literal = false,
  ): void => {
    assertBoundedString(original, `${draft.name} ${source} rule`, 2_304, true);
    const parsed = parsedOverride
      ?? parseTaggedRule(original, `${draft.name} ${source} rule`);
    const locator = locatorInput === null
      ? null
      : normalizeLocator(source, locatorInput);
    if (locator !== null) {
      if (locator.length > EVIDENCE_KEY_CODE_UNITS) {
        throw new FingerprintCatalogError(
          "CATALOG_LIMIT_EXCEEDED",
          `${draft.name} ${source} locator exceeds the evidence-key limit`,
        );
      }
      assertBoundedString(
        locator,
        `${draft.name} ${source} locator`,
        config.limits.detector.patternSourceCodeUnits,
      );
    }
    const createRule = (
      namespace: string,
      effectiveOriginal: string,
      effectiveParsed: TaggedRule,
    ): CompiledFingerprintRule => ({
      ruleId: sha256Tuple([
        namespace,
        draft.name,
        source,
        locator,
        effectiveOriginal,
      ]),
      namespace,
      technology: draft.name,
      source,
      locator,
      locatorPattern: source === "cookie" && locator !== null
        ? normalizeCookieLocator(locator)
        : null,
      original: effectiveOriginal,
      pattern: effectiveParsed.pattern === "" ? null : effectiveParsed.pattern,
      matchMode: effectiveParsed.pattern === ""
        ? "presence"
        : literal
          ? "literal"
          : "regex",
      confidence: effectiveParsed.confidence,
      versionTemplate: effectiveParsed.versionTemplate,
    });
    const upstreamRule = createRule(draft.namespace, original, parsed);
    let rule = upstreamRule;
    const targetCount = correctedTargetCounts.get(upstreamRule.ruleId);
    if (targetCount !== undefined) {
      correctedTargetCounts.set(upstreamRule.ruleId, targetCount + 1);
      if (upstreamRule.namespace !== UPSTREAM_RULE_NAMESPACE) {
        throw new FingerprintCatalogError(
          "CATALOG_INVALID",
          `Catalog correction target ${upstreamRule.ruleId} is not upstream`,
        );
      }
      if (corrections.dropRules.has(upstreamRule.ruleId)) {
        return;
      }
      const replacement = corrections.replaceRules.get(upstreamRule.ruleId);
      if (
        replacement === undefined
        || replacement.technology !== upstreamRule.technology
        || replacement.source !== upstreamRule.source
        || replacement.locator !== upstreamRule.locator
      ) {
        throw new FingerprintCatalogError(
          "CATALOG_INVALID",
          `Catalog correction replacement ${upstreamRule.ruleId} changes rule identity`,
        );
      }
      const replacementParsed = parseTaggedRule(
        replacement.original,
        `${draft.name} ${source} replacement rule`,
      );
      rule = createRule(
        CUSTOM_RULE_NAMESPACE,
        replacement.original,
        replacementParsed,
      );
    }

    if (
      rule.pattern !== null
      && rule.pattern.length > config.limits.detector.patternSourceCodeUnits
    ) {
      throw new FingerprintCatalogError(
        "CATALOG_LIMIT_EXCEEDED",
        `${draft.name} ${source} rule exceeds the pattern-source limit`,
      );
    }
    declarationCount += 1;
    if (declarationCount > config.limits.detector.patternsPerCatalog) {
      throw new FingerprintCatalogError(
        "CATALOG_LIMIT_EXCEEDED",
        "Catalog exceeds the direct-rule declaration limit",
      );
    }
    if (rule.matchMode === "regex") {
      accountRegex(rule.pattern ?? "", `${draft.name} ${source} rule`);
    }
    if (rule.locatorPattern !== null) {
      accountRegex(rule.locatorPattern, `${draft.name} cookie locator`);
    }
    const previous = rulesById.get(rule.ruleId);
    if (previous === undefined) {
      rulesById.set(rule.ruleId, rule);
    } else if (JSON.stringify(previous) !== JSON.stringify(rule)) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `Rule id collision for ${draft.name}`,
      );
    }
  };

  const addArrayRules = (
    draft: DraftTechnology,
    field: string,
    source: EvidenceSource,
    literal = false,
  ): void => {
    const value = draft.value[field];
    if (value === undefined) {
      return;
    }
    assertStringArray(value, `${draft.name}.${field}`);
    for (const original of value) {
      addRule(draft, source, null, original, undefined, literal);
    }
  };

  const addMapRules = (
    draft: DraftTechnology,
    field: string,
    source: EvidenceSource,
    literal = false,
  ): void => {
    const value = draft.value[field];
    if (value === undefined) {
      return;
    }
    assertRecord(value, `${draft.name}.${field}`);
    for (const [locator, original] of Object.entries(value)) {
      assertBoundedString(locator, `${draft.name}.${field} locator`, 1_024);
      assertNoAsciiControl(locator, `${draft.name}.${field} locator`);
      assertBoundedString(original, `${draft.name}.${field}.${locator}`, 2_304, true);
      addRule(draft, source, locator, original, undefined, literal);
      if (source === "javascript") {
        if (locator.length > config.limits.inspection.javascriptPathCodeUnits) {
          throw new FingerprintCatalogError(
            "CATALOG_LIMIT_EXCEEDED",
            `${draft.name} JavaScript path exceeds the limit`,
          );
        }
      }
      if (source === "probe") {
        let resolved: URL;
        try {
          resolved = new URL(locator, "https://catalog-probe.invalid/");
        } catch {
          throw new FingerprintCatalogError(
            "CATALOG_INVALID",
            `${draft.name} probe path is not a safe same-origin path`,
          );
        }
        if (
          !locator.startsWith("/")
          || locator.startsWith("//")
          || locator.includes("\\")
          || locator.includes("?")
          || locator.includes("#")
          || locator.length > config.limits.url.codeUnits
          || resolved.origin !== "https://catalog-probe.invalid"
          || resolved.username !== ""
          || resolved.password !== ""
          || resolved.search !== ""
          || resolved.hash !== ""
          || resolved.pathname !== locator
        ) {
          throw new FingerprintCatalogError(
            "CATALOG_INVALID",
            `${draft.name} probe path is not a safe same-origin path`,
          );
        }
      }
    }
  };

  for (const draft of drafts) {
    const rawCategories = draft.value.cats;
    if (
      !Array.isArray(rawCategories)
      || rawCategories.length === 0
      || rawCategories.length > config.limits.detector.categoriesPerTechnology
    ) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `${draft.name}.cats is outside the accepted bounds`,
      );
    }
    const categoryIds = new Set<number>();
    for (const rawId of rawCategories) {
      if (!Number.isSafeInteger(rawId) || !categoryById.has(rawId as number)) {
        throw new FingerprintCatalogError(
          "CATALOG_INVALID",
          `${draft.name} references an unknown category`,
        );
      }
      if (categoryIds.has(rawId as number)) {
        throw new FingerprintCatalogError(
          "CATALOG_INVALID",
          `${draft.name} contains a duplicate category`,
        );
      }
      categoryIds.add(rawId as number);
    }

    addArrayRules(draft, "url", "url");
    addMapRules(draft, "headers", "header");
    addMapRules(draft, "cookies", "cookie");
    addArrayRules(draft, "html", "html");
    addArrayRules(draft, "text", "text");
    addArrayRules(draft, "css", "css");
    addMapRules(draft, "meta", "meta");
    addArrayRules(draft, "scriptSrc", "script_url");
    addArrayRules(draft, "scripts", "script_content");
    addMapRules(draft, "js", "javascript");
    addArrayRules(draft, "xhr", "network_url");
    addArrayRules(draft, "robots", "robots", true);
    addMapRules(draft, "probe", "probe", true);

    const certIssuer = draft.value.certIssuer;
    if (certIssuer !== undefined) {
      assertBoundedString(certIssuer, `${draft.name}.certIssuer`, 2_304, true);
      addRule(draft, "tls_issuer", null, certIssuer, undefined, true);
    }

    const dns = draft.value.dns;
    if (dns !== undefined) {
      assertRecord(dns, `${draft.name}.dns`);
      for (const [recordType, values] of Object.entries(dns)) {
        const normalizedType = recordType.toUpperCase();
        if (!supportedDnsTypes.has(normalizedType)) {
          throw new FingerprintCatalogError(
            "CATALOG_INVALID",
            `${draft.name} uses an unsupported DNS record type`,
          );
        }
        assertStringArray(values, `${draft.name}.dns.${recordType}`);
        if (values.length === 0) {
          throw new FingerprintCatalogError(
            "CATALOG_INVALID",
            `${draft.name}.dns.${recordType} must not be empty`,
          );
        }
        for (const original of values) {
          addRule(draft, "dns_record", normalizedType, original);
        }
      }
    }

    const dom = draft.value.dom;
    if (dom !== undefined) {
      if (Array.isArray(dom)) {
        assertStringArray(dom, `${draft.name}.dom`);
        for (const original of dom) {
          const parsed = parseSelectorRule(original, `${draft.name}.dom selector`);
          validateSelector(parsed.pattern, `${draft.name}.dom selector`, config);
          addRule(
            draft,
            "dom",
            JSON.stringify([parsed.pattern, "exists", null]),
            original,
            { ...parsed, pattern: "" },
          );
        }
      } else {
        assertRecord(dom, `${draft.name}.dom`);
        for (const [selector, matcher] of Object.entries(dom)) {
          validateSelector(selector, `${draft.name}.dom selector`, config);
          assertRecord(matcher, `${draft.name}.dom.${selector}`);
          const allowedFields = new Set(["attributes", "exists", "properties", "text"]);
          if (Object.keys(matcher).some((field) => !allowedFields.has(field))) {
            throw new FingerprintCatalogError(
              "CATALOG_INVALID",
              `${draft.name}.dom.${selector} has an unsupported matcher`,
            );
          }
          if (Object.keys(matcher).length === 0) {
            addRule(
              draft,
              "dom",
              JSON.stringify([selector, "exists", null]),
              "",
            );
          }
          for (const scalarField of ["exists", "text"] as const) {
            const original = matcher[scalarField];
            if (original !== undefined) {
              assertBoundedString(
                original,
                `${draft.name}.dom.${selector}.${scalarField}`,
                2_304,
                true,
              );
              addRule(
                draft,
                "dom",
                JSON.stringify([selector, scalarField, null]),
                original,
              );
            }
          }
          for (const mapField of ["attributes", "properties"] as const) {
            const values = matcher[mapField];
            if (values === undefined) {
              continue;
            }
            assertRecord(values, `${draft.name}.dom.${selector}.${mapField}`);
            for (const [name, original] of Object.entries(values)) {
              assertBoundedString(
                name,
                `${draft.name}.dom.${selector}.${mapField} locator`,
                1_024,
              );
              assertNoAsciiControl(
                name,
                `${draft.name}.dom.${selector}.${mapField} locator`,
              );
              assertBoundedString(
                original,
                `${draft.name}.dom.${selector}.${mapField}.${name}`,
                2_304,
                true,
              );
              addRule(
                draft,
                "dom",
                JSON.stringify([selector, mapField, name]),
                original,
              );
            }
          }
        }
      }
    }

    const parseRelationArray = (field: "requires" | "excludes"): string[] => {
      const value = draft.value[field];
      if (value === undefined) {
        return [];
      }
      assertStringArray(value, `${draft.name}.${field}`);
      const targets = new Set<string>();
      for (const target of value) {
        assertBoundedString(target, `${draft.name}.${field} target`, 512);
        if (target.includes("\\;") || !seenTechnologyNames.has(target)) {
          throw new FingerprintCatalogError(
            "CATALOG_INVALID",
            `${draft.name}.${field} contains an unsupported or unknown target`,
          );
        }
        if (target === draft.name) {
          throw new FingerprintCatalogError(
            "CATALOG_INVALID",
            `${draft.name} cannot ${field} itself`,
          );
        }
        if (targets.has(target)) {
          throw new FingerprintCatalogError(
            "CATALOG_INVALID",
            `${draft.name}.${field} contains a duplicate`,
          );
        }
        targets.add(target);
      }
      relationshipCount += targets.size;
      return [...targets].sort(compareString);
    };

    const requires = parseRelationArray("requires");
    const excludes = parseRelationArray("excludes");
    const rawRequiresCategory = draft.value.requiresCategory;
    const requiresCategory: number[] = [];
    if (rawRequiresCategory !== undefined) {
      if (!Array.isArray(rawRequiresCategory)) {
        throw new FingerprintCatalogError(
          "CATALOG_INVALID",
          `${draft.name}.requiresCategory must be an array`,
        );
      }
      const ids = new Set<number>();
      for (const id of rawRequiresCategory) {
        if (!Number.isSafeInteger(id) || !categoryById.has(id as number)) {
          throw new FingerprintCatalogError(
            "CATALOG_INVALID",
            `${draft.name}.requiresCategory references an unknown category`,
          );
        }
        if (ids.has(id as number)) {
          throw new FingerprintCatalogError(
            "CATALOG_INVALID",
            `${draft.name}.requiresCategory contains a duplicate`,
          );
        }
        ids.add(id as number);
      }
      requiresCategory.push(...[...ids].sort((left, right) => left - right));
      relationshipCount += ids.size;
    }

    const rawImplies = draft.value.implies;
    const implies: CompiledImplication[] = [];
    if (rawImplies !== undefined) {
      assertStringArray(rawImplies, `${draft.name}.implies`);
      const seen = new Set<string>();
      for (const original of rawImplies) {
        const parsed = parseTaggedRule(original, `${draft.name}.implies`, 1);
        const target = parsed.pattern;
        if (!seenTechnologyNames.has(target)) {
          throw new FingerprintCatalogError(
            "CATALOG_INVALID",
            `${draft.name}.implies references an unknown technology`,
          );
        }
        const version = parsed.versionTemplate;
        if (
          version !== null
          && !/^[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}$/u.test(version)
        ) {
          throw new FingerprintCatalogError(
            "CATALOG_INVALID",
            `${draft.name}.implies has an unsafe literal version`,
          );
        }
        if (
          version !== null
          && version.length > config.limits.evidence.versionCodeUnits
        ) {
          throw new FingerprintCatalogError(
            "CATALOG_LIMIT_EXCEEDED",
            `${draft.name}.implies exceeds the configured version limit`,
          );
        }
        if (target === draft.name) {
          relationshipCount += 1;
          continue;
        }
        const ruleId = sha256Tuple([
          draft.namespace,
          draft.name,
          "implies",
          target,
          original,
        ]);
        if (seen.has(ruleId)) {
          throw new FingerprintCatalogError(
            "CATALOG_INVALID",
            `${draft.name}.implies contains a duplicate`,
          );
        }
        seen.add(ruleId);
        implies.push({
          technology: target,
          ruleId,
          confidence: parsed.confidence,
          version,
        });
      }
      relationshipCount += implies.length;
      implies.sort((left, right) =>
        compareString(left.technology, right.technology)
        || compareString(left.ruleId, right.ruleId));
    }

    if (relationshipCount > config.limits.detector.relationshipEdgesPerCatalog) {
      throw new FingerprintCatalogError(
        "CATALOG_LIMIT_EXCEEDED",
        "Catalog exceeds the relationship edge limit",
      );
    }
    technologyDefinitions.push({
      name: draft.name,
      categories: [...categoryIds]
        .map((id) => categoryById.get(id) as Category)
        .sort((left, right) => left.id - right.id || compareString(left.name, right.name)),
      requires,
      requiresCategory,
      implies,
      excludes,
    });
  }

  for (const [targetRuleId, count] of correctedTargetCounts) {
    if (count !== 1) {
      throw new FingerprintCatalogError(
        "CATALOG_INVALID",
        `Catalog correction target ${targetRuleId} is missing or duplicated`,
      );
    }
  }

  const rules = [...rulesById.values()].sort((left, right) =>
    (signalRank.get(left.source) ?? 99) - (signalRank.get(right.source) ?? 99)
    || compareString(left.technology, right.technology)
    || compareString(left.locator ?? "", right.locator ?? "")
    || compareString(left.ruleId, right.ruleId));
  const probePaths = new Set(
    rules
      .filter((rule) => rule.source === "probe" && rule.locator !== null)
      .map((rule) => rule.locator as string),
  );
  const inspectionPlan = createInspectionPlan(rules, probePaths);
  if (inspectionPlan.dom.length > config.limits.inspection.domSelectors) {
    throw new FingerprintCatalogError(
      "CATALOG_LIMIT_EXCEEDED",
      "Catalog exceeds the DOM inspection-plan limit",
    );
  }
  if (
    inspectionPlan.javascript.length
    > config.limits.inspection.javascriptPaths
  ) {
    throw new FingerprintCatalogError(
      "CATALOG_LIMIT_EXCEEDED",
      "Catalog exceeds the JavaScript inspection-plan limit",
    );
  }
  if (probePaths.size > config.limits.pages.catalogProbesPerDomain) {
    throw new FingerprintCatalogError(
      "CATALOG_LIMIT_EXCEEDED",
      "Catalog exceeds the probe inspection-plan limit",
    );
  }
  const indexes: CatalogSignalIndex[] = ruleSignals.map((source) => {
    const unkeyedRuleOrdinals: number[] = [];
    const patternLocatorRuleOrdinals: number[] = [];
    const keyed = new Map<string, number[]>();
    rules.forEach((rule, ordinal) => {
      if (rule.source !== source) {
        return;
      }
      if (rule.locatorPattern !== null) {
        patternLocatorRuleOrdinals.push(ordinal);
      } else if (rule.locator === null) {
        unkeyedRuleOrdinals.push(ordinal);
      } else {
        const ordinals = keyed.get(rule.locator) ?? [];
        ordinals.push(ordinal);
        keyed.set(rule.locator, ordinals);
      }
    });
    return {
      source,
      unkeyedRuleOrdinals,
      keyed: [...keyed]
        .sort(([left], [right]) => compareString(left, right))
        .map(([locator, ruleOrdinals]) => ({ locator, ruleOrdinals })),
      patternLocatorRuleOrdinals,
    };
  });

  const catalog: CompiledFingerprintCatalog = {
    source: input.source,
    revision: input.revision,
    digest: computeCatalogDigest(parsedFiles),
    categories,
    technologies: technologyDefinitions,
    rules,
    indexes,
    inspectionPlan,
    declarationCount,
    relationshipCount,
    regexSourceCount,
    regexSourceCodeUnits,
  };
  deepFreeze(catalog);
  return catalog;
}

export function catalogRootPath(): string {
  return fileURLToPath(new URL("../../fingerprints/", import.meta.url));
}
