import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  createDefaultScanConfig,
  parseScanConfig,
  type ScanConfig,
} from "../src/config.ts";
import {
  CATALOG_REVISION,
  CATALOG_SOURCE,
  compileFingerprintCatalog,
  computeCatalogDigest,
  CUSTOM_RULE_NAMESPACE,
  FingerprintCatalogError,
  loadFingerprintCatalog,
  PINNED_UPSTREAM_DIGEST,
  UPSTREAM_RULE_NAMESPACE,
  type CatalogCompilationInput,
  type CatalogFileKind,
  type CatalogInputFile,
  type CompiledFingerprintCatalog,
} from "../src/detect/catalog.ts";

type JsonRecord = Record<string, unknown>;

const namespace = CUSTOM_RULE_NAMESPACE;
const userAgent =
  "WebsiteTechScraper/0.1.0 (https://contact.website-tech-scraper.dev/crawler)";
const textEncoder = new TextEncoder();
const fixedSchemaBytes = readFileSync(new URL(
  "../fingerprints/upstream/webappanalyzer/schema.json",
  import.meta.url,
));

function setConfigValue(
  value: JsonRecord,
  path: readonly string[],
  replacement: unknown,
): void {
  let current = value;

  for (const key of path.slice(0, -1)) {
    const next = current[key];
    assert.equal(typeof next, "object");
    assert.notEqual(next, null);
    assert.equal(Array.isArray(next), false);
    current = next as JsonRecord;
  }

  const finalKey = path.at(-1);
  assert.notEqual(finalKey, undefined);
  current[finalKey as string] = replacement;
}

function configWith(
  replacements: ReadonlyArray<readonly [readonly string[], unknown]> = [],
): ScanConfig {
  const value = structuredClone(
    createDefaultScanConfig(userAgent),
  ) as unknown as JsonRecord;

  for (const [path, replacement] of replacements) {
    setConfigValue(value, path, replacement);
  }

  return parseScanConfig(value);
}

function inputFile(
  kind: CatalogFileKind,
  relativePath: string,
  value: unknown,
  options: {
    readonly bytes?: Uint8Array;
    readonly ruleNamespace?: string;
  } = {},
): CatalogInputFile {
  return {
    kind,
    namespace: options.ruleNamespace ?? namespace,
    relativePath,
    bytes: options.bytes ?? textEncoder.encode(JSON.stringify(value)),
  };
}

function technology(
  overrides: JsonRecord = {},
): JsonRecord {
  return {
    cats: [1],
    website: "https://technology.example",
    ...overrides,
  };
}

function compilationInput(
  technologyDocuments: readonly JsonRecord[],
  options: {
    readonly categories?: JsonRecord;
    readonly extraFiles?: readonly CatalogInputFile[];
    readonly reverseFiles?: boolean;
  } = {},
): CatalogCompilationInput {
  const files: CatalogInputFile[] = [
    inputFile(
      "schema",
      "upstream/webappanalyzer/schema.json",
      { fixed: true },
      {
        bytes: fixedSchemaBytes,
        ruleNamespace: UPSTREAM_RULE_NAMESPACE,
      },
    ),
    inputFile(
      "categories",
      "upstream/webappanalyzer/categories.json",
      options.categories ?? {
        "1": { name: "CMS", groups: [], priority: 1 },
      },
      { ruleNamespace: UPSTREAM_RULE_NAMESPACE },
    ),
    ...technologyDocuments.map((value, index) =>
      inputFile(
        "technologies",
        `custom/technologies/fixture-${index}.json`,
        value,
      ),
    ),
    ...(options.extraFiles ?? []),
  ];

  return {
    source: CATALOG_SOURCE,
    revision: CATALOG_REVISION,
    files: options.reverseFiles ? files.reverse() : files,
  };
}

function compile(
  technologyDocuments: readonly JsonRecord[],
  config = configWith(),
  options: Parameters<typeof compilationInput>[1] = {},
): CompiledFingerprintCatalog {
  return compileFingerprintCatalog(
    compilationInput(technologyDocuments, options),
    config,
  );
}

function expectCatalogError(
  action: () => unknown,
  code: "CATALOG_INVALID" | "CATALOG_LIMIT_EXCEEDED",
  message?: RegExp,
): FingerprintCatalogError {
  let caught: unknown;

  try {
    action();
  } catch (error) {
    caught = error;
  }

  if (!(caught instanceof FingerprintCatalogError)) {
    assert.fail("Expected FingerprintCatalogError.");
  }

  assert.equal(caught.code, code);
  if (message !== undefined) {
    assert.match(caught.message, message);
  }
  return caught;
}

function ruleId(values: readonly unknown[]): string {
  return `sha256:${createHash("sha256")
    .update(JSON.stringify(values), "utf8")
    .digest("hex")}`;
}

function framedDigest(files: readonly CatalogInputFile[]): string {
  const hash = createHash("sha256");
  const ordered = [...files].sort((left, right) =>
    Buffer.compare(
      Buffer.from(left.relativePath, "utf8"),
      Buffer.from(right.relativePath, "utf8"),
    ),
  );

  for (const file of ordered) {
    const path = Buffer.from(file.relativePath, "utf8");
    const bytes = Buffer.from(file.bytes);
    const pathLength = Buffer.alloc(8);
    const bytesLength = Buffer.alloc(8);
    pathLength.writeBigUInt64BE(BigInt(path.byteLength));
    bytesLength.writeBigUInt64BE(BigInt(bytes.byteLength));
    hash.update(pathLength);
    hash.update(path);
    hash.update(bytesLength);
    hash.update(bytes);
  }

  return `sha256:${hash.digest("hex")}`;
}

function assertDeepFrozenPlainData(
  value: unknown,
  seen = new Set<object>(),
): void {
  if (typeof value !== "object" || value === null || seen.has(value)) {
    assert.notEqual(typeof value, "function");
    return;
  }

  seen.add(value);
  assert.equal(Object.isFrozen(value), true);
  assert.equal(value instanceof RegExp, false);
  assert.equal(
    Object.getPrototypeOf(value),
    Array.isArray(value) ? Array.prototype : Object.prototype,
  );

  for (const child of Object.values(value)) {
    assertDeepFrozenPlainData(child, seen);
  }
}

let loadedBaseline: CompiledFingerprintCatalog | undefined;

function baseline(): CompiledFingerprintCatalog {
  loadedBaseline ??= loadFingerprintCatalog(configWith());
  return loadedBaseline;
}

test("loads the exact pinned baseline as immutable plain data", () => {
  const catalog = baseline();

  assert.equal(catalog.source, CATALOG_SOURCE);
  assert.equal(catalog.revision, CATALOG_REVISION);
  assert.equal(catalog.digest, PINNED_UPSTREAM_DIGEST);
  assert.deepEqual({
    categories: catalog.categories.length,
    technologies: catalog.technologies.length,
    rules: catalog.rules.length,
    declarationCount: catalog.declarationCount,
    relationshipCount: catalog.relationshipCount,
    regexSourceCount: catalog.regexSourceCount,
    regexSourceCodeUnits: catalog.regexSourceCodeUnits,
    domSelectors: catalog.inspectionPlan.dom.length,
    domFacts: catalog.inspectionPlan.dom.reduce(
      (total, inspection) => total + inspection.facts.length,
      0,
    ),
    javascriptPaths: catalog.inspectionPlan.javascript.length,
    probePaths: catalog.inspectionPlan.probePaths.length,
    dnsRecordTypes: catalog.inspectionPlan.dnsRecordTypes,
    tlsIssuer: catalog.inspectionPlan.tlsIssuer,
    networkUrlRules: catalog.rules.filter(
      (rule) => rule.source === "network_url",
    ).length,
    indexes: catalog.indexes.length,
  }, {
    categories: 109,
    technologies: 7_575,
    rules: 15_489,
    declarationCount: 15_496,
    relationshipCount: 2_241,
    regexSourceCount: 8_541,
    regexSourceCodeUnits: 200_325,
    domSelectors: 1_769,
    domFacts: 1_780,
    javascriptPaths: 5_570,
    probePaths: 3,
    dnsRecordTypes: ["CNAME", "MX", "NS", "SOA", "TXT"],
    tlsIssuer: true,
    networkUrlRules: 113,
    indexes: 16,
  });
  assertDeepFrozenPlainData(catalog);
  assert.deepEqual(structuredClone(catalog), catalog);
});

test("compiles exact DOM facts and JavaScript segments with matching demand", () => {
  const path = ".__NEXT_DATA__.items.0.value-with-space ";
  const doubleLeadingPath = "..double.leading";
  const catalog = compile([
    {
      Alpha: technology({
        dom: {
          "#app": {
            exists: "",
            text: "",
            attributes: {
              class: "",
              title: "^Alpha$",
            },
            properties: {
              __k: "",
            },
          },
        },
        js: {
          [path]: "",
          [doubleLeadingPath]: "",
        },
      }),
    },
    {
      Beta: technology({
        dom: {
          "#app": {
            text: "^Alpha$",
            attributes: { class: "^app$" },
          },
        },
        js: { [path]: "^Alpha$" },
      }),
    },
  ]);
  const locator = (
    kind: "exists" | "text" | "attributes" | "properties",
    name: string | null,
  ): string => JSON.stringify(["#app", kind, name]);

  assert.deepEqual(catalog.inspectionPlan.dom, [{
    selector: "#app",
    facts: [
      {
        kind: "exists",
        name: null,
        locator: locator("exists", null),
        demand: { presence: true, value: false },
      },
      {
        kind: "text",
        name: null,
        locator: locator("text", null),
        demand: { presence: true, value: true },
      },
      {
        kind: "attribute",
        name: "class",
        locator: locator("attributes", "class"),
        demand: { presence: true, value: true },
      },
      {
        kind: "attribute",
        name: "title",
        locator: locator("attributes", "title"),
        demand: { presence: false, value: true },
      },
      {
        kind: "property",
        name: "__k",
        locator: locator("properties", "__k"),
        demand: { presence: true, value: false },
      },
    ],
  }]);
  assert.deepEqual(catalog.inspectionPlan.javascript, [
    {
      path: doubleLeadingPath,
      segments: ["", "double", "leading"],
      demand: { presence: true, value: false },
    },
    {
      path,
      segments: ["__NEXT_DATA__", "items", "0", "value-with-space "],
      demand: { presence: true, value: true },
    },
  ]);
});

test("compiles XHR patterns against complete browser request URLs", () => {
  const catalog = compile([{
    Alpha: technology({
      xhr: ["/umbraco/api/", "api\\.vendor\\.tld/v1/"],
    }),
  }]);

  assert.deepEqual(
    catalog.rules.map((rule) => [rule.source, rule.pattern]),
    [
      ["network_url", "api\\.vendor\\.tld/v1/"],
      ["network_url", "/umbraco/api/"],
    ],
  );
  assert.equal(
    catalog.indexes.some((index) => index.source === "network_hostname"),
    false,
  );
});

test("preserves the pinned inspection-plan fact mix and unusual JavaScript paths", () => {
  const catalog = baseline();
  const domFacts = catalog.inspectionPlan.dom.flatMap(
    (inspection) => inspection.facts,
  );
  const summarize = <T extends { readonly demand: {
    readonly presence: boolean;
    readonly value: boolean;
  } }>(items: readonly T[]): {
    readonly presenceOnly: number;
    readonly valueOnly: number;
    readonly both: number;
  } => ({
    presenceOnly: items.filter(
      (item) => item.demand.presence && !item.demand.value,
    ).length,
    valueOnly: items.filter(
      (item) => !item.demand.presence && item.demand.value,
    ).length,
    both: items.filter(
      (item) => item.demand.presence && item.demand.value,
    ).length,
  });

  assert.deepEqual(
    Object.fromEntries(
      (["exists", "text", "attribute", "property"] as const).map((kind) => [
        kind,
        summarize(domFacts.filter((fact) => fact.kind === kind)),
      ]),
    ),
    {
      exists: { presenceOnly: 1_549, valueOnly: 0, both: 0 },
      text: { presenceOnly: 19, valueOnly: 36, both: 0 },
      attribute: { presenceOnly: 35, valueOnly: 139, both: 0 },
      property: { presenceOnly: 2, valueOnly: 0, both: 0 },
    },
  );
  assert.deepEqual(summarize(catalog.inspectionPlan.javascript), {
    presenceOnly: 5_022,
    valueOnly: 547,
    both: 1,
  });

  const byPath = new Map(
    catalog.inspectionPlan.javascript.map((inspection) => [
      inspection.path,
      inspection,
    ]),
  );
  assert.deepEqual(byPath.get(".__NEXT_DATA__.gsp")?.segments, [
    "__NEXT_DATA__",
    "gsp",
  ]);
  assert.deepEqual(
    byPath.get("__core-js_shared__.versions.0.version")?.segments,
    ["__core-js_shared__", "versions", "0", "version"],
  );
  assert.deepEqual(byPath.get("HUCKABUY NAMESPACE.sd")?.segments, [
    "HUCKABUY NAMESPACE",
    "sd",
  ]);
  assert.deepEqual(byPath.get("flb.botId ")?.segments, ["flb", "botId "]);
  assert.deepEqual(
    byPath.get("Magewire.connection-author")?.segments,
    ["Magewire", "connection-author"],
  );
  for (const inspection of catalog.inspectionPlan.javascript) {
    const traversalPath = inspection.path.startsWith(".")
      ? inspection.path.slice(1)
      : inspection.path;
    assert.deepEqual(inspection.segments, traversalPath.split("."));
  }
});

test("derives catalog semantics only from bounded bytes and the fixed schema", () => {
  const original = compilationInput([{
    Alpha: technology({ url: ["alpha"] }),
  }]);
  const wrongSchema: CatalogCompilationInput = {
    ...original,
    files: original.files.map((file) => file.kind === "schema"
      ? { ...file, bytes: textEncoder.encode("{}") }
      : file),
  };
  expectCatalogError(
    () => compileFingerprintCatalog(wrongSchema, configWith()),
    "CATALOG_INVALID",
    /fixed reviewed schema/u,
  );

  const duplicateTechnology = textEncoder.encode(
    "{\"Alpha\":{\"cats\":[1],\"website\":\"https://alpha.example\"},"
    + "\"Alpha\":{\"cats\":[1],\"website\":\"https://other.example\"}}",
  );
  const duplicateInput: CatalogCompilationInput = {
    ...original,
    files: original.files.map((file) => file.kind === "technologies"
      ? { ...file, bytes: duplicateTechnology }
      : file),
  };
  expectCatalogError(
    () => compileFingerprintCatalog(duplicateInput, configWith()),
    "CATALOG_INVALID",
    /duplicate JSON member/u,
  );

  const nested = `${"{\"nested\":".repeat(9)}null${"}".repeat(9)}`;
  const deepTechnology = textEncoder.encode(
    `{"Alpha":{"cats":[1],"website":"https://alpha.example","dom":${nested}}}`,
  );
  const deepInput: CatalogCompilationInput = {
    ...original,
    files: original.files.map((file) => file.kind === "technologies"
      ? { ...file, bytes: deepTechnology }
      : file),
  };
  expectCatalogError(
    () => compileFingerprintCatalog(
      deepInput,
      configWith([[ ["limits", "detector", "catalogJsonDepth"], 8 ]]),
    ),
    "CATALOG_LIMIT_EXCEEDED",
    /JSON depth/u,
  );
});

test("enforces the catalog file allowlist and custom-name collision policy", () => {
  const base = compilationInput([{
    Alpha: technology(),
  }]);
  const escapedPath: CatalogCompilationInput = {
    ...base,
    files: base.files.map((file) => file.kind === "technologies"
      ? { ...file, relativePath: "custom/technologies/../escape.json" }
      : file),
  };
  expectCatalogError(
    () => compileFingerprintCatalog(escapedPath, configWith()),
    "CATALOG_INVALID",
    /relative POSIX form/u,
  );

  const wrongNamespace: CatalogCompilationInput = {
    ...base,
    files: base.files.map((file) => file.kind === "schema"
      ? { ...file, namespace: CUSTOM_RULE_NAMESPACE }
      : file),
  };
  expectCatalogError(
    () => compileFingerprintCatalog(wrongNamespace, configWith()),
    "CATALOG_INVALID",
    /not allowed/u,
  );

  expectCatalogError(
    () => compileFingerprintCatalog(
      { ...base, revision: "unreviewed-revision" },
      configWith(),
    ),
    "CATALOG_INVALID",
    /fixed provenance/u,
  );

  expectCatalogError(
    () => compile([
      { Alpha: technology() },
      { Alpha: technology({ website: "https://custom.example" }) },
    ]),
    "CATALOG_INVALID",
    /declared more than once/u,
  );
});

test("pins alternate roots and rejects unexpected or symlinked entries", () => {
  const temporary = mkdtempSync(join(tmpdir(), "fingerprint-catalog-test-"));
  const sourceRoot = fileURLToPath(new URL("../fingerprints/", import.meta.url));
  const copiedRoot = join(temporary, "fingerprints");
  const linkedRoot = join(temporary, "linked-fingerprints");

  try {
    cpSync(sourceRoot, copiedRoot, { recursive: true });
    const categoriesPath = join(
      copiedRoot,
      "upstream",
      "webappanalyzer",
      "categories.json",
    );
    const originalCategories = readFileSync(categoriesPath);
    const changedCategories = JSON.parse(originalCategories.toString("utf8")) as JsonRecord;
    const firstCategory = changedCategories["1"] as JsonRecord;
    firstCategory.name = "Changed CMS";
    writeFileSync(categoriesPath, JSON.stringify(changedCategories));

    expectCatalogError(
      () => loadFingerprintCatalog(
        configWith(),
        pathToFileURL(`${copiedRoot}${sep}`),
      ),
      "CATALOG_INVALID",
      /pinned snapshot/u,
    );

    writeFileSync(categoriesPath, originalCategories);
    mkdirSync(join(copiedRoot, "unexpected"));
    expectCatalogError(
      () => loadFingerprintCatalog(
        configWith(),
        pathToFileURL(`${copiedRoot}${sep}`),
      ),
      "CATALOG_INVALID",
      /unexpected entries/u,
    );
    rmSync(join(copiedRoot, "unexpected"), { recursive: true });

    mkdirSync(join(copiedRoot, "custom", "technologies"), { recursive: true });
    symlinkSync(categoriesPath, join(copiedRoot, "custom", "technologies", "bad.json"));
    expectCatalogError(
      () => loadFingerprintCatalog(
        configWith(),
        pathToFileURL(`${copiedRoot}${sep}`),
      ),
      "CATALOG_INVALID",
      /not an allowed JSON file/u,
    );

    symlinkSync(sourceRoot, linkedRoot, "dir");
    expectCatalogError(
      () => loadFingerprintCatalog(
        configWith(),
        pathToFileURL(`${linkedRoot}${sep}`),
      ),
      "CATALOG_INVALID",
      /non-symlink directory/u,
    );
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("compiles minimal definitions in canonical order with stable rule ids", () => {
  const categories = {
    "2": { name: "Analytics", groups: [], priority: 2 },
    "1": { name: "CMS", groups: [], priority: 1 },
  };
  const document = {
    Beta: technology({
      cats: [2],
      text: ["beta"],
    }),
    Alpha: technology({
      cats: [2, 1],
      headers: {
        Server: "Alpha\\;confidence:40",
      },
      url: ["alpha\\.example"],
    }),
  };
  const first = compileFingerprintCatalog(
    compilationInput([document], { categories }),
    configWith(),
  );
  const reordered = compileFingerprintCatalog(
    compilationInput([document], { categories, reverseFiles: true }),
    configWith(),
  );

  assert.deepEqual(reordered, first);
  assert.deepEqual(first.categories, [
    { id: 1, name: "CMS" },
    { id: 2, name: "Analytics" },
  ]);
  assert.deepEqual(first.technologies.map((item) => item.name), ["Alpha", "Beta"]);
  assert.deepEqual(first.technologies[0]?.categories, [
    { id: 1, name: "CMS" },
    { id: 2, name: "Analytics" },
  ]);
  assert.deepEqual(
    first.rules.map((item) => `${item.source}:${item.technology}:${item.locator ?? ""}`),
    ["url:Alpha:", "header:Alpha:server", "text:Beta:"],
  );

  const headerRule = first.rules.find((item) => item.source === "header");
  assert.notEqual(headerRule, undefined);
  assert.equal(headerRule?.ruleId, ruleId([
    namespace,
    "Alpha",
    "header",
    "server",
    "Alpha\\;confidence:40",
  ]));
  assert.equal(headerRule?.pattern, "Alpha");
  assert.equal(headerRule?.confidence, 40);
});

test("deduplicates identical declarations after header normalization", () => {
  const catalog = compile([{
    Alpha: technology({
      headers: {
        Server: "alpha",
        server: "alpha",
      },
      url: ["alpha", "alpha"],
    }),
  }]);

  assert.equal(catalog.declarationCount, 4);
  assert.equal(catalog.rules.length, 2);
  assert.equal(catalog.regexSourceCount, 4);
  const header = catalog.rules.find((rule) => rule.source === "header");
  assert.equal(header?.locator, "server");
  const headerIndex = catalog.indexes.find((index) => index.source === "header");
  assert.deepEqual(headerIndex?.keyed, [{
    locator: "server",
    ruleOrdinals: [catalog.rules.indexOf(header!)],
  }]);
});

test("normalizes cookie locator regexes including the upstream (?i) marker", () => {
  const catalog = compile([{
    Alpha: technology({
      cookies: {
        "(?i)^session_[a-z]+$": "^alpha$",
        plain_cookie: "",
      },
    }),
  }]);
  const patterned = catalog.rules.find(
    (rule) => rule.locator === "(?i)^session_[a-z]+$",
  );
  const plain = catalog.rules.find((rule) => rule.locator === "plain_cookie");

  assert.equal(patterned?.locatorPattern, "^(?:^session_[a-z]+$)$");
  assert.equal(patterned?.pattern, "^alpha$");
  assert.equal(patterned?.matchMode, "regex");
  assert.equal(plain?.locatorPattern, "^(?:plain_cookie)$");
  assert.equal(plain?.pattern, null);
  assert.equal(plain?.matchMode, "presence");
  const cookieIndex = catalog.indexes.find((index) => index.source === "cookie");
  assert.deepEqual(cookieIndex?.keyed, []);
  assert.deepEqual(
    cookieIndex?.patternLocatorRuleOrdinals,
    catalog.rules
      .map((rule, ordinal) => ({ rule, ordinal }))
      .filter(({ rule }) => rule.source === "cookie")
      .map(({ ordinal }) => ordinal),
  );
});

test("separates presence, literal, regex, confidence, and version metadata", () => {
  const catalog = compile([{
    Alpha: technology({
      certIssuer: "Alpha CA",
      headers: {
        server: "",
      },
      meta: {
        generator: "^Alpha ([0-9.]+)\\;confidence:40\\;version:\\1",
      },
      probe: {
        "/alpha": "",
      },
      robots: ["Disallow: /alpha"],
    }),
  }]);
  const bySource = new Map(catalog.rules.map((rule) => [rule.source, rule]));

  assert.deepEqual(
    {
      pattern: bySource.get("header")?.pattern,
      matchMode: bySource.get("header")?.matchMode,
      version: bySource.get("header")?.versionTemplate,
    },
    { pattern: null, matchMode: "presence", version: null },
  );
  assert.deepEqual(
    {
      pattern: bySource.get("meta")?.pattern,
      matchMode: bySource.get("meta")?.matchMode,
      confidence: bySource.get("meta")?.confidence,
      version: bySource.get("meta")?.versionTemplate,
    },
    {
      pattern: "^Alpha ([0-9.]+)",
      matchMode: "regex",
      confidence: 40,
      version: "\\1",
    },
  );
  assert.equal(bySource.get("robots")?.matchMode, "literal");
  assert.equal(bySource.get("tls_issuer")?.matchMode, "literal");
  assert.equal(bySource.get("probe")?.matchMode, "presence");
  assert.deepEqual(catalog.inspectionPlan.probePaths, ["/alpha"]);
});

test("derives a deterministic DNS and TLS inspection plan from catalog demand", () => {
  const catalog = compile([
    {
      Alpha: technology({
        certIssuer: "Alpha CA",
        dns: {
          txt: ["alpha-verification"],
          MX: ["mail\\.alpha\\.example"],
        },
      }),
    },
    {
      Beta: technology({
        dns: {
          cname: ["edge\\.beta\\.example"],
          MX: ["mail\\.beta\\.example"],
        },
      }),
    },
  ]);
  const noInfrastructure = compile([{
    Plain: technology({ headers: { server: "Plain" } }),
  }]);

  assert.deepEqual(catalog.inspectionPlan.dnsRecordTypes, [
    "CNAME",
    "MX",
    "TXT",
  ]);
  assert.equal(catalog.inspectionPlan.tlsIssuer, true);
  assert.deepEqual(noInfrastructure.inspectionPlan.dnsRecordTypes, []);
  assert.equal(noInfrastructure.inspectionPlan.tlsIssuer, false);
});

test("preserves pinned version metadata on a presence rule", () => {
  const catalog = compile([{
    Alpha: technology({
      headers: { server: "\\;version:\\1" },
    }),
  }]);
  const rule = catalog.rules[0];

  assert.equal(rule?.pattern, null);
  assert.equal(rule?.matchMode, "presence");
  assert.equal(rule?.versionTemplate, "\\1");
});

test("rejects weak-schema nested forms during semantic compilation", () => {
  const invalidTechnologies: readonly JsonRecord[] = [
    technology({ headers: { server: 7 } }),
    technology({ cookies: { session: { nested: true } } }),
    technology({ js: { "window.Alpha": false } }),
    technology({ dns: { MX: "mail.example" } }),
    technology({ dom: "#app" }),
    technology({ dom: { "#app": [] } }),
    technology({ dom: { "#app": { unsupported: "" } } }),
    technology({ dom: { "#app": { attributes: { class: 7 } } } }),
  ];

  for (const [index, value] of invalidTechnologies.entries()) {
    expectCatalogError(
      () => compile([{ [`Invalid ${index}`]: value }]),
      "CATALOG_INVALID",
    );
  }
});

test("rejects unsafe category metadata, JavaScript paths, and probe paths", () => {
  const invalidCategories: readonly JsonRecord[] = [
    { "1": { name: "CMS", priority: 1 } },
    { "1": { name: "CMS", groups: "3", priority: 1 } },
    { "1": { name: "CMS", groups: [3, 3], priority: 1 } },
    { "1": { name: "CMS", groups: [3], priority: 0 } },
    { "1": { name: "CMS\nInjected", groups: [3], priority: 1 } },
  ];
  for (const categories of invalidCategories) {
    expectCatalogError(
      () => compile([{ Alpha: technology() }], configWith(), { categories }),
      "CATALOG_INVALID",
    );
  }

  const unsafeDefinitions: readonly JsonRecord[] = [
    { Alpha: technology({ js: { "window\n.Alpha": "" } }) },
    { Alpha: technology({ probe: { "//other.example/probe": "" } }) },
    { Alpha: technology({ probe: { "/\\other.example/probe": "" } }) },
    { Alpha: technology({ probe: { "/space here": "" } }) },
  ];
  for (const document of unsafeDefinitions) {
    expectCatalogError(() => compile([document]), "CATALOG_INVALID");
  }
});

test("rejects invalid references, self relations, and relationship tags", () => {
  const cases: readonly JsonRecord[] = [
    {
      Alpha: technology({ requires: ["Missing"] }),
    },
    {
      Alpha: technology({ requires: ["Alpha"] }),
    },
    {
      Alpha: technology({ excludes: ["Alpha"] }),
    },
    {
      Alpha: technology({ requires: ["Beta\\;confidence:50"] }),
      Beta: technology(),
    },
    {
      Alpha: technology({ requiresCategory: [2] }),
    },
    {
      Alpha: technology({ implies: ["Missing"] }),
    },
    {
      Alpha: technology({ implies: ["Beta\\;confidence:0"] }),
      Beta: technology(),
    },
    {
      Alpha: technology({ implies: ["Beta\\;unknown:value"] }),
      Beta: technology(),
    },
    {
      Alpha: technology({ implies: ["Beta\\;version:not safe"] }),
      Beta: technology(),
    },
  ];

  for (const value of cases) {
    expectCatalogError(() => compile([value]), "CATALOG_INVALID");
  }

  const selfImplication = compile([{
    Alpha: technology({ implies: ["Alpha"] }),
  }]);
  assert.deepEqual(selfImplication.technologies[0]?.implies, []);
  assert.equal(selfImplication.relationshipCount, 1);

  expectCatalogError(
    () => compile([{
      Alpha: technology({ implies: ["Alpha\\;version:not safe"] }),
    }]),
    "CATALOG_INVALID",
    /unsafe literal version/u,
  );

  const oneCodeUnitVersion = configWith([
    [["limits", "evidence", "versionCodeUnits"], 1],
  ]);
  const boundary = compile([{
    Alpha: technology({ implies: ["Beta\\;version:1"] }),
    Beta: technology(),
  }], oneCodeUnitVersion);
  assert.equal(boundary.technologies[0]?.implies[0]?.version, "1");
  expectCatalogError(
    () => compile([{
      Alpha: technology({ implies: ["Beta\\;version:12"] }),
      Beta: technology(),
    }], oneCodeUnitVersion),
    "CATALOG_LIMIT_EXCEEDED",
    /configured version limit/u,
  );
});

test("rejects malformed, duplicate, unsupported, and unsafe direct tags", () => {
  const originals = [
    "alpha\\;confidence",
    "alpha\\;confidence:101",
    "alpha\\;confidence:10\\;confidence:20",
    "alpha\\;unknown:value",
    "alpha\\;version:\\0",
    "alpha\\;version:\\1?missing-colon",
  ];

  for (const original of originals) {
    expectCatalogError(
      () => compile([{
        Alpha: technology({ url: [original] }),
      }]),
      "CATALOG_INVALID",
    );
  }
});

test("preserves reviewed Progress and PublishPress catalog behavior", () => {
  const catalog = baseline();
  const progress = catalog.rules.find(
    (rule) => rule.technology === "Progress Sitefinity" && rule.source === "meta",
  );

  assert.deepEqual(
    {
      locator: progress?.locator,
      original: progress?.original,
      pattern: progress?.pattern,
      version: progress?.versionTemplate,
    },
    {
      locator: "generator",
      original: "^Sitefinity\\s([\\S]{3,9})\\;version:\\1",
      pattern: "^Sitefinity\\s([\\S]{3,9})",
      version: "\\1",
    },
  );

  const publishInspection = catalog.inspectionPlan.dom.find((inspection) =>
    inspection.selector.includes("advanced-gutenberg/assets/css/blocks.css"),
  );
  assert.notEqual(publishInspection, undefined);
  assert.equal(publishInspection?.selector.includes("\\;version:\\1"), true);
  const publishRule = catalog.rules.find(
    (rule) => rule.technology === "PublishPress Blocks" && rule.source === "dom",
  );
  assert.equal(
    publishRule?.locator,
    JSON.stringify([publishInspection?.selector, "exists", null]),
  );
  assert.equal(publishRule?.matchMode, "presence");
  assert.equal(publishRule?.versionTemplate, null);
  assert.deepEqual(publishInspection?.facts, [{
    kind: "exists",
    name: null,
    locator: publishRule?.locator,
    demand: { presence: true, value: false },
  }]);
});

test("enforces catalog, pattern, relationship, and inspection-plan limits", () => {
  const baseInput = compilationInput([{
    Alpha: technology(),
  }]);
  const overFile: CatalogCompilationInput = {
    ...baseInput,
    files: baseInput.files.map((file, index) => index === 0
      ? inputFile(
        "schema",
        "upstream/webappanalyzer/schema.json",
        {},
        {
          bytes: new Uint8Array(524_289),
          ruleNamespace: UPSTREAM_RULE_NAMESPACE,
        },
      )
      : file),
  };
  expectCatalogError(
    () => compileFingerprintCatalog(
      overFile,
      configWith([[ ["limits", "detector", "catalogFileBytes"], 524_288 ]]),
    ),
    "CATALOG_LIMIT_EXCEEDED",
  );

  expectCatalogError(
    () => compile(
      [{ Alpha: technology({ url: ["a", "b"] }) }],
      configWith([[ ["limits", "detector", "patternsPerCatalog"], 1 ]]),
    ),
    "CATALOG_LIMIT_EXCEEDED",
  );
  expectCatalogError(
    () => compile(
      [{ Alpha: technology({ url: ["abcd"] }) }],
      configWith([[ ["limits", "detector", "totalPatternSourceCodeUnits"], 3 ]]),
    ),
    "CATALOG_LIMIT_EXCEEDED",
  );
  const literalLimit = configWith([
    [["limits", "detector", "patternSourceCodeUnits"], 3],
  ]);
  const literalBoundary = compile([{
    Alpha: technology({ robots: ["abc"] }),
  }], literalLimit);
  assert.equal(
    literalBoundary.rules.find((rule) => rule.source === "robots")?.pattern,
    "abc",
  );
  expectCatalogError(
    () => compile(
      [{ Alpha: technology({ robots: ["abcd"] }) }],
      literalLimit,
    ),
    "CATALOG_LIMIT_EXCEEDED",
  );
  expectCatalogError(
    () => compile([{
      Alpha: technology({ robots: ["x".repeat(2_049)] }),
    }]),
    "CATALOG_LIMIT_EXCEEDED",
  );
  expectCatalogError(
    () => compile(
      [{ Alpha: technology({ dom: ["#one", "#two"] }) }],
      configWith([[ ["limits", "inspection", "domSelectors"], 1 ]]),
    ),
    "CATALOG_LIMIT_EXCEEDED",
  );
  expectCatalogError(
    () => compile([{
      Alpha: technology({
        dom: {
          [`#${"a".repeat(1_023)}`]: {
            attributes: { ["b".repeat(1_024)]: "" },
          },
        },
      }),
    }]),
    "CATALOG_LIMIT_EXCEEDED",
    /evidence-key limit/u,
  );
  expectCatalogError(
    () => compile(
      [{
        Alpha: technology({ requires: ["Beta"], excludes: ["Gamma"] }),
        Beta: technology(),
        Gamma: technology(),
      }],
      configWith([[ ["limits", "detector", "relationshipEdgesPerCatalog"], 1 ]]),
    ),
    "CATALOG_LIMIT_EXCEEDED",
  );
  expectCatalogError(
    () => compile(
      [{ AA: technology() }],
      configWith([[ ["limits", "detector", "technologyNameCodePoints"], 1 ]]),
    ),
    "CATALOG_LIMIT_EXCEEDED",
  );
});

test("uses sorted UTF-8 paths and unsigned 64-bit framing for catalog digests", () => {
  const first = inputFile(
    "technologies",
    "z/alpha.json",
    {},
    { bytes: textEncoder.encode("payload-a") },
  );
  const second = inputFile(
    "technologies",
    "a/beta.json",
    {},
    { bytes: textEncoder.encode("payload-b") },
  );
  const ordered = [first, second];

  assert.equal(computeCatalogDigest(ordered), framedDigest(ordered));
  assert.equal(computeCatalogDigest([...ordered].reverse()), framedDigest(ordered));

  const ambiguousOne = [inputFile(
    "schema",
    "a",
    {},
    { bytes: textEncoder.encode("bc") },
  )];
  const ambiguousTwo = [inputFile(
    "schema",
    "ab",
    {},
    { bytes: textEncoder.encode("c") },
  )];
  assert.notEqual(
    computeCatalogDigest(ambiguousOne),
    computeCatalogDigest(ambiguousTwo),
  );
});
