import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { createDefaultScanConfig } from "../src/config.ts";
import {
  loadFingerprintCatalog,
  type CatalogSignalIndex,
  type CompiledFingerprintCatalog,
  type CompiledFingerprintRule,
} from "../src/detect/catalog.ts";
import {
  createDetectorPool,
  type DetectorCandidate,
} from "../src/detect/pool.ts";

interface CorrectionFixture {
  readonly label: string;
  readonly source: DetectorCandidate["source"];
  readonly kind?: DetectorCandidate["kind"];
  readonly key?: string | null;
  readonly value: string;
  readonly expected: readonly string[];
}

const userAgent =
  "WebsiteTechScraper/0.1.5 (https://contact.website-tech-scraper.dev/crawler)";

let loadedCatalog: CompiledFingerprintCatalog | undefined;

function fullCatalog(): CompiledFingerprintCatalog {
  loadedCatalog ??= loadFingerprintCatalog(createDefaultScanConfig(userAgent));
  return loadedCatalog;
}

function isolatedCatalog(
  rules: readonly CompiledFingerprintRule[],
): CompiledFingerprintCatalog {
  const full = fullCatalog();
  const technologyNames = new Set(rules.map((rule) => rule.technology));
  const sources = [...new Set(rules.map((rule) => rule.source))];
  const indexes: CatalogSignalIndex[] = sources.map((source) => {
    const unkeyedRuleOrdinals: number[] = [];
    const keyed = new Map<string, number[]>();
    const patternLocatorRuleOrdinals: number[] = [];
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
      keyed: [...keyed].map(([locator, ruleOrdinals]) => ({
        locator,
        ruleOrdinals,
      })),
      patternLocatorRuleOrdinals,
    };
  });

  return {
    source: full.source,
    revision: full.revision,
    digest: full.digest,
    categories: full.categories,
    technologies: full.technologies.filter((technology) =>
      technologyNames.has(technology.name)),
    rules,
    indexes,
    inspectionPlan: {
      dom: [],
      javascript: [],
      probePaths: [],
      dnsRecordTypes: [],
      tlsIssuer: false,
    },
    declarationCount: rules.length,
    relationshipCount: 0,
    regexSourceCount: rules.length,
    regexSourceCodeUnits: rules.reduce(
      (total, rule) => total + (rule.pattern?.length ?? 0),
      0,
    ),
  };
}

function correctionCatalog(): CompiledFingerprintCatalog {
  const technologyNames = new Set([
    "Lightbox",
    "Liveinternet",
    "Magento",
    "Onsen UI",
    "Sirvoy",
    "Store Vantage",
    "TYPO3 CMS",
    "WebsiteBuilder",
    "Wix eCommerce",
  ]);
  return isolatedCatalog(fullCatalog().rules.filter((rule) =>
    technologyNames.has(rule.technology)));
}

test("correction fixtures match only the reviewed exact signals", {
  timeout: 20_000,
}, async () => {
  const fixtures = JSON.parse(readFileSync(new URL(
    "./fixtures/catalog-corrections.v1.json",
    import.meta.url,
  ), "utf8")) as CorrectionFixture[];
  const catalog = correctionCatalog();
  const pool = await createDetectorPool(
    catalog,
    createDefaultScanConfig(userAgent),
  );

  try {
    for (const [index, fixture] of fixtures.entries()) {
      const candidate: DetectorCandidate = {
        id: index.toString().padStart(4, "0"),
        priority: true,
        kind: fixture.kind ?? "value",
        source: fixture.source,
        key: fixture.key ?? null,
        value: fixture.value,
      };
      const result = await pool.match([candidate]);
      assert.equal(result.completed, true, fixture.label);
      assert.deepEqual(result.errors, [], fixture.label);
      assert.deepEqual(
        [...new Set(result.matches.map((match) =>
          catalog.rules[match.ruleOrdinal]?.technology))]
          .filter((name): name is string => name !== undefined)
          .sort(),
        [...fixture.expected].sort(),
        fixture.label,
      );
    }
  } finally {
    await pool.close();
  }
});

test("the bounded Liveinternet replacement rejects a 4 MiB negative without timeout", {
  timeout: 20_000,
}, async () => {
  const catalog = correctionCatalog();
  const pool = await createDetectorPool(
    catalog,
    createDefaultScanConfig(userAgent),
  );

  try {
    const result = await pool.match([{
      id: "negative-liveinternet",
      priority: true,
      kind: "value",
      source: "html",
      key: null,
      value: `<script>${"x".repeat(4 * 1_024 * 1_024)}</script>`,
    }]);
    assert.equal(result.completed, true);
    assert.deepEqual(result.matches, []);
    assert.equal(
      result.errors.some((error) => error.code === "REGEX_RULE_TIMEOUT"),
      false,
    );
  } finally {
    await pool.close();
  }
});

test("shared alias observations emit only the retained canonical technology", {
  timeout: 20_000,
}, async () => {
  const selected = [
    ["LiteSpeed Cache", "header", "x-litespeed-cache", ""],
    [
      "All in One SEO",
      "html",
      null,
      "<!-- all in one seo pack ([\\d.]+) \\;version:\\1",
    ],
    ["Material UI", "css", null, "\\.MuiPaper-root"],
    ["Adobe Fonts", "script_url", null, "use\\.typekit\\.com"],
  ] as const;
  const full = fullCatalog();
  const rules = selected.map(([technology, source, locator, original]) => {
    const rule = full.rules.find((candidate) =>
      candidate.technology === technology
      && candidate.source === source
      && candidate.locator === locator
      && candidate.original === original);
    assert.notEqual(rule, undefined, technology);
    return rule as CompiledFingerprintRule;
  });
  const catalog = isolatedCatalog(rules);
  const pool = await createDetectorPool(
    catalog,
    createDefaultScanConfig(userAgent),
  );
  const candidates: readonly DetectorCandidate[] = [
    {
      id: "0001",
      priority: true,
      kind: "value",
      source: "header",
      key: "x-litespeed-cache",
      value: "hit",
    },
    {
      id: "0002",
      priority: true,
      kind: "value",
      source: "html",
      key: null,
      value: "<!-- all in one seo pack 4.6.0 -->",
    },
    {
      id: "0003",
      priority: true,
      kind: "value",
      source: "css",
      key: null,
      value: ".MuiPaper-root { display: block; }",
    },
    {
      id: "0004",
      priority: true,
      kind: "value",
      source: "script_url",
      key: null,
      value: "https://use.typekit.com/abc.js",
    },
  ];

  try {
    const result = await pool.match(candidates);
    assert.equal(result.completed, true);
    assert.deepEqual(result.errors, []);
    assert.deepEqual(
      [...new Set(result.matches.map((match) =>
        catalog.rules[match.ruleOrdinal]?.technology))]
        .filter((name): name is string => name !== undefined)
        .sort(),
      ["Adobe Fonts", "All in One SEO", "LiteSpeed Cache", "Material UI"],
    );
  } finally {
    await pool.close();
  }
});
