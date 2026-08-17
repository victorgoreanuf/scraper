import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { validateHeaderValue } from "node:http";

import { Ajv2020, type AnySchemaObject } from "ajv/dist/2020.js";

export type ScanConfig = {
  readonly schemaVersion: 1;
  readonly scanMode: "full";
  readonly userAgent: string;
  readonly inputPolicy: {
    readonly format: "parquet";
    readonly selectedColumn: "root_domain";
    readonly allowedCodecs: readonly ["UNCOMPRESSED", "SNAPPY"];
  };
  readonly policyVersions: {
    readonly parquet: 1;
    readonly hostname: 1;
    readonly address: 1;
    readonly target: 1;
    readonly robots: 1;
    readonly pageSelection: 1;
    readonly sanitizer: 1;
    readonly evidence: 1;
    readonly relationships: 1;
    readonly detector: 1;
    readonly browserEgress: 1;
    readonly output: 1;
  };
  readonly registryPins: {
    readonly specialUseDomainsReviewedOn: "2026-08-17";
    readonly ianaIpv4UpdatedOn: "2025-10-09";
    readonly ianaIpv6UpdatedOn: "2025-10-09";
    readonly addressOverlayVersion: 1;
  };
  readonly targetPolicy: {
    readonly candidateOrder: readonly [
      "https://{domain}/",
      "https://www.{domain}/",
      "http://{domain}/",
      "http://www.{domain}/",
    ];
    readonly portsByScheme: {
      readonly http: 80;
      readonly https: 443;
    };
    readonly topLevelMethod: "GET";
  };
  readonly limits: {
    readonly concurrency: {
      readonly globalHttp: number;
      readonly perOriginHttp: number;
      readonly fullScans: number;
    };
    readonly timeMs: {
      readonly activeDomain: number;
      readonly httpRequest: number;
      readonly browserPage: number;
      readonly browserSettle: number;
      readonly retryAfterCap: number;
      readonly robotsCache: number;
    };
    readonly parquet: {
      readonly rows: number;
      readonly rowsPerRowGroup: number;
      readonly metadataBytes: number;
      readonly selectedChunkCompressedBytes: number;
      readonly selectedChunkUncompressedBytes: number;
    };
    readonly target: {
      readonly candidates: number;
      readonly redirectsPerChain: number;
    };
    readonly hostname: {
      readonly inputCodeUnits: number;
    };
    readonly url: {
      readonly codeUnits: number;
    };
    readonly http: {
      readonly transactionsPerDomain: number;
      readonly transientRetriesPerRequest: number;
      readonly headerFields: number;
      readonly headerBytes: number;
      readonly htmlCompressedBytesPerPage: number;
      readonly htmlDecompressedBytesPerPage: number;
      readonly staticDecompressedBytesPerDomain: number;
      readonly probeCompressedBytes: number;
      readonly probeDecompressedBytes: number;
    };
    readonly pages: {
      readonly topLevelPerDomain: number;
      readonly catalogProbesPerDomain: number;
      readonly extractedUrlsPerPage: number;
      readonly visibleTextBytesPerPage: number;
    };
    readonly scripts: {
      readonly urlCandidatesPerDomain: number;
      readonly bodiesPerDomain: number;
      readonly bodyBytes: number;
      readonly totalBodyBytesPerDomain: number;
    };
    readonly browser: {
      readonly contextsPerDomain: number;
      readonly activePagesPerContext: number;
      readonly networkHostnamesPerDomain: number;
      readonly requestsPerPage: number;
      readonly requestsPerDomain: number;
      readonly transferBytesPerPage: number;
      readonly transferBytesPerDomain: number;
    };
    readonly cookies: {
      readonly perDomain: number;
      readonly nameCodeUnits: number;
      readonly valueBytes: number;
      readonly totalBytesPerDomain: number;
    };
    readonly dns: {
      readonly recordsPerType: number;
      readonly recordsPerDomain: number;
      readonly txtItemBytes: number;
      readonly textBytesPerDomain: number;
    };
    readonly robots: {
      readonly bodyBytes: number;
      readonly redirects: number;
      readonly lines: number;
      readonly rules: number;
      readonly ruleCodeUnits: number;
      readonly matchingStatesPerUrl: number;
    };
    readonly inspection: {
      readonly domSelectors: number;
      readonly domSelectorCodeUnits: number;
      readonly domMatchesPerSelector: number;
      readonly javascriptPaths: number;
      readonly javascriptPathCodeUnits: number;
      readonly returnedValueBytes: number;
      readonly returnedValuesBytesPerPage: number;
    };
    readonly detector: {
      readonly workers: number;
      readonly technologiesPerCatalog: number;
      readonly technologyNameCodePoints: number;
      readonly categoryNameCodePoints: number;
      readonly categoriesPerTechnology: number;
      readonly categoriesPerCatalog: number;
      readonly relationshipEdgesPerCatalog: number;
      readonly patternsPerCatalog: number;
      readonly patternSourceCodeUnits: number;
      readonly totalPatternSourceCodeUnits: number;
      readonly compileWatchdogMs: number;
      readonly workerOldHeapBytes: number;
      readonly workerYoungHeapBytes: number;
      readonly workerStackBytes: number;
      readonly ruleWatchdogMs: number;
      readonly watchdogPollMs: number;
      readonly activeMsPerDomain: number;
      readonly timeoutsPerDomain: number;
      readonly checkpointRules: number;
      readonly executionsPerDomain: number;
    };
    readonly evidence: {
      readonly matchCodePoints: number;
      readonly safePathSegmentCodeUnits: number;
      readonly hexTokenMinCodeUnits: number;
      readonly base64UrlTokenMinCodeUnits: number;
      readonly versionCodeUnits: number;
    };
    readonly output: {
      readonly jsonlRecordBytes: number;
      readonly technologiesPerDomain: number;
      readonly errorsPerDomain: number;
      readonly evidencePerTechnology: number;
      readonly evidencePerDomain: number;
      readonly inferencesPerTechnology: number;
      readonly inferencesPerDomain: number;
    };
  };
  readonly security: {
    readonly network: {
      readonly allowUrlCredentials: false;
      readonly allowIpInput: false;
      readonly requirePublicAddresses: true;
      readonly rejectMixedAddressAnswers: true;
      readonly validateConnectedAddress: true;
      readonly revalidateRedirects: true;
      readonly connectOnlySelectedAddress: true;
      readonly verifyTls: true;
    };
    readonly robots: {
      readonly productToken: "WebsiteTechScraper";
      readonly failurePolicy: "fail-closed";
      readonly protectedTransportRequired: true;
    };
    readonly browser: {
      readonly allowedMethods: readonly ["GET", "HEAD", "OPTIONS"];
      readonly persistentContexts: false;
      readonly sandbox: true;
      readonly bypassCsp: false;
      readonly serviceWorkers: "block";
      readonly downloads: "deny";
      readonly permissions: readonly [];
      readonly proxyRequired: true;
      readonly proxyBypass: false;
      readonly startupCanaryRequired: true;
      readonly quic: false;
      readonly nonProxiedWebRtc: false;
      readonly webSockets: "block";
      readonly mutableMethods: "block";
      readonly popups: "block";
      readonly crossOriginMainFrames: "block";
      readonly interactions: "deny";
      readonly abortedResourceTypes: readonly ["image", "font", "media"];
    };
    readonly evidence: {
      readonly persistRawObservations: false;
      readonly persistRequestHeaders: false;
      readonly persistCookieValues: false;
      readonly hashCookieValues: false;
      readonly persistResponseBodies: false;
      readonly redactUnknownValues: true;
      readonly redactQueryValues: true;
      readonly redactSensitivePathSegments: true;
      readonly redactSensitiveResponseHeaders: true;
      readonly stripUrlUserInfo: true;
      readonly stripUrlFragments: true;
      readonly emitVersionsFromRedactedSources: false;
      readonly includeErrorStackTraces: false;
    };
  };
};

export type ConfigDigest = `sha256:${string}`;

const scanConfigSchema = JSON.parse(
  readFileSync(
    new URL("../schemas/scan-config.v1.schema.json", import.meta.url),
    "utf8",
  ),
) as AnySchemaObject;

const ajv = new Ajv2020({
  allErrors: true,
  coerceTypes: false,
  ownProperties: true,
  removeAdditional: false,
  strict: true,
  useDefaults: false,
  validateFormats: false,
});
const validateAgainstSchema = ajv.compile(scanConfigSchema);

function hasValidUserAgentHeader(value: unknown): boolean {
  if (
    typeof value !== "object" ||
    value === null ||
    !("userAgent" in value) ||
    typeof value.userAgent !== "string"
  ) {
    return false;
  }

  try {
    validateHeaderValue("user-agent", value.userAgent);
    return true;
  } catch {
    return false;
  }
}

export function validateScanConfig(value: unknown): value is ScanConfig {
  return validateAgainstSchema(value) && hasValidUserAgentHeader(value);
}

function validationMessage(): string {
  const errors = validateAgainstSchema.errors;

  if (errors === null || errors === undefined) {
    return "userAgent is not a valid HTTP header value";
  }

  return errors
    .map((error) => `${error.instancePath || "/"} ${error.message ?? "is invalid"}`)
    .join("; ");
}

function cloneInput(value: unknown): unknown {
  try {
    return structuredClone(value);
  } catch {
    throw new TypeError("Invalid scan configuration: value is not cloneable");
  }
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

export function parseScanConfig(value: unknown): ScanConfig {
  const candidate = cloneInput(value);

  if (!validateScanConfig(candidate)) {
    throw new TypeError(`Invalid scan configuration: ${validationMessage()}`);
  }

  deepFreeze(candidate);
  return candidate as ScanConfig;
}

export function createDefaultScanConfig(userAgent: string): ScanConfig {
  return parseScanConfig({
    schemaVersion: 1,
    scanMode: "full",
    userAgent,
    inputPolicy: {
      format: "parquet",
      selectedColumn: "root_domain",
      allowedCodecs: ["UNCOMPRESSED", "SNAPPY"],
    },
    policyVersions: {
      parquet: 1,
      hostname: 1,
      address: 1,
      target: 1,
      robots: 1,
      pageSelection: 1,
      sanitizer: 1,
      evidence: 1,
      relationships: 1,
      detector: 1,
      browserEgress: 1,
      output: 1,
    },
    registryPins: {
      specialUseDomainsReviewedOn: "2026-08-17",
      ianaIpv4UpdatedOn: "2025-10-09",
      ianaIpv6UpdatedOn: "2025-10-09",
      addressOverlayVersion: 1,
    },
    targetPolicy: {
      candidateOrder: [
        "https://{domain}/",
        "https://www.{domain}/",
        "http://{domain}/",
        "http://www.{domain}/",
      ],
      portsByScheme: {
        http: 80,
        https: 443,
      },
      topLevelMethod: "GET",
    },
    limits: {
      concurrency: {
        globalHttp: 20,
        perOriginHttp: 2,
        fullScans: 3,
      },
      timeMs: {
        activeDomain: 60_000,
        httpRequest: 10_000,
        browserPage: 15_000,
        browserSettle: 2_000,
        retryAfterCap: 2_000,
        robotsCache: 86_400_000,
      },
      parquet: {
        rows: 1_000_000,
        rowsPerRowGroup: 65_536,
        metadataBytes: 16_777_216,
        selectedChunkCompressedBytes: 33_554_432,
        selectedChunkUncompressedBytes: 33_554_432,
      },
      target: {
        candidates: 4,
        redirectsPerChain: 5,
      },
      hostname: {
        inputCodeUnits: 2_048,
      },
      url: {
        codeUnits: 2_048,
      },
      http: {
        transactionsPerDomain: 40,
        transientRetriesPerRequest: 1,
        headerFields: 100,
        headerBytes: 65_536,
        htmlCompressedBytesPerPage: 2_097_152,
        htmlDecompressedBytesPerPage: 4_194_304,
        staticDecompressedBytesPerDomain: 33_554_432,
        probeCompressedBytes: 262_144,
        probeDecompressedBytes: 524_288,
      },
      pages: {
        topLevelPerDomain: 3,
        catalogProbesPerDomain: 5,
        extractedUrlsPerPage: 5_000,
        visibleTextBytesPerPage: 524_288,
      },
      scripts: {
        urlCandidatesPerDomain: 80,
        bodiesPerDomain: 20,
        bodyBytes: 2_097_152,
        totalBodyBytesPerDomain: 16_777_216,
      },
      browser: {
        contextsPerDomain: 1,
        activePagesPerContext: 1,
        networkHostnamesPerDomain: 200,
        requestsPerPage: 150,
        requestsPerDomain: 300,
        transferBytesPerPage: 15_728_640,
        transferBytesPerDomain: 31_457_280,
      },
      cookies: {
        perDomain: 100,
        nameCodeUnits: 256,
        valueBytes: 4_096,
        totalBytesPerDomain: 65_536,
      },
      dns: {
        recordsPerType: 32,
        recordsPerDomain: 128,
        txtItemBytes: 4_096,
        textBytesPerDomain: 65_536,
      },
      robots: {
        bodyBytes: 524_288,
        redirects: 5,
        lines: 5_000,
        rules: 500,
        ruleCodeUnits: 512,
        matchingStatesPerUrl: 1_000_000,
      },
      inspection: {
        domSelectors: 5_000,
        domSelectorCodeUnits: 1_024,
        domMatchesPerSelector: 20,
        javascriptPaths: 10_000,
        javascriptPathCodeUnits: 512,
        returnedValueBytes: 8_192,
        returnedValuesBytesPerPage: 2_097_152,
      },
      detector: {
        workers: 2,
        technologiesPerCatalog: 20_000,
        technologyNameCodePoints: 256,
        categoryNameCodePoints: 128,
        categoriesPerTechnology: 32,
        categoriesPerCatalog: 1_024,
        relationshipEdgesPerCatalog: 100_000,
        patternsPerCatalog: 20_000,
        patternSourceCodeUnits: 2_048,
        totalPatternSourceCodeUnits: 1_000_000,
        compileWatchdogMs: 5_000,
        workerOldHeapBytes: 134_217_728,
        workerYoungHeapBytes: 33_554_432,
        workerStackBytes: 4_194_304,
        ruleWatchdogMs: 50,
        watchdogPollMs: 10,
        activeMsPerDomain: 2_000,
        timeoutsPerDomain: 3,
        checkpointRules: 128,
        executionsPerDomain: 500_000,
      },
      evidence: {
        matchCodePoints: 256,
        safePathSegmentCodeUnits: 64,
        hexTokenMinCodeUnits: 16,
        base64UrlTokenMinCodeUnits: 24,
        versionCodeUnits: 64,
      },
      output: {
        jsonlRecordBytes: 16_777_216,
        technologiesPerDomain: 20_000,
        errorsPerDomain: 128,
        evidencePerTechnology: 256,
        evidencePerDomain: 20_000,
        inferencesPerTechnology: 256,
        inferencesPerDomain: 20_000,
      },
    },
    security: {
      network: {
        allowUrlCredentials: false,
        allowIpInput: false,
        requirePublicAddresses: true,
        rejectMixedAddressAnswers: true,
        validateConnectedAddress: true,
        revalidateRedirects: true,
        connectOnlySelectedAddress: true,
        verifyTls: true,
      },
      robots: {
        productToken: "WebsiteTechScraper",
        failurePolicy: "fail-closed",
        protectedTransportRequired: true,
      },
      browser: {
        allowedMethods: ["GET", "HEAD", "OPTIONS"],
        persistentContexts: false,
        sandbox: true,
        bypassCsp: false,
        serviceWorkers: "block",
        downloads: "deny",
        permissions: [],
        proxyRequired: true,
        proxyBypass: false,
        startupCanaryRequired: true,
        quic: false,
        nonProxiedWebRtc: false,
        webSockets: "block",
        mutableMethods: "block",
        popups: "block",
        crossOriginMainFrames: "block",
        interactions: "deny",
        abortedResourceTypes: ["image", "font", "media"],
      },
      evidence: {
        persistRawObservations: false,
        persistRequestHeaders: false,
        persistCookieValues: false,
        hashCookieValues: false,
        persistResponseBodies: false,
        redactUnknownValues: true,
        redactQueryValues: true,
        redactSensitivePathSegments: true,
        redactSensitiveResponseHeaders: true,
        stripUrlUserInfo: true,
        stripUrlFragments: true,
        emitVersionsFromRedactedSources: false,
        includeErrorStackTraces: false,
      },
    },
  });
}

function canonicalizeValue(value: unknown): string {
  if (value === null || typeof value === "boolean") {
    return JSON.stringify(value);
  }

  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError("Cannot canonicalize a non-safe-integer configuration value");
    }

    return JSON.stringify(value);
  }

  if (typeof value === "string") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeValue(item)).join(",")}]`;
  }

  if (typeof value === "object" && value !== null) {
    const record = value as Record<string, unknown>;
    const entries = Object.keys(record)
      .sort()
      .map(
        (key) => `${JSON.stringify(key)}:${canonicalizeValue(record[key])}`,
      );

    return `{${entries.join(",")}}`;
  }

  throw new TypeError("Cannot canonicalize a non-JSON configuration value");
}

export function canonicalizeScanConfig(value: unknown): string {
  return canonicalizeValue(parseScanConfig(value));
}

export function computeConfigDigest(value: unknown): ConfigDigest {
  const canonicalConfig = canonicalizeScanConfig(value);
  const digest = createHash("sha256").update(canonicalConfig, "utf8").digest("hex");

  return `sha256:${digest}`;
}
