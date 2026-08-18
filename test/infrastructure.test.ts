import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer as createHttpServer } from "node:http";
import { type Server, type Socket } from "node:net";
import {
  setImmediate as waitForImmediate,
  setTimeout as delay,
} from "node:timers/promises";
import { test, type TestContext } from "node:test";

import {
  createDefaultScanConfig,
  parseScanConfig,
  type ScanConfig,
} from "../src/config.ts";
import {
  DNS_RECORD_TYPES,
  type CatalogInspectionPlan,
  type DnsRecordObservation,
  type DnsRecordType,
  type HttpEntryResult,
  type HttpResponseObservations,
  type InfrastructureResult,
  type ScanError,
} from "../src/model.ts";
import {
  installInfrastructureRuntimeHook,
  runWithInfrastructureRuntime,
} from "./support/infrastructure-runtime.ts";
import {
  installTransportRuntimeHook,
  setupTransportRuntime,
} from "./support/transport-runtime.ts";

installInfrastructureRuntimeHook();
installTransportRuntimeHook();

const { collectInfrastructure } = await import(
  "../src/crawl/infrastructure.ts"
);
const { createProtectedHttpTransport } = await import(
  "../src/crawl/transport.ts"
);

type JsonRecord = Record<string, unknown>;

const userAgent =
  "WebsiteTechScraper/0.1.0 (https://contact.website-tech-scraper.dev/crawler)";

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

function inspectionPlan(
  dnsRecordTypes: readonly DnsRecordType[] = [],
  tlsIssuer = false,
): CatalogInspectionPlan {
  return Object.freeze({
    dom: Object.freeze([]),
    javascript: Object.freeze([]),
    probePaths: Object.freeze([]),
    dnsRecordTypes: Object.freeze([...dnsRecordTypes]),
    tlsIssuer,
  });
}

function responseObservations(
  finalNetworkUrl: string,
  tlsIssuer: string | null,
  tlsHandshakeMs: number | null,
): HttpResponseObservations {
  return Object.freeze({
    finalNetworkUrl,
    statusCode: 200,
    redirects: Object.freeze([]),
    headers: Object.freeze([]),
    cookies: Object.freeze([]),
    cookiesTruncated: false,
    tlsIssuer,
    tlsHandshakeMs,
  });
}

function httpResult(
  finalNetworkUrl = "http://shop.vendor.tld/",
  tlsIssuer: string | null = null,
  tlsHandshakeMs: number | null = null,
): HttpEntryResult {
  return Object.freeze({
    kind: "non-html" as const,
    response: responseObservations(
      finalNetworkUrl,
      tlsIssuer,
      tlsHandshakeMs,
    ),
    robots: Object.freeze([]),
    errors: Object.freeze([]),
  });
}

function scanError(
  stage: ScanError["stage"],
  code: ScanError["code"],
): ScanError {
  return Object.freeze({
    stage,
    code,
    pageId: null,
    retryable: true,
    message: "Controlled fixture failure.",
    ruleId: null,
    signal: null,
    limit: null,
    catalogRevision: null,
  });
}

function failedHttpResult(): HttpEntryResult {
  return Object.freeze({
    kind: "failed" as const,
    response: null,
    robots: Object.freeze([]),
    errors: Object.freeze([
      scanError("http", "HTTP_REQUEST_FAILED"),
    ]) as readonly [ScanError],
  });
}

function createSession(
  t: TestContext,
  config: ScanConfig,
  signal?: AbortSignal,
) {
  const transport = createProtectedHttpTransport(config);
  const session = transport.createSession(
    signal === undefined ? {} : { signal },
  );
  t.after(() => session.close());
  return session;
}

async function listenOnLoopback(t: TestContext, server: Server): Promise<number> {
  const sockets = new Set<Socket>();

  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");

  const address = server.address();
  if (address === null || typeof address === "string") {
    assert.fail("The controlled HTTP server did not expose an IP port.");
  }

  t.after(async () => {
    for (const socket of sockets) {
      socket.destroy();
    }

    if (server.listening) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  return address.port;
}

async function consumePublicTransportDnsRecord(
  t: TestContext,
  session: ReturnType<ReturnType<typeof createProtectedHttpTransport>["createSession"]>,
): Promise<void> {
  const server = createHttpServer((_request, response) => {
    response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    response.end("<p>fixture</p>");
  });
  const port = await listenOnLoopback(t, server);
  setupTransportRuntime({
    lookup: () => [{ address: "8.8.8.8", family: 4 }],
    routes: new Map([
      ["8.8.8.8", { physicalPort: port }],
    ]),
  });

  const response = await session.requestHop({
    url: "http://shop.vendor.tld/",
    purpose: "page",
  });
  assert.equal(response.statusCode, 200);
}

function dnsError(code: string, detail = "untrusted resolver detail"): Error {
  return Object.assign(new Error(detail), { code });
}

function errorCodes(result: InfrastructureResult): string[] {
  return result.errors.map((error) => error.code);
}

function assertTiming(value: number | null): void {
  assert.notEqual(value, null);
  assert.equal(Number.isInteger(value), true);
  assert.ok((value as number) >= 0);
}

function assertDeepFrozen(value: unknown): void {
  if (typeof value !== "object" || value === null) {
    return;
  }

  assert.equal(Object.isFrozen(value), true);

  for (const nested of Object.values(value)) {
    assertDeepFrozen(nested);
  }
}

test("issues only demanded typed DNS queries and normalizes every supported record", async (t) => {
  const config = configWith();
  const session = createSession(t, config);
  const answers = new Map<string, unknown>([
    ["A", ["8.8.8.8", "1.1.1.1", "8.8.8.8"]],
    [
      "AAAA",
      [
        "2001:4860:4860:0000:0000:0000:0000:8888",
        "2606:4700:4700::1111",
      ],
    ],
    [
      "CAA",
      [
        { critical: 0, issue: "ca.example" },
        { critical: 0, issuewild: "wild-ca.example" },
        { critical: 0, iodef: "mailto:security@example.com" },
      ],
    ],
    ["CNAME", ["CDN.Vendor.TLD.", "cdn.vendor.tld"]],
    [
      "MX",
      [
        { exchange: "Mail-B.Vendor.TLD.", priority: 20 },
        { exchange: "MAIL-A.Vendor.TLD.", priority: 10 },
      ],
    ],
    ["NS", ["NS2.Vendor.TLD.", "ns1.vendor.tld."]],
    ["PTR", ["PTR.Vendor.TLD."]],
    [
      "SOA",
      {
        nsname: "NS1.Vendor.TLD.",
        hostmaster: "Hostmaster.Vendor.TLD.",
        serial: 1,
        refresh: 2,
        retry: 3,
        expire: 4,
        minttl: 5,
      },
    ],
    [
      "SRV",
      [
        { name: "Service-B.Vendor.TLD.", port: 443, priority: 20, weight: 1 },
        { name: "SERVICE-A.Vendor.TLD.", port: 8443, priority: 10, weight: 2 },
      ],
    ],
    ["TXT", [["verification=", "alpha"], ["alpha", "-token"], ["alpha", "-token"]]],
  ]);

  await runWithInfrastructureRuntime(
    {
      resolve(_hostname, recordType) {
        const answer = answers.get(recordType);
        assert.notEqual(answer, undefined);
        return answer;
      },
    },
    async (harness) => {
      const result = await collectInfrastructure("shop.vendor.tld", {
        config,
        session,
        inspectionPlan: inspectionPlan([...DNS_RECORD_TYPES].reverse()),
        httpResult: failedHttpResult(),
      });

      assert.deepEqual(
        harness.resolveCalls.map(({ hostname, recordType }) => ({
          hostname,
          recordType,
        })),
        DNS_RECORD_TYPES.map((recordType) => ({
          hostname: "shop.vendor.tld",
          recordType,
        })),
      );
      assert.equal(
        harness.resolveCalls.some((call) => call.recordType === "ANY"),
        false,
      );
      assert.deepEqual(harness.resolverOptions, [{
        timeout: config.limits.timeMs.dnsLookup,
        tries: 1,
        maxTimeout: config.limits.timeMs.dnsLookup,
      }]);
      assert.deepEqual(harness.cancelCalls, [1]);
      assert.deepEqual(result.observations.dnsRecords, [
        { type: "A", value: "1.1.1.1" },
        { type: "A", value: "8.8.8.8" },
        { type: "AAAA", value: "2001:4860:4860::8888" },
        { type: "AAAA", value: "2606:4700:4700::1111" },
        { type: "CAA", value: "ca.example" },
        { type: "CAA", value: "mailto:security@example.com" },
        { type: "CAA", value: "wild-ca.example" },
        { type: "CNAME", value: "cdn.vendor.tld" },
        { type: "MX", value: "mail-a.vendor.tld" },
        { type: "MX", value: "mail-b.vendor.tld" },
        { type: "NS", value: "ns1.vendor.tld" },
        { type: "NS", value: "ns2.vendor.tld" },
        { type: "PTR", value: "ptr.vendor.tld" },
        { type: "SOA", value: "ns1.vendor.tld" },
        { type: "SRV", value: "service-a.vendor.tld" },
        { type: "SRV", value: "service-b.vendor.tld" },
        { type: "TXT", value: "alpha-token" },
        { type: "TXT", value: "verification=alpha" },
      ] satisfies readonly DnsRecordObservation[]);
      assert.deepEqual(result.errors, []);
      assert.equal(result.completed, true);
      assertTiming(result.dnsMs);
      assert.equal(result.tlsMs, null);
    },
  );
});

test("treats ENODATA and ENOTFOUND as normal typed-record absence", async (t) => {
  const config = configWith();
  const session = createSession(t, config);

  await runWithInfrastructureRuntime(
    {
      resolve(_hostname, recordType) {
        throw dnsError(recordType === "A" ? "ENODATA" : "ENOTFOUND");
      },
    },
    async (harness) => {
      const result = await collectInfrastructure("shop.vendor.tld", {
        config,
        session,
        inspectionPlan: inspectionPlan(["A", "TXT"]),
        httpResult: failedHttpResult(),
      });

      assert.deepEqual(
        harness.resolveCalls.map((call) => call.recordType),
        ["A", "TXT"],
      );
      assert.deepEqual(result.observations.dnsRecords, []);
      assert.deepEqual(result.errors, []);
      assert.equal(result.completed, true);
      assertTiming(result.dnsMs);
    },
  );
});

test("preserves valid DNS records around malformed and transient typed answers", async (t) => {
  const config = configWith();
  const session = createSession(t, config);

  await runWithInfrastructureRuntime(
    {
      resolve(_hostname, recordType) {
        if (recordType === "A") {
          return ["8.8.8.8"];
        }

        if (recordType === "CNAME") {
          return [42];
        }

        throw dnsError("ETIMEOUT", "secret upstream response");
      },
    },
    async () => {
      const result = await collectInfrastructure("shop.vendor.tld", {
        config,
        session,
        inspectionPlan: inspectionPlan(["A", "CNAME", "MX"]),
        httpResult: failedHttpResult(),
      });

      assert.deepEqual(result.observations.dnsRecords, [
        { type: "A", value: "8.8.8.8" },
      ]);
      assert.deepEqual(errorCodes(result), [
        "DNS_LOOKUP_FAILED",
        "DNS_LOOKUP_FAILED",
      ]);
      assert.deepEqual(
        result.errors.map((error) => error.retryable).sort(),
        [false, true],
      );
      assert.equal(
        result.errors.some((error) => error.message.includes("secret")),
        false,
      );
      assert.equal(result.completed, false);
    },
  );
});

test("rejects private and mixed A or AAAA answers without keeping a public subset", async (t) => {
  const cases = [
    {
      type: "A" as const,
      answer: ["10.0.0.1"],
      code: "SSRF_NON_PUBLIC_ADDRESS",
    },
    {
      type: "AAAA" as const,
      answer: ["2606:4700:4700::1111", "::1"],
      code: "SSRF_MIXED_ADDRESSES",
    },
  ];

  for (const fixture of cases) {
    const config = configWith();
    const session = createSession(t, config);

    await runWithInfrastructureRuntime(
      { resolve: () => fixture.answer },
      async () => {
        const result = await collectInfrastructure("shop.vendor.tld", {
          config,
          session,
          inspectionPlan: inspectionPlan([fixture.type]),
          httpResult: failedHttpResult(),
        });

        assert.deepEqual(result.observations.dnsRecords, []);
        assert.deepEqual(errorCodes(result), [fixture.code]);
        assert.equal(result.errors[0]?.retryable, false);
        assert.equal(result.completed, false);
      },
    );
  }
});

test("applies the per-type raw record cap before normalization and deduplication", async (t) => {
  const config = configWith([
    [["limits", "dns", "recordsPerType"], 1],
  ]);
  const session = createSession(t, config);

  await runWithInfrastructureRuntime(
    { resolve: () => ["8.8.8.8", "8.8.8.8"] },
    async () => {
      const result = await collectInfrastructure("shop.vendor.tld", {
        config,
        session,
        inspectionPlan: inspectionPlan(["A"]),
        httpResult: failedHttpResult(),
      });

      assert.deepEqual(result.observations.dnsRecords, []);
      assert.deepEqual(errorCodes(result), ["DNS_LIMIT_EXCEEDED"]);
      assert.equal(result.errors[0]?.limit, null);
      assert.equal(result.completed, false);
    },
  );
});

test("rejects a TXT item whose joined chunks exceed its UTF-8 byte cap", async (t) => {
  const config = configWith([
    [["limits", "dns", "txtItemBytes"], 4],
  ]);
  const session = createSession(t, config);

  await runWithInfrastructureRuntime(
    { resolve: () => [["abc", "de"]] },
    async () => {
      const result = await collectInfrastructure("shop.vendor.tld", {
        config,
        session,
        inspectionPlan: inspectionPlan(["TXT"]),
        httpResult: failedHttpResult(),
      });

      assert.deepEqual(result.observations.dnsRecords, []);
      assert.deepEqual(errorCodes(result), ["DNS_LIMIT_EXCEEDED"]);
      assert.equal(result.completed, false);
    },
  );
});

test("shares the raw record budget with the transport session and keeps its admitted prefix", async (t) => {
  const config = configWith([
    [["limits", "dns", "recordsPerDomain"], 2],
  ]);
  const session = createSession(t, config);
  await consumePublicTransportDnsRecord(t, session);

  await runWithInfrastructureRuntime(
    { resolve: () => ["B.Vendor.TLD.", "A.Vendor.TLD."] },
    async () => {
      const result = await collectInfrastructure("shop.vendor.tld", {
        config,
        session,
        inspectionPlan: inspectionPlan(["CNAME"]),
        httpResult: failedHttpResult(),
      });

      assert.deepEqual(result.observations.dnsRecords, [
        { type: "CNAME", value: "a.vendor.tld" },
      ]);
      assert.deepEqual(errorCodes(result), ["DNS_LIMIT_EXCEEDED"]);
      assert.equal(result.completed, false);
    },
  );
});

test("shares the DNS text budget and stops before the first record that does not fit", async (t) => {
  const config = configWith([
    [["limits", "dns", "recordsPerDomain"], 8],
    [["limits", "dns", "textBytesPerDomain"], 12],
  ]);
  const session = createSession(t, config);
  await consumePublicTransportDnsRecord(t, session);

  await runWithInfrastructureRuntime(
    { resolve: () => [["bbb"], ["cccc"], ["d"]] },
    async () => {
      const result = await collectInfrastructure("shop.vendor.tld", {
        config,
        session,
        inspectionPlan: inspectionPlan(["TXT"]),
        httpResult: failedHttpResult(),
      });

      assert.deepEqual(result.observations.dnsRecords, [
        { type: "TXT", value: "bbb" },
      ]);
      assert.deepEqual(errorCodes(result), ["DNS_LIMIT_EXCEEDED"]);
      assert.equal(result.completed, false);
    },
  );
});

test("uses one absolute DNS deadline, cancels the resolver, and ignores late answers", async (t) => {
  const config = configWith([
    [["limits", "timeMs", "activeDomain"], 1_000],
    [["limits", "timeMs", "dnsLookup"], 80],
  ]);
  const session = createSession(t, config);
  const lateAnswer = Promise.withResolvers<unknown>();

  await runWithInfrastructureRuntime(
    {
      async resolve(_hostname, recordType) {
        if (recordType === "A") {
          await delay(60);
          return ["8.8.8.8"];
        }

        return lateAnswer.promise;
      },
    },
    async (harness) => {
      const startedAt = performance.now();
      const result = await collectInfrastructure("shop.vendor.tld", {
        config,
        session,
        inspectionPlan: inspectionPlan(["A", "CNAME"]),
        httpResult: failedHttpResult(),
      });
      const elapsedMs = performance.now() - startedAt;
      const beforeLateAnswer = structuredClone(result);

      assert.ok(elapsedMs < 130, `DNS collection took ${elapsedMs}ms`);
      assert.deepEqual(harness.cancelCalls, [2]);
      assert.deepEqual(result.observations.dnsRecords, [
        { type: "A", value: "8.8.8.8" },
      ]);
      assert.deepEqual(errorCodes(result), ["DNS_LOOKUP_FAILED"]);
      assert.equal(result.completed, false);

      lateAnswer.resolve(["LATE.Vendor.TLD."]);
      await waitForImmediate();
      assert.deepEqual(result, beforeLateAnswer);
    },
  );
});

test("cancels outstanding DNS work when the shared session is aborted", async (t) => {
  const config = configWith();
  const controller = new AbortController();
  const session = createSession(t, config, controller.signal);
  const lookupStarted = Promise.withResolvers<void>();
  const never = Promise.withResolvers<unknown>();

  await runWithInfrastructureRuntime(
    {
      resolve() {
        lookupStarted.resolve();
        return never.promise;
      },
    },
    async (harness) => {
      const collecting = collectInfrastructure("shop.vendor.tld", {
        config,
        session,
        inspectionPlan: inspectionPlan(["TXT"]),
        httpResult: failedHttpResult(),
      });

      await lookupStarted.promise;
      controller.abort(new DOMException("fixture abort", "AbortError"));
      const result = await collecting;

      assert.deepEqual(harness.cancelCalls, [2]);
      assert.deepEqual(result.observations.dnsRecords, []);
      assert.equal(result.errors.length, 1);
      assert.equal(result.errors[0]?.stage, "dns");
      assert.equal(result.completed, false);
    },
  );
});

test("starts no resolver work when the shared session is already aborted", async (t) => {
  const config = configWith();
  const controller = new AbortController();
  controller.abort(new DOMException("fixture pre-abort", "AbortError"));
  const session = createSession(t, config, controller.signal);

  await runWithInfrastructureRuntime(
    { resolve: () => assert.fail("A pre-aborted session must not query DNS.") },
    async (harness) => {
      const result = await collectInfrastructure("shop.vendor.tld", {
        config,
        session,
        inspectionPlan: inspectionPlan(["A"]),
        httpResult: failedHttpResult(),
      });

      assert.deepEqual(harness.resolverOptions, []);
      assert.deepEqual(harness.resolveCalls, []);
      assert.deepEqual(harness.cancelCalls, []);
      assert.deepEqual(result.observations.dnsRecords, []);
      assert.deepEqual(errorCodes(result), ["DOMAIN_DEADLINE_EXCEEDED"]);
      assert.equal(result.completed, false);
      assertTiming(result.dnsMs);
    },
  );
});

test("does not construct a resolver when the inspection plan requests no DNS", async (t) => {
  const config = configWith();
  const session = createSession(t, config);

  await runWithInfrastructureRuntime(
    {
      resolve() {
        assert.fail("No DNS query was planned.");
      },
    },
    async (harness) => {
      const result = await collectInfrastructure("shop.vendor.tld", {
        config,
        session,
        inspectionPlan: inspectionPlan(),
        httpResult: failedHttpResult(),
      });

      assert.deepEqual(harness.resolverOptions, []);
      assert.deepEqual(harness.resolveCalls, []);
      assert.deepEqual(harness.cancelCalls, []);
      assert.deepEqual(result.observations, {
        dnsRecords: [],
        tlsIssuer: null,
      });
      assert.deepEqual(result.errors, []);
      assert.equal(result.dnsMs, null);
      assert.equal(result.tlsMs, null);
      assert.equal(result.completed, true);
    },
  );
});

test("reuses the verified HTTPS response issuer and handshake timing", async (t) => {
  const config = configWith();
  const session = createSession(t, config);

  await runWithInfrastructureRuntime(
    { resolve: () => assert.fail("TLS reuse must not perform DNS.") },
    async () => {
      const result = await collectInfrastructure("shop.vendor.tld", {
        config,
        session,
        inspectionPlan: inspectionPlan([], true),
        httpResult: httpResult(
          "https://shop.vendor.tld/",
          "C=US\nO=Example Verified CA",
          17,
        ),
      });

      assert.deepEqual(result.observations, {
        dnsRecords: [],
        tlsIssuer: "C=US\nO=Example Verified CA",
      });
      assert.deepEqual(result.errors, []);
      assert.equal(result.dnsMs, null);
      assert.equal(result.tlsMs, 17);
      assert.equal(result.completed, true);
    },
  );
});

test("skips TLS without error for HTTP, no final response, or no catalog demand", async (t) => {
  const fixtures = [
    {
      plan: inspectionPlan([], true),
      result: httpResult("http://shop.vendor.tld/", null, null),
    },
    {
      plan: inspectionPlan([], true),
      result: failedHttpResult(),
    },
    {
      plan: inspectionPlan([], true),
      result: httpResult("https://shop.vendor.tld/", null, 12),
    },
    {
      plan: inspectionPlan([], false),
      result: httpResult("https://shop.vendor.tld/", "Ignored CA", 9),
    },
  ];

  for (const fixture of fixtures) {
    const config = configWith();
    const session = createSession(t, config);

    await runWithInfrastructureRuntime(
      { resolve: () => assert.fail("No DNS query was planned.") },
      async () => {
        const result = await collectInfrastructure("shop.vendor.tld", {
          config,
          session,
          inspectionPlan: fixture.plan,
          httpResult: fixture.result,
        });

        assert.equal(result.observations.tlsIssuer, null);
        assert.equal(result.tlsMs, null);
        assert.deepEqual(result.errors, []);
        assert.equal(result.completed, true);
      },
    );
  }
});

test("rejects oversized or malformed TLS issuer text without truncation", async (t) => {
  const fixtures = [
    { issuer: "abcde", issuerBytes: 4 },
    { issuer: "bad\u0000issuer", issuerBytes: 4_096 },
    { issuer: "bad\ud800issuer", issuerBytes: 4_096 },
  ];

  for (const fixture of fixtures) {
    const config = configWith([
      [["limits", "tls", "issuerBytes"], fixture.issuerBytes],
    ]);
    const session = createSession(t, config);

    await runWithInfrastructureRuntime(
      { resolve: () => assert.fail("No DNS query was planned.") },
      async () => {
        const result = await collectInfrastructure("shop.vendor.tld", {
          config,
          session,
          inspectionPlan: inspectionPlan([], true),
          httpResult: httpResult(
            "https://shop.vendor.tld/",
            fixture.issuer,
            11,
          ),
        });

        assert.equal(result.observations.tlsIssuer, null);
        assert.deepEqual(errorCodes(result), ["TLS_LIMIT_EXCEEDED"]);
        assert.equal(result.errors[0]?.retryable, false);
        assert.equal(result.tlsMs, 11);
        assert.equal(result.completed, false);
      },
    );
  }
});

test("returns a deeply immutable infrastructure result", async (t) => {
  const config = configWith();
  const session = createSession(t, config);

  await runWithInfrastructureRuntime(
    { resolve: () => ["8.8.8.8"] },
    async () => {
      const result = await collectInfrastructure("shop.vendor.tld", {
        config,
        session,
        inspectionPlan: inspectionPlan(["A"], true),
        httpResult: httpResult("https://shop.vendor.tld/", "Example CA", 3),
      });

      assertDeepFrozen(result);
      assert.throws(() => {
        (result.observations.dnsRecords as DnsRecordObservation[]).push({
          type: "TXT",
          value: "mutation",
        });
      }, TypeError);
    },
  );
});
