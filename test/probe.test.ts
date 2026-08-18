import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createDefaultScanConfig,
  parseScanConfig,
  type ScanConfig,
} from "../src/config.ts";
import {
  collectCatalogProbes,
} from "../src/crawl/probe.ts";
import {
  RobotsPolicyError,
  type RobotsCheck,
  type RobotsPolicyService,
} from "../src/crawl/robots.ts";
import {
  ProtectedTransportError,
  type ProtectedTransportRequest,
  type ProtectedTransportResponse,
  type ProtectedTransportSession,
  type ProtectedTransportUsage,
} from "../src/crawl/transport.ts";
import type { DnsRecordObservation } from "../src/model.ts";

type JsonRecord = Record<string, unknown>;
type SessionStep = (
  request: ProtectedTransportRequest,
) => ProtectedTransportResponse | Promise<ProtectedTransportResponse>;

const userAgent =
  "WebsiteTechScraper/0.1.0 (https://contact.website-tech-scraper.dev/crawler)";
const finalUrl = "https://shop.vendor.tld/store/landing";

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

function response(
  url: string,
  statusCode: number,
  options: {
    readonly body?: string | Uint8Array;
    readonly headers?: ReadonlyArray<readonly [string, string]>;
    readonly redirectUrl?: string | null;
  } = {},
): ProtectedTransportResponse {
  return Object.freeze({
    url,
    statusCode,
    headers: Object.freeze((options.headers ?? []).map(([name, value]) =>
      Object.freeze({ name: name.toLowerCase(), value })
    )),
    body: typeof options.body === "string"
      ? Buffer.from(options.body, "utf8")
      : options.body ?? new Uint8Array(),
    redirectUrl: options.redirectUrl ?? null,
    tlsIssuer: null,
    tlsHandshakeMs: null,
  });
}

class ScriptedSession implements ProtectedTransportSession {
  readonly calls: ProtectedTransportRequest[] = [];
  private readonly steps: readonly SessionStep[];
  private readonly signal: AbortSignal;
  private index = 0;

  constructor(
    steps: readonly SessionStep[],
    signal: AbortSignal = new AbortController().signal,
  ) {
    this.steps = steps;
    this.signal = signal;
  }

  async requestHop(
    request: ProtectedTransportRequest,
  ): Promise<ProtectedTransportResponse> {
    this.calls.push(Object.freeze({ ...request }));
    const step = this.steps[this.index];
    this.index += 1;
    if (step === undefined) {
      assert.fail(`Unexpected probe request ${request.url}`);
    }
    return step(request);
  }

  admitDnsRecords(records: readonly DnsRecordObservation[]) {
    return Object.freeze({
      records: Object.freeze([...records]),
      limitExceeded: false,
    });
  }

  getSignal(): AbortSignal {
    return this.signal;
  }

  getUsage(): ProtectedTransportUsage {
    return Object.freeze({
      httpRequests: this.calls.length,
      retries: this.calls.filter((call) => call.isRetry === true).length,
      probesIssued: this.calls.filter((call) => call.purpose === "probe").length,
      staticTransferredBytes: 0,
    });
  }

  close(): void {}
}

function robotsService(
  decide: (url: string, index: number) => RobotsCheck | Promise<RobotsCheck>,
  checks: string[] = [],
): RobotsPolicyService {
  return {
    async check(_session, url): Promise<RobotsCheck> {
      checks.push(url);
      return decide(url, checks.length - 1);
    },
    allowsCached(): boolean {
      return false;
    },
    clear(): void {},
  };
}

function allowedRobots(
  url: string,
  text: string | null = null,
): RobotsCheck {
  const origin = new URL(url).origin;
  return Object.freeze({
    allowed: true,
    robotsText: text,
    ownerOrigin: origin,
    fetchedUrl: `${origin}/robots.txt`,
  });
}

test("collects catalog probes in canonical order on the exact final origin", async () => {
  const checks: string[] = [];
  const robotsText = "User-agent: *\nAllow: /";
  const session = new ScriptedSession([
    (request) => response(request.url, 200, {
      headers: [["content-type", "application/octet-stream"]],
      body: "alpha body",
    }),
    (request) => response(request.url, 200, { body: "zulu body" }),
  ]);

  const result = await collectCatalogProbes(finalUrl, {
    config: configWith(),
    session,
    robots: robotsService(
      (url) => allowedRobots(url, robotsText),
      checks,
    ),
    probePaths: ["/zulu", "/alpha"],
  });

  assert.deepEqual(checks, [
    "https://shop.vendor.tld/alpha",
    "https://shop.vendor.tld/zulu",
  ]);
  assert.deepEqual(session.calls.map((call) => ({
    url: call.url,
    purpose: call.purpose,
    isRetry: call.isRetry,
  })), [
    {
      url: "https://shop.vendor.tld/alpha",
      purpose: "probe",
      isRetry: undefined,
    },
    {
      url: "https://shop.vendor.tld/zulu",
      purpose: "probe",
      isRetry: undefined,
    },
  ]);
  assert.deepEqual(result, {
    observations: [
      { path: "/alpha", body: "alpha body" },
      { path: "/zulu", body: "zulu body" },
    ],
    robots: [{
      ownerOrigin: "https://shop.vendor.tld",
      fetchedUrl: "https://shop.vendor.tld/robots.txt",
      text: robotsText,
    }],
    errors: [],
    completed: true,
  });
});

test("keeps normal absence bounded and records an explicit denial", async () => {
  const paths = [
    "/absent",
    "/beyond-http-status",
    "/denied",
    "/later",
    "/server-error",
  ];
  const checks: string[] = [];
  const session = new ScriptedSession([
    (request) => response(request.url, 404),
    (request) => response(request.url, 600),
    (request) => response(request.url, 403),
  ]);

  const result = await collectCatalogProbes(finalUrl, {
    config: configWith(),
    session,
    robots: robotsService((url) => allowedRobots(url), checks),
    probePaths: paths,
  });

  assert.deepEqual(checks, [
    "https://shop.vendor.tld/absent",
    "https://shop.vendor.tld/beyond-http-status",
    "https://shop.vendor.tld/denied",
  ]);
  assert.deepEqual(
    session.calls.map((call) => call.url),
    checks,
  );
  assert.deepEqual(result.observations, []);
  assert.deepEqual(result.errors.map((error) => ({
    stage: error.stage,
    code: error.code,
    retryable: error.retryable,
    message: error.message,
    pageId: error.pageId,
  })), [{
    stage: "http",
    code: "HTTP_REQUEST_FAILED",
    retryable: false,
    message: "A catalog probe was denied.",
    pageId: null,
  }]);
  assert.equal(result.completed, false);
});

test("classifies every denial and transient stop status deterministically", async () => {
  const cases = [
    { status: 401, retryable: false, message: "A catalog probe was denied." },
    { status: 403, retryable: false, message: "A catalog probe was denied." },
    { status: 407, retryable: false, message: "A catalog probe was denied." },
    { status: 451, retryable: false, message: "A catalog probe was denied." },
    {
      status: 408,
      retryable: true,
      message: "A catalog probe received a transient response.",
    },
    {
      status: 425,
      retryable: true,
      message: "A catalog probe received a transient response.",
    },
    {
      status: 429,
      retryable: true,
      message: "A catalog probe received a transient response.",
    },
    {
      status: 500,
      retryable: true,
      message: "A catalog probe received a transient response.",
    },
    {
      status: 599,
      retryable: true,
      message: "A catalog probe received a transient response.",
    },
  ] as const;

  for (const current of cases) {
    const session = new ScriptedSession([
      (request) => response(request.url, current.status),
    ]);
    const result = await collectCatalogProbes(finalUrl, {
      config: configWith(),
      session,
      robots: robotsService((url) => allowedRobots(url)),
      probePaths: ["/first", "/later"],
    });

    assert.deepEqual(
      session.calls.map((call) => call.url),
      ["https://shop.vendor.tld/first"],
      String(current.status),
    );
    assert.deepEqual(result.observations, [], String(current.status));
    assert.deepEqual(result.errors.map((error) => ({
      code: error.code,
      retryable: error.retryable,
      message: error.message,
    })), [{
      code: "HTTP_REQUEST_FAILED",
      retryable: current.retryable,
      message: current.message,
    }], String(current.status));
    assert.equal(result.completed, false, String(current.status));
  }
});

test("admits empty 2xx bodies and stops on a transient response", async () => {
  const session = new ScriptedSession([
    (request) => response(request.url, 204),
    (request) => response(request.url, 205),
    (request) => response(request.url, 500),
  ]);

  const result = await collectCatalogProbes(finalUrl, {
    config: configWith(),
    session,
    robots: robotsService((url) => allowedRobots(url)),
    probePaths: ["/empty-204", "/empty-205", "/server-error"],
  });

  assert.deepEqual(session.calls.map((call) => call.url), [
    "https://shop.vendor.tld/empty-204",
    "https://shop.vendor.tld/empty-205",
    "https://shop.vendor.tld/server-error",
  ]);
  assert.deepEqual(result.observations, [
    { path: "/empty-204", body: "" },
    { path: "/empty-205", body: "" },
  ]);
  assert.deepEqual(result.errors.map((error) => ({
    stage: error.stage,
    code: error.code,
    retryable: error.retryable,
    message: error.message,
  })), [{
    stage: "http",
    code: "HTTP_REQUEST_FAILED",
    retryable: true,
    message: "A catalog probe received a transient response.",
  }]);
  assert.equal(result.completed, false);
});

test("does not follow same-origin or cross-origin probe redirects", async () => {
  const session = new ScriptedSession([
    (request) => response(request.url, 302, {
      headers: [["location", "/redirected"]],
      redirectUrl: "https://shop.vendor.tld/redirected",
    }),
    (request) => response(request.url, 302, {
      headers: [["location", "https://other.vendor.tld/redirected"]],
      redirectUrl: "https://other.vendor.tld/redirected",
    }),
    (request) => response(request.url, 200, { body: "still collected" }),
  ]);

  const result = await collectCatalogProbes(finalUrl, {
    config: configWith(),
    session,
    robots: robotsService((url) => allowedRobots(url)),
    probePaths: ["/cross-origin", "/same-origin", "/success"],
  });

  assert.deepEqual(session.calls.map((call) => call.url), [
    "https://shop.vendor.tld/cross-origin",
    "https://shop.vendor.tld/same-origin",
    "https://shop.vendor.tld/success",
  ]);
  assert.deepEqual(result.observations, [
    { path: "/success", body: "still collected" },
  ]);
  assert.deepEqual(result.errors, []);
});

test("treats robots denial as a skip and stops on robots unavailability", async () => {
  const checks: string[] = [];
  const robotsText = "User-agent: *\nDisallow: /blocked";
  const session = new ScriptedSession([
    (request) => response(request.url, 200, { body: "allowed" }),
  ]);
  const robots = robotsService((url) => {
    if (new URL(url).pathname === "/blocked") {
      const allowed = allowedRobots(url, robotsText);
      return Object.freeze({ ...allowed, allowed: false });
    }
    if (new URL(url).pathname === "/unavailable") {
      throw new RobotsPolicyError("ROBOTS_UNAVAILABLE", false);
    }
    return allowedRobots(url, robotsText);
  }, checks);

  const result = await collectCatalogProbes(finalUrl, {
    config: configWith(),
    session,
    robots,
    probePaths: ["/allowed", "/blocked", "/unavailable", "/unused"],
  });

  assert.deepEqual(checks, [
    "https://shop.vendor.tld/allowed",
    "https://shop.vendor.tld/blocked",
    "https://shop.vendor.tld/unavailable",
  ]);
  assert.deepEqual(session.calls.map((call) => call.url), [
    "https://shop.vendor.tld/allowed",
  ]);
  assert.deepEqual(result.observations, [
    { path: "/allowed", body: "allowed" },
  ]);
  assert.deepEqual(result.robots, [{
    ownerOrigin: "https://shop.vendor.tld",
    fetchedUrl: "https://shop.vendor.tld/robots.txt",
    text: robotsText,
  }]);
  assert.deepEqual(result.errors.map((error) => ({
    stage: error.stage,
    code: error.code,
    retryable: error.retryable,
    pageId: error.pageId,
  })), [{
    stage: "robots",
    code: "ROBOTS_UNAVAILABLE",
    retryable: false,
    pageId: null,
  }]);
  assert.equal(result.completed, false);
});

test("decodes invalid UTF-8 with replacement without losing probe presence", async () => {
  const session = new ScriptedSession([
    (request) => response(request.url, 200, {
      headers: [["content-type", "text/plain; charset=windows-1252"]],
      body: Uint8Array.of(0xff),
    }),
    (request) => response(request.url, 200, {
      headers: [["content-type", "image/svg+xml"]],
      body: "<svg>TYPO3</svg>",
    }),
  ]);

  const result = await collectCatalogProbes(finalUrl, {
    config: configWith(),
    session,
    robots: robotsService((url) => allowedRobots(url)),
    probePaths: ["/invalid", "/valid.svg"],
  });

  assert.deepEqual(result.observations, [
    { path: "/invalid", body: "\ufffd" },
    { path: "/valid.svg", body: "<svg>TYPO3</svg>" },
  ]);
  assert.deepEqual(result.errors, []);
  assert.equal(result.completed, true);
});

test("stops after a protected transport failure and preserves its stable error", async () => {
  const session = new ScriptedSession([
    (request) => response(request.url, 200, { body: "first" }),
    () => {
      throw new ProtectedTransportError(
        "HTTP_RESPONSE_LIMIT_EXCEEDED",
        "http",
        false,
      );
    },
  ]);

  const result = await collectCatalogProbes(finalUrl, {
    config: configWith(),
    session,
    robots: robotsService((url) => allowedRobots(url)),
    probePaths: ["/first", "/limit", "/unused"],
  });

  assert.deepEqual(session.calls.map((call) => call.url), [
    "https://shop.vendor.tld/first",
    "https://shop.vendor.tld/limit",
  ]);
  assert.deepEqual(result.observations, [{ path: "/first", body: "first" }]);
  assert.deepEqual(result.errors.map((error) => ({
    stage: error.stage,
    code: error.code,
    retryable: error.retryable,
    pageId: error.pageId,
  })), [{
    stage: "http",
    code: "HTTP_RESPONSE_LIMIT_EXCEEDED",
    retryable: false,
    pageId: null,
  }]);
  assert.equal(result.completed, false);
});

test("keeps admitted probes when the domain deadline fires between paths", async () => {
  const controller = new AbortController();
  const session = new ScriptedSession([
    (request) => {
      controller.abort(new DOMException(
        "The active domain deadline was exceeded.",
        "TimeoutError",
      ));
      return response(request.url, 200, { body: "first" });
    },
  ], controller.signal);

  const result = await collectCatalogProbes(finalUrl, {
    config: configWith(),
    session,
    robots: robotsService((url) => allowedRobots(url)),
    probePaths: ["/first", "/later"],
  });

  assert.deepEqual(session.calls.map((call) => call.url), [
    "https://shop.vendor.tld/first",
  ]);
  assert.deepEqual(result.observations, [{ path: "/first", body: "first" }]);
  assert.deepEqual(result.errors.map((error) => ({
    stage: error.stage,
    code: error.code,
    retryable: error.retryable,
    message: error.message,
    pageId: error.pageId,
  })), [{
    stage: "http",
    code: "DOMAIN_DEADLINE_EXCEEDED",
    retryable: true,
    message: "The active domain deadline was exceeded.",
    pageId: null,
  }]);
  assert.equal(result.completed, false);
});

test("validates the bounded same-origin plan before robots or network work", async () => {
  const invalidPlans: readonly (readonly string[])[] = [
    ["/alpha", "/alpha"],
    ["//other.vendor.tld/probe"],
    ["/probe?token=secret"],
    ["/probe#fragment"],
    ["/probe\\escape"],
    ["relative"],
  ];

  for (const probePaths of invalidPlans) {
    const checks: string[] = [];
    const session = new ScriptedSession([]);
    await assert.rejects(
      collectCatalogProbes(finalUrl, {
        config: configWith(),
        session,
        robots: robotsService((url) => allowedRobots(url), checks),
        probePaths,
      }),
      /Catalog probe plan contains/u,
    );
    assert.deepEqual(checks, []);
    assert.deepEqual(session.calls, []);
  }

  await assert.rejects(
    collectCatalogProbes(finalUrl, {
      config: configWith([[ ["limits", "pages", "catalogProbesPerDomain"], 1 ]]),
      session: new ScriptedSession([]),
      robots: robotsService((url) => allowedRobots(url)),
      probePaths: ["/alpha", "/beta"],
    }),
    /exceeds the configured limit/u,
  );

  await assert.rejects(
    collectCatalogProbes("https://user:secret@shop.vendor.tld/", {
      config: configWith(),
      session: new ScriptedSession([]),
      robots: robotsService((url) => allowedRobots(url)),
      probePaths: ["/alpha"],
    }),
    /Final probe origin is not canonical HTTP\(S\)/u,
  );

  const checks: string[] = [];
  const overlongSession = new ScriptedSession([]);
  const overlong = await collectCatalogProbes(
    "https://very-long-hostname.vendor.tld/",
    {
      config: configWith([[ ["limits", "url", "codeUnits"], 40 ]]),
      session: overlongSession,
      robots: robotsService((url) => allowedRobots(url), checks),
      probePaths: ["/probe"],
    },
  );
  assert.deepEqual(checks, []);
  assert.deepEqual(overlongSession.calls, []);
  assert.deepEqual(overlong.errors.map((error) => ({
    stage: error.stage,
    code: error.code,
    retryable: error.retryable,
    message: error.message,
  })), [{
    stage: "http",
    code: "HTTP_LIMIT_EXCEEDED",
    retryable: false,
    message: "A catalog probe URL exceeded the configured limit.",
  }]);
  assert.equal(overlong.completed, false);

  const emptyChecks: string[] = [];
  const emptySession = new ScriptedSession([]);
  const empty = await collectCatalogProbes(finalUrl, {
    config: configWith([[ ["limits", "pages", "catalogProbesPerDomain"], 0 ]]),
    session: emptySession,
    robots: robotsService((url) => allowedRobots(url), emptyChecks),
    probePaths: [],
  });
  assert.deepEqual(emptyChecks, []);
  assert.deepEqual(emptySession.calls, []);
  assert.deepEqual(empty, {
    observations: [],
    robots: [],
    errors: [],
    completed: true,
  });
});

test("propagates caller cancellation before checking robots", async () => {
  const controller = new AbortController();
  const reason = new DOMException("caller cancelled", "AbortError");
  controller.abort(reason);
  const checks: string[] = [];
  const session = new ScriptedSession([], controller.signal);

  await assert.rejects(
    collectCatalogProbes(finalUrl, {
      config: configWith(),
      session,
      robots: robotsService((url) => allowedRobots(url), checks),
      probePaths: ["/alpha"],
      callerSignal: controller.signal,
    }),
    (error: unknown) => error === reason,
  );
  assert.deepEqual(checks, []);
  assert.deepEqual(session.calls, []);
});
