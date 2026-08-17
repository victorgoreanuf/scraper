import assert from "node:assert/strict";
import { once } from "node:events";
import {
  createServer as createHttpServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { type Server, type Socket } from "node:net";
import { test, type TestContext } from "node:test";

import {
  createDefaultScanConfig,
  parseScanConfig,
  type ScanConfig,
} from "../src/config.ts";
import {
  installTransportRuntimeHook,
  setupTransportRuntime,
} from "./support/transport-runtime.ts";

installTransportRuntimeHook();

const { createProtectedHttpTransport, ProtectedTransportError } = await import(
  "../src/crawl/transport.ts"
);
const {
  createRobotsPolicyService,
  RobotsPolicyError,
} = await import("../src/crawl/robots.ts");

type JsonRecord = Record<string, unknown>;

const userAgent =
  "WebsiteTechScraper/0.1.0 (https://contact.website-tech-scraper.dev/crawler)";
const publicAddress = "8.8.8.8";

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
    assert.fail("The local robots server did not expose a socket address.");
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

async function createControlledSession(
  t: TestContext,
  config: ScanConfig,
  handler: (request: IncomingMessage, response: ServerResponse) => void,
) {
  const server = createHttpServer(handler);
  const port = await listenOnLoopback(t, server);
  const runtimeOptions = {
    lookup: () => [{ address: publicAddress, family: 4 }],
    routes: new Map([
      [publicAddress, { physicalPort: port }],
    ]),
  } as const;
  const session = createProtectedHttpTransport(config).createSession();
  t.after(() => session.close());
  return {
    activate: () => setupTransportRuntime(runtimeOptions),
    session,
  };
}

async function expectRobotsError(
  action: () => Promise<unknown>,
  code: string,
  retryable?: boolean,
): Promise<InstanceType<typeof RobotsPolicyError>> {
  let caught: unknown;

  try {
    await action();
  } catch (error) {
    caught = error;
  }

  if (!(caught instanceof RobotsPolicyError)) {
    assert.fail("The robots check did not throw RobotsPolicyError.");
  }

  assert.equal(caught.code, code);

  if (retryable !== undefined) {
    assert.equal(caught.retryable, retryable);
  }

  return caught;
}

test("applies the exact product group and caches decisions per origin", async (t) => {
  const config = configWith();
  let requests = 0;
  const controlled = await createControlledSession(t, config, (_request, response) => {
    requests += 1;
    response.writeHead(200, { "Content-Type": "text/plain" });
    response.end([
      "User-agent: *",
      "Disallow: /",
      "User-agent: WEBSITEtechscraper",
      "Disallow: /private",
      "Allow: /private/public",
      "Allow: /same",
      "Disallow: /same",
      "Unknown: ignored",
      "not-a-directive",
    ].join("\n"));
  });
  controlled.activate();
  const { session } = controlled;
  const policies = createRobotsPolicyService(config);

  assert.equal(
    (await policies.check(session, "http://shop.vendor.tld/private")).allowed,
    false,
  );
  assert.equal(
    (await policies.check(session, "http://shop.vendor.tld/private/public")).allowed,
    true,
  );
  assert.equal(
    (await policies.check(session, "http://shop.vendor.tld/same")).allowed,
    true,
  );
  assert.equal(
    (await policies.check(session, "http://shop.vendor.tld/other")).allowed,
    true,
  );
  assert.equal(requests, 1);
  assert.equal(session.getUsage().httpRequests, 1);
});

test("normalizes unreserved escapes without decoding reserved escapes", async (t) => {
  const config = configWith();
  const controlled = await createControlledSession(t, config, (_request, response) => {
    response.writeHead(200);
    response.end([
      "User-agent: WebsiteTechScraper",
      "Disallow: /%7Eprivate",
      "Disallow: /encoded%2fslash",
      "Disallow: /query?mode=%66ull",
    ].join("\n"));
  });
  controlled.activate();
  const { session } = controlled;
  const policies = createRobotsPolicyService(config);

  assert.equal(
    (await policies.check(session, "http://shop.vendor.tld/~private")).allowed,
    false,
  );
  assert.equal(
    (await policies.check(session, "http://shop.vendor.tld/%7eprivate")).allowed,
    false,
  );
  assert.equal(
    (await policies.check(session, "http://shop.vendor.tld/encoded%2Fslash")).allowed,
    false,
  );
  assert.equal(
    (await policies.check(session, "http://shop.vendor.tld/encoded/slash")).allowed,
    true,
  );
  assert.equal(
    (await policies.check(session, "http://shop.vendor.tld/query?mode=full#ignored")).allowed,
    false,
  );
});

test("implements the fail-closed robots status table", async (t) => {
  const config = configWith();
  const statuses = new Map<string, number>([
    ["empty.vendor.tld", 204],
    ["missing.vendor.tld", 404],
    ["gone.vendor.tld", 410],
    ["method.vendor.tld", 405],
    ["unauthorized.vendor.tld", 401],
    ["forbidden.vendor.tld", 403],
    ["proxy.vendor.tld", 407],
    ["legal.vendor.tld", 451],
    ["limited.vendor.tld", 429],
    ["timeout.vendor.tld", 408],
    ["early.vendor.tld", 425],
    ["failure.vendor.tld", 500],
    ["cached.vendor.tld", 304],
    ["redirect.vendor.tld", 302],
  ]);
  const controlled = await createControlledSession(t, config, (request, response) => {
    const hostname = request.headers.host;
    const statusCode = hostname === undefined ? 500 : statuses.get(hostname) ?? 500;
    response.writeHead(statusCode);
    response.end("ignored");
  });
  controlled.activate();
  const { session } = controlled;
  const policies = createRobotsPolicyService(config);

  for (const hostname of [
    "empty.vendor.tld",
    "missing.vendor.tld",
    "gone.vendor.tld",
    "method.vendor.tld",
  ]) {
    const result = await policies.check(session, `http://${hostname}/`);
    assert.equal(result.allowed, true);
    assert.equal(result.robotsText, hostname === "empty.vendor.tld" ? "" : null);
  }

  for (const hostname of [
    "unauthorized.vendor.tld",
    "forbidden.vendor.tld",
    "proxy.vendor.tld",
    "legal.vendor.tld",
    "cached.vendor.tld",
    "redirect.vendor.tld",
  ]) {
    await expectRobotsError(
      () => policies.check(session, `http://${hostname}/`),
      "ROBOTS_UNAVAILABLE",
      false,
    );
  }

  for (const hostname of [
    "timeout.vendor.tld",
    "early.vendor.tld",
    "limited.vendor.tld",
    "failure.vendor.tld",
  ]) {
    await expectRobotsError(
      () => policies.check(session, `http://${hostname}/`),
      "ROBOTS_UNAVAILABLE",
      true,
    );
  }
});

test("decodes strict UTF-8 and preserves the bounded robots signal", async (t) => {
  const config = configWith();
  const invalid = Buffer.from([0xff, 0xfe, 0xfd]);
  const valid = Buffer.concat([
    Buffer.from([0xef, 0xbb, 0xbf]),
    Buffer.from(
      "User-agent: WebsiteTechScraper\rDisallow: /blocked\r\n# comment\n",
      "utf8",
    ),
  ]);
  const controlled = await createControlledSession(t, config, (request, response) => {
    response.writeHead(200);
    response.end(request.headers.host === "invalid.vendor.tld" ? invalid : valid);
  });
  controlled.activate();
  const { session } = controlled;
  const policies = createRobotsPolicyService(config);

  await expectRobotsError(
    () => policies.check(session, "http://invalid.vendor.tld/"),
    "ROBOTS_UNAVAILABLE",
    false,
  );
  const result = await policies.check(session, "http://valid.vendor.tld/blocked");
  assert.equal(result.allowed, false);
  assert.equal(result.robotsText?.startsWith("User-agent:"), true);
  assert.equal(result.robotsText?.includes("# comment"), true);
});

test("enforces line, expanded-rule, and canonical-pattern limits", async (t) => {
  const cases = new Map<string, string>([
    ["lines-ok.vendor.tld", "User-agent: *\nDisallow: /x"],
    ["lines-over.vendor.tld", "User-agent: *\nDisallow: /x\nAllow: /y"],
    ["rules-ok.vendor.tld", "User-agent: *\nDisallow:"],
    [
      "rules-over.vendor.tld",
      "User-agent: *\nUser-agent: WebsiteTechScraper\nDisallow:",
    ],
    ["length-ok.vendor.tld", "User-agent: *\nDisallow: /abc"],
    ["length-over.vendor.tld", "User-agent: *\nDisallow: /abcd"],
  ]);
  const config = configWith([
    [["limits", "robots", "lines"], 2],
    [["limits", "robots", "rules"], 1],
    [["limits", "robots", "ruleCodeUnits"], 4],
  ]);
  const controlled = await createControlledSession(t, config, (request, response) => {
    response.writeHead(200);
    response.end(cases.get(request.headers.host ?? "") ?? "");
  });
  controlled.activate();
  const { session } = controlled;
  const policies = createRobotsPolicyService(config);

  assert.equal(
    (await policies.check(session, "http://lines-ok.vendor.tld/other")).allowed,
    true,
  );
  assert.equal(
    (await policies.check(session, "http://rules-ok.vendor.tld/other")).allowed,
    true,
  );
  assert.equal(
    (await policies.check(session, "http://length-ok.vendor.tld/other")).allowed,
    true,
  );

  for (const hostname of [
    "lines-over.vendor.tld",
    "rules-over.vendor.tld",
    "length-over.vendor.tld",
  ]) {
    await expectRobotsError(
      () => policies.check(session, `http://${hostname}/`),
      "ROBOTS_LIMIT_EXCEEDED",
      false,
    );
  }
});

test("ignores malformed records without changing valid group semantics", async (t) => {
  const config = configWith();
  const policiesByHost = new Map<string, string>([
    [
      "invalid-agent.vendor.tld",
      [
        "User-agent: *",
        "Disallow: /",
        "User-agent: WebsiteTechScraper/1",
      ].join("\n"),
    ],
    [
      "other-record.vendor.tld",
      [
        "User-agent: WebsiteTechScraper",
        "Sitemap: https://other-record.vendor.tld/sitemap.xml",
        "User-agent: OtherBot",
        "Disallow: /",
      ].join("\n"),
    ],
    [
      "invalid-rule.vendor.tld",
      "User-agent: WebsiteTechScraper\nDisallow: relative-path",
    ],
    [
      "wildcard-rule.vendor.tld",
      "User-agent: WebsiteTechScraper\nDisallow: *.gif$",
    ],
  ]);
  const controlled = await createControlledSession(t, config, (request, response) => {
    response.writeHead(200);
    response.end(policiesByHost.get(request.headers.host ?? "") ?? "");
  });
  controlled.activate();
  const { session } = controlled;
  const policies = createRobotsPolicyService(config);

  assert.equal(
    (await policies.check(session, "http://invalid-agent.vendor.tld/")).allowed,
    false,
  );
  assert.equal(
    (await policies.check(session, "http://other-record.vendor.tld/")).allowed,
    false,
  );
  assert.equal(
    (await policies.check(session, "http://invalid-rule.vendor.tld/relative-path"))
      .allowed,
    true,
  );
  assert.equal(
    (await policies.check(session, "http://wildcard-rule.vendor.tld/image.gif"))
      .allowed,
    false,
  );
});

test("preserves empty exact groups and bounds rules after an empty agent", async (t) => {
  const config = configWith([
    [["limits", "robots", "rules"], 2],
  ]);
  const policiesByHost = new Map<string, string>([
    [
      "empty-rule.vendor.tld",
      [
        "User-agent: *",
        "Disallow: /",
        "User-agent: WebsiteTechScraper",
        "Disallow:",
      ].join("\n"),
    ],
    [
      "empty-eof.vendor.tld",
      [
        "User-agent: *",
        "Disallow: /",
        "User-agent: WebsiteTechScraper",
      ].join("\n"),
    ],
    [
      "empty-agent.vendor.tld",
      [
        "User-agent: *",
        "Disallow:",
        "User-agent:",
        "Disallow: /hidden",
        "Allow: /public",
      ].join("\n"),
    ],
  ]);
  const controlled = await createControlledSession(t, config, (request, response) => {
    response.writeHead(200);
    response.end(policiesByHost.get(request.headers.host ?? "") ?? "");
  });
  controlled.activate();
  const { session } = controlled;
  const policies = createRobotsPolicyService(config);

  assert.equal(
    (await policies.check(session, "http://empty-rule.vendor.tld/")).allowed,
    true,
  );
  assert.equal(
    (await policies.check(session, "http://empty-eof.vendor.tld/")).allowed,
    true,
  );
  await expectRobotsError(
    () => policies.check(session, "http://empty-agent.vendor.tld/hidden"),
    "ROBOTS_LIMIT_EXCEEDED",
    false,
  );
});

test("bounds matching work without corrupting the cached policy", async (t) => {
  const config = configWith([
    [["limits", "robots", "matchingStatesPerUrl"], 12],
  ]);
  let requests = 0;
  const controlled = await createControlledSession(t, config, (_request, response) => {
    requests += 1;
    response.writeHead(200);
    response.end("User-agent: *\nUser-agent: *\nDisallow: /a");
  });
  controlled.activate();
  const { session } = controlled;
  const policies = createRobotsPolicyService(config);

  assert.equal(
    (await policies.check(session, "http://shop.vendor.tld/x")).allowed,
    true,
  );
  await expectRobotsError(
    () => policies.check(session, "http://shop.vendor.tld/xx"),
    "ROBOTS_LIMIT_EXCEEDED",
    false,
  );
  assert.equal(
    (await policies.check(session, "http://shop.vendor.tld/x")).allowed,
    true,
  );
  assert.equal(requests, 1);
});

test("applies cross-authority redirects only to their original owner", async (t) => {
  const config = configWith();
  const requests: string[] = [];
  const controlled = await createControlledSession(t, config, (request, response) => {
    const host = request.headers.host ?? "";
    requests.push(`${host}${request.url ?? ""}`);

    if (host === "owner.vendor.tld" && request.url === "/robots.txt") {
      response.writeHead(302, {
        Location: "http://policy.vendor.tld/shared-rules",
      });
      response.end();
      return;
    }

    if (host === "policy.vendor.tld" && request.url === "/shared-rules") {
      response.writeHead(200);
      response.end("User-agent: *\nDisallow: /blocked");
      return;
    }

    response.writeHead(404);
    response.end();
  });
  controlled.activate();
  const { session } = controlled;
  const policies = createRobotsPolicyService(config);

  const owner = await policies.check(session, "http://owner.vendor.tld/blocked");
  assert.equal(owner.allowed, false);
  assert.equal(owner.ownerOrigin, "http://owner.vendor.tld");
  assert.equal(owner.fetchedUrl, "http://policy.vendor.tld/shared-rules");

  const redirectHost = await policies.check(
    session,
    "http://policy.vendor.tld/blocked",
  );
  assert.equal(redirectHost.allowed, true);
  assert.deepEqual(requests, [
    "owner.vendor.tld/robots.txt",
    "policy.vendor.tld/shared-rules",
    "policy.vendor.tld/robots.txt",
  ]);
});

test("allows five robots redirects and rejects the sixth or a loop", async (t) => {
  const config = configWith();
  const controlled = await createControlledSession(t, config, (request, response) => {
    const host = request.headers.host ?? "";
    const path = request.url ?? "";

    if (host === "loop.vendor.tld") {
      response.writeHead(302, { Location: "/robots.txt" });
      response.end();
      return;
    }

    const match = /^\/(?:robots\.txt|r(\d+))$/u.exec(path);
    const current = path === "/robots.txt" ? 0 : Number(match?.[1] ?? -1);
    const maximum = host === "five.vendor.tld" ? 5 : 6;

    if (current < maximum) {
      response.writeHead(302, { Location: `/r${current + 1}` });
      response.end();
      return;
    }

    response.writeHead(200);
    response.end("User-agent: *\nAllow: /");
  });
  controlled.activate();
  const { session } = controlled;
  const policies = createRobotsPolicyService(config);

  assert.equal(
    (await policies.check(session, "http://five.vendor.tld/")).allowed,
    true,
  );
  await expectRobotsError(
    () => policies.check(session, "http://six.vendor.tld/"),
    "ROBOTS_LIMIT_EXCEEDED",
    false,
  );
  await expectRobotsError(
    () => policies.check(session, "http://loop.vendor.tld/"),
    "ROBOTS_LIMIT_EXCEEDED",
    false,
  );
});

test("coalesces cache misses, expires exactly, and clears run state", async (t) => {
  const config = configWith([
    [["limits", "timeMs", "robotsCache"], 10],
  ]);
  let now = 0;
  let requests = 0;
  const controlled = await createControlledSession(t, config, (_request, response) => {
    requests += 1;
    response.writeHead(200);
    response.end("User-agent: *\nAllow: /");
  });
  controlled.activate();
  const { session } = controlled;
  const policies = createRobotsPolicyService(config, { now: () => now });

  const [first, second] = await Promise.all([
    policies.check(session, "http://shop.vendor.tld/one"),
    policies.check(session, "http://shop.vendor.tld/two"),
  ]);
  assert.equal(first.allowed, true);
  assert.equal(second.allowed, true);
  assert.equal(requests, 1);

  now = 9;
  await policies.check(session, "http://shop.vendor.tld/three");
  assert.equal(requests, 1);

  now = 10;
  await policies.check(session, "http://shop.vendor.tld/four");
  assert.equal(requests, 2);

  policies.clear();
  await policies.check(session, "http://shop.vendor.tld/five");
  assert.equal(requests, 3);
});

test("evicts rejected fetches and preserves transport security errors", async (t) => {
  const config = configWith([
    [["limits", "robots", "bodyBytes"], 4],
  ]);
  let attempts = 0;
  const controlled = await createControlledSession(t, config, (request, response) => {
    attempts += 1;

    if (request.headers.host === "retry.vendor.tld" && attempts === 1) {
      response.writeHead(500);
      response.end();
      return;
    }

    response.writeHead(200);
    response.end(request.headers.host === "large.vendor.tld" ? "12345" : "");
  });
  controlled.activate();
  const { session } = controlled;
  const policies = createRobotsPolicyService(config);

  await expectRobotsError(
    () => policies.check(session, "http://retry.vendor.tld/"),
    "ROBOTS_UNAVAILABLE",
    true,
  );
  assert.equal(
    (await policies.check(session, "http://retry.vendor.tld/")).allowed,
    true,
  );

  let caught: unknown;

  try {
    await policies.check(session, "http://large.vendor.tld/");
  } catch (error) {
    caught = error;
  }

  assert.ok(caught instanceof ProtectedTransportError);
  assert.equal(caught.code, "HTTP_RESPONSE_LIMIT_EXCEEDED");
});

test("blocks private robots redirects before a second connection", async (t) => {
  const config = configWith();
  const controlled = await createControlledSession(
    t,
    config,
    (_request, response) => {
      response.writeHead(302, { Location: "http://127.0.0.1/robots.txt" });
      response.end();
    },
  );
  const runtime = controlled.activate();
  const { session } = controlled;
  const policies = createRobotsPolicyService(config);
  let caught: unknown;

  try {
    await policies.check(session, "http://shop.vendor.tld/");
  } catch (error) {
    caught = error;
  }

  assert.ok(caught instanceof ProtectedTransportError);
  assert.equal(caught.code, "SSRF_NON_PUBLIC_ADDRESS");
  assert.equal(runtime.connectCalls.length, 1);
});
