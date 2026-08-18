import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import {
  createServer as createNetServer,
  type Server,
  type Socket,
} from "node:net";
import {
  setImmediate as waitForImmediate,
  setTimeout as delay,
} from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";
import { test, type TestContext } from "node:test";

import {
  createDefaultScanConfig,
  parseScanConfig,
  type ScanConfig,
} from "../src/config.ts";
import {
  installTransportRuntimeHook,
  setupTransportRuntime as runtimeHarness,
} from "./support/transport-runtime.ts";

installTransportRuntimeHook();

const transportModule = await import("../src/crawl/transport.ts");
const {
  createProtectedHttpTransport,
  ProtectedTransportError,
  resolveRedirectTarget,
} = transportModule;

type JsonRecord = Record<string, unknown>;

const userAgent =
  "WebsiteTechScraper/0.1.0 (https://contact.website-tech-scraper.dev/crawler)";
const execFileAsync = promisify(execFile);
const primaryPublicAddress = "8.8.8.8";
const secondaryPublicAddress = "1.1.1.1";
const tlsKey = readFileSync(
  new URL("./fixtures/transport/key.pem", import.meta.url),
);
const tlsCertificate = readFileSync(
  new URL("./fixtures/transport/cert.pem", import.meta.url),
);
const tlsCertificatePath = fileURLToPath(
  new URL("./fixtures/transport/cert.pem", import.meta.url),
);

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
    assert.fail("The local server did not expose an IP socket address.");
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

function bodyBuffer(response: unknown): Buffer {
  if (
    typeof response !== "object"
    || response === null
    || !("body" in response)
  ) {
    assert.fail("The transport response is missing its body.");
  }

  const body = (response as { readonly body: unknown }).body;
  assert.ok(body instanceof Uint8Array);
  return Buffer.from(body);
}

function responseStatus(response: unknown): number {
  if (
    typeof response !== "object"
    || response === null
    || !("statusCode" in response)
  ) {
    assert.fail("The transport response is missing its status code.");
  }

  const statusCode = (response as { readonly statusCode: unknown }).statusCode;

  if (typeof statusCode !== "number") {
    assert.fail("The transport response status code is not numeric.");
  }

  return statusCode;
}

function responseHeader(response: unknown, name: string): string | undefined {
  if (
    typeof response !== "object"
    || response === null
    || !("headers" in response)
  ) {
    assert.fail("The transport response is missing its headers.");
  }

  const headers = (response as { readonly headers: unknown }).headers;

  if (Array.isArray(headers)) {
    const match = headers.find(
      (header: unknown) =>
        typeof header === "object"
        && header !== null
        && "name" in header
        && typeof header.name === "string"
        && header.name.toLowerCase() === name.toLowerCase(),
    );

    if (
      typeof match === "object"
      && match !== null
      && "value" in match
      && typeof match.value === "string"
    ) {
      return match.value;
    }

    return undefined;
  }

  if (
    typeof headers === "object"
    && headers !== null
    && "get" in headers
    && typeof headers.get === "function"
  ) {
    const value = headers.get(name);
    return typeof value === "string" ? value : undefined;
  }

  assert.equal(typeof headers, "object");
  assert.notEqual(headers, null);
  const record = headers as Record<string, unknown>;
  const value = record[name] ?? record[name.toLowerCase()];

  if (Array.isArray(value)) {
    const first = value[0];
    return typeof first === "string" ? first : undefined;
  }

  return typeof value === "string" ? value : undefined;
}

async function expectTransportError(
  action: () => Promise<unknown>,
  code: string,
): Promise<InstanceType<typeof ProtectedTransportError>> {
  let caught: unknown;

  try {
    await action();
  } catch (error) {
    caught = error;
  }

  if (!(caught instanceof ProtectedTransportError)) {
    assert.fail("The request did not throw ProtectedTransportError.");
  }

  assert.equal(caught.code, code);
  return caught;
}

function redirectString(value: unknown): string {
  if (value instanceof URL) {
    return value.href;
  }

  if (typeof value !== "string") {
    assert.fail("The redirect target is neither a URL nor a string.");
  }

  return value;
}

test("exposes no injectable transport runtime from the production module", () => {
  assert.equal("createProtectedHttpTransportForTesting" in transportModule, false);
  assert.equal("nodeRuntime" in transportModule, false);
});

test("pins a successful HTTP request while preserving Host and usage", async (t) => {
  let method: string | undefined;
  let path: string | undefined;
  let host: string | undefined;
  const server = createHttpServer((request, response) => {
    method = request.method;
    path = request.url;
    host = request.headers.host;
    response.setHeader("content-type", "text/html; charset=utf-8");
    response.end("ok");
  });
  const port = await listenOnLoopback(t, server);
  const harness = runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([
      [primaryPublicAddress, { physicalPort: port }],
    ]),
  });
  const session = createSession(t, configWith());

  const response = await session.requestHop({
    url: "http://shop.vendor.tld/",
    purpose: "page",
  });

  assert.equal(responseStatus(response), 200);
  assert.equal(bodyBuffer(response).toString("utf8"), "ok");
  assert.equal(method, "GET");
  assert.equal(path, "/");
  assert.equal(host, "shop.vendor.tld");
  assert.equal(harness.lookupCalls.length, 1);
  assert.deepEqual(harness.lookupCalls[0], {
    hostname: "shop.vendor.tld",
    options: { all: true, order: "verbatim" },
  });
  assert.equal(harness.connectCalls.length, 1);
  assert.equal(harness.connectCalls[0]?.address, primaryPublicAddress);
  assert.equal(harness.connectCalls[0]?.port, 80);
  assert.deepEqual(session.getUsage(), {
    httpRequests: 1,
    retries: 0,
    staticTransferredBytes: 2,
  });
});

test("rejects private and mixed DNS answers before dialing", async (t) => {
  const cases = [
    {
      answers: [{ address: "127.0.0.1", family: 4 }],
      code: "SSRF_NON_PUBLIC_ADDRESS",
    },
    {
      answers: [
        { address: primaryPublicAddress, family: 4 },
        { address: "10.0.0.1", family: 4 },
      ],
      code: "SSRF_MIXED_ADDRESSES",
    },
    {
      answers: [
        { address: "10.0.0.1", family: 4 },
        { address: primaryPublicAddress, family: 4 },
      ],
      code: "SSRF_MIXED_ADDRESSES",
    },
  ] as const;

  for (const entry of cases) {
    const harness = runtimeHarness({
      lookup: () => entry.answers,
    });
    const session = createSession(t, configWith());

    await expectTransportError(
      () => session.requestHop({
        url: "http://shop.vendor.tld/",
        purpose: "page",
      }),
      entry.code,
    );

    assert.equal(harness.connectCalls.length, 0);
    assert.equal(session.getUsage().httpRequests, 1);
    session.close();
  }
});

test("rejects a connected address mismatch before writing HTTP bytes", async (t) => {
  let connections = 0;
  let bytesReceived = 0;
  const server = createNetServer((socket) => {
    connections += 1;
    socket.on("data", (chunk: Buffer) => {
      bytesReceived += chunk.byteLength;
    });
  });
  const port = await listenOnLoopback(t, server);
  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([
      [primaryPublicAddress, {
        physicalPort: port,
        remoteAddress: secondaryPublicAddress,
      }],
    ]),
  });
  const session = createSession(t, configWith());

  await expectTransportError(
    () => session.requestHop({
      url: "http://shop.vendor.tld/",
      purpose: "page",
    }),
    "SSRF_REMOTE_ADDRESS_MISMATCH",
  );
  await delay(10);

  assert.equal(connections, 1);
  assert.equal(bytesReceived, 0);
});

test("compares equivalent expanded and compressed IPv6 peers semantically", async (t) => {
  const expandedAddress = "2606:4700:4700:0:0:0:0:1111";
  const server = createHttpServer((_request, response) => response.end("ok"));
  const port = await listenOnLoopback(t, server);
  const harness = runtimeHarness({
    lookup: () => [{ address: expandedAddress, family: 6 }],
    routes: new Map([
      [
        expandedAddress,
        {
          physicalPort: port,
          remoteAddress: "2606:4700:4700::1111",
        },
      ],
    ]),
  });
  const session = createSession(t, configWith());

  const response = await session.requestHop({
    url: "http://shop.vendor.tld/",
    purpose: "page",
  });

  assert.equal(responseStatus(response), 200);
  assert.equal(harness.connectCalls[0]?.family, 6);
});

test("resolves only valid canonical redirect targets", () => {
  assert.equal(
    redirectString(
      resolveRedirectTarget(
        "http://shop.vendor.tld/start",
        "/next",
        2_048,
      ),
    ),
    "http://shop.vendor.tld/next",
  );
  assert.equal(
    redirectString(
      resolveRedirectTarget(
        "https://shop.vendor.tld/start",
        "https://8.8.8.8/path",
        2_048,
      ),
    ),
    "https://8.8.8.8/path",
  );

  for (const location of [
    "ftp://shop.vendor.tld/",
    "http:shop.vendor.tld/",
    "https:/shop.vendor.tld/",
    "http:\\\\shop.vendor.tld\\path",
    "http://user:password@shop.vendor.tld/",
    "http://shop.vendor.tld:8080/",
    "http://134744072/",
    "http://0x08080808/",
    "http://010.010.010.010/",
    "http://8.8.2056/",
    "http://8.526344/",
    "http://008.008.008.008/",
    "http://8.8.8.8./",
    "http://[fe80::1%25en0]/",
    "http://bad host/",
    `http://shop.vendor.tld/${"a".repeat(2_048)}`,
  ]) {
    assert.throws(
      () => resolveRedirectTarget(
        "http://shop.vendor.tld/",
        location,
        2_048,
      ),
      (error: unknown) => {
        if (!(error instanceof ProtectedTransportError)) {
          assert.fail(`Expected ProtectedTransportError for ${location}`);
        }

        assert.equal(error.code, "TARGET_REDIRECT_INVALID", location);
        return true;
      },
    );
  }

  assert.throws(
    () => resolveRedirectTarget(
      "http://shop.vendor.tld/",
      "http://127.0.0.1/",
      2_048,
    ),
    (error: unknown) => {
      if (!(error instanceof ProtectedTransportError)) {
        assert.fail("Expected ProtectedTransportError for private redirect");
      }

      assert.equal(error.code, "SSRF_NON_PUBLIC_ADDRESS");
      return true;
    },
  );

  for (const invalidLimit of [0, 2_049, 1.5]) {
    assert.throws(
      () => resolveRedirectTarget(
        "http://shop.vendor.tld/",
        "/next",
        invalidLimit,
      ),
      ProtectedTransportError,
    );
  }
});

test("rejects malformed absolute request URLs before budget or DNS", async (t) => {
  const harness = runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
  });
  const session = createSession(t, configWith());

  for (const url of [
    "http:shop.vendor.tld/",
    "https:/shop.vendor.tld/",
    "http:\\\\shop.vendor.tld\\path",
    "http://134744072/",
    "http://0x08080808/",
    "http://010.010.010.010/",
    "http://8.8.2056/",
    "http://8.526344/",
    "http://008.008.008.008/",
    "http://8.8.8.8./",
  ]) {
    const error = await expectTransportError(
      () => session.requestHop({ url, purpose: "page" }),
      "TARGET_REDIRECT_INVALID",
    );
    assert.equal(error.retryable, false, url);
  }

  assert.equal(harness.lookupCalls.length, 0);
  assert.equal(harness.connectCalls.length, 0);
  assert.deepEqual(session.getUsage(), {
    httpRequests: 0,
    retries: 0,
    staticTransferredBytes: 0,
  });
});

test("keeps TLS certificate verification enabled on a pinned connection", async (t) => {
  let httpRequests = 0;
  const server = createHttpsServer(
    { key: tlsKey, cert: tlsCertificate },
    (_request, response) => {
      httpRequests += 1;
      response.end("unexpected");
    },
  );
  const port = await listenOnLoopback(t, server);
  const harness = runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([
      [primaryPublicAddress, { physicalPort: port }],
    ]),
  });
  const session = createSession(t, configWith());

  const error = await expectTransportError(
    () => session.requestHop({
      url: "https://shop.vendor.tld/",
      purpose: "page",
    }),
    "TLS_CERTIFICATE_INVALID",
  );

  assert.equal(error.stage, "tls");
  assert.equal(error.retryable, false);
  assert.equal(httpRequests, 0);
  assert.equal(harness.connectCalls[0]?.port, 443);
});

test("preserves Host and SNI for trusted TLS and rejects a trusted wrong name", async (t) => {
  const requests: Array<{
    readonly host: string | undefined;
    readonly servername: string | undefined;
  }> = [];
  const server = createHttpsServer(
    { key: tlsKey, cert: tlsCertificate },
    (request, response) => {
      const servername =
        "servername" in request.socket &&
        typeof request.socket.servername === "string"
          ? request.socket.servername
          : undefined;
      requests.push({ host: request.headers.host, servername });
      response.end("secure");
    },
  );
  const port = await listenOnLoopback(t, server);
  const supportUrl = new URL("./support/transport-runtime.ts", import.meta.url).href;
  const configUrl = new URL("../src/config.ts", import.meta.url).href;
  const transportUrl = new URL("../src/crawl/transport.ts", import.meta.url).href;
  const childScript = `
    const support = await import(${JSON.stringify(supportUrl)});
    support.installTransportRuntimeHook();
    const { createDefaultScanConfig } = await import(${JSON.stringify(configUrl)});
    const { createProtectedHttpTransport } = await import(${JSON.stringify(transportUrl)});
    const address = ${JSON.stringify(primaryPublicAddress)};
    support.setupTransportRuntime({
      lookup: () => [{ address, family: 4 }],
      routes: new Map([[address, { physicalPort: Number(process.env.TRANSPORT_TEST_PORT) }]]),
    });
    const transport = createProtectedHttpTransport(
      createDefaultScanConfig(${JSON.stringify(userAgent)}),
    );
    const accepted = transport.createSession();
    const acceptedResponse = await accepted.requestHop({
      url: "https://shop.vendor.tld/",
      purpose: "page",
    });
    accepted.close();
    const wrongName = transport.createSession();
    let wrongNameCode;
    try {
      await wrongName.requestHop({
        url: "https://wrong.vendor.tld/",
        purpose: "page",
      });
    } catch (error) {
      wrongNameCode = error?.code;
    } finally {
      wrongName.close();
    }
    process.stdout.write(JSON.stringify({
      statusCode: acceptedResponse.statusCode,
      body: new TextDecoder().decode(acceptedResponse.body),
      tlsIssuer: acceptedResponse.tlsIssuer,
      tlsHandshakeMs: acceptedResponse.tlsHandshakeMs,
      wrongNameCode,
    }));
  `;
  const { stdout } = await execFileAsync(
    process.execPath,
    ["--input-type=module", "--eval", childScript],
    {
      env: {
        ...process.env,
        NODE_EXTRA_CA_CERTS: tlsCertificatePath,
        TRANSPORT_TEST_PORT: String(port),
      },
      encoding: "utf8",
      timeout: 5_000,
    },
  );
  const childResult = JSON.parse(String(stdout)) as {
    readonly statusCode: number;
    readonly body: string;
    readonly tlsIssuer: string | null;
    readonly tlsHandshakeMs: number | null;
    readonly wrongNameCode: string;
  };

  assert.equal(childResult.statusCode, 200);
  assert.equal(childResult.body, "secure");
  assert.equal(childResult.wrongNameCode, "TLS_CERTIFICATE_INVALID");
  assert.equal(typeof childResult.tlsIssuer, "string");
  assert.ok((childResult.tlsIssuer?.length ?? 0) > 0);
  assert.equal(Number.isSafeInteger(childResult.tlsHandshakeMs), true);
  assert.ok((childResult.tlsHandshakeMs ?? -1) >= 0);
  assert.deepEqual(requests, [{
    host: "shop.vendor.tld",
    servername: "shop.vendor.tld",
  }]);
});

test("performs redirect hops individually with fresh DNS and counters", async (t) => {
  const paths: string[] = [];
  const server = createHttpServer((request, response) => {
    paths.push(request.url ?? "");

    if (request.url === "/start") {
      response.statusCode = 302;
      response.setHeader("location", "/finish");
      response.end();
      return;
    }

    response.end("done");
  });
  const port = await listenOnLoopback(t, server);
  const harness = runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([
      [primaryPublicAddress, { physicalPort: port }],
    ]),
  });
  const session = createSession(t, configWith());

  const first = await session.requestHop({
    url: "http://shop.vendor.tld/start",
    purpose: "page",
  });
  assert.equal(responseStatus(first), 302);
  const location = responseHeader(first, "location");
  assert.equal(location, "/finish");
  const target = resolveRedirectTarget(
    "http://shop.vendor.tld/start",
    location,
    2_048,
  );
  const second = await session.requestHop({
    url: redirectString(target),
    purpose: "page",
  });

  assert.equal(responseStatus(second), 200);
  assert.equal(bodyBuffer(second).toString("utf8"), "done");
  assert.deepEqual(paths, ["/start", "/finish"]);
  assert.equal(harness.lookupCalls.length, 2);
  assert.equal(harness.connectCalls.length, 2);
  assert.equal(session.getUsage().httpRequests, 2);
});

test("a late DNS result cannot dial after the absolute request timeout", async (t) => {
  const config = configWith([
    [["limits", "timeMs", "httpRequest"], 20],
  ]);
  const harness = runtimeHarness({
    lookup: async () => {
      await delay(60);
      return [{ address: primaryPublicAddress, family: 4 }];
    },
  });
  const session = createSession(t, config);

  await expectTransportError(
    () => session.requestHop({
      url: "http://shop.vendor.tld/",
      purpose: "page",
    }),
    "HTTP_TIMEOUT",
  );
  await delay(70);

  assert.equal(harness.connectCalls.length, 0);
});

test("slow trickle responses cannot extend the absolute request timeout", async (t) => {
  const intervals = new Set<NodeJS.Timeout>();
  const server = createHttpServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/html" });
    const interval = setInterval(() => response.write("x"), 5);
    intervals.add(interval);
    response.once("close", () => {
      clearInterval(interval);
      intervals.delete(interval);
    });
  });
  t.after(() => {
    for (const interval of intervals) {
      clearInterval(interval);
    }
  });
  const port = await listenOnLoopback(t, server);
  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([
      [primaryPublicAddress, { physicalPort: port }],
    ]),
  });
  const session = createSession(
    t,
    configWith([[ ["limits", "timeMs", "httpRequest"], 35 ]]),
  );
  const startedAt = performance.now();

  await expectTransportError(
    () => session.requestHop({
      url: "http://shop.vendor.tld/",
      purpose: "page",
    }),
    "HTTP_TIMEOUT",
  );

  assert.ok(performance.now() - startedAt < 500);
});

test("enforces response header field count including duplicate fields", async (t) => {
  const exactServer = createNetServer((socket) => {
    socket.once("data", () => {
      socket.end(
        "HTTP/1.1 200 OK\r\n"
        + "X-One: 1\r\n"
        + "X-Two: 2\r\n"
        + "Content-Length: 0\r\n"
        + "\r\n",
      );
    });
  });
  const overflowServer = createNetServer((socket) => {
    socket.once("data", () => {
      socket.end(
        "HTTP/1.1 200 OK\r\n"
        + "Set-Cookie: a=1\r\n"
        + "Set-Cookie: b=2\r\n"
        + "X-Three: 3\r\n"
        + "Content-Length: 0\r\n"
        + "\r\n",
      );
    });
  });
  const exactPort = await listenOnLoopback(t, exactServer);
  const overflowPort = await listenOnLoopback(t, overflowServer);
  const config = configWith([
    [["limits", "http", "headerFields"], 3],
  ]);

  for (const [address, physicalPort, expectedCode] of [
    [primaryPublicAddress, exactPort, undefined],
    [secondaryPublicAddress, overflowPort, "HTTP_RESPONSE_LIMIT_EXCEEDED"],
  ] as const) {
    runtimeHarness({
      lookup: () => [{ address, family: 4 }],
      routes: new Map([[address, { physicalPort }]]),
    });
    const session = createSession(t, config);
    const action = () => session.requestHop({
      url: "http://shop.vendor.tld/",
      purpose: "page" as const,
    });

    if (expectedCode === undefined) {
      assert.equal(responseStatus(await action()), 200);
    } else {
      await expectTransportError(action, expectedCode);
    }

    session.close();
  }
});

test("rejects any non-empty response trailers", async (t) => {
  const server = createNetServer((socket) => {
    socket.once("data", () => {
      socket.end(
        "HTTP/1.1 200 OK\r\n"
        + "Transfer-Encoding: chunked\r\n"
        + "Trailer: X-Trailer\r\n"
        + "\r\n"
        + "1\r\nx\r\n"
        + "0\r\n"
        + "X-Trailer: yes\r\n"
        + "\r\n",
      );
    });
  });
  const port = await listenOnLoopback(t, server);
  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([[primaryPublicAddress, { physicalPort: port }]]),
  });
  const session = createSession(t, configWith());

  await expectTransportError(
    () => session.requestHop({
      url: "http://shop.vendor.tld/",
      purpose: "page",
    }),
    "HTTP_RESPONSE_LIMIT_EXCEEDED",
  );
});

test("rejects zero-field and OWS-only informational responses", async (t) => {
  for (const informationalBlock of [
    "HTTP/1.1 103 Early Hints\r\n\r\n",
    "HTTP/1.1 103 Early Hints\r\nX-Padding: \t \r\n\r\n",
  ]) {
    const server = createNetServer((socket) => {
      socket.once("data", () => {
        socket.end(
          informationalBlock
          + "HTTP/1.1 200 OK\r\n"
          + "Content-Length: 0\r\n"
          + "\r\n",
        );
      });
    });
    const port = await listenOnLoopback(t, server);
    runtimeHarness({
      lookup: () => [{ address: primaryPublicAddress, family: 4 }],
      routes: new Map([[primaryPublicAddress, { physicalPort: port }]]),
    });
    const session = createSession(t, configWith());

    const error = await expectTransportError(
      () => session.requestHop({
        url: "http://shop.vendor.tld/",
        purpose: "page",
      }),
      "HTTP_RESPONSE_LIMIT_EXCEEDED",
    );

    assert.equal(error.retryable, false);
    session.close();
  }
});

test("uses the configured response header byte cap rather than Node's default", async (t) => {
  const acceptedHeader = "a".repeat(20 * 1_024);
  const acceptedServer = createNetServer((socket) => {
    socket.once("data", () => {
      socket.end(
        "HTTP/1.1 200 OK\r\n"
        + `X-Large: ${acceptedHeader}\r\n`
        + "Content-Length: 0\r\n\r\n",
      );
    });
  });
  const overflowServer = createNetServer((socket) => {
    socket.once("data", () => {
      socket.end(
        "HTTP/1.1 200 OK\r\n"
        + `X-Large: ${"b".repeat(400)}\r\n`
        + "Content-Length: 0\r\n\r\n",
      );
    });
  });
  const acceptedPort = await listenOnLoopback(t, acceptedServer);
  const overflowPort = await listenOnLoopback(t, overflowServer);

  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([[primaryPublicAddress, { physicalPort: acceptedPort }]]),
  });
  const acceptedSession = createSession(t, configWith());
  assert.equal(
    responseStatus(await acceptedSession.requestHop({
      url: "http://shop.vendor.tld/",
      purpose: "page",
    })),
    200,
  );

  runtimeHarness({
    lookup: () => [{ address: secondaryPublicAddress, family: 4 }],
    routes: new Map([[secondaryPublicAddress, { physicalPort: overflowPort }]]),
  });
  const overflowSession = createSession(
    t,
    configWith([[ ["limits", "http", "headerBytes"], 256 ]]),
  );
  await expectTransportError(
    () => overflowSession.requestHop({
      url: "http://shop.vendor.tld/",
      purpose: "page",
    }),
    "HTTP_RESPONSE_LIMIT_EXCEEDED",
  );
});

test("rejects response bodies from the head before reading or decompressing", async (t) => {
  const rejectedBody = Buffer.from("not-gzip".repeat(32));
  const observedHeads: Array<{ readonly statusCode: number; readonly url: string }> = [];
  const server = createHttpServer((request, response) => {
    response.setHeader("content-type", "text/html");
    response.setHeader("content-encoding", "gzip");

    if (request.url === "/denied") {
      response.statusCode = 403;
    }

    response.end(rejectedBody);
  });
  const port = await listenOnLoopback(t, server);
  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([[primaryPublicAddress, { physicalPort: port }]]),
  });
  const session = createSession(
    t,
    configWith([
      [["limits", "http", "htmlCompressedBytesPerPage"], 32],
      [["limits", "http", "htmlDecompressedBytesPerPage"], 64],
    ]),
  );

  const denied = await session.requestHop({
    url: "http://shop.vendor.tld/denied",
    purpose: "page",
  });
  const declined = await session.requestHop({
    url: "http://shop.vendor.tld/declined",
    purpose: "page",
    acceptBody: (head) => {
      observedHeads.push({ statusCode: head.statusCode, url: head.url });
      return false;
    },
  });

  assert.equal(denied.statusCode, 403);
  assert.equal(denied.body.byteLength, 0);
  assert.equal(declined.statusCode, 200);
  assert.equal(declined.body.byteLength, 0);
  assert.deepEqual(observedHeads, [{
    statusCode: 200,
    url: "http://shop.vendor.tld/declined",
  }]);
  assert.deepEqual(session.getUsage(), {
    httpRequests: 2,
    retries: 0,
    staticTransferredBytes: 0,
  });
});

test("never reads or decompresses 204 and 205 response bodies", async (t) => {
  const junk = Buffer.from("definitely-not-a-gzip-stream");
  const server = createNetServer((socket) => {
    socket.once("data", (chunk) => {
      const request = chunk.toString("ascii");
      const isNoContent = request.startsWith("GET /no-content ");
      const status = isNoContent
        ? "204 No Content"
        : "205 Reset Content";

      socket.write(
        `HTTP/1.1 ${status}\r\n`
        + "Content-Type: text/html\r\n"
        + "Content-Encoding: gzip\r\n"
        + `Content-Length: ${junk.byteLength}\r\n`
        + "Connection: close\r\n"
        + "\r\n",
      );
      socket.end(junk);
    });
  });
  const port = await listenOnLoopback(t, server);
  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([[primaryPublicAddress, { physicalPort: port }]]),
  });
  const session = createSession(
    t,
    configWith([
      [["limits", "http", "htmlCompressedBytesPerPage"], 4],
      [["limits", "http", "htmlDecompressedBytesPerPage"], 4],
    ]),
  );

  const noContent = await session.requestHop({
    url: "http://shop.vendor.tld/no-content",
    purpose: "page",
  });
  const resetContent = await session.requestHop({
    url: "http://shop.vendor.tld/reset-content",
    purpose: "page",
  });

  assert.equal(noContent.statusCode, 204);
  assert.equal(noContent.body.byteLength, 0);
  assert.equal(resetContent.statusCode, 205);
  assert.equal(resetContent.body.byteLength, 0);
  assert.deepEqual(session.getUsage(), {
    httpRequests: 2,
    retries: 0,
    staticTransferredBytes: 0,
  });
});

test("rejects the non-v1 x-gzip content encoding token", async (t) => {
  const server = createHttpServer((_request, response) => {
    response.setHeader("content-type", "text/html");
    response.setHeader("content-encoding", "x-gzip");
    response.end(gzipSync(Buffer.from("valid gzip payload")));
  });
  const port = await listenOnLoopback(t, server);
  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([[primaryPublicAddress, { physicalPort: port }]]),
  });
  const session = createSession(t, configWith());

  const error = await expectTransportError(
    () => session.requestHop({
      url: "http://shop.vendor.tld/legacy-encoding",
      purpose: "page",
    }),
    "HTTP_DECOMPRESSION_FAILED",
  );

  assert.equal(error.retryable, false);
  assert.equal(session.getUsage().staticTransferredBytes, 0);
});

test("collects a valid body delivered across many small writes", async (t) => {
  const expected = "small writes remain one ordered response body";
  const server = createHttpServer(async (_request, response) => {
    response.setHeader("content-type", "text/html");

    for (const character of expected) {
      response.write(character);
      await delay(1);
    }

    response.end();
  });
  const port = await listenOnLoopback(t, server);
  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([[primaryPublicAddress, { physicalPort: port }]]),
  });
  const session = createSession(t, configWith());

  const response = await session.requestHop({
    url: "http://shop.vendor.tld/chunked",
    purpose: "page",
  });

  assert.equal(bodyBuffer(response).toString("utf8"), expected);
  assert.equal(
    session.getUsage().staticTransferredBytes,
    Buffer.byteLength(expected),
  );
});

test("enforces compressed and decompressed body limits and rejects corrupt gzip", async (t) => {
  const identityServer = createHttpServer((_request, response) => {
    response.setHeader("content-type", "text/html");
    response.end("x".repeat(65));
  });
  const bomb = gzipSync(Buffer.from("y".repeat(128)));
  const gzipServer = createHttpServer((_request, response) => {
    response.setHeader("content-type", "text/html");
    response.setHeader("content-encoding", "gzip");
    response.end(bomb);
  });
  const corruptServer = createHttpServer((_request, response) => {
    response.setHeader("content-type", "text/html");
    response.setHeader("content-encoding", "gzip");
    response.end(Buffer.from("not-a-gzip-stream"));
  });
  const identityPort = await listenOnLoopback(t, identityServer);
  const gzipPort = await listenOnLoopback(t, gzipServer);
  const corruptPort = await listenOnLoopback(t, corruptServer);
  const config = configWith([
    [["limits", "http", "htmlCompressedBytesPerPage"], 64],
    [["limits", "http", "htmlDecompressedBytesPerPage"], 32],
    [["limits", "http", "staticDecompressedBytesPerDomain"], 64],
  ]);

  for (const [address, physicalPort, expectedCode, mustReadBody] of [
    [primaryPublicAddress, identityPort, "HTTP_RESPONSE_LIMIT_EXCEEDED", false],
    [secondaryPublicAddress, gzipPort, "HTTP_RESPONSE_LIMIT_EXCEEDED", true],
  ] as const) {
    runtimeHarness({
      lookup: () => [{ address, family: 4 }],
      routes: new Map([[address, { physicalPort }]]),
    });
    const session = createSession(t, config);
    await expectTransportError(
      () => session.requestHop({
        url: "http://shop.vendor.tld/",
        purpose: "page",
      }),
      expectedCode,
    );
    if (mustReadBody) {
      assert.ok(session.getUsage().staticTransferredBytes > 0);
    }
    session.close();
  }

  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([[primaryPublicAddress, { physicalPort: corruptPort }]]),
  });
  const corruptSession = createSession(t, config);
  await expectTransportError(
    () => corruptSession.requestHop({
      url: "http://shop.vendor.tld/",
      purpose: "page",
    }),
    "HTTP_DECOMPRESSION_FAILED",
  );
});

test("latches a decompressed domain-cap overflow before later body admission", async (t) => {
  const server = createHttpServer((request, response) => {
    response.setHeader("content-type", "text/html");
    response.end(request.url === "/overflow" ? "123456789" : "x");
  });
  const port = await listenOnLoopback(t, server);
  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([[primaryPublicAddress, { physicalPort: port }]]),
  });
  const session = createSession(
    t,
    configWith([
      [["limits", "http", "htmlCompressedBytesPerPage"], 64],
      [["limits", "http", "htmlDecompressedBytesPerPage"], 64],
      [["limits", "http", "staticDecompressedBytesPerDomain"], 8],
    ]),
  );

  await expectTransportError(
    () => session.requestHop({
      url: "http://shop.vendor.tld/overflow",
      purpose: "page",
    }),
    "HTTP_RESPONSE_LIMIT_EXCEEDED",
  );
  const afterOverflow = session.getUsage();

  await expectTransportError(
    () => session.requestHop({
      url: "http://shop.vendor.tld/small",
      purpose: "page",
    }),
    "HTTP_RESPONSE_LIMIT_EXCEEDED",
  );

  assert.equal(afterOverflow.staticTransferredBytes, 9);
  assert.deepEqual(session.getUsage(), {
    httpRequests: 2,
    retries: 0,
    staticTransferredBytes: afterOverflow.staticTransferredBytes,
  });
});

test("charges per-page decoded overflows to the shared domain budget", async (t) => {
  const server = createHttpServer((request, response) => {
    response.setHeader("content-type", "text/html");
    response.end(request.url === "/small" ? "x" : "12345");
  });
  const port = await listenOnLoopback(t, server);
  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([[primaryPublicAddress, { physicalPort: port }]]),
  });
  const session = createSession(
    t,
    configWith([
      [["limits", "http", "htmlCompressedBytesPerPage"], 64],
      [["limits", "http", "htmlDecompressedBytesPerPage"], 4],
      [["limits", "http", "staticDecompressedBytesPerDomain"], 15],
    ]),
  );

  for (const suffix of ["one", "two", "three"]) {
    await expectTransportError(
      () => session.requestHop({
        url: `http://shop.vendor.tld/${suffix}`,
        purpose: "page",
      }),
      "HTTP_RESPONSE_LIMIT_EXCEEDED",
    );
  }

  const afterPageOverflows = session.getUsage();
  assert.equal(afterPageOverflows.staticTransferredBytes, 15);

  await expectTransportError(
    () => session.requestHop({
      url: "http://shop.vendor.tld/small",
      purpose: "page",
    }),
    "HTTP_RESPONSE_LIMIT_EXCEEDED",
  );

  assert.deepEqual(session.getUsage(), {
    httpRequests: 4,
    retries: 0,
    staticTransferredBytes: afterPageOverflows.staticTransferredBytes,
  });
});

test("maps an abruptly closed partial gzip body to a retryable request failure", async (t) => {
  const complete = gzipSync(Buffer.from("partial-gzip-payload".repeat(32)));
  const partial = complete.subarray(0, Math.max(1, Math.floor(complete.length / 2)));
  const server = createNetServer((socket) => {
    socket.once("data", () => {
      socket.write(
        "HTTP/1.1 200 OK\r\n"
        + "Content-Type: text/html\r\n"
        + "Content-Encoding: gzip\r\n"
        + `Content-Length: ${complete.length}\r\n`
        + "Connection: close\r\n"
        + "\r\n",
      );
      socket.end(partial);
    });
  });
  const port = await listenOnLoopback(t, server);
  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([[primaryPublicAddress, { physicalPort: port }]]),
  });
  const session = createSession(t, configWith());

  const error = await expectTransportError(
    () => session.requestHop({
      url: "http://shop.vendor.tld/partial",
      purpose: "page",
    }),
    "HTTP_REQUEST_FAILED",
  );

  assert.equal(error.stage, "http");
  assert.equal(error.retryable, true);
});

test("counts retries atomically and rejects transactions beyond the domain cap", async (t) => {
  const server = createHttpServer((_request, response) => response.end("x"));
  const port = await listenOnLoopback(t, server);
  const harness = runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([[primaryPublicAddress, { physicalPort: port }]]),
  });
  const session = createSession(
    t,
    configWith([[ ["limits", "http", "transactionsPerDomain"], 2 ]]),
  );

  await session.requestHop({
    url: "http://shop.vendor.tld/one",
    purpose: "page",
  });
  await session.requestHop({
    url: "http://shop.vendor.tld/two",
    purpose: "page",
    isRetry: true,
  });
  await expectTransportError(
    () => session.requestHop({
      url: "http://shop.vendor.tld/three",
      purpose: "page",
    }),
    "HTTP_LIMIT_EXCEEDED",
  );

  assert.equal(harness.lookupCalls.length, 2);
  assert.equal(harness.connectCalls.length, 2);
  assert.deepEqual(session.getUsage(), {
    httpRequests: 2,
    retries: 1,
    staticTransferredBytes: 2,
  });
});

test("requires an initial transaction and permits at most one retry for it", async (t) => {
  const server = createHttpServer((_request, response) => response.end("x"));
  const port = await listenOnLoopback(t, server);
  const harness = runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([[primaryPublicAddress, { physicalPort: port }]]),
  });
  const transport = createProtectedHttpTransport(configWith());
  const firstRetrySession = transport.createSession();
  const boundedRetrySession = transport.createSession();
  t.after(() => {
    firstRetrySession.close();
    boundedRetrySession.close();
  });

  await expectTransportError(
    () => firstRetrySession.requestHop({
      url: "http://shop.vendor.tld/retry-first",
      purpose: "page",
      isRetry: true,
    }),
    "HTTP_LIMIT_EXCEEDED",
  );
  assert.deepEqual(firstRetrySession.getUsage(), {
    httpRequests: 0,
    retries: 0,
    staticTransferredBytes: 0,
  });

  await boundedRetrySession.requestHop({
    url: "http://shop.vendor.tld/initial",
    purpose: "page",
  });
  await boundedRetrySession.requestHop({
    url: "http://shop.vendor.tld/retry-one",
    purpose: "page",
    isRetry: true,
  });
  await expectTransportError(
    () => boundedRetrySession.requestHop({
      url: "http://shop.vendor.tld/retry-two",
      purpose: "page",
      isRetry: true,
    }),
    "HTTP_LIMIT_EXCEEDED",
  );

  assert.equal(harness.lookupCalls.length, 2);
  assert.equal(harness.connectCalls.length, 2);
  assert.deepEqual(boundedRetrySession.getUsage(), {
    httpRequests: 2,
    retries: 1,
    staticTransferredBytes: 2,
  });
});

test("counts repeated identical DNS answers only once against DNS limits", async (t) => {
  const server = createHttpServer((_request, response) => response.end("ok"));
  const port = await listenOnLoopback(t, server);
  const repeatedAnswers = [
    { address: primaryPublicAddress, family: 4 },
    { address: primaryPublicAddress, family: 4 },
    { address: primaryPublicAddress, family: 4 },
  ];
  const harness = runtimeHarness({
    lookup: () => repeatedAnswers,
    routes: new Map([[primaryPublicAddress, { physicalPort: port }]]),
  });
  const session = createSession(
    t,
    configWith([
      [["limits", "dns", "recordsPerType"], 1],
      [["limits", "dns", "recordsPerDomain"], 1],
    ]),
  );

  const first = await session.requestHop({
    url: "http://shop.vendor.tld/one",
    purpose: "page",
  });
  const second = await session.requestHop({
    url: "http://shop.vendor.tld/two",
    purpose: "page",
  });

  assert.equal(first.statusCode, 200);
  assert.equal(second.statusCode, 200);
  assert.equal(harness.lookupCalls.length, 2);
  assert.equal(harness.connectCalls.length, 2);
});

test("enforces global and per-origin concurrency without leaking queue slots", async (t) => {
  let active = 0;
  let maximumActive = 0;
  const server = createHttpServer(async (_request, response) => {
    active += 1;
    maximumActive = Math.max(maximumActive, active);
    await delay(30);
    active -= 1;
    response.end("x");
  });
  const port = await listenOnLoopback(t, server);
  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([[primaryPublicAddress, { physicalPort: port }]]),
  });
  const transport = createProtectedHttpTransport(
    configWith([
      [["limits", "concurrency", "globalHttp"], 2],
      [["limits", "concurrency", "perOriginHttp"], 1],
    ]),
  );
  const session = transport.createSession();
  t.after(() => session.close());

  await Promise.all([
    session.requestHop({
      url: "http://a.vendor.tld/one",
      purpose: "page",
    }),
    session.requestHop({
      url: "http://a.vendor.tld/two",
      purpose: "page",
    }),
  ]);
  assert.equal(maximumActive, 1);

  maximumActive = 0;
  await Promise.all([
    session.requestHop({
      url: "http://a.vendor.tld/three",
      purpose: "page",
    }),
    session.requestHop({
      url: "http://b.vendor.tld/four",
      purpose: "page",
    }),
  ]);
  assert.equal(maximumActive, 2);
});

test("aborting an HTTP scheduler waiter never starts a post-abort connection", async (t) => {
  let markHeldRequestStarted: (() => void) | undefined;
  let finishHeldResponse: (() => void) | undefined;
  let markQueuedLookupStarted: (() => void) | undefined;
  let connections = 0;
  let unexpectedRequests = 0;
  const heldRequestStarted = new Promise<void>((resolve) => {
    markHeldRequestStarted = resolve;
  });
  const queuedLookupStarted = new Promise<void>((resolve) => {
    markQueuedLookupStarted = resolve;
  });
  const server = createHttpServer((request, response) => {
    if (request.url === "/hold") {
      finishHeldResponse = () => {
        if (!response.writableEnded) {
          response.end("ok");
        }
      };
      markHeldRequestStarted?.();
      return;
    }

    unexpectedRequests += 1;
    response.end("ok");
  });
  server.on("connection", () => {
    connections += 1;
  });
  const port = await listenOnLoopback(t, server);
  const harness = runtimeHarness({
    lookup: (hostname) => {
      if (hostname === "queued.vendor.tld") {
        markQueuedLookupStarted?.();
      }

      return [{ address: primaryPublicAddress, family: 4 }];
    },
    routes: new Map([[primaryPublicAddress, { physicalPort: port }]]),
  });
  const transport = createProtectedHttpTransport(
    configWith([
      [["limits", "concurrency", "globalHttp"], 1],
      [["limits", "concurrency", "perOriginHttp"], 1],
    ]),
  );
  const heldSession = transport.createSession();
  const queuedController = new AbortController();
  const abortReason = new DOMException(
    "The queued request was aborted.",
    "AbortError",
  );
  const queuedSession = transport.createSession({
    signal: queuedController.signal,
  });
  t.after(() => {
    heldSession.close();
    queuedSession.close();
    finishHeldResponse?.();
  });

  const unhandledRejections: unknown[] = [];
  const onUnhandledRejection = (reason: unknown): void => {
    unhandledRejections.push(reason);
  };
  process.on("unhandledRejection", onUnhandledRejection);
  t.after(() => process.off("unhandledRejection", onUnhandledRejection));

  const heldRequest = heldSession.requestHop({
    url: "http://shop.vendor.tld/hold",
    purpose: "page",
    acceptBody: () => {
      queueMicrotask(() => queuedController.abort(abortReason));
      return false;
    },
  });
  void heldRequest.catch(() => undefined);
  await heldRequestStarted;

  const queuedRequest = queuedSession.requestHop({
    url: "http://queued.vendor.tld/must-not-start",
    purpose: "page",
  });
  const queuedOutcome = queuedRequest.then(
    () => undefined,
    (error: unknown) => error,
  );
  await queuedLookupStarted;
  await waitForImmediate();
  assert.equal(harness.connectCalls.length, 1);
  assert.equal(connections, 1);

  finishHeldResponse?.();

  const queuedError = await queuedOutcome;
  assert.equal(queuedError, abortReason);
  assert.equal(responseStatus(await heldRequest), 200);
  await waitForImmediate();
  await waitForImmediate();

  assert.deepEqual(queuedSession.getUsage(), {
    httpRequests: 1,
    retries: 0,
    staticTransferredBytes: 0,
  });
  assert.equal(harness.lookupCalls.length, 2);
  assert.equal(harness.connectCalls.length, 1);
  assert.equal(connections, 1);
  assert.equal(unexpectedRequests, 0);
  assert.deepEqual(unhandledRejections, []);
});

test("explicit session close aborts in-flight work without reporting a domain deadline", async (t) => {
  let markRequestStarted: (() => void) | undefined;
  const requestStarted = new Promise<void>((resolve) => {
    markRequestStarted = resolve;
  });
  const server = createHttpServer(() => {
    markRequestStarted?.();
  });
  const port = await listenOnLoopback(t, server);
  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([[primaryPublicAddress, { physicalPort: port }]]),
  });
  const session = createSession(t, configWith());
  const request = session.requestHop({
    url: "http://shop.vendor.tld/hang",
    purpose: "page",
  });
  await requestStarted;
  session.close();

  await assert.rejects(
    request,
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.equal(error.name, "AbortError");
      assert.equal(error instanceof ProtectedTransportError, false);
      return true;
    },
  );
});

test("hanging DNS does not occupy HTTP slots needed by an IP-literal request", async (t) => {
  let markLookupStarted: (() => void) | undefined;
  let releaseLookup: ((answers: unknown) => void) | undefined;
  const lookupStarted = new Promise<void>((resolve) => {
    markLookupStarted = resolve;
  });
  const server = createHttpServer((_request, response) => response.end("ok"));
  const port = await listenOnLoopback(t, server);
  const harness = runtimeHarness({
    lookup: () => new Promise<unknown>((resolve) => {
      releaseLookup = resolve;
      markLookupStarted?.();
    }),
    routes: new Map([[primaryPublicAddress, { physicalPort: port }]]),
  });
  const transport = createProtectedHttpTransport(
    configWith([
      [["limits", "concurrency", "globalHttp"], 1],
      [["limits", "concurrency", "perOriginHttp"], 1],
      [["limits", "timeMs", "httpRequest"], 1_000],
    ]),
  );
  const session = transport.createSession();
  t.after(() => session.close());
  const firstDnsRequest = session.requestHop({
    url: "http://one.vendor.tld/",
    purpose: "page",
  });
  void firstDnsRequest.catch(() => undefined);
  await lookupStarted;
  const queuedDnsRequest = session.requestHop({
    url: "http://two.vendor.tld/",
    purpose: "page",
  });
  void queuedDnsRequest.catch(() => undefined);
  await delay(10);
  assert.equal(harness.lookupCalls.length, 1);

  try {
    const literalResponse = await Promise.race([
      session.requestHop({
        url: `http://${primaryPublicAddress}/literal`,
        purpose: "page",
      }),
      delay(200).then(() => {
        assert.fail("The IP-literal request remained blocked behind DNS.");
      }),
    ]);

    assert.notEqual(literalResponse, undefined);
    assert.equal(literalResponse.statusCode, 200);
    assert.equal(harness.lookupCalls.length, 1);
    assert.equal(harness.connectCalls.length, 1);
  } finally {
    session.close();
    releaseLookup?.([{ address: primaryPublicAddress, family: 4 }]);
  }

  const [firstResult, queuedResult] = await Promise.allSettled([
    firstDnsRequest,
    queuedDnsRequest,
  ]);
  assert.equal(firstResult.status, "rejected");
  assert.equal(queuedResult.status, "rejected");

  if (firstResult.status === "rejected") {
    assert.equal(firstResult.reason?.name, "AbortError");
  }

  if (queuedResult.status === "rejected") {
    assert.equal(queuedResult.reason?.name, "AbortError");
  }
});

test("aborting a session destroys pending work and releases resources", async (t) => {
  let socketClosed = false;
  const server = createHttpServer(() => {
    // Keep the response pending until the caller aborts.
  });
  server.on("connection", (socket) => {
    socket.once("close", () => {
      socketClosed = true;
    });
  });
  const port = await listenOnLoopback(t, server);
  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([[primaryPublicAddress, { physicalPort: port }]]),
  });
  const controller = new AbortController();
  const session = createSession(t, configWith(), controller.signal);
  const request = session.requestHop({
    url: "http://shop.vendor.tld/",
    purpose: "page",
  });
  await delay(10);
  controller.abort(new Error("test abort"));

  await assert.rejects(request);
  await delay(10);
  assert.equal(socketClosed, true);
  session.close();
});
