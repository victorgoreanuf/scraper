import assert from "node:assert/strict";
import { once } from "node:events";
import {
  request as makeHttpRequest,
  createServer as createHttpServer,
} from "node:http";
import {
  createConnection as createNetConnection,
  createServer as createNetServer,
  type Server,
  type Socket,
} from "node:net";
import { test, type TestContext } from "node:test";
import { setImmediate as waitForImmediate } from "node:timers/promises";

import {
  createDefaultScanConfig,
  parseScanConfig,
  type ScanConfig,
} from "../src/config.ts";
import type {
  ProtectedBrowserProxy,
  ProtectedTransportError,
} from "../src/crawl/transport.ts";
import {
  installTransportRuntimeHook,
  setupTransportRuntime as runtimeHarness,
} from "./support/transport-runtime.ts";

installTransportRuntimeHook();

const transportModule = await import("../src/crawl/transport.ts");
const { createProtectedHttpTransport } = transportModule;

type JsonRecord = Record<string, unknown>;

const userAgent =
  "WebsiteTechScraper/0.1.0 (https://contact.website-tech-scraper.dev/crawler)";
const primaryPublicAddress = "8.8.8.8";
const secondaryPublicAddress = "1.1.1.1";

interface ProxyResponse {
  readonly statusCode: number | null;
  readonly body: Buffer;
  readonly error: unknown | null;
}

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
    assert.fail("The controlled server did not expose an IP socket address.");
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

async function createProxy(
  t: TestContext,
  config: ScanConfig = configWith(),
): Promise<ProtectedBrowserProxy> {
  const proxy = await createProtectedHttpTransport(config).createBrowserProxy();
  t.after(() => proxy.close());
  return proxy;
}

function proxyEndpoint(proxy: ProtectedBrowserProxy): {
  readonly hostname: string;
  readonly port: number;
} {
  const url = new URL(proxy.server);
  return { hostname: url.hostname, port: Number(url.port) };
}

function requestThroughProxy(
  proxy: ProtectedBrowserProxy,
  targetUrl: string,
  method = "GET",
  body?: string,
): Promise<ProxyResponse> {
  const endpoint = proxyEndpoint(proxy);
  const target = new URL(targetUrl);

  return new Promise<ProxyResponse>((resolve) => {
    let settled = false;
    const settle = (result: ProxyResponse): void => {
      if (!settled) {
        settled = true;
        resolve(result);
      }
    };
    const request = makeHttpRequest({
      hostname: endpoint.hostname,
      port: endpoint.port,
      method,
      path: targetUrl,
      agent: false,
      headers: {
        Host: target.host,
        ...(body === undefined
          ? {}
          : { "Content-Length": Buffer.byteLength(body) }),
      },
    });
    request.once("response", (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.once("end", () => {
        settle({
          statusCode: response.statusCode ?? null,
          body: Buffer.concat(chunks),
          error: null,
        });
      });
      response.once("error", (error) => {
        settle({ statusCode: response.statusCode ?? null, body: Buffer.alloc(0), error });
      });
    });
    request.once("error", (error) => {
      settle({ statusCode: null, body: Buffer.alloc(0), error });
    });
    request.end(body);
  });
}

function connectToProxy(proxy: ProtectedBrowserProxy): Promise<Socket> {
  const endpoint = proxyEndpoint(proxy);
  const socket = createNetConnection(endpoint);
  return once(socket, "connect").then(() => socket);
}

async function readUntil(
  socket: Socket,
  marker: string,
): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    const onData = (chunk: Buffer): void => {
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      if (combined.includes(marker)) {
        cleanup();
        resolve(combined);
      }
    };
    const onError = (error: Error): void => {
      cleanup();
      reject(error);
    };
    const onClose = (): void => {
      cleanup();
      reject(new Error("The proxy socket closed before the expected marker."));
    };
    const cleanup = (): void => {
      socket.removeListener("data", onData);
      socket.removeListener("error", onError);
      socket.removeListener("close", onClose);
    };
    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("close", onClose);
  });
}

async function writeRawUntilClose(
  proxy: ProtectedBrowserProxy,
  payload: string,
): Promise<Buffer> {
  const socket = await connectToProxy(proxy);
  return new Promise<Buffer>((resolve) => {
    const chunks: Buffer[] = [];
    let settled = false;
    const settle = (): void => {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolve(Buffer.concat(chunks));
      }
    };
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.once("error", settle);
    socket.once("close", settle);
    socket.write(payload);
  });
}

function assertFailure(
  proxy: ProtectedBrowserProxy,
  code: string,
  stage: string,
): ProtectedTransportError {
  const failure = proxy.getFailure();
  assert.notEqual(failure, null);
  assert.equal(failure?.code, code);
  assert.equal(failure?.stage, stage);
  assert.equal(proxy.getFailureSignal().aborted, true);
  assert.equal(proxy.getFailureSignal().reason, failure);
  return failure as ProtectedTransportError;
}

test("the proxy forwards absolute-form HTTP through a validated pinned address", async (t) => {
  let observedPath = "";
  let observedHost = "";
  let observedUserAgent = "";
  const upstream = createHttpServer((request, response) => {
    observedPath = request.url ?? "";
    observedHost = request.headers.host ?? "";
    observedUserAgent = request.headers["user-agent"] ?? "";
    response.writeHead(200, {
      "Content-Length": "5",
      "X-Upstream": "controlled",
    });
    response.end("hello");
  });
  const upstreamPort = await listenOnLoopback(t, upstream);
  const runtime = runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([
      [primaryPublicAddress, { physicalPort: upstreamPort }],
    ]),
  });
  const proxy = await createProxy(t);
  const server = proxy.server;

  proxy.activateDomain();
  proxy.startPage("p1");
  const targetUrl = "http://shop.vendor.tld/path?q=1";
  proxy.recordRequestAttempt({ pageId: "p1", url: targetUrl, forward: true });
  const response = await requestThroughProxy(proxy, targetUrl);

  assert.equal(response.error, null);
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.toString(), "hello");
  assert.equal(observedPath, "/path?q=1");
  assert.equal(observedHost, "shop.vendor.tld");
  assert.equal(observedUserAgent, userAgent);
  assert.deepEqual(runtime.lookupCalls.map((call) => call.hostname), [
    "shop.vendor.tld",
  ]);
  assert.deepEqual(runtime.connectCalls, [
    { address: primaryPublicAddress, family: 4, port: 80 },
  ]);
  assert.deepEqual(proxy.getUsage(), {
    browserRequests: 1,
    browserTransferredBytes: 5,
  });
  assert.equal(proxy.getFailure(), null);

  await proxy.finishPage("p1");
  await proxy.finishDomain();
  proxy.activateDomain();
  proxy.startPage("p2");
  assert.equal(proxy.server, server);
  assert.deepEqual(proxy.getUsage(), {
    browserRequests: 0,
    browserTransferredBytes: 0,
  });
  await proxy.finishPage("p2");
  await proxy.finishDomain();
});

test("an unapproved authority is rejected before DNS and latches the first failure", async (t) => {
  const runtime = runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
  });
  const proxy = await createProxy(t);
  proxy.activateDomain();
  proxy.startPage("p1");
  const targetUrl = "http://blocked.vendor.tld/";
  proxy.recordRequestAttempt({ pageId: "p1", url: targetUrl, forward: false });

  await requestThroughProxy(proxy, targetUrl);

  const firstFailure = assertFailure(proxy, "BROWSER_PROXY_FAILED", "browser");
  assert.deepEqual(runtime.lookupCalls, []);
  assert.deepEqual(runtime.connectCalls, []);
  assert.throws(
    () => proxy.recordRequestAttempt({ pageId: "p1", url: targetUrl, forward: true }),
    (error) => error === firstFailure,
  );
  await proxy.finishPage("p1");
  await proxy.finishDomain();
});

test("non-boolean forwarding input never grants proxy access", async (t) => {
  const runtime = runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
  });
  const proxy = await createProxy(t);
  proxy.activateDomain();
  proxy.startPage("p1");
  const targetUrl = "http://truthy.vendor.tld/";

  proxy.recordRequestAttempt({
    pageId: "p1",
    url: targetUrl,
    forward: 1,
  } as unknown as Parameters<typeof proxy.recordRequestAttempt>[0]);
  await requestThroughProxy(proxy, targetUrl);

  assertFailure(proxy, "BROWSER_PROXY_FAILED", "browser");
  assert.deepEqual(runtime.lookupCalls, []);
  assert.deepEqual(runtime.connectCalls, []);
  await proxy.finishPage("p1");
  await proxy.finishDomain();
});

test("each admitted HTTP attempt grants exactly one proxy transaction", async (t) => {
  let upstreamRequests = 0;
  const upstream = createHttpServer((_request, response) => {
    upstreamRequests += 1;
    response.writeHead(200, { "Content-Length": "2" });
    response.end("ok");
  });
  const upstreamPort = await listenOnLoopback(t, upstream);
  const runtime = runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([
      [primaryPublicAddress, { physicalPort: upstreamPort }],
    ]),
  });
  const proxy = await createProxy(t);
  proxy.activateDomain();
  proxy.startPage("p1");
  const targetUrl = "http://single-grant.vendor.tld/";
  proxy.recordRequestAttempt({ pageId: "p1", url: targetUrl, forward: true });

  const first = await requestThroughProxy(proxy, targetUrl);
  const second = await requestThroughProxy(proxy, targetUrl);

  assert.equal(first.statusCode, 200);
  assert.equal(first.body.toString(), "ok");
  assert.notEqual(second.statusCode, 200);
  assert.equal(upstreamRequests, 1);
  assert.equal(runtime.lookupCalls.length, 1);
  assert.equal(runtime.connectCalls.length, 1);
  assert.deepEqual(proxy.getUsage(), {
    browserRequests: 1,
    browserTransferredBytes: 2,
  });
  assertFailure(proxy, "BROWSER_PROXY_FAILED", "browser");
  await proxy.finishPage("p1");
  await proxy.finishDomain();
});

test("methods, request bodies, excess headers, and upgrades are rejected before DNS", async (t) => {
  const scenarios = [
    {
      name: "method",
      expectedCode: "BROWSER_PROXY_FAILED",
      config: configWith(),
      payload:
        "POST http://guard.vendor.tld/ HTTP/1.1\r\nHost: guard.vendor.tld\r\nContent-Length: 0\r\n\r\n",
    },
    {
      name: "body",
      expectedCode: "BROWSER_PROXY_FAILED",
      config: configWith(),
      payload:
        "GET http://guard.vendor.tld/ HTTP/1.1\r\nHost: guard.vendor.tld\r\nContent-Length: 1\r\n\r\nx",
    },
    {
      name: "headers",
      expectedCode: "BROWSER_LIMIT_EXCEEDED",
      config: configWith([
        [["limits", "http", "headerFields"], 1],
      ]),
      payload:
        "GET http://guard.vendor.tld/ HTTP/1.1\r\nHost: guard.vendor.tld\r\nX-Extra: rejected\r\n\r\n",
    },
    {
      name: "upgrade",
      expectedCode: "BROWSER_PROXY_FAILED",
      config: configWith(),
      payload:
        "GET http://guard.vendor.tld/ HTTP/1.1\r\nHost: guard.vendor.tld\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    },
  ] as const;

  for (const scenario of scenarios) {
    await t.test(scenario.name, async (subtest) => {
      const runtime = runtimeHarness({
        lookup: () => [{ address: primaryPublicAddress, family: 4 }],
      });
      const proxy = await createProxy(subtest, scenario.config);
      proxy.activateDomain();
      proxy.startPage("p1");
      proxy.recordRequestAttempt({
        pageId: "p1",
        url: "http://guard.vendor.tld/",
        forward: true,
      });

      await writeRawUntilClose(proxy, scenario.payload);

      assertFailure(proxy, scenario.expectedCode, "browser");
      assert.deepEqual(runtime.lookupCalls, []);
      assert.deepEqual(runtime.connectCalls, []);
      await proxy.finishPage("p1");
      await proxy.finishDomain();
    });
  }
});

test("all DNS answers are validated and mixed public/private answers never connect", async (t) => {
  const runtime = runtimeHarness({
    lookup: () => [
      { address: primaryPublicAddress, family: 4 },
      { address: "127.0.0.1", family: 4 },
    ],
  });
  const proxy = await createProxy(t);
  proxy.activateDomain();
  proxy.startPage("p1");
  const targetUrl = "http://mixed.vendor.tld/";
  proxy.recordRequestAttempt({ pageId: "p1", url: targetUrl, forward: true });

  await requestThroughProxy(proxy, targetUrl);

  assertFailure(proxy, "SSRF_MIXED_ADDRESSES", "dns");
  assert.equal(runtime.lookupCalls.length, 1);
  assert.deepEqual(runtime.connectCalls, []);
  await proxy.finishPage("p1");
  await proxy.finishDomain();
});

test("the connected peer must equal the selected validated address", async (t) => {
  const upstream = createNetServer((socket) => socket.end());
  const upstreamPort = await listenOnLoopback(t, upstream);
  const runtime = runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([
      [
        primaryPublicAddress,
        { physicalPort: upstreamPort, remoteAddress: secondaryPublicAddress },
      ],
    ]),
  });
  const proxy = await createProxy(t);
  proxy.activateDomain();
  proxy.startPage("p1");
  const targetUrl = "http://rebound.vendor.tld/";
  proxy.recordRequestAttempt({ pageId: "p1", url: targetUrl, forward: true });

  await requestThroughProxy(proxy, targetUrl);

  assertFailure(proxy, "SSRF_REMOTE_ADDRESS_MISMATCH", "browser");
  assert.equal(runtime.connectCalls.length, 1);
  await proxy.finishPage("p1");
  await proxy.finishDomain();
});

test("finishing a page aborts late DNS work before it can dial", async (t) => {
  const lookupStarted = Promise.withResolvers<void>();
  const lookupResult = Promise.withResolvers<unknown>();
  const runtime = runtimeHarness({
    lookup: () => {
      lookupStarted.resolve();
      return lookupResult.promise;
    },
  });
  const proxy = await createProxy(t);
  proxy.activateDomain();
  proxy.startPage("p1");
  const targetUrl = "http://late.vendor.tld/";
  proxy.recordRequestAttempt({ pageId: "p1", url: targetUrl, forward: true });
  const request = requestThroughProxy(proxy, targetUrl);
  await lookupStarted.promise;

  await proxy.finishPage("p1");
  lookupResult.resolve([{ address: primaryPublicAddress, family: 4 }]);
  await request;
  await waitForImmediate();

  assert.deepEqual(runtime.connectCalls, []);
  assert.equal(proxy.getFailure(), null);
  proxy.startPage("p2");
  await proxy.finishPage("p2");
  await proxy.finishDomain();
});

test("page cleanup remains available after the external domain signal aborts", async (t) => {
  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
  });
  const proxy = await createProxy(t);
  const controller = new AbortController();
  proxy.activateDomain(controller.signal);
  proxy.startPage("p1");

  controller.abort(new DOMException("cancelled", "AbortError"));

  await proxy.finishPage("p1");
  await proxy.finishDomain();
  assert.equal(proxy.getFailure(), null);
});

test("CONNECT is restricted to an approved HTTPS authority and counts downstream tunnel bytes", async (t) => {
  const reply = Buffer.from("encrypted-reply");
  const upstream = createNetServer((socket) => {
    socket.once("data", (chunk) => {
      assert.equal(chunk.toString(), "encrypted-request");
      socket.end(reply);
    });
  });
  const upstreamPort = await listenOnLoopback(t, upstream);
  const runtime = runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([
      [primaryPublicAddress, { physicalPort: upstreamPort }],
    ]),
  });
  const proxy = await createProxy(t);
  proxy.activateDomain();
  proxy.startPage("p1");
  proxy.recordRequestAttempt({
    pageId: "p1",
    url: "https://secure.vendor.tld/page",
    forward: true,
  });

  const client = await connectToProxy(proxy);
  t.after(() => client.destroy());
  client.write(
    "CONNECT secure.vendor.tld:443 HTTP/1.1\r\nHost: secure.vendor.tld:443\r\n\r\n",
  );
  const connectResponse = await readUntil(client, "\r\n\r\n");
  assert.match(connectResponse.toString(), /^HTTP\/1\.1 200 /);
  client.write("encrypted-request");
  const downstream = await readUntil(client, reply.toString());

  assert.equal(downstream.toString(), reply.toString());
  assert.deepEqual(runtime.connectCalls, [
    { address: primaryPublicAddress, family: 4, port: 443 },
  ]);
  assert.deepEqual(proxy.getUsage(), {
    browserRequests: 1,
    browserTransferredBytes: reply.byteLength,
  });
  assert.equal(proxy.getFailure(), null);
  client.destroy();
  await proxy.finishPage("p1");
  await proxy.finishDomain();
});

test("CONNECT rejects any port other than 443 before DNS", async (t) => {
  const runtime = runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
  });
  const proxy = await createProxy(t);
  proxy.activateDomain();
  proxy.startPage("p1");
  proxy.recordRequestAttempt({
    pageId: "p1",
    url: "https://secure.vendor.tld/",
    forward: true,
  });
  const client = await connectToProxy(proxy);
  t.after(() => client.destroy());
  client.write(
    "CONNECT secure.vendor.tld:80 HTTP/1.1\r\nHost: secure.vendor.tld:80\r\n\r\n",
  );
  await once(client, "close");

  assertFailure(proxy, "BROWSER_PROXY_FAILED", "browser");
  assert.deepEqual(runtime.lookupCalls, []);
  assert.deepEqual(runtime.connectCalls, []);
  await proxy.finishPage("p1");
  await proxy.finishDomain();
});

test("finishing a page closes both sides of an active CONNECT tunnel", async (t) => {
  const upstreamConnected = Promise.withResolvers<void>();
  const upstreamClosed = Promise.withResolvers<void>();
  const upstream = createNetServer((socket) => {
    upstreamConnected.resolve();
    socket.once("close", () => upstreamClosed.resolve());
  });
  const upstreamPort = await listenOnLoopback(t, upstream);
  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([
      [primaryPublicAddress, { physicalPort: upstreamPort }],
    ]),
  });
  const proxy = await createProxy(t);
  proxy.activateDomain();
  proxy.startPage("p1");
  proxy.recordRequestAttempt({
    pageId: "p1",
    url: "https://held.vendor.tld/",
    forward: true,
  });
  const client = await connectToProxy(proxy);
  client.write(
    "CONNECT held.vendor.tld:443 HTTP/1.1\r\nHost: held.vendor.tld:443\r\n\r\n",
  );
  await readUntil(client, "\r\n\r\n");
  await upstreamConnected.promise;
  const clientClosed = new Promise<void>((resolve) => {
    client.once("close", () => resolve());
  });

  await proxy.finishPage("p1");
  await Promise.all([clientClosed, upstreamClosed.promise]);

  assert.equal(client.destroyed, true);
  assert.equal(proxy.getFailure(), null);
  proxy.startPage("p2");
  await proxy.finishPage("p2");
  await proxy.finishDomain();
});

test("logical request and downstream byte caps latch stable browser limit failures", async (t) => {
  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
  });
  const requestLimited = await createProxy(
    t,
    configWith([
      [["limits", "browser", "requestsPerPage"], 1],
    ]),
  );
  requestLimited.activateDomain();
  requestLimited.startPage("p1");
  requestLimited.recordRequestAttempt({
    pageId: "p1",
    url: "http://one.vendor.tld/",
    forward: false,
  });
  assert.throws(
    () => requestLimited.recordRequestAttempt({
      pageId: "p1",
      url: "http://two.vendor.tld/",
      forward: false,
    }),
    (error: unknown) =>
      error instanceof transportModule.ProtectedTransportError
      && error.code === "BROWSER_LIMIT_EXCEEDED",
  );
  assertFailure(requestLimited, "BROWSER_LIMIT_EXCEEDED", "browser");
  assert.deepEqual(requestLimited.getUsage(), {
    browserRequests: 1,
    browserTransferredBytes: 0,
  });
  await requestLimited.finishPage("p1");
  await requestLimited.finishDomain();

  const upstream = createHttpServer((_request, response) => {
    response.writeHead(200, { "Content-Length": "5" });
    response.end("12345");
  });
  const upstreamPort = await listenOnLoopback(t, upstream);
  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
    routes: new Map([
      [primaryPublicAddress, { physicalPort: upstreamPort }],
    ]),
  });
  const byteLimited = await createProxy(
    t,
    configWith([
      [["limits", "browser", "transferBytesPerPage"], 4],
      [["limits", "browser", "transferBytesPerDomain"], 4],
    ]),
  );
  byteLimited.activateDomain();
  byteLimited.startPage("p1");
  const targetUrl = "http://bytes.vendor.tld/";
  byteLimited.recordRequestAttempt({ pageId: "p1", url: targetUrl, forward: true });
  await requestThroughProxy(byteLimited, targetUrl);

  assertFailure(byteLimited, "BROWSER_LIMIT_EXCEEDED", "browser");
  assert.deepEqual(byteLimited.getUsage(), {
    browserRequests: 1,
    browserTransferredBytes: 0,
  });
  await byteLimited.finishPage("p1");
  await byteLimited.finishDomain();
});

test("the startup canary proves proxy rejection without reaching its private listener", async (t) => {
  runtimeHarness({
    lookup: () => [{ address: primaryPublicAddress, family: 4 }],
  });
  const proxy = await createProxy(t);
  const canary = await proxy.prepareCanary();

  assert.match(canary.chromiumHostResolverArg, /^--host-resolver-rules=MAP /);
  const response = await requestThroughProxy(proxy, canary.targetUrl);
  assert.equal(response.statusCode, 502);
  assert.equal(response.error, null);
  assert.doesNotThrow(() => canary.verify());
  assert.equal(proxy.getFailure(), null);
  await canary.close();

  proxy.activateDomain();
  proxy.startPage("p1");
  await proxy.finishPage("p1");
  await proxy.finishDomain();
});
