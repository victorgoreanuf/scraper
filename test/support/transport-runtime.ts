import { AsyncLocalStorage } from "node:async_hooks";
import { registerHooks } from "node:module";
import {
  createConnection as createLoopbackConnection,
  isIP as nativeIsIp,
  type Socket,
} from "node:net";

const transportModuleUrl = new URL(
  "../../src/crawl/transport.ts",
  import.meta.url,
).href;
const shimModuleUrl = import.meta.url;

export interface TransportRoute {
  readonly physicalPort: number;
  readonly remoteAddress?: string;
  readonly lateConnectResetErrors?: 1 | 2;
}

export interface TransportLookupCall {
  readonly hostname: string;
  readonly options: {
    readonly all: true;
    readonly order: "verbatim";
  };
}

export interface TransportConnectCall {
  readonly address: string;
  readonly family: 4 | 6;
  readonly port: number;
}

export interface TransportRuntimeHarness {
  readonly lookupCalls: TransportLookupCall[];
  readonly connectCalls: TransportConnectCall[];
}

interface RuntimeOptions {
  readonly lookup: (
    hostname: string,
    callIndex: number,
  ) => unknown | Promise<unknown>;
  readonly routes?: ReadonlyMap<string, TransportRoute>;
}

interface ActiveRuntime extends TransportRuntimeHarness {
  readonly options: RuntimeOptions;
}

interface LookupOptions {
  readonly all: true;
  readonly order: "verbatim";
}

interface ConnectionOptions {
  readonly host?: string;
  readonly port?: number | string;
  readonly family?: number;
}

function connectionResetError(): NodeJS.ErrnoException {
  const error = new Error(
    "The controlled transport peer reset the connection.",
  ) as NodeJS.ErrnoException;
  error.code = "ECONNRESET";
  return error;
}

let hookInstalled = false;
const activeRuntimes = new AsyncLocalStorage<ActiveRuntime>();

export function installTransportRuntimeHook(): void {
  if (hookInstalled) {
    return;
  }

  registerHooks({
    resolve(specifier, context, nextResolve) {
      if (
        context.parentURL === transportModuleUrl
        && (specifier === "node:dns/promises" || specifier === "node:net")
      ) {
        return {
          url: shimModuleUrl,
          shortCircuit: true,
        };
      }

      return nextResolve(specifier, context);
    },
  });
  hookInstalled = true;
}

export function setupTransportRuntime(
  options: RuntimeOptions,
): TransportRuntimeHarness {
  const harness: ActiveRuntime = {
    options,
    lookupCalls: [],
    connectCalls: [],
  };
  activeRuntimes.enterWith(harness);
  return harness;
}

function currentRuntime(): ActiveRuntime {
  const runtime = activeRuntimes.getStore();

  if (runtime === undefined) {
    throw new Error("The transport test runtime was not configured.");
  }

  return runtime;
}

export async function lookup(
  hostname: string,
  options: LookupOptions,
): Promise<unknown> {
  const runtime = currentRuntime();
  runtime.lookupCalls.push({
    hostname,
    options: { all: options.all, order: options.order },
  });
  return runtime.options.lookup(hostname, runtime.lookupCalls.length - 1);
}

export function createConnection(options: ConnectionOptions): Socket {
  const runtime = currentRuntime();
  const address = options.host;
  const port = Number(options.port);
  const family = options.family;

  if (
    address === undefined
    || !Number.isInteger(port)
    || (family !== 4 && family !== 6)
  ) {
    throw new Error("The transport supplied invalid connection options.");
  }

  runtime.connectCalls.push({ address, family, port });
  const route = runtime.options.routes?.get(address);

  if (route === undefined) {
    throw new Error(`No controlled loopback route exists for ${address}.`);
  }

  const socket = createLoopbackConnection({
    host: "127.0.0.1",
    port: route.physicalPort,
  });

  Object.defineProperty(socket, "remoteAddress", {
    configurable: true,
    enumerable: true,
    value: route.remoteAddress ?? address,
  });

  if (route.lateConnectResetErrors !== undefined) {
    socket.once("connect", () => {
      process.nextTick(() => {
        socket.destroy(connectionResetError());
        if (route.lateConnectResetErrors === 2) {
          process.nextTick(() => {
            socket.emit("error", connectionResetError());
          });
        }
      });
    });
  }

  return socket;
}

export const isIP = nativeIsIp;
