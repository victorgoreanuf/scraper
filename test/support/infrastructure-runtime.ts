import { AsyncLocalStorage } from "node:async_hooks";
import { registerHooks } from "node:module";

const infrastructureModuleUrl = new URL(
  "../../src/crawl/infrastructure.ts",
  import.meta.url,
).href;
const shimModuleUrl = import.meta.url;

export interface InfrastructureResolverOptions {
  readonly timeout?: number;
  readonly tries?: number;
  readonly maxTimeout?: number;
}

export interface InfrastructureResolveCall {
  readonly hostname: string;
  readonly recordType: string;
  readonly resolverIndex: number;
}

export interface InfrastructureRuntimeHarness {
  readonly resolverOptions: InfrastructureResolverOptions[];
  readonly resolveCalls: InfrastructureResolveCall[];
  readonly cancelCalls: number[];
}

interface RuntimeOptions {
  readonly resolve: (
    hostname: string,
    recordType: string,
    callIndex: number,
    resolverIndex: number,
  ) => unknown | Promise<unknown>;
  readonly cancel?: (resolverIndex: number) => void;
}

interface ActiveRuntime extends InfrastructureRuntimeHarness {
  readonly options: RuntimeOptions;
}

let hookInstalled = false;
const activeRuntimes = new AsyncLocalStorage<ActiveRuntime>();

export function installInfrastructureRuntimeHook(): void {
  if (hookInstalled) {
    return;
  }

  registerHooks({
    resolve(specifier, context, nextResolve) {
      if (
        context.parentURL === infrastructureModuleUrl
        && specifier === "node:dns/promises"
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

export async function runWithInfrastructureRuntime<T>(
  options: RuntimeOptions,
  action: (harness: InfrastructureRuntimeHarness) => T | Promise<T>,
): Promise<T> {
  const runtime: ActiveRuntime = {
    options,
    resolverOptions: [],
    resolveCalls: [],
    cancelCalls: [],
  };

  return activeRuntimes.run(runtime, () => action(runtime));
}

function currentRuntime(): ActiveRuntime {
  const runtime = activeRuntimes.getStore();

  if (runtime === undefined) {
    throw new Error("The infrastructure test runtime was not configured.");
  }

  return runtime;
}

export class Resolver {
  readonly #runtime: ActiveRuntime;
  readonly #resolverIndex: number;
  readonly #pending = new Set<{
    readonly reject: (reason: unknown) => void;
  }>();

  constructor(options: InfrastructureResolverOptions = {}) {
    this.#runtime = currentRuntime();
    this.#resolverIndex = this.#runtime.resolverOptions.length;
    this.#runtime.resolverOptions.push(Object.freeze({ ...options }));
    this.#runtime.cancelCalls.push(0);
  }

  resolve(hostname: string, recordType: string): Promise<unknown> {
    const callIndex = this.#runtime.resolveCalls.length;
    this.#runtime.resolveCalls.push(Object.freeze({
      hostname,
      recordType,
      resolverIndex: this.#resolverIndex,
    }));

    return new Promise<unknown>((resolve, reject) => {
      const pending = { reject };
      this.#pending.add(pending);

      void Promise.resolve().then(() =>
        this.#runtime.options.resolve(
          hostname,
          recordType,
          callIndex,
          this.#resolverIndex,
        )).then(
          (value) => {
            if (this.#pending.delete(pending)) {
              resolve(value);
            }
          },
          (error: unknown) => {
            if (this.#pending.delete(pending)) {
              reject(error);
            }
          },
        );
    });
  }

  cancel(): void {
    const calls = this.#runtime.cancelCalls[this.#resolverIndex];

    if (calls === undefined) {
      throw new Error("The infrastructure resolver counter is missing.");
    }

    this.#runtime.cancelCalls[this.#resolverIndex] = calls + 1;
    this.#runtime.options.cancel?.(this.#resolverIndex);

    const error = Object.assign(
      new Error("DNS query cancelled"),
      { code: "ECANCELLED" },
    );
    for (const pending of this.#pending) {
      pending.reject(error);
    }
    this.#pending.clear();
  }
}
