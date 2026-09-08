import { execFileSync } from "node:child_process";
import { win32 } from "node:path";

interface OpenSslResolutionOptions {
  readonly env?: NodeJS.ProcessEnv;
  readonly platform?: NodeJS.Platform;
  readonly readVersion?: (executable: string) => string;
}

function environmentValue(
  env: NodeJS.ProcessEnv,
  name: string,
  platform: NodeJS.Platform,
): string | undefined {
  if (platform !== "win32") return env[name];
  const key = Object.keys(env).find((candidate) =>
    candidate.toLowerCase() === name.toLowerCase());
  return key === undefined ? undefined : env[key];
}

function supportedVersion(output: string): boolean {
  const version = /^OpenSSL\s+(\d+)\.(\d+)\.(\d+)(?:[a-z]+)?(?:\s|$)/u.exec(output);
  if (version === null) return false;
  const major = Number(version[1]);
  const minor = Number(version[2]);
  const patch = Number(version[3]);
  return major > 1 || (major === 1 && (minor > 1 || (minor === 1 && patch >= 1)));
}

/** Resolve a test prerequisite without changing the machine's PATH. */
export function resolveOpenSslExecutable(
  options: OpenSslResolutionOptions = {},
): string {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const readVersion = options.readVersion ?? ((executable: string): string =>
    execFileSync(executable, ["version"], {
      encoding: "utf8",
      env,
      stdio: "pipe",
      timeout: 5_000,
      windowsHide: true,
    }));
  const explicit = environmentValue(env, "OPENSSL_PATH", platform);
  const candidates = explicit === undefined ? ["openssl"] : [explicit];
  if (explicit === undefined && platform === "win32") {
    const roots = new Set<string>();
    for (const name of ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"]) {
      const directory = environmentValue(env, name, platform);
      if (directory !== undefined && directory.length > 0) {
        roots.add(win32.join(directory, "Git"));
      }
    }
    const localAppData = environmentValue(env, "LOCALAPPDATA", platform);
    if (localAppData !== undefined && localAppData.length > 0) {
      roots.add(win32.join(localAppData, "Programs", "Git"));
    }
    for (const root of roots) {
      candidates.push(
        win32.join(root, "usr", "bin", "openssl.exe"),
        win32.join(root, "mingw64", "bin", "openssl.exe"),
      );
    }
  }

  let lastFailure: unknown;
  for (const executable of candidates) {
    try {
      if (executable.length === 0) {
        throw new Error("OPENSSL_PATH is empty.");
      }
      if (!supportedVersion(readVersion(executable))) {
        throw new Error("The executable does not report OpenSSL 1.1.1 or newer.");
      }
      return executable;
    } catch (error) {
      lastFailure = error;
    }
  }
  const discoveryAdvice = platform === "win32"
    ? "Add it to PATH, install Git for Windows, or set OPENSSL_PATH to its full executable path."
    : "Add it to PATH or set OPENSSL_PATH to its full executable path.";
  const message = explicit === undefined
    ? `TLS tests require OpenSSL 1.1.1 or newer. ${discoveryAdvice}`
    : "OPENSSL_PATH is set but does not identify a working OpenSSL 1.1.1 or newer executable. Correct it or unset it to allow automatic discovery.";
  throw new Error(message, { cause: lastFailure });
}
