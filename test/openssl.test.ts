import assert from "node:assert/strict";
import { test } from "node:test";

import { resolveOpenSslExecutable } from "./support/openssl.ts";

const currentVersion = "OpenSSL 3.2.3 3 Sep 2024 (Library: OpenSSL 3.2.3 3 Sep 2024)\n";

function unavailable(): never {
  throw Object.assign(new Error("Executable not found"), { code: "ENOENT" });
}

test("OpenSSL discovery preserves an explicit executable path containing spaces", () => {
  const executable = "C:\\Tools with spaces\\openssl.exe";
  const attempted: string[] = [];
  assert.equal(resolveOpenSslExecutable({
    env: { OPENSSL_PATH: executable, ProgramFiles: "C:\\Program Files" },
    platform: "win32",
    readVersion: (candidate) => {
      attempted.push(candidate);
      return currentVersion;
    },
  }), executable);
  assert.deepEqual(attempted, [executable]);
});

test("an invalid explicit OpenSSL path fails without silently selecting another executable", () => {
  const attempted: string[] = [];
  assert.throws(() => resolveOpenSslExecutable({
    env: { OPENSSL_PATH: "C:\\missing executable.exe", ProgramFiles: "C:\\Program Files" },
    platform: "win32",
    readVersion: (candidate) => {
      attempted.push(candidate);
      return candidate === "openssl" ? currentVersion : unavailable();
    },
  }), /OPENSSL_PATH is set/u);
  assert.deepEqual(attempted, ["C:\\missing executable.exe"]);
  assert.throws(() => resolveOpenSslExecutable({
    env: { OPENSSL_PATH: "" },
    readVersion: () => assert.fail("An empty explicit path must not execute anything"),
  }), /OPENSSL_PATH is set/u);
});

test("OpenSSL discovery honors Windows environment variable casing", () => {
  const executable = "C:\\Security tools\\openssl.exe";
  assert.equal(resolveOpenSslExecutable({
    env: { openssl_path: executable },
    platform: "win32",
    readVersion: (candidate) => {
      assert.equal(candidate, executable);
      return currentVersion;
    },
  }), executable);
});

test("a supported OpenSSL on PATH takes precedence over Git installations", () => {
  const attempted: string[] = [];
  assert.equal(resolveOpenSslExecutable({
    env: { ProgramFiles: "C:\\Program Files" },
    platform: "win32",
    readVersion: (candidate) => {
      attempted.push(candidate);
      return currentVersion;
    },
  }), "openssl");
  assert.deepEqual(attempted, ["openssl"]);
});

test("Windows can use Git OpenSSL when PATH is too old and the first Git binary is missing", () => {
  const executable = "C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe";
  const attempted: string[] = [];
  assert.equal(resolveOpenSslExecutable({
    env: { ProgramW6432: "C:\\Program Files", ProgramFiles: "C:\\Program Files" },
    platform: "win32",
    readVersion: (candidate) => {
      attempted.push(candidate);
      if (candidate === "openssl") return "OpenSSL 1.0.2u 20 Dec 2019\n";
      return candidate === executable ? currentVersion : unavailable();
    },
  }), executable);
  assert.deepEqual(attempted, [
    "openssl",
    "C:\\Program Files\\Git\\usr\\bin\\openssl.exe",
    executable,
  ]);
});

test("missing OpenSSL reports the test prerequisite and accepts supported legacy versions", () => {
  assert.throws(() => resolveOpenSslExecutable({
    env: {},
    platform: "linux",
    readVersion: unavailable,
  }), /TLS tests require OpenSSL 1\.1\.1 or newer/u);
  assert.equal(resolveOpenSslExecutable({
    env: {},
    platform: "darwin",
    readVersion: () => "OpenSSL 1.1.1w 11 Sep 2023\n",
  }), "openssl");
  assert.throws(() => resolveOpenSslExecutable({
    env: {},
    platform: "darwin",
    readVersion: () => "LibreSSL 3.3.6\n",
  }), /TLS tests require OpenSSL/u);
});
