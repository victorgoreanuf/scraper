import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs, { constants } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, symlink } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test, type TestContext } from "node:test";

import { isPrivateFile, open, openSync } from "../src/platform/files.ts";

async function temporaryDirectory(t: TestContext): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "scraper-platform-files-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

const PRIVATE_CREATE = constants.O_RDWR | constants.O_CREAT | constants.O_EXCL;
const READ_NOFOLLOW = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);

test("safe creation is exclusive and preserves private file access through descriptor operations", async (t) => {
  const directory = await temporaryDirectory(t);
  const path = join(directory, "private.jsonl");
  const handle = await open(path, PRIVATE_CREATE, 0o600);
  try {
    await assert.rejects(open(path, PRIVATE_CREATE, 0o600), { code: "EEXIST" });
    const bytes = Buffer.from("abc");
    assert.equal((await handle.write(bytes, 0, bytes.length, 0)).bytesWritten, 3);
    await handle.truncate(2);
    await handle.sync();
    assert.equal((await handle.stat()).size, 2);
    const readBytes = Buffer.alloc(2);
    assert.equal((await handle.read(readBytes, 0, 2, 0)).bytesRead, 2);
    assert.equal(readBytes.toString(), "ab");
  } finally {
    await handle.close();
  }
  assert.equal(await isPrivateFile(path), true);
  if (process.platform === "win32") {
    const script = [
      "$ErrorActionPreference = 'Stop'",
      "$acl = [System.IO.File]::GetAccessControl($env:SCRAPER_TEST_ACL_PATH)",
      "$sidType = [System.Security.Principal.SecurityIdentifier]",
      "$rules = $acl.GetAccessRules($true, $true, $sidType)",
      "$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
      "[pscustomobject]@{ Current = $current; Owner = $acl.GetOwner($sidType).Value; Protected = $acl.AreAccessRulesProtected; Rules = @($rules | ForEach-Object { [pscustomobject]@{ Sid = $_.IdentityReference.Value; Inherited = $_.IsInherited; Type = $_.AccessControlType.ToString(); Rights = [int]$_.FileSystemRights } }) } | ConvertTo-Json -Depth 4 -Compress",
    ].join("; ");
    const acl = JSON.parse(execFileSync("powershell.exe", [
      "-NoProfile", "-NonInteractive", "-Command", script,
    ], {
      encoding: "utf8",
      env: { ...process.env, SCRAPER_TEST_ACL_PATH: path },
    })) as {
      Current: string;
      Owner: string;
      Protected: boolean;
      Rules: { Sid: string; Inherited: boolean; Type: string; Rights: number }[];
    };
    assert.equal(acl.Owner, acl.Current);
    assert.equal(acl.Protected, true);
    assert.ok(acl.Rules.some((rule) => rule.Sid === acl.Current && rule.Rights === 0x1f01ff));
    for (const rule of acl.Rules) {
      assert.equal(rule.Inherited, false);
      assert.equal(rule.Type, "Allow");
      assert.ok([acl.Current, "S-1-5-18", "S-1-5-32-544"].includes(rule.Sid));
    }
  }
});

test("safe open rejects a final directory link without following it", async (t) => {
  const directory = await temporaryDirectory(t);
  const target = join(directory, "target");
  const alias = join(directory, "alias");
  await mkdir(target);
  await symlink(target, alias, process.platform === "win32" ? "junction" : "dir");
  await assert.rejects(open(alias, READ_NOFOLLOW), { code: "ELOOP" });
  assert.throws(() => openSync(alias, READ_NOFOLLOW), { code: "ELOOP" });
});

test("Windows close waits for admitted operations and closes once after success or failure", {
  skip: process.platform !== "win32" ? "Windows descriptor adapter lifecycle; POSIX uses Node FileHandle." : false,
}, async (t) => {
  const directory = await temporaryDirectory(t);
  for (const failure of [false, true]) {
    let closeCalls = 0;
    const releaseWrites: (() => void)[] = [];
    const originalClose = fs.close;
    const originalWrite = fs.write;
    const closeMock = t.mock.method(fs, "close", (
      fd: number,
      callback: (error: NodeJS.ErrnoException | null) => void,
    ) => {
      closeCalls += 1;
      originalClose(fd, callback);
    });
    const writeMock = t.mock.method(fs, "write", (
      fd: number,
      buffer: Uint8Array,
      offset: number,
      length: number,
      position: number | null,
      callback: (error: NodeJS.ErrnoException | null, bytesWritten: number, buffer: Uint8Array) => void,
    ) => {
      let released = false;
      releaseWrites.push(() => {
        if (released) return;
        released = true;
        if (failure) callback(Object.assign(new Error("Injected write failure"), { code: "EIO" }), 0, buffer);
        else originalWrite(fd, buffer, offset, length, position, callback);
      });
    });
    syncBuiltinESMExports();
    const isolated = await import(new URL(
      "../src/platform/files.ts?close-test=" + String(failure), import.meta.url,
    ).href) as typeof import("../src/platform/files.ts");
    const path = join(directory, failure ? "failed.txt" : "successful.txt");
    const handle = await isolated.open(path, PRIVATE_CREATE, 0o600);
    const operations: Promise<{ bytesWritten: number }>[] = [];
    try {
      const bytes = Buffer.from("pending write");
      operations.push(
        handle.write(bytes, 0, 7, 0),
        handle.write(bytes, 7, bytes.length - 7, 7),
      );
      const outcomes = operations.map((operation) => operation.then(
        (value) => ({ ok: true as const, value }),
        (error: unknown) => ({ ok: false as const, error }),
      ));
      const closing = handle.close();
      assert.strictEqual(handle.close(), closing);
      assert.equal(closeCalls, 0);
      assert.equal(releaseWrites.length, 2);
      await assert.rejects(handle.stat(), { code: "EBADF" });
      await assert.rejects(handle.sync(), { code: "EBADF" });
      await assert.rejects(handle.truncate(0), { code: "EBADF" });
      await assert.rejects(handle.read(bytes, 0, bytes.length, 0), { code: "EBADF" });
      await assert.rejects(handle.write(bytes, 0, bytes.length, 0), { code: "EBADF" });
      assert.equal(closeCalls, 0);
      releaseWrites[0]!();
      await outcomes[0];
      assert.equal(closeCalls, 0);
      releaseWrites[1]!();
      for (const result of await Promise.all(outcomes)) {
        assert.equal(result.ok, !failure);
        if (!result.ok) assert.equal((result.error as NodeJS.ErrnoException).code, "EIO");
      }
      await closing;
      assert.equal(closeCalls, 1);
      assert.strictEqual(handle.close(), closing);
      assert.equal(await readFile(path, "utf8"), failure ? "" : bytes.toString());
    } finally {
      releaseWrites.forEach((release) => release());
      await Promise.allSettled(operations);
      await handle.close().catch(() => undefined);
      closeMock.mock.restore();
      writeMock.mock.restore();
      syncBuiltinESMExports();
    }
  }
});
