import { createHash } from "node:crypto";
import {
  close, constants, fstat, fsync, ftruncate, openSync as nodeOpenSync,
  read, readFileSync, write, type PathLike, type Stats,
} from "node:fs";
import { open as nodeOpen, lstat } from "node:fs/promises";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

/** Only the descriptor operations used by the scanner; no path-based reopen. */
export interface FileHandle {
  readonly fd: number;
  close(): Promise<void>;
  stat(): Promise<Stats>;
  sync(): Promise<void>;
  truncate(length: number): Promise<void>;
  read(buffer: Uint8Array, offset: number, length: number, position: number | null): Promise<{ bytesRead: number }>;
  write(buffer: Uint8Array, offset: number, length: number, position: number | null): Promise<{ bytesWritten: number }>;
}

type WindowsFiles = {
  open(path: string, flags: number, privateCreate: boolean): number;
  protect(fd: number): void;
  isPrivate(fd: number): boolean;
};

let implementation: WindowsFiles | undefined;
function windowsFiles(): WindowsFiles {
  if (implementation !== undefined) return implementation;
  try {
    const require = createRequire(import.meta.url);
    const binaryUrl = new URL(
      `../../.cache/windows-files/${process.arch}/windows-files.node`, import.meta.url,
    );
    const manifest = JSON.parse(readFileSync(new URL("build.json", binaryUrl), "utf8")) as Record<string, unknown>;
    const digest = (bytes: Buffer): string => createHash("sha256").update(bytes).digest("hex");
    if (manifest.schemaVersion !== 1 || manifest.napi !== 8
      || manifest.recipeHash !== digest(readFileSync(new URL("../../scripts/build-windows-files.mjs", import.meta.url)))
      || manifest.node !== process.versions.node || manifest.arch !== process.arch
      || manifest.sourceHash !== digest(readFileSync(new URL("../../native/windows-files.c", import.meta.url)))
      || manifest.binaryHash !== digest(readFileSync(binaryUrl))) {
      throw new Error("Native Windows file support is stale or has changed.");
    }
    implementation = require(fileURLToPath(binaryUrl)) as WindowsFiles;
  } catch (cause) {
    throw new Error("Native Windows file support is unavailable. Run npm run prepare:windows with the pinned Node.js and Visual Studio C++ Build Tools.", { cause });
  }
  return implementation;
}

function localPath(path: PathLike): string {
  return resolve(path instanceof URL ? fileURLToPath(path) : path.toString());
}

const closeDescriptor = promisify(close);
const statDescriptor = promisify(fstat);
const syncDescriptor = promisify(fsync);
const truncateDescriptor = promisify(ftruncate);

class WindowsFileHandle implements FileHandle {
  #closePromise: Promise<void> | undefined;
  #pendingOperations = 0;
  #resolveDrained: (() => void) | undefined;
  readonly fd: number;
  constructor(fd: number) { this.fd = fd; }
  #checkOpen(): void {
    if (this.#closePromise !== undefined) {
      throw Object.assign(new Error("File descriptor is closed."), { code: "EBADF" });
    }
  }
  async #run<T>(operation: () => Promise<T>): Promise<T> {
    this.#checkOpen();
    this.#pendingOperations += 1;
    try {
      return await operation();
    } finally {
      this.#pendingOperations -= 1;
      if (this.#pendingOperations === 0) {
        const resolveDrained = this.#resolveDrained;
        this.#resolveDrained = undefined;
        resolveDrained?.();
      }
    }
  }
  close(): Promise<void> {
    if (this.#closePromise === undefined) {
      const drained = this.#pendingOperations === 0
        ? Promise.resolve()
        : new Promise<void>((resolve) => { this.#resolveDrained = resolve; });
      this.#closePromise = drained.then(() => closeDescriptor(this.fd));
    }
    return this.#closePromise;
  }
  stat(): Promise<Stats> {
    return this.#run(() => statDescriptor(this.fd));
  }
  sync(): Promise<void> {
    return this.#run(() => syncDescriptor(this.fd));
  }
  truncate(length: number): Promise<void> {
    return this.#run(() => truncateDescriptor(this.fd, length));
  }
  read(buffer: Uint8Array, offset: number, length: number, position: number | null): Promise<{ bytesRead: number }> {
    return this.#run(() => new Promise((resolve, reject) => {
      read(this.fd, buffer, offset, length, position, (error, bytesRead) => {
        if (error !== null) reject(error);
        else resolve({ bytesRead });
      });
    }));
  }
  write(buffer: Uint8Array, offset: number, length: number, position: number | null): Promise<{ bytesWritten: number }> {
    return this.#run(() => new Promise((resolve, reject) => {
      write(this.fd, buffer, offset, length, position, (error, bytesWritten) => {
        if (error !== null) reject(error);
        else resolve({ bytesWritten });
      });
    }));
  }
}

export function openSync(path: PathLike, flags: number): number {
  if (process.platform !== "win32") return nodeOpenSync(path, flags);
  return windowsFiles().open(localPath(path), flags, false);
}

export async function open(path: PathLike, flags: number, mode?: number): Promise<FileHandle> {
  if (process.platform !== "win32") return nodeOpen(path, flags, mode);
  const creating = (flags & constants.O_CREAT) !== 0;
  if (creating && mode !== 0o600) throw new Error("Safe output creation requires private file permissions.");
  const handle = new WindowsFileHandle(windowsFiles().open(localPath(path), flags, creating));
  try {
    if (creating && !windowsFiles().isPrivate(handle.fd)) {
      throw new Error("The filesystem did not preserve the private Windows ACL.");
    }
    return handle;
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
}

/** Apply only after validation, before writing through an existing result handle. */
export function protectPrivate(handle: FileHandle): void {
  if (process.platform === "win32") {
    windowsFiles().protect(handle.fd);
    if (!windowsFiles().isPrivate(handle.fd)) throw new Error("The file ACL is not private.");
  }
}

/** Checks actual Windows DACL/owner, or the POSIX private file mode. */
export async function isPrivateFile(path: PathLike): Promise<boolean> {
  if (process.platform !== "win32") {
    const stats = await lstat(path);
    return stats.isFile() && (stats.mode & 0o777) === 0o600;
  }
  const handle = await open(path, constants.O_RDONLY);
  try { return windowsFiles().isPrivate(handle.fd); }
  finally { await handle.close(); }
}
