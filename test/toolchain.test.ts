import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";

type DevEngine = {
  name: string;
  version: string;
  onFail: "error" | "warn" | "ignore";
};

type PackageManifest = {
  name: string;
  version: string;
  private: boolean;
  type: string;
  license: string;
  packageManager: string;
  engines: {
    node: string;
  };
  devEngines: {
    runtime: DevEngine;
    packageManager: DevEngine;
  };
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  scripts: Record<string, string>;
};

type LockedPackage = {
  name?: string;
  version?: string;
  engines?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  resolved?: string;
  integrity?: string;
};

type PackageLock = {
  name: string;
  version: string;
  lockfileVersion: number;
  packages: Record<string, LockedPackage>;
};

const projectRoot = process.cwd();

function readJson<T>(fileName: string): T {
  const contents = readFileSync(resolve(projectRoot, fileName), "utf8");

  return JSON.parse(contents) as T;
}

function readManifest(): PackageManifest {
  return readJson<PackageManifest>("package.json");
}

test("runs with the repository-pinned Node.js version", () => {
  const manifest = readManifest();
  const pinnedVersion = readFileSync(
    resolve(projectRoot, ".node-version"),
    "utf8",
  ).trim();

  assert.match(pinnedVersion, /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/);
  assert.equal(process.versions.node, pinnedVersion);
  assert.equal(manifest.engines.node, pinnedVersion);
  assert.deepEqual(manifest.devEngines.runtime, {
    name: "node",
    version: pinnedVersion,
    onFail: "error",
  });
});

test("keeps the npm declarations consistent", () => {
  const manifest = readManifest();
  const prefix = "npm@";

  assert.ok(manifest.packageManager.startsWith(prefix));

  const packageManagerVersion = manifest.packageManager.slice(prefix.length);

  assert.match(
    packageManagerVersion,
    /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/,
  );
  assert.deepEqual(manifest.devEngines.packageManager, {
    name: "npm",
    version: packageManagerVersion,
    onFail: "error",
  });
});

test("keeps direct dependency versions exact", () => {
  const manifest = readManifest();
  const directDependencies = {
    ...manifest.dependencies,
    ...manifest.devDependencies,
  };
  const exactVersion =
    /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

  assert.ok(Object.keys(manifest.dependencies).length > 0);
  assert.ok(Object.keys(manifest.devDependencies).length > 0);

  for (const [packageName, version] of Object.entries(directDependencies)) {
    assert.match(version, exactVersion, `${packageName} must use an exact version`);
  }
});

test("keeps the npm v3 lockfile aligned with the manifest", () => {
  const manifest = readManifest();
  const lock = readJson<PackageLock>("package-lock.json");
  const lockRoot = lock.packages[""];

  assert.ok(lockRoot);
  assert.equal(lock.lockfileVersion, 3);
  assert.equal(lock.name, manifest.name);
  assert.equal(lock.version, manifest.version);
  assert.equal(lockRoot.name, manifest.name);
  assert.equal(lockRoot.version, manifest.version);
  assert.deepEqual(lockRoot.engines, manifest.engines);
  assert.deepEqual(lockRoot.dependencies, manifest.dependencies);
  assert.deepEqual(lockRoot.devDependencies, manifest.devDependencies);

  const directDependencies = {
    ...manifest.dependencies,
    ...manifest.devDependencies,
  };

  for (const [packageName, version] of Object.entries(directDependencies)) {
    const lockedPackage = lock.packages[`node_modules/${packageName}`];

    assert.ok(lockedPackage, `${packageName} must exist in package-lock.json`);
    assert.equal(lockedPackage.version, version);
    assert.match(lockedPackage.resolved ?? "", /^https:\/\//);
    assert.match(lockedPackage.integrity ?? "", /^sha512-/);
  }
});

test("keeps the repository private, ESM, and GPL-3.0-only", () => {
  const manifest = readManifest();

  assert.equal(manifest.private, true);
  assert.equal(manifest.type, "module");
  assert.equal(manifest.license, "GPL-3.0-only");
});

test("builds only application source into dist", () => {
  const manifest = readManifest();
  const buildConfig = readJson<{
    extends: string;
    compilerOptions: { rootDir: string; outDir: string };
    include: string[];
    exclude: string[];
  }>("tsconfig.build.json");

  assert.equal(
    manifest.scripts.clean,
    "node --input-type=module --eval \"import { rmSync } from 'node:fs'; rmSync('dist', { recursive: true, force: true });\"",
  );
  assert.equal(
    manifest.scripts.build,
    "npm run clean && tsc --project tsconfig.build.json",
  );
  assert.equal(buildConfig.extends, "./tsconfig.json");
  assert.deepEqual(buildConfig.compilerOptions, {
    rootDir: "src",
    outDir: "dist",
  });
  assert.deepEqual(buildConfig.include, ["src/**/*.ts"]);
  assert.ok(buildConfig.exclude.includes("test"));
});
