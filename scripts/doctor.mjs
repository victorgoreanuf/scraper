import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { release, tmpdir } from 'node:os';
import { delimiter, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const overallStatus = checks => checks.some(x => x.status === 'FAIL') ? 'FAIL'
  : checks.some(x => x.status === 'BLOCKED') ? 'BLOCKED' : 'PASS';

export function findNpmCli() {
  const runtimeDirectory = dirname(process.execPath);
  const candidates = [process.env.npm_execpath,
    join(runtimeDirectory, 'node_modules/npm/bin/npm-cli.js'),
    resolve(runtimeDirectory, '../lib/node_modules/npm/bin/npm-cli.js')];
  for (const entry of (process.env.PATH ?? '').split(delimiter)) {
    if (!entry) continue;
    candidates.push(join(entry, 'node_modules/npm/bin/npm-cli.js'));
    try { candidates.push(realpathSync(join(entry, 'npm'))); } catch { /* absent */ }
  }
  return candidates.find(x => x && x.endsWith('npm-cli.js') && existsSync(x)) ?? null;
}

function supportedOpenSSL(version) {
  const parsed = /^OpenSSL\s+(\d+)\.(\d+)\.(\d+)(?:[a-z]+)?(?:\s|$)/.exec(version);
  return Boolean(parsed && (Number(parsed[1]) > 1 || Number(parsed[1]) === 1
    && (Number(parsed[2]) > 1 || Number(parsed[2]) === 1 && Number(parsed[3]) >= 1)));
}

export function findOpenSSL() {
  // Explicit overrides are authoritative, including invalid or empty values.
  if (process.env.OPENSSL_PATH !== undefined) return process.env.OPENSSL_PATH;
  const name = process.platform === 'win32' ? 'openssl.exe' : 'openssl';
  const candidates = (process.env.PATH ?? '').split(delimiter).filter(Boolean).map(entry => join(entry, name));
  if (process.platform === 'win32') {
    const bases = [process.env.ProgramW6432, process.env.ProgramFiles, process.env['ProgramFiles(x86)'],
      process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, 'Programs')].filter(Boolean);
    for (const base of bases) {
      for (const suffix of ['Git/usr/bin/openssl.exe', 'Git/mingw64/bin/openssl.exe']) candidates.push(join(base, suffix));
    }
  }
  for (const candidate of new Set(candidates)) {
    if (!existsSync(candidate)) continue;
    try {
      const version = execFileSync(candidate, ['version'], { encoding: 'utf8', timeout: 5_000, windowsHide: true, stdio: 'pipe' });
      if (supportedOpenSSL(version)) return candidate;
    } catch { /* Try the next installed candidate. */ }
  }
  return null;
}

export function childEnvironment(doctor) {
  const environment = { ...process.env, PATH: dirname(process.execPath) + delimiter + (process.env.PATH ?? '') };
  if (doctor.tools.openssl) {
    environment.OPENSSL_PATH = doctor.tools.openssl;
    environment.PATH = dirname(doctor.tools.openssl) + delimiter + environment.PATH;
  }
  return environment;
}

function filesystemChecks(checks) {
  let directory;
  try {
    directory = mkdtempSync(join(tmpdir(), 'scraper-doctor-'));
    const source = join(directory, 'source.txt');
    writeFileSync(source, 'local capability probe\n', { mode: 0o600, flag: 'wx' });
    checks.push({ id: 'temporary-files', status: 'PASS', detail: 'Temporary file creation succeeded.' });
    for (const [id, create, inspect] of [
      ['hardlinks', target => linkSync(source, target), target => lstatSync(target).nlink >= 2],
      ['symlinks', target => symlinkSync(source, target, 'file'), target => lstatSync(target).isSymbolicLink()],
    ]) {
      try {
        const target = join(directory, id);
        create(target);
        if (!inspect(target)) throw new Error('Link identity was not retained.');
        checks.push({ id, status: 'PASS', detail: 'Creation and inspection succeeded.' });
      } catch (error) { checks.push({ id, status: 'BLOCKED', detail: (error.code ?? 'ERROR') + ': ' + error.message }); }
    }
    const mode = lstatSync(source).mode & 0o777;
    checks.push({ id: 'unix-file-mode',
      status: process.platform === 'win32' ? 'NOT_APPLICABLE' : mode === 0o600 ? 'PASS' : 'FAIL',
      detail: 'Observed mode: ' + mode.toString(8) + (process.platform === 'win32'
        ? '. Unix mode bits do not verify Windows ACLs.' : '; expected 600.') });
  } catch (error) { checks.push({ id: 'temporary-files', status: 'BLOCKED', detail: error.message }); }
  finally {
    if (directory) {
      try { rmSync(directory, { recursive: true, force: true, maxRetries: 3 }); }
      catch (error) { checks.push({ id: 'temporary-cleanup', status: 'FAIL', detail: error.message }); }
    }
  }
}


function nativeWindowsCheck(checks) {
  if (process.platform !== 'win32') {
    checks.push({ id: 'native-windows-files', status: 'NOT_APPLICABLE', detail: 'Other systems use the standard Node filesystem implementation.' });
    return;
  }
  if (process.arch !== 'x64') {
    checks.push({ id: 'native-windows-files', status: 'BLOCKED', detail: 'Native Windows file support currently targets x64 only. This architecture has not been validated.' });
    return;
  }
  const directory = join(projectRoot, '.cache/windows-files', process.arch);
  const binary = join(directory, 'windows-files.node');
  try {
    const build = JSON.parse(readFileSync(join(directory, 'build.json'), 'utf8'));
    if (build.node !== process.versions.node || build.arch !== process.arch
      || build.sourceHash !== sha256(readFileSync(join(projectRoot, 'native/windows-files.c')))
      || build.binaryHash !== sha256(readFileSync(binary))) {
      throw new Error('The native build does not match the current source/runtime.');
    }
  } catch (error) {
    checks.push({ id: 'native-windows-files', status: 'BLOCKED', executable: binary,
      detail: 'Run npm run prepare:windows with the pinned Node and Visual Studio C++ Build Tools. ' + error.message });
    return;
  }
  try {
    const code = [
      "import { constants } from 'node:fs';",
      "import { mkdtemp, rm } from 'node:fs/promises';",
      "import { tmpdir } from 'node:os'; import { join } from 'node:path';",
      "import { open, isPrivateFile } from './src/platform/files.ts';",
      "const directory = await mkdtemp(join(tmpdir(), 'scraper-native-doctor-')); let handle;",
      "try { const path = join(directory, 'private.txt');",
      "handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_RDWR, 0o600);",
      "await handle.write(Buffer.from('abc'), 0, 3, 0); await handle.truncate(1); await handle.sync();",
      "const bytes = Buffer.alloc(2); const result = await handle.read(bytes, 0, 2, 0);",
      "if (result.bytesRead !== 1 || bytes[0] !== 97) throw new Error('Native read/write/truncate did not preserve the expected byte.');",
      "await handle.close(); handle = undefined;",
      "if (!await isPrivateFile(path)) throw new Error('Private Windows ACL was not retained.');",
      "console.log('Private ACL, create, write, truncate, read, sync and close succeeded.');",
      "} finally { await handle?.close(); await rm(directory, { recursive: true, force: true }); }",
    ].join('\n');
    const detail = execFileSync(process.execPath, ['--input-type=module', '--eval', code],
      { cwd: projectRoot, encoding: 'utf8', timeout: 15_000, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    checks.push({ id: 'native-windows-files', status: 'PASS', executable: binary, detail });
  } catch (error) {
    checks.push({ id: 'native-windows-files', status: 'FAIL', executable: binary, detail: error.stderr?.toString().trim() || error.message });
  }
}

export async function runDoctor() {
  const manifest = JSON.parse(readFileSync(join(projectRoot, 'package.json'), 'utf8'));
  const checks = [];
  const npmCli = findNpmCli();
  const openssl = findOpenSSL();
  checks.push({ id: 'node', status: process.versions.node === manifest.engines.node ? 'PASS' : 'FAIL',
    detail: process.versions.node + '; required ' + manifest.engines.node, executable: process.execPath });
  let npmVersion = null;
  try {
    if (!npmCli) throw new Error('npm CLI not found. Run this command with the project npm installation.');
    npmVersion = execFileSync(process.execPath, [npmCli, '--version'], { encoding: 'utf8', timeout: 10_000, windowsHide: true }).trim();
    const expected = manifest.packageManager.replace(/^npm@/, '');
    checks.push({ id: 'npm', status: npmVersion === expected ? 'PASS' : 'FAIL',
      detail: npmVersion + '; required ' + expected, executable: npmCli });
  } catch (error) { checks.push({ id: 'npm', status: 'BLOCKED', detail: error.message }); }
  let dependenciesPresent = true;
  for (const [name, expected] of Object.entries({ ...manifest.dependencies, ...manifest.devDependencies })) {
    try {
      const actual = JSON.parse(readFileSync(join(projectRoot, 'node_modules', name, 'package.json'), 'utf8')).version;
      if (actual !== expected) throw new Error(actual + '; required ' + expected);
    } catch (error) {
      dependenciesPresent = false;
      checks.push({ id: 'dependency:' + name, status: 'BLOCKED', detail: 'Run npm ci. ' + error.message });
    }
  }
  if (dependenciesPresent) checks.push({ id: 'dependencies', status: 'PASS', detail: 'All direct dependency versions match package.json.' });
  try {
    const version = execFileSync(process.execPath, [join(projectRoot, 'node_modules/typescript/bin/tsc'), '--version'],
      { encoding: 'utf8', timeout: 15_000, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    checks.push({ id: 'typescript-native', status: 'PASS', detail: version + '; ' + process.platform + '/' + process.arch });
  } catch (error) { checks.push({ id: 'typescript-native', status: 'BLOCKED', detail: 'Reinstall with npm ci, including optional packages. ' + error.message }); }
  try {
    if (!openssl) throw new Error('OpenSSL not found. Set OPENSSL_PATH to its executable or add it to PATH for TLS tests.');
    const version = execFileSync(openssl, ['version'], { encoding: 'utf8', timeout: 10_000, windowsHide: true }).trim();
    const supported = supportedOpenSSL(version);
    checks.push({ id: 'openssl', status: supported ? 'PASS' : 'BLOCKED', executable: openssl,
      detail: version + '; TLS tests require OpenSSL 1.1.1 or newer.' });
  } catch (error) { checks.push({ id: 'openssl', status: 'BLOCKED', detail: error.message }); }
  try {
    const { chromium } = await import(pathToFileURL(join(projectRoot, 'node_modules/playwright/index.mjs')).href);
    const executable = chromium.executablePath();
    const installed = existsSync(executable);
    checks.push({ id: 'chromium-installed', status: installed ? 'PASS' : 'BLOCKED', executable,
      detail: installed ? 'Executable exists; launch and protected transport are verified by tests.'
        : 'Run npm exec -- playwright install chromium. Linux also needs the supported system libraries.' });
  } catch (error) { checks.push({ id: 'chromium-installed', status: 'BLOCKED', detail: error.message }); }
  // Frozen public pins: src/detect/catalog.ts and test/evaluation-calibration.test.ts.
  for (const [id, path, expected] of [
    ['catalog-schema-bytes', 'fingerprints/upstream/webappanalyzer/schema.json', '4dad6720aab3ad69e0727d7aee64d67f334fc5910ff942ca25067e6ae819441e'],
    ['paired-preregistration-bytes', 'shadow-category-ablation.v1.json', 'bf924836872efc40ee30b92ae51eb456d08ce3172b19de25b401be422107f849'],
  ]) {
    try {
      const actual = sha256(readFileSync(join(projectRoot, path)));
      checks.push({ id, status: actual === expected ? 'PASS' : 'FAIL', path, expected, actual,
        detail: actual === expected ? 'Frozen bytes match.' : 'Frozen bytes differ. Inspect line endings/local edits; do not change the digest to hide this mismatch.' });
    } catch (error) { checks.push({ id, status: 'FAIL', detail: error.message }); }
  }
  if (dependenciesPresent && process.versions.node === manifest.engines.node) {
    try {
      const code = "const { createDefaultScanConfig } = await import('./src/config.ts');"
        + "const { loadFingerprintCatalog } = await import('./src/detect/catalog.ts');"
        + "const config = createDefaultScanConfig(" + JSON.stringify('WebsiteTechScraper/' + manifest.version + ' (https://crawler.veridion.com/contact)') + ");"
        + "const catalog = loadFingerprintCatalog(config); console.log(JSON.stringify({ digest: catalog.digest, revision: catalog.revision }));";
      const identity = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '--eval', code],
        { cwd: projectRoot, encoding: 'utf8', timeout: 45_000, windowsHide: true, maxBuffer: 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }));
      checks.push({ id: 'catalog-integrity', status: 'PASS', detail: 'Catalog validates against pinned schema, upstream bytes and corrections.', ...identity });
    } catch (error) { checks.push({ id: 'catalog-integrity', status: 'FAIL', detail: error.stderr?.toString().trim() || error.message }); }
  } else checks.push({ id: 'catalog-integrity', status: 'BLOCKED', detail: 'Requires the pinned runtime and installed dependencies.' });
  nativeWindowsCheck(checks);
  filesystemChecks(checks);
  return { schemaVersion: 1, kind: 'local-environment', generatedAt: new Date().toISOString(), status: overallStatus(checks),
    platform: { os: process.platform, architecture: process.arch, release: release(), node: process.versions.node, npm: npmVersion },
    tools: { node: process.execPath, npmCli, openssl }, checks };
}

export function printChecks(checks) {
  for (const check of checks) console.log('[' + check.status + '] ' + check.id + ': ' + check.detail);
}
export function writeReport(path, report) {
  const destination = resolve(path);
  mkdirSync(dirname(destination), { recursive: true });
  writeFileSync(destination, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  return destination;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.includes('--help')) console.log('Usage: npm run doctor -- [--json] [--output <report.json>]\nChecks prerequisites without downloads or system changes. Missing capabilities produce BLOCKED and exit 1.');
    else {
      let output;
      let json = false;
      for (let index = 0; index < args.length; index++) {
        if (args[index] === '--json') json = true;
        else if (args[index] === '--output' && args[index + 1]) output = args[++index];
        else throw new Error('Unknown or incomplete argument: ' + args[index]);
      }
      const report = await runDoctor();
      if (output) writeReport(output, report);
      if (json) console.log(JSON.stringify(report, null, 2)); else printChecks(report.checks);
      process.exitCode = report.status === 'PASS' ? 0 : 1;
    }
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
