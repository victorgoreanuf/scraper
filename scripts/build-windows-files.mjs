import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
if (process.platform !== 'win32') {
  console.log('Native Windows file support is not applicable on this platform.');
} else {
  if (process.arch !== 'x64') throw new Error('Native Windows support is currently verified for x64 only.');
  const source = join(root, 'native', 'windows-files.c');
  const output = join(root, '.cache', 'windows-files', process.arch);
  const binary = join(output, 'windows-files.node');
  const manifest = join(output, 'build.json');
  const sourceHash = createHash('sha256').update(readFileSync(source)).digest('hex');
  const recipeHash = createHash('sha256').update(readFileSync(fileURLToPath(import.meta.url))).digest('hex');
  const expected = { schemaVersion: 1, sourceHash, recipeHash, node: process.versions.node, arch: process.arch, napi: 8 };
  let previous;
  try { previous = JSON.parse(readFileSync(manifest, 'utf8')); } catch {}
  if (existsSync(binary) && Object.entries(expected).every(([key, value]) => previous?.[key] === value)
      && previous.binaryHash === createHash('sha256').update(readFileSync(binary)).digest('hex')) {
    console.log('Native Windows file support is current.');
  } else {
    mkdirSync(output, { recursive: true });
    const version = `v${process.versions.node}`;
    const cache = join(root, '.cache', 'node-build', version);
    mkdirSync(cache, { recursive: true });
    const base = `https://nodejs.org/dist/${version}/`;
    const response = await fetch(base + 'SHASUMS256.txt');
    if (!response.ok) throw new Error(`Cannot fetch Node checksums: ${response.status}`);
    const checksums = await response.text();
    async function download(name, path) {
      const line = checksums.split(/\r?\n/).find(line => line.trim().split(/\s+/)[1] === name);
      if (!line) throw new Error(`No official checksum for ${name}`);
      const hash = line.trim().split(/\s+/)[0];
      if (existsSync(path) && createHash('sha256').update(readFileSync(path)).digest('hex') === hash) return;
      const result = await fetch(base + name);
      if (!result.ok) throw new Error(`Cannot fetch ${name}: ${result.status}`);
      const bytes = Buffer.from(await result.arrayBuffer());
      if (createHash('sha256').update(bytes).digest('hex') !== hash) throw new Error(`Checksum mismatch for ${name}`);
      writeFileSync(path, bytes);
    }
    const archive = join(cache, 'headers.tar.gz');
    await download(`node-${version}-headers.tar.gz`, archive);
    const library = join(cache, 'node.lib');
    await download('win-x64/node.lib', library);
    execFileSync('tar.exe', ['-xf', archive, '-C', cache], { stdio: 'inherit', windowsHide: true });
    const headers = join(cache, `node-${version}`, 'include', 'node');
    const locator = join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'Microsoft Visual Studio', 'Installer', 'vswhere.exe');
    if (!existsSync(locator)) throw new Error('Windows build requires Visual Studio C++ Build Tools (Desktop development with C++).');
    const installation = execFileSync(locator, ['-utf8', '-latest', '-products', '*', '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'], { encoding: 'utf8', windowsHide: true }).trim();
    if (!installation) throw new Error('Visual Studio C++ compiler component is missing.');
    const developer = join(installation, 'Common7', 'Tools', 'VsDevCmd.bat');
    const command = join(output, 'compile.cmd');
    // Paths are local build inputs, never URLs or CLI-supplied shell fragments.
    for (const path of [developer, output, headers, source, binary, library]) {
      if (/[\r\n"%]/.test(path)) throw new Error('Unsupported characters in native build path.');
    }
    // The batch is ASCII; Unicode paths travel in the Windows environment block.
    writeFileSync(command, [
      '@echo off',
      'call "%SCRAPER_VSDEVCMD%" -no_logo -arch=x64 -host_arch=x64',
      'if errorlevel 1 exit /b %errorlevel%',
      'cd /d "%SCRAPER_BUILDDIR%"',
      'cl.exe /nologo /LD /MD /O2 /W4 /DNAPI_VERSION=8 /DNODE_GYP_MODULE_NAME=windows_files /I"%SCRAPER_HEADERS%" "%SCRAPER_NATIVE_SOURCE%" /link /OUT:"%SCRAPER_NATIVE_BINARY%" "%SCRAPER_NODE_LIBRARY%" advapi32.lib',
      'exit /b %errorlevel%', ''
    ].join('\r\n'), 'ascii');
    execFileSync(process.env.ComSpec || 'cmd.exe', ['/d', '/c', 'call "%SCRAPER_COMPILE_SCRIPT%"'], {
      stdio: 'inherit', windowsHide: true, windowsVerbatimArguments: true,
      env: { ...process.env, SCRAPER_VSDEVCMD: developer, SCRAPER_BUILDDIR: output,
        SCRAPER_HEADERS: headers, SCRAPER_NATIVE_SOURCE: source, SCRAPER_NATIVE_BINARY: binary,
        SCRAPER_NODE_LIBRARY: library, SCRAPER_COMPILE_SCRIPT: command },
    });
    writeFileSync(manifest, JSON.stringify({ ...expected, binaryHash: createHash('sha256').update(readFileSync(binary)).digest('hex') }, null, 2) + '\n');
    console.log('Built native Windows file support.');
  }
}
