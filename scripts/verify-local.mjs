import { spawn, execFileSync } from 'node:child_process';
import { createWriteStream, lstatSync, mkdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { childEnvironment, overallStatus, printChecks, projectRoot, runDoctor, sha256, writeReport } from './doctor.mjs';

function sourceIdentity(reportRoot) {
  const names = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
    { cwd: projectRoot, encoding: 'utf8', windowsHide: true, timeout: 15_000, maxBuffer: 8 * 1024 * 1024 }).split('\0').filter(Boolean);
  const excluded = /^(?:node_modules|dist|coverage|\.runtime|\.git|output|test-results|playwright-report|\.cache|tmp)(?:\/|$)/;
  const reportRelative = relative(projectRoot, reportRoot);
  const reportsInsideRepository = reportRelative !== '' && reportRelative !== '..' && !reportRelative.startsWith('..' + sep) && !/^(?:[A-Za-z]:|\/)/.test(reportRelative);
  const files = [...new Set(names)].filter(name => {
    const fromReports = relative(reportRoot, join(projectRoot, name));
    const inReports = fromReports === '' || (!fromReports.startsWith('..' + sep) && fromReports !== '..' && !/^(?:[A-Za-z]:|\/)/.test(fromReports));
    return !excluded.test(name) && name !== 'input/domains.parquet' && !(reportsInsideRepository && inReports);
  }).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))).map(path => {
    const absolute = join(projectRoot, path);
    let stats;
    try { stats = lstatSync(absolute); } catch (error) {
      if (error.code === 'ENOENT') return { path, state: 'deleted' };
      throw error;
    }
    if (!stats.isFile() || stats.isSymbolicLink()) throw new Error('Source identity requires regular files: ' + path);
    return { path, sha256: sha256(readFileSync(absolute)) };
  });
  const revision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: projectRoot, encoding: 'utf8', timeout: 10_000, windowsHide: true }).trim();
  return { revision, digest: 'sha256:' + sha256(JSON.stringify(files)), files,
    excludes: ['dependencies', 'build/generated outputs', 'runtime installation', 'local challenge input', 'Git-ignored files', reportRoot] };
}

function stopStep(child) {
  if (!child.pid) return;
  if (process.platform === 'win32') {
    try { execFileSync('taskkill.exe', ['/pid', String(child.pid), '/t', '/f'], { windowsHide: true, timeout: 10_000, stdio: 'ignore' }); }
    catch { child.kill(); }
  } else {
    try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
  }
}

function runStep(name, npmCli, environment, outputDirectory) {
  const logPath = join(outputDirectory, name + '.log');
  console.log('Running ' + name + '; log: ' + logPath);
  return new Promise(resolveStep => {
    const startedAt = Date.now();
    const log = createWriteStream(logPath, { flags: 'wx', mode: 0o600 });
    let tail = '';
    let partialLine = '';
    const skippedTests = [];
    let launchError;
    let timedOut = false;
    const child = spawn(process.execPath, [npmCli, 'run', name], {
      cwd: projectRoot, env: environment, windowsHide: true, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'],
    });
    const receive = chunk => {
      log.write(chunk);
      const text = chunk.toString();
      tail = (tail + text).slice(-128 * 1024);
      const lines = (partialLine + text).split(/\r?\n/);
      partialLine = lines.pop();
      for (const line of lines) if (/# SKIP\b/i.test(line)) skippedTests.push(line);
    };
    child.stdout.on('data', receive);
    child.stderr.on('data', receive);
    child.on('error', error => { launchError = error.message; });
    log.on('error', error => { launchError = 'Could not save log: ' + error.message; stopStep(child); });
    const timer = setTimeout(() => { timedOut = true; stopStep(child); }, 10 * 60_000);
    const progress = setInterval(() => console.log('Still running ' + name + ' (' + Math.round((Date.now() - startedAt) / 1000) + ' s).'), 30_000);
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      clearInterval(progress);
      log.end(() => {
        const counts = {};
        for (const key of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
          const pattern = new RegExp('(?:^|\\n)(?:#|ℹ)\\s+' + key + '\\s+(\\d+)\\s*(?:\\n|$)', 'g');
          for (const match of tail.matchAll(pattern)) counts[key] = Number(match[1]);
        }
        resolveStep({ id: name, status: code === 0 && !launchError && !timedOut ? 'PASS' : 'FAIL',
          detail: launchError ?? (timedOut ? 'Exceeded the 10-minute local step limit.' : 'Exit code ' + code + (signal ? '; signal ' + signal : '')),
          command: [process.execPath, npmCli, 'run', name], logPath, exitCode: code, elapsedMs: Date.now() - startedAt,
          ...(name === 'test' ? { counts, skippedTests } : {}) });
      });
    });
  });
}

try {
  const args = process.argv.slice(2);
  if (args.includes('--help')) console.log('Usage: npm run verify:local -- [--output-dir <directory>] [--dry-run]\nRuns doctor, build, typecheck and the full test suite locally, saving logs and JSON. No CI, downloads or system changes. --dry-run only checks prerequisites and records planned steps.');
  else {
    let reportRoot = join(projectRoot, 'output/work/local-verification');
    let dryRun = false;
    for (let index = 0; index < args.length; index++) {
      if (args[index] === '--dry-run') dryRun = true;
      else if (args[index] === '--output-dir' && args[index + 1]) reportRoot = resolve(args[++index]);
      else throw new Error('Unknown or incomplete argument: ' + args[index]);
    }
    // Preserve previous evidence. Every run gets its own directory.
    const outputDirectory = join(reportRoot, new Date().toISOString().replace(/[:.]/g, '-') + '-' + process.pid);
    mkdirSync(outputDirectory, { recursive: true });
    const doctor = await runDoctor();
    printChecks(doctor.checks);
    writeReport(join(outputDirectory, 'doctor.json'), doctor);
    const checks = [];
    let sources;
    try { sources = sourceIdentity(reportRoot); checks.push({ id: 'source-identity', status: 'PASS', detail: sources.digest }); }
    catch (error) { checks.push({ id: 'source-identity', status: 'BLOCKED', detail: error.message }); }
    const steps = [];
    const prerequisites = doctor.checks.filter(x => ['node', 'npm', 'typescript-native', 'native-windows-files'].includes(x.id) || x.id.startsWith('dependency:'));
    if (dryRun) checks.push({ id: 'execution', status: 'NOT_APPLICABLE', detail: 'Dry run: build, typecheck and tests were not executed.' });
    else if (prerequisites.some(x => x.status !== 'PASS' && x.status !== 'NOT_APPLICABLE')) checks.push({ id: 'execution', status: 'BLOCKED', detail: 'Prepare the pinned runtime, dependencies and platform file support before running verification.' });
    else {
      for (const name of ['build', 'typecheck', 'test']) steps.push(await runStep(name, doctor.tools.npmCli, childEnvironment(doctor), outputDirectory));
      const tests = steps.find(step => step.id === 'test');
      if (!Number.isInteger(tests?.counts.tests) || tests.counts.tests < 1) {
        checks.push({ id: 'test-summary', status: 'BLOCKED', detail: 'No complete test count could be read. Inspect test.log.' });
      }
      if (tests?.counts.skipped) {
        const knownFifo = process.platform === 'win32' && tests.counts.skipped === 1 && tests.skippedTests.length === 1
          && tests.skippedTests[0].includes('rejects non-regular config and input files without blocking');
        checks.push({ id: 'omitted-tests', status: knownFifo ? 'NOT_APPLICABLE' : 'BLOCKED',
          detail: knownFifo ? 'The single omitted test uses POSIX mkfifo, which does not apply to Windows.'
            : tests.counts.skipped + ' tests were omitted. Review individual reasons in test.log before claiming complete verification.' });
      }
      if (sources) {
        try {
          const after = sourceIdentity(reportRoot);
          checks.push({ id: 'sources-unchanged', status: after.digest === sources.digest ? 'PASS' : 'FAIL',
            detail: 'Before ' + sources.digest + '; after ' + after.digest });
        } catch (error) { checks.push({ id: 'sources-unchanged', status: 'BLOCKED', detail: error.message }); }
      }
    }
    const report = { schemaVersion: 1, kind: 'local-verification', generatedAt: new Date().toISOString(),
      mode: dryRun ? 'dry-run' : 'verification', completed: !dryRun && steps.length === 3,
      status: dryRun ? 'NOT_APPLICABLE' : overallStatus([...doctor.checks, ...checks, ...steps]),
      platform: doctor.platform, sources, doctor, checks, plannedSteps: ['npm run build', 'npm run typecheck', 'npm run test'], steps };
    const reportPath = writeReport(join(outputDirectory, 'report.json'), report);
    printChecks([...checks, ...steps]);
    console.log((dryRun ? 'DRY RUN' : report.status) + ': ' + reportPath);
    process.exitCode = dryRun || report.status === 'PASS' ? 0 : 1;
  }
} catch (error) { console.error(error.message); process.exitCode = 1; }
