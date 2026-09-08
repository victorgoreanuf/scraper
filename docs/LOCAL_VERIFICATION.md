# Local verification on macOS, Linux and Windows

Use the same source revision and working-tree changes on each machine. Node.js
24.19.0 and npm 11.17.0 are pinned in the repository. Install dependencies on each
system with `npm ci`; native TypeScript, browser and Windows adapter binaries
must not be copied between platforms.

## Setup

Run these commands from the project directory after activating the pinned runtime:

```text
npm ci
npm exec -- playwright install chromium
```

- **macOS:** make OpenSSL >=1.1.1 available on PATH or set `OPENSSL_PATH` to its
  executable. The system LibreSSL executable does not satisfy the TLS fixtures.
- **Linux:** use a distribution supported by the locked Playwright release and
  install Chromium's system libraries with
  `npm exec -- playwright install-deps chromium`. This step may require elevated
  privileges. OpenSSL >=1.1.1 and POSIX `mkfifo` must also be available.
- **Windows x64:** follow [Windows setup](WINDOWS.md), including Visual Studio C++
  Build Tools, a supported fixed local filesystem, symbolic-link permissions and
  OpenSSL. Run `npm run prepare:windows` before `doctor` on a fresh checkout.
  Windows ARM64 is not supported by the current native adapter.

Browser prerequisites follow the locked Playwright version; see the
[Playwright browser documentation](https://playwright.dev/docs/browsers).
WSL runs the Linux path and does not validate native Windows support.

For Linux containers, run the scanner as a non-root user and use the
[official Playwright seccomp profile](https://github.com/microsoft/playwright/blob/v1.62.1/utils/docker/seccomp_profile.json)
to permit Chromium's user namespaces. The default Docker profile can block
browser startup even when `doctor` finds the executable and all libraries.
Follow the [Playwright Docker configuration](https://playwright.dev/docs/docker)
and provide sufficient shared memory. Keep the scanner's Chromium sandbox enabled.

## Run and interpret verification

The commands are identical in a POSIX shell, PowerShell and Command Prompt:

```text
npm run doctor
npm run verify:local
```

`doctor` checks the environment and disposable filesystem probes. Its Chromium
check establishes that the executable exists; the tests establish that Chromium
actually launches through the protected transport.

`verify:local` runs doctor, build, typecheck and the full test suite. It preserves
logs and `report.json` in a new directory under `output/work/local-verification/`.
`npm test` explicitly selects Node's built-in TAP reporter so the verifier reads
the same format on all three systems, with test names and omission reasons.
It runs at most two test files concurrently so catalog workers and Chromium do
not compete with every other suite at once on smaller machines or containers.
All tests still run, and scanner timeouts and safety limits are unchanged.

| Result | Meaning |
| --- | --- |
| `PASS` | All applicable checks passed and complete, consistent test counts were recorded. |
| `NOT_APPLICABLE` | A specifically recognized check belongs to another platform. It was not executed. |
| `BLOCKED` | A prerequisite is missing, tests are unexpectedly omitted or TODO, or the test summary is incomplete/inconsistent. |
| `FAIL` | A command or check failed, a test failed/was cancelled, or source contents changed during verification. |

Only these exact platform omissions are accepted, with at most one omitted test:

| Current OS | Test allowed to be `NOT_APPLICABLE` |
| --- | --- |
| Windows | `rejects non-regular config and input files without blocking` (POSIX FIFO) |
| macOS / Linux | `Windows close waits for admitted operations and closes once after success or failure` (Windows descriptor adapter) |

Additional skips remain blocking even when an expected platform skip is present.
Missing symbolic-link privileges, Chromium or OpenSSL are not platform exceptions.
A test process exiting zero is insufficient if tests are TODO or results are missing.

## Evidence across systems

For a compatibility claim, retain a `PASS` report from every claimed OS and
architecture. Compare `sources.revision` and `sources.digest` across reports;
the digest also covers uncommitted, non-ignored source changes. A report's
`platform`, `checks` and `steps` record what actually ran. A Linux container
validates that Linux environment, not native Windows or every Linux distribution.

Unit tests exercise the reporting rules for `darwin`, `linux` and `win32` on
every host. They do not replace execution of the scanner and native filesystem
tests on those systems. Published v0.1.9 benchmark results remain historical;
verification does not rerun the 200-domain benchmark or alter those artifacts.
