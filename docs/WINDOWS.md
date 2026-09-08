# Local Windows verification

This compatibility revision is scanner **0.1.11**. The published 0.1.9 results remain historical baseline artifacts and must not be resumed with this version. No GitHub workflow is required or included.

## Requirements

- Windows 11 x64 and a fixed local volume with ACL and hard-link support (tested on NTFS).
- The pinned Node.js 24.19.0 and npm 11.17.0.
- Dependencies installed with `npm ci`, including optional native TypeScript packages.
- Chromium from the locked Playwright version: `npm exec -- playwright install chromium`.
- Visual Studio C++ Build Tools with the Desktop development with C++ component, Windows SDK, and `tar.exe` for the Windows file adapter build. The helper is built locally; its source and binary hashes plus exact Node version are checked before loading. macOS/Linux use the existing Node filesystem implementation and do not build this helper.
- OpenSSL >=1.1.1 for development TLS tests. The resolver checks `OPENSSL_PATH`, PATH, and known Git installations on Windows. It does not change global PATH. An explicit invalid `OPENSSL_PATH` fails instead of silently selecting another executable.
- Permission to create symbolic links for the tests which construct them. If Windows denies this capability, verification is **BLOCKED**, even if the functional scanner tests pass. Running only ordinary tests does not establish this guarantee.

The native build downloads headers and the import library for the exact running Node version from nodejs.org and validates them against its published SHA-256 list. It uses the installed Visual Studio compiler. It does not install a compiler or change Windows policies. Cache files live under `.cache/`, which is local and ignored by Git.

## Commands

Open a terminal where `node --version` and `npm --version` show the pinned versions. Commands below work from the project directory.

```text
npm ci
npm exec -- playwright install chromium
npm run prepare:windows
npm run doctor
npm run verify:local
```

`npm run build` and `npm test` also prepare the native Windows adapter before compiling/running tests. Preparation reuses a matching verified binary. `doctor` is read-only apart from disposable probes and its requested report; it never enables Developer Mode or installs system components.

`verify:local` writes a new timestamped directory below `output/work/local-verification/`. To select another local report directory:

```text
npm run verify:local -- --output-dir "output/work/custom-verification"
```

Reports include the source digest, OS and architecture, versions, prerequisites, build/typecheck/test logs and counts. A dry run is explicitly marked as not executed:

```text
npm run verify:local -- --dry-run
```

A PASS applies only to the operations actually listed in that report. A missing capability is not a passed test. The report is not proof of macOS/Linux compatibility, the full 200-domain benchmark, live HTTPS browser coverage, or every possible filesystem.

## File guarantees in this revision

- `.gitattributes` preserves byte-pinned catalog, canonical fixtures and published result files. Hash values are not changed to accommodate CRLF conversions.
- Windows opens regular files with `FILE_FLAG_OPEN_REPARSE_POINT`, rejects final reparse points/directories on the native handle, and passes that same handle into Node through libuv's descriptor bridge. Existing canonical parent directory and descriptor identity checks remain in place.
- New result/summary files receive a protected DACL at creation allowing the current user, SYSTEM and Administrators. The owner must be the current user. Existing result descriptors receive the private DACL after resume validation and before modification. No pathname-based reopen is used to apply this policy.
- Windows appends use explicit byte positions through the validated descriptor. This permits safe truncation for resume/force and preserves the existing prefix, including UTF-8 and partial writes. POSIX retains O_APPEND.
- Summary publication retains exclusive hard-link semantics. There is still no supported cross-process concurrent writer to the same output directory.
- POSIX private permissions and Windows owner/DACL checks are tested according to their actual platform behavior. A Windows stat mode of 0666 is not treated as proof of access permissions.

The supported scope is fixed local volumes and trusted canonical parent directories. The final-component no-follow check is not a new guarantee against every possible concurrent replacement of ancestor directories. UNC shares, removable volumes, alternate data streams and unsupported reparse/cloud placeholders are rejected by the Windows adapter. Wider filesystem support requires separate testing and design.

## Verification limits and later systems

The original POSIX FIFO test is not applicable on Windows; Windows-specific regular-file/reparse cases cover its relevant file types separately. Symbolic-link fixture permissions must be available for a complete test run.

On macOS, obtain the same source revision and locked manifest, then install dependencies locally; do not copy Windows `node_modules`, `.runtime` or `.cache` binaries. Run the same doctor/verify commands and retain a separate report. Linux remains a separate validation step.
