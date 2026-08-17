# Website Technologies Scraper

> Project status: toolchain foundation complete. The crawler and fingerprint catalog have not been implemented yet.

## Goal

Build a batch CLI that reads website domains, identifies the technologies used
by each website, and records a reproducible rule and safely publishable evidence
for every direct detection.

The provided benchmark contains 200 unique domains in a Snappy-compressed Parquet file. Veridion identified 477 technologies across those domains. The project should maximize useful detections while keeping false positives explainable and controlled.

## Required deliverables

- A runnable batch CLI.
- A result file containing the technologies identified for every input domain.
- Evidence and confidence for every direct detection.
- Source code and detection logic.
- A solution explanation and results summary.
- README discussion of limitations, scaling to millions of domains in one to two months, and discovering new technologies.

## Scope

### In scope

- Reading the supplied `root_domain` values from Parquet.
- Normalizing and resolving HTTP/HTTPS targets safely.
- Static HTTP collection: redirects, headers, cookies, HTML, metadata, and resource URLs.
- Browser collection: rendered DOM, selected JavaScript properties, cookies, and network requests.
- Optional infrastructure signals: DNS records and TLS certificate issuer.
- Data-driven technology fingerprints.
- Direct and inferred detections, version extraction, confidence, and evidence.
- Bounded concurrency, timeouts, partial results, incremental output, and resume support.
- A machine-readable run summary.

### Out of scope for the challenge implementation

- A browser extension or graphical interface.
- A public API.
- Microservices, Kubernetes, Kafka, or cloud infrastructure.
- A production database.
- Contact enrichment or lead generation.
- Circumventing authentication, CAPTCHAs, or access controls.

## Architecture principles

1. **Modular monolith:** one CLI application with explicit internal boundaries.
2. **One work unit:** `scanDomain()` is the unit used by both the local batch and a future distributed worker.
3. **Collection and detection are separate:** collectors observe public signals; the detector interprets them.
4. **Fingerprints are data:** technology definitions stay outside the crawler implementation.
5. **Evidence first:** every direct detection retains the rule, locator, and a
   safe matched fragment or an explicit redaction marker.
6. **Failure isolation:** one broken website must not stop the batch.
7. **Streaming by default:** input and output should not require loading the entire dataset into memory.
8. **Bounded resources:** requests, pages, redirects, response sizes, scripts, browser contexts, and time are limited.
9. **No speculative layers:** no service containers, plugin framework, repositories, controllers, or generic utility folders without a current need.

## Planned repository layout

```text
.
├── src/
│   ├── cli.ts
│   ├── config.ts
│   ├── model.ts
│   ├── pipeline.ts
│   ├── input/
│   │   └── parquet.ts
│   ├── crawl/
│   │   ├── target.ts
│   │   ├── transport.ts
│   │   ├── http.ts
│   │   ├── robots.ts
│   │   ├── browser.ts
│   │   └── infrastructure.ts
│   ├── detect/
│   │   ├── catalog.ts
│   │   ├── engine.ts
│   │   ├── pool.ts
│   │   └── worker.ts
│   └── output/
│       ├── writer.ts
│       └── summary.ts
├── fingerprints/
│   ├── upstream/
│   │   └── webappanalyzer/
│   │       ├── schema.json
│   │       ├── categories.json
│   │       └── technologies/
│   │           ├── a.json
│   │           ├── b.json
│   │           └── ...
│   └── custom/
│       └── technologies/
├── test/
│   ├── fixtures/
│   ├── toolchain.test.ts
│   ├── target.test.ts
│   ├── engine.test.ts
│   └── pipeline.test.ts
├── input/
│   └── domains.parquet
├── output/
│   ├── results.jsonl
│   └── results.summary.json
├── AGENTS.md
├── DECISIONS.md
├── README.md
├── LICENSE
├── THIRD_PARTY_NOTICES.md
├── package-lock.json
├── package.json
├── tsconfig.json
├── .node-version
└── .gitignore
```

Only directories needed by the current implementation stage should receive files. Empty folders do not require placeholder files.

## Dependency direction

```text
cli
 └── pipeline
      ├── input
      ├── crawl
      ├── detect
      └── output

crawl  ──> model
detect ──> model + fingerprints
output ──> model
```

Rules:

- `detect` performs no network requests.
- `crawl` does not decide which technologies are present.
- every crawler request path uses the destination checks, limits, and
  cancellation owned by `crawl/transport.ts`;
- `input` and `output` do not know about the chosen browser automation library.
- Lower-level modules never import `cli` or `pipeline`.
- No mutable global state is shared between domain scans.
- No barrel `index.ts` files are added unless they remove real import noise.

## Core work unit

Conceptually, the application revolves around:

```text
scanDomain(domain, runtimeContext) -> DomainResult
```

The runtime context owns immutable configuration, the validated and indexed
fingerprint catalog data, and reusable bounded resources such as the browser and
detector-worker pools. Each detector worker compiles its own RegExp objects
inside its V8 isolate. `scanDomain()` must not know whether the domain came from
a Parquet file or a queue, or whether the result is written to JSONL or a
database.

## Scan lifecycle

```text
Load and validate configuration
        ↓
Load, validate, and index fingerprint data once; compile it per detector worker
        ↓
Stream domains from Parquet
        ↓
Normalize the domain and resolve an allowed canonical target
        ↓
Fetch and apply robots.txt for each top-level authority
        ↓
Collect the entry page with HTTP and the isolated browser
        ↓
Select at most two eligible internal pages deterministically
        ↓
Collect the selected pages, DNS, TLS, scripts, and bounded probes
        ↓
Match direct fingerprints in the isolated detector pool
        ↓
Apply requires / requiresCategory / implies / excludes relationships
        ↓
Sanitize, merge, sort, and write one complete result record
        ↓
Generate run summary
```

## Initial scan policy

The first implemented scan mode is `full`. It is intentionally exhaustive for
the supplied 200-domain benchmark: every eligible page receives both the static
HTTP collector and the browser collector. A future tiered mode is defined in
the scaling section, but it is not another abstraction to implement before the
full-mode benchmark provides measurements.

### Canonical target

Input is a hostname, not a URL. Normalization uses lowercase ASCII/IDNA and
rejects a supplied scheme, path, credentials, port, or IP address. The target
resolver tries these unique candidates in order:

1. `https://domain/`;
2. `https://www.domain/` when the input does not already start with `www.`;
3. `http://domain/`;
4. `http://www.domain/` when applicable.

Top-level requests use `GET`; there is no preliminary `HEAD`. Only HTTP(S) on
ports 80 and 443 is allowed. Every DNS answer, actual connection destination,
and redirect destination is revalidated by the shared SSRF policy. A chain may
contain at most five redirects, and a cross-origin redirect must pass the new
origin's robots policy before the next top-level request.

`401`, `403`, `407`, `451`, a CAPTCHA, or another explicit block is permanent:
the scanner does not retry, open a browser, or try an alias to bypass it.
`429` receives at most one retry with `Retry-After` capped at two seconds, then
ends target resolution without an alias. Other non-denial `4xx` responses move
to the next candidate without retry. `408`, `425`, `5xx`, DNS/connect/timeout,
and TLS failures receive at most one retry and then move to the next candidate.
A redirect-policy, SSRF, or invalid-target rejection is permanent for the
domain. The first final `2xx` response selects the target; a non-HTML response
retains safe HTTP evidence but schedules no pages or browser and becomes
`partial`. HTTP fallback is a separate candidate for sites that genuinely
serve HTTP, never a TLS validation bypass. Every redirect hop and retry consumes
the single HTTP transaction budget.

### Robots and page selection

Before any top-level page or catalog probe, the crawler fetches `/robots.txt`
with the same protected transport and evaluates the relevant
[RFC 9309](https://www.rfc-editor.org/rfc/rfc9309.html) rules for product token
`WebsiteTechScraper`. `robots-parser` supplies grouping and wildcard matching;
a project wrapper first normalizes percent-encoded ASCII-unreserved octets in
both rules and target paths and tests the relevant RFC cases. We do not claim
that the package alone implements every RFC normalization detail.

A complete descriptive user agent with a real contact URL or email is required
before a public run. `404`, `410`, and non-denial `4xx` responses mean no rules;
`401`, `403`, `429`, `5xx`, network failure, limit overflow, or unusable content
is fail-closed for that authority. A 2xx body is decoded as bounded UTF-8;
unknown or malformed lines are ignored while valid lines remain effective. Up
to five robots redirects are allowed. Content reached through a cross-authority
robots redirect still defines rules for the original scheme and authority; it
does not authorize crawling the redirect host.

The parsed policy is cached by scheme, authority, and product token for the
shorter of the run or 24 hours and is also made available to the detector as a
possible fingerprint signal. An explicit homepage disallow ends that candidate
without trying an alias as an evasion. Robots controls crawler-initiated pages
and probes; it is not treated as legal authorization.

The scanner visits at most three top-level pages:

1. the canonical entry page;
2. one discovered product or detail page;
3. one discovered collection, category, shop, or useful content page.

Candidates come only from links observed on the static or rendered entry page;
the crawler does not guess paths or recurse through internal pages. They must
use the exact final origin, have no credentials or query string, pass robots,
and be safe `GET` targets. Authentication, account, admin, cart, checkout,
logout, search, legal/privacy, fragments, files, and duplicates are excluded.
A fixed path-class rank followed by shortest normalized path and UTF-16
code-unit order makes the same entry observation select the same pages. If a
preferred class is absent, the shortest remaining useful internal page fills
the slot.

Catalog probes do not count as pages. At most five unique probes are allowed;
each must be a validated relative path on the exact final origin, contain no
query or fragment, use `GET`, pass robots, and remain inside the separate
request and byte budgets.

### Browser behavior

Every selected 2xx HTML page in `full` mode is rendered in a non-persistent
Chromium context dedicated to that domain. The same context is reused
sequentially for its maximum three pages and then destroyed; only one page is
active at a time. Collection waits for `DOMContentLoaded` and a bounded
two-second settle window, never unbounded `networkidle`.

The browser keeps its sandbox and CSP, has no permissions, blocks service
workers, disables downloads, and never clicks, scrolls, submits forms, accepts
consent, authenticates, or bypasses access controls. `GET`, `HEAD`, and
`OPTIONS` may continue. Other methods and WebSockets are recorded only as
attempted requests, contribute only a hostname observation, and are then
aborted; images, fonts, and media contribute their URL/hostname observations
and are aborted to conserve the budget. Context-wide routing rejects every
popup and every main-frame request or redirect outside the exact selected
origin before network access; same-origin top-level redirects must still pass
robots. Up to 20 bounded script bodies are collected from responses the browser
already fetched, rather than downloaded a second time. Eligible script URLs are
deduplicated and ranked by same-origin first, then page ID and normalized URL in
UTF-16 code-unit order; the fixed top 20 are used, and an unavailable response
is not replaced based on completion timing.

All browser HTTP(S) and CONNECT traffic passes through the project-owned local
forward proxy in `crawl/transport.ts`. The proxy resolves each hostname,
rejects mixed or non-public answers, connects only to the selected public
address on port 80/443, and owns browser request/byte accounting. Chromium is
configured to use the proxy without a bypass, with service workers, QUIC, and
non-proxied WebRTC traffic disabled. Playwright interception is an additional
navigation/method guard, not the SSRF boundary.

Startup launches a loopback canary server and asks the proxied browser to reach
it through a synthetic hostname which both test resolvers map to that canary.
The proxy must record a policy rejection and the canary must receive zero
connections; proxy configuration and required Chromium controls are also
checked. Any failed preflight stops `full` mode before input processing. At
production scale, host/container egress rules also restrict Chromium to the
local proxy. A proxy failure during a domain scan closes the context and yields
a partial result.

## Observation and detection boundaries

Collectors produce normalized observations such as:

- final URL and redirect chain;
- status and response headers;
- cookie names and bounded values retained only in memory for matching;
- bounded HTML and visible text held only in memory during the scan;
- metadata;
- script, stylesheet, image, iframe, and link URLs;
- rendered DOM facts requested by the fingerprint catalog;
- selected JavaScript property paths requested by the catalog;
- network request hostnames;
- DNS records and TLS issuer.

The detector consumes those observations and produces:

- technology name and categories;
- optional version;
- confidence from `0` to `100`;
- `direct` or `inferred` detection type;
- one or more evidence records;
- the pages on which the technology was observed.

The browser collector should receive a generic inspection plan generated from the fingerprint catalog. It should inspect only requested selectors and JavaScript paths, rather than enumerate the entire DOM or `window` object.

## Result and evidence contract v1

The primary output is UTF-8 JSON Lines. Each line is one complete
`DomainResult`; fixed fields are always present, unavailable scalar values are
`null`, and collections are arrays. The logical key is `(runId, domain)`.
`runId` is one UUID generated when a new output starts and reused by resume;
`domain` is canonical lowercase ASCII without a trailing dot.
A representative direct detection is shown below; the eventual TypeScript and
JSON Schema definitions must preserve this contract.

```json
{
  "schemaVersion": 1,
  "runId": "37937a78-f39d-49ed-a51d-6d398ae45a20",
  "domain": "example.com",
  "scannedAt": "2026-08-17T00:00:00.000Z",
  "status": "success",
  "finalUrl": "https://example.com/",
  "scanMode": "full",
  "pages": [
    {
      "id": "p1",
      "role": "entry",
      "url": "https://example.com/",
      "httpStatus": 200,
      "collectors": ["http", "browser"]
    }
  ],
  "technologies": [
    {
      "name": "Example",
      "categories": [{ "id": 6, "name": "JavaScript frameworks" }],
      "version": "1.2.0",
      "confidence": 50,
      "type": "direct",
      "pageIds": ["p1"],
      "evidence": [
        {
          "collector": "http",
          "source": "script_url",
          "pageId": "p1",
          "key": "src",
          "match": {
            "kind": "value",
            "value": "https://cdn.example.com/example-1.2.0.js",
            "truncated": false
          },
          "ruleId": "sha256:...",
          "pattern": "example-([0-9.]+)\\.js",
          "confidence": 50,
          "version": "1.2.0"
        }
      ],
      "inferredFrom": []
    }
  ],
  "errors": [],
  "timings": {
    "totalMs": 912,
    "targetMs": 42,
    "robotsMs": 21,
    "httpMs": 124,
    "dnsMs": 8,
    "tlsMs": 17,
    "browserMs": 731,
    "detectMs": 18
  },
  "usage": {
    "httpRequests": 3,
    "browserRequests": 24,
    "retries": 0,
    "pagesVisited": 1,
    "probesIssued": 0,
    "scriptBodiesInspected": 4,
    "staticTransferredBytes": 18320,
    "browserTransferredBytes": 130000
  },
  "provenance": {
    "scannerVersion": "0.1.0",
    "runtime": {
      "node": "24.19.0",
      "playwright": "1.62.1",
      "chromiumRevision": "..."
    },
    "catalog": {
      "source": "enthec/webappanalyzer",
      "revision": "5e7c47b1d441ded0bd476b252261e87634349f96",
      "digest": "sha256:..."
    },
    "configDigest": "sha256:..."
  }
}
```

Evidence `source` is one of `url`, `header`, `cookie`, `html`, `text`, `css`,
`meta`, `script_url`, `script_content`, `dom`, `javascript`, `network_hostname`,
`dns_record`, `tls_issuer`, `robots`, or `probe`. `collector` is `http`,
`browser`, `dns`, or `tls`; `pageId` is `null` for non-page infrastructure
signals. `key` identifies the header, cookie, metadata name, selector,
JavaScript path, DNS record type, or equivalent locator.

`PageRecord.collectors` lists only collectors which completed for that page;
failures are linked by `pageId`. Error `stage` is one of `target`, `robots`,
`http`, `dns`, `tls`, `browser`, or `detect`. `usage.httpRequests` excludes
browser traffic, while `usage.browserRequests` counts requests admitted or
explicitly aborted by browser policy. Every candidate, robots fetch, redirect
hop, retry, page, and probe which reaches the HTTP transport increments
`httpRequests`; `retries` counts only additional attempts. `pagesVisited` equals
the number of emitted `PageRecord` values, `probesIssued` counts probes which
reach transport, and `scriptBodiesInspected` counts bounded bodies admitted to
detection.

`staticTransferredBytes` counts compressed response-body bytes read by the
protected Node transport. `browserTransferredBytes` counts downstream bytes at
the browser proxy; for HTTPS CONNECT this is conservative encrypted tunnel
traffic, not a claim about decoded response-body size. `scannedAt` is the UTC
wall-clock time at which the domain receives its active slot. `totalMs` and all
seven named stage timings are non-negative integer milliseconds measured with a
monotonic clock; stage times measure active wall time and may overlap, so they
need not sum to total. A skipped or never-started stage is `null`, while a
completed sub-millisecond stage may be `0`. Usage values are non-negative
integers and remain `0` when the corresponding work is skipped.

A direct detection has at least one evidence item and an empty `inferredFrom`
array. An inferred detection has no evidence or page IDs and instead records
one or more `{ technology, ruleId, confidence, version }` parent relationships.
If a technology is both observed and inferred, the direct result wins. A scan
error has `{ stage, code, pageId, retryable, message, ruleId, signal, limit,
catalogRevision }`; the four regex-specific fields are nullable for other
errors and for failures with no active rule. They are `string | null`, with
`signal` using the evidence-source vocabulary and `limit` using a stable value
such as `50ms`. Messages are application controlled and sanitized.

Confidence is deterministic:

- direct confidence is `min(100, sum of unique matched-rule confidence)`;
- matching the same rule on multiple pages does not increase confidence again;
- inferred confidence is the maximum, across valid paths, of the minimum of
  parent confidence and relationship confidence;
- every evidence item retains the version extracted by its rule; a technology
  version is the candidate with the highest sum of unique supporting-rule
  confidence, or `null` when different candidates tie.

`inferredFrom.confidence` is that effective minimum for the recorded parent
edge. Its `ruleId` hashes a canonical tuple of catalog namespace, parent
technology, `implies`, target technology, and the original tagged relationship
value. It is distinct from a direct signal-rule ID. An inferred relationship
also carries `version: string | null` for a safe literal version asserted by its
`implies` tag.

For direct evidence, `ruleId` is SHA-256 over a canonical JSON tuple containing
catalog namespace, technology, signal type, locator, and the original rule
including metadata; it does not depend on a mutable array index. Evidence
`pattern` is the parsed executable regex source without `confidence` or
`version` tags, or `null` for a non-regex presence rule. `p1` is the entry page.
Internal page URLs are canonicalized and sorted before receiving `p2` and `p3`. Evidence is
deduplicated by `(ruleId, collector, source, pageId, key, match.kind,
match.value, version)`. String comparisons use ascending UTF-16 code-unit order
with direct `<`/`>` comparison, never `localeCompare`, and `null` sorts before a
string. Pages sort entry first and then URL; technologies by name; categories by
numeric ID then name; evidence by collector (`http`, `browser`, `dns`, `tls`),
source in the enum order above, page ID, key, rule ID, match kind/value, and
version; inferences by parent technology then rule ID; errors by stage
(`target`, `robots`, `http`, `dns`, `tls`, `browser`, `detect`), code, page ID,
rule ID, then message. Operational timestamps and timings are not promised to
be byte-identical.

Digests have one construction. `catalog.digest` is SHA-256 over the sorted
relative paths and raw bytes of the effective schema, categories, upstream, and
custom fingerprint files; each UTF-8 path and byte payload is prefixed by its
unsigned 64-bit big-endian length. `configDigest` is SHA-256 over UTF-8
`JSON.stringify` of the validated fixed-key configuration object in schema
order. It includes the scan mode, complete user agent, target/robots/page
policy versions, every request/byte/time/candidate limit, sanitizer version,
regex limits, and browser-egress policy; only output paths and log verbosity are
excluded. Digests are lowercase `sha256:<hex>` strings.

### Relationship resolution

Relationships are resolved once per domain from the complete set of raw direct
matches. The semantic compiler requires every technology and category reference
to exist, rejects self-`requires` and self-`excludes`, and treats a self-`implies`
edge as a no-op. Version 1 accepts only `confidence` and a safe literal `version`
tag on `implies`; tags on `requires`, `requiresCategory`, or `excludes`, unknown
tags, duplicate tags, and malformed confidence values reject the catalog.

All entries across `requires` and `requiresCategory` form one OR admission gate.
An ungated raw direct candidate is admitted immediately; a gated candidate is
admitted when another already admitted direct or inferred technology matches at
least one named technology or category. A candidate cannot satisfy its own
gate. Newly admitted candidates and implications are processed to a fixed point,
with each raw direct candidate admitted at most once. The gate is an admission
condition, not an invariant rechecked after exclusions; this preserves the
catalog's specific-variant pattern where an admitted technology can exclude the
base technology which unlocked it.

`implies` uses a multi-source widest-path closure from admitted direct
detections. Relationship confidence defaults to `100` and must be an integer
from `1` through `100`. Path strength is the minimum confidence along the path;
stronger paths win, then fewer hops. `inferredFrom` contains every immediate
parent edge which realizes that winning strength and shortest depth, sorted by
parent name and rule ID. Parent depth must be exactly one less than child depth,
so self edges and cycles cannot create cyclic provenance. A direct detection
always wins over inference. Safe literal versions asserted by winning parent
edges are kept when they agree; conflicting non-null versions produce `null`.

Exclusions run once after admission and implication closure. A unilateral
`A excludes B` edge suppresses `B` when `A` survives; rank cannot reverse that
direction. Resolution operates on exact technology nodes: all zero-incoming
nodes survive, suppress their outgoing targets, and are then removed from the
working graph. Suppressed nodes never apply their own exclusions. If no exact
zero-incoming node remains, each zero-incoming cyclic component keeps one
winner—direct before inferred, then higher confidence, then technology name in
UTF-16 order—and removes its other members before exact-node processing resumes.
This lets an external unilateral edge break a cycle before a tie-break. The
process ends when every candidate is retained or suppressed; suppressed
candidates are neither reintroduced nor emitted. The result is independent of
JSON, page, and worker order.

Finally, implication confidence, version, and provenance are recomputed from
the retained direct detections, with every exclusion-suppressed technology name
forbidden. An inferred detection with no remaining path is pruned; a surviving
inferred detection can reference only emitted parents at a lower depth. This
final pass does not reopen requirement gates, rerun exclusions, or reintroduce
any suppressed candidate. Version conflicts are recalculated from only the
remaining winning paths.

The pinned snapshot contains 2,241 relationship entries, two cyclic `implies`
components, and three cyclic `excludes` components. All current technology and
category references resolve, and its only self-edge is the supported no-op
`implies` case. These policies therefore cover observed catalog data rather
than only hypothetical conflicts.

Evidence redaction is part of the schema contract:

- `match.value` contains only an allowlisted exact sanitized match, never the
  surrounding document, element, script, or header, and is capped at 256
  Unicode code points with deterministic truncation;
- every URL persisted anywhere in results, evidence, errors, or logs uses the
  same sanitizer: userinfo and fragments are removed, query values become
  `[redacted]`, and an opaque or sensitive path segment becomes `[redacted]`;
  a path segment is retained only when it is at most 64 unreserved code units
  and is not a UUID, a hexadecimal token of at least 16 characters, an
  unseparated base64url-like token of at least 24 characters, or adjacent to
  `token`, `key`, `signature`, `session`, `auth`, `password`, `secret`, or
  `code`;
- cookie values are never emitted or hashed; only the cookie name remains and a
  value-dependent match uses `match.kind: "redacted"`;
- request headers are never persisted; sensitive response-header names and
  values, including authorization, cookies, tokens, secrets, signatures, API
  keys, and credentials, are always redacted;
- `value` is allowed only for sanitized URL/hostname signals, DNS names, TLS
  issuer text, or bounded non-sensitive response-header and `generator` /
  `application-name` metadata values which also pass the token classifier;
  HTML, visible text, CSS, script content, DOM values, JavaScript values, probe
  bodies, robots content, cookie values, and unknown classes are redacted by
  default;
- `presence` represents an existence rule, `value` a safe displayed match, and
  `redacted` a real match whose value cannot be disclosed. `presence` and
  `redacted` always use `value: null` and `truncated: false`;
- an extracted version is emitted only from a non-redacted source and only when
  it matches `[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}`; otherwise both the evidence
  version and that technology's candidate version are `null`;
- unknown values fail closed to redaction, and errors never include stack
  traces, response bodies, raw headers, cookies, or unsanitized URLs.

Raw observations are bounded and exist only in memory until detection and
sanitization finish. Version 1 does not persist HTML, DOM, script bodies,
headers, cookies, JavaScript values, network logs, or hashes of secrets.

Allowed domain statuses are:

- `success`: all stages required by the selected mode completed and `errors` is
  empty; zero detections is valid;
- `partial`: at least one bounded signal was admitted to the detector, and at
  least one terminal per-domain error records a required stage failure, timeout,
  or hard limit;
- `failed`: no signal was admitted to the detector, `technologies` is empty,
  and at least one terminal per-domain error is present.

An intentional policy skip is not an error, and a transient attempt which later
succeeds affects usage/retry counters and optional sanitized stderr diagnostics,
not `errors` or the domain status. Only fatal configuration, input, catalog, or
required detector-worker/browser-egress preflight errors stop the run before
domain processing. Other errors are per-domain data; runtime loss of the
detector pool follows the explicit `DETECTOR_UNAVAILABLE` completion policy
below.

## Initial resource budget

These are starting values, not final performance claims:

| Limit | Initial value |
|---|---:|
| Global HTTP concurrency | 20 |
| Per-origin HTTP concurrency | 2 |
| Concurrent full scans / browser contexts | 3 |
| Active domain deadline | 60 seconds |
| Individual HTTP request | 10 seconds |
| Browser page including settle | 15 seconds |
| Canonical target candidates | 4 |
| Redirects per chain | 5 |
| Static HTTP transactions per domain | 40 total, including robots, candidates, redirects, retries, pages, and probes |
| Transient retry | 1 per request, still inside the 40-transaction total |
| Top-level pages | 3 |
| Catalog probes | 5 |
| Any input, fetched, or persisted URL | 2,048 UTF-16 code units |
| Header fields / total header bytes | 100 / 64 KiB |
| HTML body per page | 2 MiB compressed / 4 MiB decompressed |
| Total static decompressed bytes | 32 MiB per domain |
| Probe body | 256 KiB compressed / 512 KiB decompressed |
| Script URL candidates / bodies | 80 / 20; bodies 2 MiB each / 16 MiB total |
| Unique browser network hostnames | 200 per domain |
| Browser requests | 150 per page / 300 per domain |
| Browser transfer | 15 MiB per page / 30 MiB per domain |
| Cookies | 100 per domain; 256-code-unit name / 4 KiB value / 64 KiB total |
| DNS | 32 records per type / 128 total; 4 KiB TXT item / 64 KiB DNS text total |
| robots.txt | 512 KiB; 5,000 lines; 500 rules; 512 code units per rule |
| Robots matching work | 1,000,000 pattern-path character states per checked URL |
| Extracted link/resource URLs | 5,000 per page |
| Extracted visible text | 512 KiB per page |
| DOM inspection | 5,000 selectors; 1,024 code units each; 20 matches per selector |
| JavaScript inspection | 10,000 paths; 512 code units each |
| DOM + JavaScript returned values | 8 KiB each / 2 MiB total per page |

Queue wait is measured separately; the domain deadline begins only after the
job receives a full-scan slot. Reaching a limit cancels the affected work,
releases resources, records a stable error, and preserves earlier observations.
All limits live in one validated runtime configuration with explicit CLI
overrides rather than a separate YAML system.

The pinned catalog currently yields 1,769 unique DOM selectors and 5,570 unique
JavaScript paths after deduplication, so the inspection-plan caps admit the
entire reviewed baseline. A future effective upstream-plus-custom catalog which
exceeds a catalog-wide plan cap is rejected before crawling rather than silently
dropping fingerprint rules.

## Reliability and safety requirements

- Accept only HTTP and HTTPS targets.
- Reject loopback, private, link-local, and cloud metadata destinations before connection and after every redirect.
- Re-resolve redirect targets and guard against DNS rebinding where practical.
- Use explicit decompressed response-size limits.
- Isolate browser contexts between domains.
- Reuse a bounded browser process pool instead of launching one browser per domain.
- Use a descriptive user agent and conservative timeouts.
- Do not bypass authentication, CAPTCHAs, or explicit access controls.
- Record partial results when a later stage fails.

## Incremental output and resume

JSON Lines is the selected primary output because a newline terminates one
complete domain record. A new output receives one `runId`; `--resume` reuses it
and accepts only records with the same schema version, scanner version, Node,
Playwright and Chromium versions, catalog revision/digest, scan mode, and
configuration digest. Each `(runId, domain)` appears exactly once; duplicates
and malformed middle lines are errors, not last-write wins. At most one
incomplete final fragment may be removed before append. This is process-crash
recovery at record granularity, not a claim of power-loss durability.

Initial controls:

```text
--resume
--force
```

`--retry-failed` is not promised until replacement can use a temporary file and
atomic rename without appending duplicate keys. A separate checkpoint database
is unnecessary for the challenge. Progress and sanitized diagnostics go to
stderr; result data goes only through the output writer, so logs cannot corrupt
JSONL. The paired summary replaces a terminal `.jsonl` with `.summary.json`
(`results.jsonl` becomes `results.summary.json`); another result suffix receives
an appended `.summary.json`. It carries the same `runId`, complete
runtime/browser versions, scan configuration and limits, and catalog
provenance. Version 1 has no independent summary-path override.

`--resume` and `--force` are mutually exclusive. The writer canonicalizes the
existing parent directory once; every existing result or paired-summary target
must be a regular non-symlink file opened without following the final path
component and verified through its file descriptor. `--resume` scans, removes
an allowed incomplete final fragment, and appends through that same validated
result descriptor. `--force` may truncate only that exact validated result,
creates a new `runId`, and replaces only its validated paired summary. A normal
new run refuses existing targets and creates them exclusively. Summary updates
use a new exclusive temporary file in the same canonical parent followed by an
atomic rename; no mode removes an output directory or another path implicitly.

## Run summary

The final summary should include at least:

- input, processed, successful, partial, and failed domain counts;
- direct, inferred, total, and unique technology counts;
- raw direct candidates gated or suppressed by relationship rules;
- average and percentile scan duration;
- HTTP-only detections versus additional browser detections;
- incremental direct-detection lift and cost for probes, internal pages,
  browser rendering, and script-content matching;
- retry counts, hard-limit hits, pages visited, probes issued, browser requests,
  and script bodies inspected;
- error counts grouped by stage and stable error code;
- fingerprint catalog version or source revision;
- relevant runtime limits used for the run;
- the shared `runId`, configuration digest, and runtime/browser versions.

## Testing strategy

- Foundation tests keep the pinned Node/npm declarations, exact direct
  dependency versions, npm v3 lockfile, ESM mode, private-package guard, and
  project license consistent before application behavior exists.
- Unit tests for target normalization and public-address validation.
- Robots status/rule semantics and deterministic page-selection tests.
- Fingerprint catalog validation and isolated regex compilation tests.
- Catastrophic regex, watchdog termination, worker replacement, checkpoint,
  replay accounting, per-domain timeout, crash, whole-pool loss, remaining
  failed records, and redacted-error tests.
- Detector tests using small synthetic HTML/header/cookie/network fixtures.
- Evidence, confidence, version, implication, technology/category requirement,
  exclusion, cycle, conflict, and deduplication tests.
- Relationship fixtures cover a unilateral `A -> B -> C` exclusion chain,
  an external edge breaking a cycle, gate-then-exclude of a base technology,
  and pruning an inference whose only parent was suppressed.
- Pipeline tests against a local HTTP server, not unstable public websites.
- Browser-egress tests proving that private, link-local, loopback, metadata, and
  mixed DNS destinations never receive a connection.
- Resume and partial-result tests.
- A small optional real-site smoke run that is not required in CI.
- Deterministic sorting and output-schema checks.

## Scaling path

The local CLI performs:

```text
Parquet -> bounded local worker pool -> scanDomain() -> result file
```

A simple distributed `full` run can preserve one domain as one job:

```text
Queue -> stateless workers -> scanDomain() -> object storage / analytical database
```

The measured tiered deployment is a different orchestration shape: it stores a
durable stage result and routes only selected domains to later HTTP or browser
queues. The collectors, detector, `DomainResult`, and output contracts remain
reusable, but the claim is not that only the source and sink change.
Idempotency keys, leases, retries with backoff, dead-letter handling, per-host
rate limits, partitioned storage, metrics, and recrawl scheduling belong to
that distributed orchestration layer, not the challenge CLI.

The measured scaling policy has four tiers:

1. every domain receives canonical-target resolution, robots, static entry-page
   HTTP, DNS/TLS, headers, metadata, and resource-URL matching;
2. bounded probes and one internal static page run for likely ecommerce/CMS
   sites, thin client-rendered shells, or zero direct detections;
3. the browser renders the entry page and captures its bounded script-response
   bodies for sites selected by the commercial objective or dynamic/unknown
   signals, plus a deterministic 1% control sample;
4. a product page and its bounded script-response bodies are rendered only for
   the ecommerce subset whose entry page did not expose sufficient application
   signals.

The 200-domain `full` run is the reference dataset used to simulate these
triggers before implementing tiered orchestration. The initial acceptance target
is at least 95% of `full` mode's direct detections while rendering at most 20%
of domains. If measurements miss either bound, triggers change before capacity
is extrapolated. HTTP and browser worker counts are then sized independently
from observed p95 cost with at least 2x throughput headroom. Robots, opt-out,
retention, terms-of-service review, and an operational contact remain release
gates for a production-scale crawl.

## Runtime baseline

The project runtime is **Node.js 24.19.0 LTS (Krypton)**. The exact version is
recorded in `.node-version`, which is the repository's canonical local runtime
declaration. `package.json` repeats it in `engines.node` and
`devEngines.runtime` so runtime upgrades remain deliberate and reviewable.

For a new zsh session with `fnm` installed, activate the repository runtime with:

```sh
eval "$(fnm env --shell zsh)"
fnm use
node --version
```

The expected output is `v24.19.0`. The shell integration is local developer setup; `fnm` is not an application dependency.

## Package manager and dependency policy

The selected package manager is **npm 11.17.0**, the version bundled with the
selected Node.js 24.19.0 runtime. This is a single-package CLI, so pnpm or Yarn
would add bootstrap and configuration without solving a current problem.
`package-lock.json` version 3 will be committed and automated environments will
use `npm ci`, which installs the locked tree without rewriting the manifest or
lockfile. No npm update, Corepack setup, workspace, `.npmrc`, or shrinkwrap file
is required.

The manifest declares `packageManager: npm@11.17.0`, enforces the selected
Node/npm pair through `devEngines`, keeps the project private, and saves direct
dependency versions exactly. The following releases were reviewed and resolved
on 2026-08-17:

| Scope | Package | Version | Boundary it owns |
| --- | --- | ---: | --- |
| Runtime | [`hyparquet`](https://github.com/hyparam/hyparquet) | `1.28.2` | Read the local Parquet input and its Snappy-compressed `root_domain` column. Snappy support is built in, so `hyparquet-compressors` is not needed. |
| Runtime | [`cheerio`](https://github.com/cheeriojs/cheerio) | `1.2.0` | Parse bounded static HTML and evaluate the catalog's supported CSS selectors without executing page JavaScript. |
| Runtime | [`ajv`](https://github.com/ajv-validator/ajv) | `8.20.0` | Validate catalog files against the pinned JSON Schema 2020-12 contract before compilation. |
| Runtime | [`robots-parser`](https://github.com/samclarke/robots-parser) | `3.0.1` | Parse already-fetched, bounded robots.txt content and evaluate allow/disallow rules without creating another network path. |
| Runtime | [`playwright`](https://playwright.dev/docs/library) | `1.62.1` | Collect rendered DOM, known JavaScript paths, and browser network observations in isolated Chromium contexts. |
| Development | [`typescript`](https://github.com/microsoft/TypeScript) | `7.0.2` | Compile and type-check the strict TypeScript project. |
| Development | [`@types/node`](https://github.com/DefinitelyTyped/DefinitelyTyped/tree/master/types/node) | `24.13.3` | Supply Node.js 24 API types; the runtime packages above already ship their own types. |

All seven direct packages use MIT or Apache-2.0 licenses, which are compatible
with distribution inside this GPL-3.0-only project when their notices are
preserved. Their resolved tree, integrity hashes, install scripts, declared
licenses, and advisories were reviewed with the generated lockfile; direct
dependency notices are recorded in `THIRD_PARTY_NOTICES.md`.

Usage constraints keep the packages inside their intended boundaries:

- `hyparquet` reads only the required columns and uses bounded row windows for
  larger files; extra codecs, Arrow, DuckDB, and a Parquet writer are excluded;
- Cheerio receives only bytes already fetched and bounded by our HTTP transport;
  `cheerio.fromURL()` is forbidden because it would create an unguarded request
  and redirect path;
- `robots-parser` receives only a prevalidated body fetched by that same
  transport; a wrapper owns RFC percent-encoding normalization and the package
  never owns fetching. Body, line, rule, path, and calculated character-state
  work limits bound its synchronous matching algorithm;
- Ajv compiles only the pinned, locally vendored, reviewed schema using its
  JSON Schema 2020-12 entry point; CLI-selected schemas, remote references,
  custom keywords, formats, coercion, defaults, and mutation are forbidden;
- the upstream schema is necessary but not sufficient: the catalog compiler
  must also validate supported fields, references, selectors, paths, pattern
  syntax, lengths, counts, and depth before accepting a definition;
- Playwright is an application dependency, not a test framework. Only its
  matching Chromium build will be provisioned in an explicit later setup step;
  browser downloads are never hidden in `postinstall`, and the sandbox remains
  enabled for untrusted pages. The browser binary is a separate third-party
  artifact: it is not committed, and its licenses/notices must be preserved if
  a future distributable bundles it.

Node.js 24 owns CLI parsing (`util.parseArgs`), hardened HTTP(S), URL/DNS/TLS
handling, cancellation and timeouts, decompression, bounded worker control,
JSONL file streams, hashing, and tests (`node:test` plus `node:assert`). We do
not add Commander, Axios, a direct Undici dependency, `p-limit`, dotenv, a
logger, Zod, a separate test framework, a TypeScript runtime loader, or lint and
format packages before a concrete need appears. Stable built-in TypeScript type
stripping may be used for small development commands, while `tsc` remains the
type-checking contract. A separate application build configuration will be
added with the first real source file so tests are never emitted as CLI output.

No regex package is selected. Heuristic validators do not prove ReDoS safety,
while RE2-style engines reject JavaScript features present in the catalog and
would introduce a second matching semantic. Native worker isolation below owns
that boundary without another dependency.

The toolchain foundation was generated with Node.js 24.19.0 and npm 11.17.0.
`package-lock.json` uses lockfile version 3, all direct specifications are exact,
and every registry package recorded in the lock has an integrity hash. The
resolved tree declares only MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, and ISC
licenses; npm reported zero known vulnerabilities when the lockfile was created
on 2026-08-17. The lock retains TypeScript's optional platform packages for
Linux and macOS instead of producing a host-only compiler lock.

The first local install used `npm ci --ignore-scripts` while the resolved tree
was inspected. Playwright 1.62.1 has no install lifecycle script, so no browser
binary was downloaded; Chromium provisioning remains the explicit later setup
step described above. `node_modules` and compiled `dist` output remain local and
Git-ignored.

The available foundation commands are:

```sh
npm run typecheck
npm test
npm run check
```

Tests use Node.js 24's built-in test runner and type stripping for `.test.ts`
files. TypeScript still owns strict type checking. There is intentionally no
application `build` command while `src` is empty; it will be introduced with a
source-only build configuration when the first implementation slice adds real
application code.

## Regex execution policy

Fingerprint expressions use native JavaScript `RegExp` with the catalog's
case-insensitive `i` semantics, but they are never compiled or executed on the
main thread. A persistent pool of two local
[`worker_threads`](https://nodejs.org/docs/latest-v24.x/api/worker_threads.html)
compiles the validated declarative catalog and matches only bounded, normalized
candidate strings. Workers start from a fixed local module, never `eval`,
receive no runtime objects through the task protocol, perform no network or
filesystem I/O, and return rule and candidate identifiers plus match
positions/captures rather than raw values in diagnostics.

The catalog compiler indexes rules first by signal type and then by their exact
locator where one exists: header, cookie, metadata, DOM, and JavaScript rules
run only against observations with the same normalized key, selector, or path.
Unkeyed signals use the deterministic candidate caps in the resource table,
including at most 80 script URLs, 20 script bodies, three page URLs, and 200
browser request hostnames. They are deduplicated and ranked by page ID, then
their source URL, hostname, or locator in UTF-16 code-unit order; script
responses first apply the same-origin ranking defined by the browser policy.
Before dispatch, the detector calculates a conservative upper bound from
applicable rules times admitted candidates. It truncates candidate lists by that stable ranking when
needed, records `REGEX_EXECUTION_LIMIT`, and never sends a task capable of
exceeding the 500,000-execution domain limit. A prefilter may remove provably
inapplicable rules but must not be required for correctness or for respecting
the cap.

The parent owns a per-domain cumulative counter in shared memory which survives
worker replacement. A worker must atomically reserve one unit before every
`RegExp` execution. The timed-out call and every replay after a checkpoint count
again; a replacement receives only the remaining budget and stops with
`REGEX_EXECUTION_LIMIT` before it could exceed 500,000. The pre-dispatch upper
bound avoids predictable overflow, while this cumulative counter is the final
enforcement boundary.

The initial limits are:

| Regex control | Initial value |
| --- | ---: |
| Worker pool | 2 |
| Technologies per effective catalog | 20,000 |
| Relationship edges per effective catalog | 100,000 |
| Pattern source | 2,048 UTF-16 code units |
| Patterns per catalog | 20,000 |
| Total pattern source | 1,000,000 UTF-16 code units |
| Catalog compilation watchdog threshold | 5 seconds |
| Worker old / young heap | 128 MiB / 32 MiB |
| Worker stack | 4 MiB |
| One rule across one domain watchdog threshold | 50 ms |
| Parent watchdog polling target | 10 ms |
| Total active detection budget per domain | 2 seconds |
| Regex timeouts per domain | 3 |
| Confirmed-result checkpoint | every 128 rules |
| RegExp executions per domain | 500,000 |

The worker updates a small `SharedArrayBuffer` with phase, current rule, and
progress. The parent watchdog can therefore identify stalled work without an
IPC message for every expression. On a runtime timeout it terminates and
replaces the worker, resumes from the last confirmed checkpoint, and skips only
the offending rule for that domain. The rule is not disabled globally, because
that would make results depend on concurrent domain order. After three regex
timeouts or the two-second detector budget, completed matches are preserved,
the remaining work is cancelled, and the domain is `partial`.

The 50 ms value is a watchdog threshold, not an exact real-time ceiling:
termination happens on the first available parent poll after the threshold and
includes event-loop scheduling plus asynchronous termination latency. The
parent makes one bounded replacement attempt after a timeout or crash. If it
fails while another ready detector worker remains, the current domain keeps its
confirmed matches, records `REGEX_WORKER_RESTART_FAILED`, becomes `partial`,
and the pool continues at reduced capacity without a spawn loop. If no ready
worker remains, the pool latches unavailable without another spawn loop. An
in-flight domain preserves observations and confirmed matches and becomes
`partial` or `failed` under the normal status rules. Remaining input domains are
not crawled; each receives a `failed` record with `DETECTOR_UNAVAILABLE`. The
batch still writes a complete summary and one result per input domain, then
exits non-zero.

Invalid syntax, size/count overflow, catalog compile timeout, or worker startup
failure rejects the catalog before crawling. Runtime failures use stable codes
`REGEX_RULE_TIMEOUT`, `REGEX_DOMAIN_BUDGET_EXCEEDED`, `REGEX_EXECUTION_LIMIT`,
`REGEX_WORKER_CRASH`, `REGEX_WORKER_RESTART_FAILED`, or
`DETECTOR_UNAVAILABLE`. Their structured `ruleId`, `signal`, `limit`, and
`catalogRevision` fields are populated when applicable and otherwise remain
`null`; the candidate value is never included. A timed-out rule produces no
confidence or evidence.

Static validation remains useful for syntax and limits but is not described as
proof that backtracking is safe. `worker.terminate()` is the enforceable CPU-hang
boundary for this pinned catalog. Node's worker memory limits are defense in
depth rather than full process isolation; a subprocess or RE2 compatibility
tier is reconsidered only if externally supplied catalogs or measurements
justify the extra cost and semantics.

## Fingerprint catalog decision

The selected baseline is the community-maintained
[`enthec/webappanalyzer`](https://github.com/enthec/webappanalyzer) catalog,
pinned to commit
[`5e7c47b1d441ded0bd476b252261e87634349f96`](https://github.com/enthec/webappanalyzer/commit/5e7c47b1d441ded0bd476b252261e87634349f96)
from 2026-08-12. The upstream project describes itself as a community
continuation of the former public Wappalyzer repository after it went private;
it is not the current commercial Wappalyzer product.

The pinned snapshot was inspected on 2026-08-17 and contains 7,575 technology
definitions in 27 JSON files and 109 categories. Its declarative format covers
the signals required by this project, including headers, cookies, metadata,
DOM selectors, JavaScript properties, page and script URLs, script content,
visible text, CSS, request hostnames, robots, bounded probes, DNS, certificate issuer,
version extraction, confidence, and technology relationships.

The upstream repository is licensed under
[`GPL-3.0`](https://github.com/enthec/webappanalyzer/blob/5e7c47b1d441ded0bd476b252261e87634349f96/LICENSE).
Because it does not grant a separate license for the fingerprint data, this
project treats the catalog conservatively as `GPL-3.0-only` and will release
the project source code and original fingerprint additions under
`GPL-3.0-only`. Third-party material retains its own license and notices. This
is an engineering compliance choice, not legal advice.

The supplied `input/domains.parquet` benchmark is third-party challenge input,
not project-authored material. No separate redistribution license was found in
the supplied challenge text, so the file remains local and Git-ignored until
permission is confirmed. The project license does not claim to relicense it.

Import policy:

- vendor only the pinned `schema.json`, `src/categories.json`, and
  `src/technologies/*.json` files needed by the detector;
- do not import upstream executable code, dependencies, icons, or branding;
- preserve the upstream snapshot under `fingerprints/upstream/webappanalyzer`
  and keep original additions under `fingerprints/custom`;
- do not edit vendored files in place; refreshes use a newly reviewed and
  explicitly pinned commit;
- record the source, commit, retrieval date, license, and local modifications
  in `THIRD_PARTY_NOTICES.md` before the first import;
- keep the complete `GPL-3.0-only` project `LICENSE` and update
  `THIRD_PARTY_NOTICES.md` when the pinned snapshot is imported;
- validate every definition and reject unsupported or unsafe patterns before
  enabling it; a licensed catalog is still untrusted input.

The official commercial Wappalyzer catalog, website, extension, npm
placeholder, and API are not sources for this project. Mirrors or MIT-licensed
wrappers do not override the license of the catalog they copy. Additional
catalogs will be considered only after benchmark results show a concrete gap.
No third-party fingerprint files have been copied into this repository during
this decision stage.

## Implementation roadmap

- [x] Confirm challenge scope and input format.
- [x] Inspect the supplied Parquet file.
- [x] Agree on the modular architecture and dependency direction.
- [x] Define evidence, reliability, scaling, and testing expectations.
- [x] Select the Node.js runtime baseline: Node.js 24.19.0 LTS.
- [x] Select the fingerprint source and resulting license: pinned
  WebAppAnalyzer baseline and `GPL-3.0-only` project.
- [x] Select npm 11.17.0 and the minimal runtime and development dependencies.
- [x] Select the initial `full` page/browser policy, JSONL result and redacted
  evidence contract, and killable regex-worker policy.
- [x] Add `package.json`, `tsconfig.json`, npm v3 lockfile, and foundation tests.
- [ ] Implement configuration and shared data contracts.
- [ ] Implement Parquet input and target normalization.
- [ ] Implement the static HTTP collector.
- [ ] Implement the fingerprint catalog compiler and detector.
- [ ] Implement the browser collector and browser pool.
- [ ] Add DNS/TLS signals.
- [ ] Add incremental output, resume, and summary generation.
- [ ] Run deterministic tests and a small real-site smoke test.
- [ ] Scan all 200 domains and analyze misses and false positives.
- [ ] Produce final results and complete the debate topics.

## Readiness gate for the coding stage

Coding starts only after these decisions are explicit:

1. Node.js runtime baseline: **Node.js 24.19.0 LTS (selected).**
2. Fingerprint catalog source and license: **pinned WebAppAnalyzer baseline and
   `GPL-3.0-only` project (selected).**
3. Package manager and minimal dependency list: **npm 11.17.0 plus five runtime
   and two development packages (selected).**
4. Initial page-selection policy: **`full`, at most three deterministic pages,
   with HTTP and protected browser collection (selected).**
5. Result and evidence contract: **JSONL `schemaVersion: 1`, sanitized direct
   evidence, explicit inference, and no raw persistence (selected).**
6. Untrusted fingerprint regex execution: **bounded native RegExp in a
   watchdog-controlled worker pool (selected).**

The readiness gate and toolchain foundation are complete. The next implementation
slice remains limited to validated configuration, shared data contracts, Parquet
input, and target normalization. Crawling and browser automation are separate
later slices.
