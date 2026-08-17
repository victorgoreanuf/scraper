# Website Technologies Scraper

> Project status: first application-foundation slice complete. Validated
> immutable configuration, shared result types and semantic validation,
> fail-fast Parquet input, and hostname/public-address policy are implemented
> and tested. The network crawler and fingerprint catalog are not implemented.

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
7. **Streaming by default:** row payloads and completed results are not retained
   as one in-memory dataset; the bounded v1 duplicate preflight is the explicit
   exception described in the Parquet contract.
8. **Bounded resources:** requests, pages, redirects, response sizes, scripts, browser contexts, and time are limited.
9. **No speculative layers:** no service containers, plugin framework, repositories, controllers, or generic utility folders without a current need.

## Planned repository layout

```text
.
├── src/
│   ├── cli.ts
│   ├── config.ts
│   ├── model.ts
│   ├── network-policy.ts
│   ├── pipeline.ts
│   ├── input/
│   │   └── parquet.ts
│   ├── crawl/
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
├── schemas/
│   ├── domain-result.v1.schema.json
│   └── scan-config.v1.schema.json
├── test/
│   ├── fixtures/
│   ├── toolchain.test.ts
│   ├── config.test.ts
│   ├── domain-result-schema.test.ts
│   ├── model.test.ts
│   ├── parquet.test.ts
│   ├── scan-config-schema.test.ts
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
├── tsconfig.build.json
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
input + crawl + model ──> network-policy
```

Rules:

- `detect` performs no network requests.
- `network-policy` is the application-module-independent shared owner of
  hostname normalization and public-address classification.
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
Preflight the complete Parquet input without network or output writes
        ↓
Load, validate, and index fingerprint data once; compile it per detector worker
        ↓
Preflight the detector pool and protected browser egress
        ↓
Schedule canonical domains in Parquet row order
        ↓
Build a target candidate and validate all resolved addresses
        ↓
Fetch robots.txt through the protected transport and evaluate the candidate path
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

The robots fetch is itself an infrastructure request and is not gated by
robots. Before every top-level redirect hop, the new destination is normalized,
resolved, and checked by the same address policy; the cached or newly fetched
robots policy for that scheme and authority is then evaluated for the new path
before the next page request. A cross-authority redirect therefore receives its
own robots policy, while a same-authority redirect still receives a new path
decision.

## Parquet input contract v1

The input is an untrusted Parquet file with exactly one top-level primitive
field named `root_domain`; a second field with that name, a nested field, or a
`REPEATED` field is invalid. Its physical type is `BYTE_ARRAY` annotated as
logical `STRING`; the equivalent legacy `ConvertedType.UTF8` annotation is
accepted for compatibility. If both annotations exist, they must agree. An
unannotated binary field is not decoded optimistically. The field may be
`REQUIRED` or `OPTIONAL`, but every row must contain a non-null string. Other
columns are allowed and are ignored without being decoded. Version 1 accepts
only `UNCOMPRESSED` and `SNAPPY` for the selected column. Parquet
`FileMetaData.version` is accepted only when it is `1` or `2`.

Input processing is a fail-fast global preflight. The reader projects only
`root_domain` and makes two bounded, row-group-based passes:

1. validate every row, normalize it, and retain only canonical-domain keys and
   their first 1-based row number for duplicate detection;
2. after the whole file succeeds, read the selected column again and schedule
   the canonical domains in Parquet row order with backpressure.

The first pass therefore uses bounded but material `O(n)` memory for at most one
million canonical keys; it does not retain arbitrary columns or raw row values.
The distributed design replaces this local challenge tradeoff with partitioned
validation or an external sort/key store rather than copying the Map into every
worker.

There is no `trim`, type coercion, skipped invalid row, first-row-wins, or
automatic deduplication. `Shop.Vendor.TLD`, `shop.vendor.tld.`, and an
IDNA-equivalent value collide after canonicalization. A null, non-string, empty,
or invalid value, or any duplicate canonical domain rejects the complete input
before a run file is created or modified and before any network request starts.
Fatal diagnostics use 1-based row numbers but never echo the raw invalid value.

The initial input limits are:

| Limit | Value |
| --- | ---: |
| Rows | 1,000,000 |
| Rows in one row group | 65,536 |
| Parquet metadata/footer | 16 MiB |
| Compressed `root_domain` column chunk | 32 MiB |
| Uncompressed `root_domain` column chunk | 32 MiB |

Zero rows is invalid. Corrupt or truncated input, unsupported schema or
compression, and any limit violation are fatal global errors. The stable input
codes are `INPUT_OPEN_FAILED`, `INPUT_PARQUET_INVALID`,
`INPUT_SCHEMA_INVALID`, `INPUT_LIMIT_EXCEEDED`, `INPUT_DOMAIN_INVALID`, and
`INPUT_DOMAIN_DUPLICATE`. They are stderr/run-start failures, not
`DomainResult.errors`, because no valid per-domain run exists yet.

The current reader validates the footer, schema, selected chunk offsets and
sizes before decoding, gives `hyparquet` a one-row-group projected metadata
view, and caps each Snappy output allocation. One production-hardening gap is
explicit: `hyparquet@1.28.2` does not expose a public pre-decode hook for every
page-header count/RLE allocation. The supplied benchmark and bounded valid
files are covered by the current implementation and tests; before accepting
arbitrary externally uploaded Parquet at scale, decoding must additionally run
behind a killable resource boundary or use a reviewed page-header preflight.

## Initial scan policy

The first implemented scan mode is `full`. It is intentionally exhaustive for
the supplied 200-domain benchmark: every eligible page receives both the static
HTTP collector and the browser collector. A future tiered mode is defined in
the scaling section, but it is not another abstraction to implement before the
full-mode benchmark provides measurements.

### Canonical target

Input is a hostname, not a URL, and is normalized by one exact boundary:

1. require a JavaScript string of 1 through 2,048 UTF-16 code units, with no
   unpaired surrogate, control character, whitespace, or NUL; do not trim;
2. reject URL syntax or ambiguous authority syntax, including `/`, `\`, `:`,
   `@`, `?`, `#`, `[`, `]`, and `%`;
3. convert with Node.js `domainToASCII()` and reject an empty or failed result;
4. allow and remove exactly one trailing ASCII root dot, then lowercase the
   ASCII result; another empty label is invalid;
5. require 2 through 127 labels and at most 253 ASCII characters excluding the
   removed root dot; every label is 1 through 63 characters and matches
   `[a-z0-9](?:[a-z0-9-]*[a-z0-9])?`;
6. require the final label to contain at least one ASCII letter and reject
   underscores, wildcards, IP literals, and legacy numeric/hex/octal IPv4
   forms; URL hostname serialization must reproduce the same non-IP hostname;
7. reject every registered
   [IANA Special-Use Domain](https://www.iana.org/assignments/special-use-domain-names/special-use-domain-names.xhtml)
   and its descendants using the policy-v1 snapshot reviewed 2026-08-17.

Version 1 deliberately has no Public Suffix List dependency. A syntactically
valid multi-label hostname with an unknown suffix may proceed to DNS, while
single-label/search-suffix names and special-use names fail before resolution.
The target resolver then tries these unique candidates in order:

1. `https://domain/`;
2. `https://www.domain/` when the input does not already start with `www.`;
3. `http://domain/`;
4. `http://www.domain/` when applicable.

This hostname-only rule applies to Parquet input. A URL received from the
network is parsed with the WHATWG URL parser; a canonical public IP literal in
a redirect may proceed only after the same address-policy check, while legacy
or non-public forms remain blocked. `http:` is restricted to effective port 80
and `https:` to effective port 443; credentials and scoped IPv6 addresses are
always invalid.

### Public-address and connection contract

Every new socket resolves the candidate hostname with
`dns.lookup(hostname, { all: true, order: "verbatim" })`. An empty answer,
malformed address, scoped IPv6 address, or answer count beyond the DNS budget is
an error. Every A and AAAA answer must be ordinary public unicast; one blocked
answer mixed with public answers rejects the whole authority rather than
selecting the convenient answer.

The versioned IPv4 deny table is the union of the IANA special-purpose registry,
multicast, and one explicit cloud control endpoint:

```text
0.0.0.0/8          10.0.0.0/8         100.64.0.0/10
127.0.0.0/8        168.63.129.16/32    169.254.0.0/16
172.16.0.0/12      192.0.0.0/24        192.0.2.0/24
192.31.196.0/24    192.52.193.0/24     192.88.99.0/24
192.168.0.0/16     192.175.48.0/24     198.18.0.0/15
198.51.100.0/24    203.0.113.0/24      224.0.0.0/4
240.0.0.0/4
```

IPv6 is fail-closed: an address must first be inside `2000::/3`, then must not
be inside `2001::/23`, `2001:db8::/32`, `2002::/16`,
`2620:4f:8000::/48`, or `3fff::/20`. This also rejects unspecified, loopback,
IPv4-mapped, translation, unique-local, link-local, documentation, transition,
and multicast space. Policy v1 uses the
[IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
and
[IANA IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml)
registry snapshots updated 2025-10-09, reviewed 2026-08-17, plus the documented
[Azure platform address](https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16).
The scanner never downloads registries at runtime. The policy intentionally
blocks special-purpose exceptions which may be globally reachable because
ordinary public websites do not require them.

After resolution, the transport selects only from the validated answer set and
pins the socket to that address without an implicit second lookup. The original
hostname is preserved for HTTP `Host`, TLS SNI, and certificate verification,
and the actual `remoteAddress` must equal a selected validated address. Each
retry, new socket, and redirect repeats resolution, all-answer validation, and
pinning. The browser forward proxy uses this same contract. URL interception is
only an additional policy layer, never the address boundary.

### Protected HTTP transport v1

`crawl/transport.ts` performs exactly one protected `GET` transaction. It does
not follow redirects or hide retries: the robots and static-HTTP orchestrators
must inspect the response, apply policy, and explicitly start the next hop or
attempt. Every such call therefore repeats URL validation, DNS resolution,
all-answer SSRF validation, connection pinning, and peer verification. For v1,
the first validated answer in `verbatim` resolver order is selected and every
transaction uses a fresh socket; there is no implicit DNS lookup, keep-alive,
proxy environment handling, or multi-address fallback inside Node's client.

After URL and already-aborted-session validation, the transaction is reserved
before DNS. Resolution uses its own bounded scheduler; a validated destination
then waits for the global/per-origin HTTP scheduler. This bounds queued work and
means queued, DNS, SSRF, connect, TLS, header, and body failures still consume
the 40-transaction domain budget. Retry pairing and backoff remain owned by the
future orchestrator; the transport rejects a retry before an initial attempt
and enforces that aggregate retries never exceed the configured one-per-initial
budget. The active-domain deadline includes queue time. The per-request absolute
deadline begins after transaction reservation and covers DNS, the HTTP
scheduler wait, connection, TLS, headers, body, decompression, and trailers;
slow trickle traffic cannot extend it.

Node's `dns.lookup()` cannot cancel underlying libuv work. A timed-out result is
ignored and can never open a socket, while a separate scheduler caps unresolved
lookups at the global HTTP concurrency instead of retaining HTTP slots forever.
The DNS domain budget counts unique canonical A/AAAA addresses; each lookup is
also capped at 128 raw answers before deduplication. This is a bounded
availability tradeoff, not a relaxation of the SSRF policy.

Node's final response-header block is guarded by native `maxHeaderSize` plus the
project field-count check. V1 rejects every informational response and every
non-empty trailer block: Node's high-level API normalizes surrounding
whitespace, so their cumulative wire size cannot be reconstructed exactly after
parsing. Status and bounded final headers are available before body admission.
Redirect, non-2xx, `204`, and `205` bodies are discarded, and a caller may also
reject another 2xx body from its headers, so access denials, retryable statuses,
and unsupported content types cannot be replaced by a body/decompression error.
An admitted body accepts only one of `identity`,
`gzip`, `deflate`, or `br`; wire, per-body decompressed, and per-domain
decompressed limits are enforced while streaming. `robots.txt` uses its 512 KiB
limit for both wire and decoded bytes in v1.

Redirect `Location` values are resolved and validated lexically by the
transport helper, including canonical public IP literals, but are not fetched
automatically. The next explicit hop performs the authoritative DNS and socket
checks. Local adversarial tests hook Node's DNS/socket modules only inside the
test process before loading the production module. The hook lives under
`test/`, is excluded from `dist`, and the built transport exports no injectable
resolver, connector, peer metadata, or production option that disables policy.

Top-level requests use `GET`; there is no preliminary `HEAD`. Every DNS answer,
actual connection destination,
and redirect destination is revalidated by the shared SSRF policy. A chain may
contain at most five redirects, and a cross-origin redirect must pass the new
origin's robots policy before the next top-level request.

`401`, `403`, `407`, `451`, a CAPTCHA, or another explicit block is permanent:
the scanner does not retry, open a browser, or try an alias to bypass it.
`429` receives at most one retry with `Retry-After` capped at two seconds, then
ends target resolution without an alias. Other non-denial `4xx` responses move
to the next candidate without retry. `408`, `425`, `5xx`, DNS/connect/timeout,
and transient TLS transport failures receive at most one retry and then move to
the next candidate. Certificate-validation and deterministic TLS protocol
failures are permanent, as are redirect-policy, SSRF, and invalid-target
rejections. The first final `2xx` response selects the target. A non-HTML response
retains bounded safe HTTP signals, schedules no page, browser, probe, or alias
fallback, and emits terminal `http/UNSUPPORTED_CONTENT_TYPE` with
`retryable: false`; it is therefore `partial`. HTTP fallback is a separate
candidate for sites that genuinely serve HTTP, never a TLS validation bypass.
Every redirect hop and retry consumes the single HTTP transaction budget.

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

1. the canonical `entry` page;
2. one discovered product or `detail` page;
3. one discovered collection/category/shop `listing`, or a useful `content`
   fallback.

Candidates come only from links observed on the static or rendered entry page;
the crawler does not guess paths or recurse through internal pages. They must
use the exact final origin, have no credentials or query string, pass robots,
and be safe `GET` targets. Authentication, account, admin, cart, checkout,
logout, search, legal/privacy, fragments, files, and duplicates are excluded.
A fixed path-class rank followed by shortest normalized path and UTF-16
code-unit order makes the same entry observation select the same pages. If a
`detail` candidate is absent, that slot stays empty. If a `listing` candidate is
absent, the shortest remaining useful internal page may fill only that slot as
`content`; the two internal slots never cross-fill or produce duplicate roles.

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
checked. Any failed preflight stops `full` mode before domain processing or
output creation. At
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
The normative wire contracts are
`schemas/domain-result.v1.schema.json` and
`schemas/scan-config.v1.schema.json`, using JSON Schema 2020-12 with no remote
references and `additionalProperties: false` at every object boundary.
`src/model.ts` mirrors the result schema with TypeScript types, but the JSON
Schema remains the serialization boundary. Ajv compiles only these fixed local
schemas with coercion, defaults, mutation, remote loading, custom keywords, and
external formats disabled.

JSON Schema enforces the closed wire shape, lexical bounds, and the local
direct/inferred, status, collector, and redaction variants which can be expressed
without runtime context. The implemented semantic validator checks
canonical URL/time values, page and parent references, status/signal meaning,
`pagesVisited`, sorting/deduplication, confidence/version calculation, inference
acyclicity, sanitizer compliance, scalar Unicode validity, and digest
correctness. The output writer and resume reader must pass both layers; schema
validity alone never authorizes a semantically inconsistent result.

At scan time the writer must supply the non-serialized `signalAdmitted` fact to
validate the `partial`/`failed` distinction; omitting that boolean is itself a
validation failure. A future resume reader can recheck every persisted
invariant, but cannot reconstruct that collection-history fact from the v1 wire
record alone; it therefore trusts the status previously validated by the writer
while still enforcing its schema-level cardinalities.

Every result has exactly the top-level fields `schemaVersion`, `runId`,
`domain`, `scannedAt`, `status`, `finalUrl`, `scanMode`, `pages`,
`technologies`, `errors`, `timings`, `usage`, and `provenance`.
`schemaVersion` is `1`; `runId` is a UUID; `scannedAt` is the exact UTC form
produced by `Date.prototype.toISOString()`; and `scanMode` is `full` in this
version. `finalUrl` is the only nullable top-level scalar. Arrays always exist,
all usage counters are non-negative integers, `totalMs` is a non-negative
integer, and each named stage timing is a non-negative integer or `null` when
that stage never started or was skipped. Provenance is complete and non-null
because missing runtime, catalog, or validated configuration identity is a
global preflight failure rather than a per-domain result.

A `PageRecord` has exactly `id`, `role`, `url`, `httpStatus`, and `collectors`.
IDs are `p1`, `p2`, and `p3` in deterministic page order. `p1` has role
`entry`; later roles are `detail`, `listing`, or the deterministic fallback
`content`. With three records there is exactly one `detail` and exactly one
`listing` or `content`; their `p2`/`p3` order follows the canonical URL sort.
With two records, the second may use either class. `httpStatus` is an integer
or `null`. Collectors preserve fixed order and are exactly `[]`, `["http"]`,
or `["http", "browser"]`; a browser-only page is impossible.

A representative direct detection is shown below.

```json
{
  "schemaVersion": 1,
  "runId": "37937a78-f39d-49ed-a51d-6d398ae45a20",
  "domain": "shop.vendor.tld",
  "scannedAt": "2026-08-17T00:00:00.000Z",
  "status": "success",
  "finalUrl": "https://shop.vendor.tld/",
  "scanMode": "full",
  "pages": [
    {
      "id": "p1",
      "role": "entry",
      "url": "https://shop.vendor.tld/",
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
            "value": "https://cdn.vendor.tld/example-1.2.0.js",
            "truncated": false
          },
          "ruleId": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
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
      "chromiumRevision": "chromium-123456"
    },
    "catalog": {
      "source": "enthec/webappanalyzer",
      "revision": "5e7c47b1d441ded0bd476b252261e87634349f96",
      "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    },
    "configDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
  }
}
```

Evidence `source` is one of `url`, `header`, `cookie`, `html`, `text`, `css`,
`meta`, `script_url`, `script_content`, `dom`, `javascript`, `network_hostname`,
`dns_record`, `tls_issuer`, `robots`, or `probe`. `collector` is `http`,
`browser`, `dns`, or `tls`; `pageId` is `null` for non-page infrastructure
signals and is required for every browser observation. `key` identifies the
header, cookie, metadata name, selector, JavaScript path, DNS record type, or
equivalent locator and is `null` for an unkeyed signal; `dns_record` always uses
a non-null uppercase record-type key. Evidence `pageId`,
`key`, `pattern`, and `version` are the only nullable evidence scalars.
`match.value` is nullable under the redaction rules below.

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

A technology has exactly `name`, `categories`, `version`, `confidence`, `type`,
`pageIds`, `evidence`, and `inferredFrom`; only its scalar `version` is
nullable. A direct detection has at least one evidence item and an empty
`inferredFrom` array. An inferred detection has no evidence or page IDs and
instead records one or more exact `{ technology, ruleId, confidence, version }`
parent relationships. If a technology is both observed and inferred, the
direct result wins.

A scan error has exactly `{ stage, code, pageId, retryable, message, ruleId,
signal, limit, catalogRevision }`. `pageId`, `ruleId`, `signal`, `limit`, and
`catalogRevision` are `string | null`; the other fields are non-null. `signal`
uses the evidence-source vocabulary and `limit` uses a stable value such as
`50ms`. Messages are application controlled and sanitized. `retryable` means a
fresh scan could succeed, not that the current attempt will necessarily retry.
`ruleId`, `signal`, `limit`, and `catalogRevision` are detector context and are
therefore all `null` when `stage` is not `detect`.

The schema admits append-only error codes matching
`^[A-Z][A-Z0-9_]*$`; a central TypeScript registry will contain every code the
implementation can emit. Adding a registered code is compatible with schema
v1, but removing one or changing its meaning is not. The initial non-regex
registry is:

| Stage area | Codes |
| --- | --- |
| Target | `TARGET_NOT_FOUND`, `TARGET_ACCESS_DENIED`, `TARGET_REDIRECT_INVALID`, `TARGET_REDIRECT_LIMIT_EXCEEDED` |
| Robots | `ROBOTS_DISALLOWED`, `ROBOTS_UNAVAILABLE`, `ROBOTS_LIMIT_EXCEEDED` |
| HTTP | `HTTP_REQUEST_FAILED`, `HTTP_TIMEOUT`, `HTTP_LIMIT_EXCEEDED`, `HTTP_RESPONSE_LIMIT_EXCEEDED`, `HTTP_DECOMPRESSION_FAILED`, `UNSUPPORTED_CONTENT_TYPE` |
| DNS | `DNS_LOOKUP_FAILED`, `DNS_NO_ADDRESS`, `DNS_LIMIT_EXCEEDED` |
| TLS | `TLS_CONNECTION_FAILED`, `TLS_CERTIFICATE_INVALID`, `TLS_TIMEOUT` |
| Browser | `BROWSER_UNAVAILABLE`, `BROWSER_NAVIGATION_FAILED`, `BROWSER_TIMEOUT`, `BROWSER_LIMIT_EXCEEDED`, `BROWSER_PROXY_FAILED` |
| Destination policy | `SSRF_NON_PUBLIC_ADDRESS`, `SSRF_MIXED_ADDRESSES`, `SSRF_REMOTE_ADDRESS_MISMATCH` |
| Domain | `DOMAIN_DEADLINE_EXCEEDED` |
| Result materialization | `RESULT_LIMIT_EXCEEDED` |

The regex-worker codes remain `REGEX_RULE_TIMEOUT`,
`REGEX_DOMAIN_BUDGET_EXCEEDED`, `REGEX_EXECUTION_LIMIT`,
`REGEX_WORKER_CRASH`, `REGEX_WORKER_RESTART_FAILED`, and
`DETECTOR_UNAVAILABLE`. Error `stage` remains one of `target`, `robots`,
`http`, `dns`, `tls`, `browser`, or `detect`; the stage names the request or
work boundary that emitted the code.

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

### Configuration and digest contract v1

`ScanConfig` is immutable behavioral input validated against
`schemas/scan-config.v1.schema.json` before any other work. It groups the full
user-agent identity and policy versions plus concurrency, Parquet, target,
robots, HTTP, page, browser, DNS/TLS, detection/regex, evidence, redaction, and
output limits. Every behavior-affecting boolean, integer, string, order, retry
rule, and resource limit that may vary within policy v1 has one named schema
field.
Fixed algorithms, registries, enumerations, and retry classifications are
identified by their policy-version or registry pin. Unknown fields, unsafe
integers, non-finite values, and implicit defaults are rejected. The object is
not mutated after validation.

Input and output paths, `--resume`, `--force`, stderr verbosity, and progress
presentation are operational CLI options, not `ScanConfig`, and therefore do
not affect `configDigest`. Runtime, browser, and catalog identities are recorded
separately in provenance and are still required to match on resume.

Digests have one construction. `catalog.digest` is SHA-256 over the sorted
relative paths and raw bytes of the effective schema, categories, upstream, and
custom fingerprint files; each UTF-8 path and byte payload is prefixed by its
unsigned 64-bit big-endian length. `configDigest` is SHA-256 over the UTF-8
RFC 8785 JSON Canonicalization Scheme representation of the validated
`ScanConfig`. Object properties sort recursively by raw UTF-16 code units;
array order is preserved; and only JSON strings, booleans, safe integers,
arrays, and objects admitted by the schema participate. Digests are lowercase
`sha256:<hex>` strings. Configuration schema property order and JavaScript
insertion order are not part of this identity.

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
- `value` is allowed only for sanitized URL/hostname signals, public `A`/`AAAA`
  addresses and hostname-bearing `CNAME`/`MX`/`NS`/`PTR`/`SRV` DNS records, TLS
  issuer text, or bounded non-sensitive response-header and `generator` /
  `application-name` metadata values which also pass the token classifier;
  `TXT`, `CAA`, `SOA`, cryptographic, and unknown DNS record values are redacted;
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
Cookie names and bounded values may exist only long enough to evaluate the
catalog rule; values are never persisted, logged, or hashed, and a
value-dependent result exposes only the cookie name plus a redacted match. The
rendered DOM remains owned by Chromium: Node receives only bounded facts for
selectors and JavaScript paths explicitly requested by the validated catalog,
never a serialized DOM or an enumeration of the complete `window` object.

Allowed domain statuses are:

- `success`: all stages required by the selected mode completed and `errors` is
  empty; zero detections is valid;
- `partial`: at least one bounded signal was admitted to the detector, and at
  least one terminal per-domain error records a required stage failure, timeout,
  or hard limit;
- `failed`: no signal was admitted to the detector, `technologies` is empty,
  and at least one terminal per-domain error is present.

A final 2xx non-HTML response satisfies `partial`, not `success`, because its
bounded HTTP observations enter detection together with terminal
`http/UNSUPPORTED_CONTENT_TYPE`; no page or browser work follows.

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
| Input hostname | 2,048 UTF-16 code units |
| Any fetched or persisted URL | 2,048 UTF-16 code units |
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
| Catalog names / categories | 256-code-point technology name; 128-code-point category name; category IDs 1–1,000,000; 32 categories per technology; 1,024 categories total |
| Result collections | 20,000 technologies; 128 errors; 256 evidence or inference records per technology; 20,000 of each per domain |
| JSONL record | 16 MiB UTF-8, including its terminating newline |

Unless a row explicitly says code units or code points, text limits are measured
as UTF-8 bytes after the documented normalization. Compressed limits count wire
body bytes, decompressed limits count decoded body bytes, and browser transfer
limits use the proxy accounting defined in the result contract.

The output builder enforces both the configured collection limits and the final
UTF-8 record limit before append. If any is exceeded, it discards the oversized
materialization and emits one bounded terminal
`detect/RESULT_LIMIT_EXCEEDED` record: `partial` when a signal reached the
detector, otherwise `failed`. Existing JSONL lines above the configured byte cap
are rejected during resume before `JSON.parse`; the minimum configurable cap is
64 KiB so the bounded failure shape itself remains representable.

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

Input rows are scheduled in validated Parquet order, but bounded concurrent
scans append complete JSONL records in completion order. Global line order is
therefore deliberately unspecified and may differ between runs; resume keeps
the existing order and appends newly completed records without sorting.
Determinism is guaranteed inside each record after excluding operational
timestamps and timings. Consumers and tests compare by `(runId, domain)` or a
separately sorted copy, never by raw JSONL line position.

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
  dependency versions, npm v3 lockfile, ESM mode, private-package guard, build
  boundary, and project license consistent as application behavior is added.
- Contract tests compile the two fixed local JSON Schemas with Ajv and validate
  representative positive, negative, nullable, unknown-field, and cross-variant
  fixtures without network access.
- Configuration/model tests cover immutability, JCS digest binding, sanitizer
  behavior, references, deterministic ordering, inferred provenance, status,
  redaction, and configured lower limits.
- Parquet tests cover the exact `root_domain` schema, metadata versions,
  allowed compression, ignored binary-column statistics, row-group
  backpressure, null/empty/invalid rows, limits, corrupt input, and duplicates
  which appear only after canonicalization.
- Unit tests cover target normalization, candidate boundaries, and
  public-address validation.
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

- `hyparquet` reads only the required column through row-group-local projected
  metadata and bounded chunk limits; extra codecs, Arrow, DuckDB, and a Parquet
  writer are excluded;
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
type-checking contract. `tsconfig.build.json` emits application source only, so
tests are never compiled into CLI output. `npm run build` first removes only the
generated, Git-ignored `dist` directory so renamed sources cannot leave stale
JavaScript artifacts.

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

The available project checks are:

```sh
npm run typecheck
npm test
npm run check
npm run build
```

Tests use Node.js 24's built-in test runner and type stripping for `.test.ts`
files. TypeScript still owns strict type checking, while the separate build
configuration emits only `src` into `dist`.

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
- [x] Freeze the Parquet, hostname/address, result, configuration, lifecycle,
  and output-order contracts required by the first coding slice.
- [x] Add the two local JSON Schemas and their contract tests without crawler
  behavior.
- [x] Implement validated configuration, shared TypeScript data contracts, and
  semantic result validation.
- [x] Implement Parquet input and target normalization.
- [x] Implement the protected single-hop HTTP transport and local adversarial
  tests.
- [ ] Implement robots policy and the static HTTP observation collector.
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
7. Input and destination boundaries: **fail-fast Parquet v1 plus exact hostname,
   public-address, and connection-pinning contracts (selected).**
8. Machine contracts: **fixed JSON Schema 2020-12 result/configuration schemas,
   JCS configuration digest, stable error registry, and completion-order JSONL
   semantics (selected).**

The readiness gate, application foundation, and protected single-hop HTTP
transport are complete. The next coding slice is robots policy, followed by the
static HTTP observation collector that orchestrates candidates, redirect hops,
retry policy, content admission, and extraction. Browser automation and
fingerprint detection remain separate later slices.
