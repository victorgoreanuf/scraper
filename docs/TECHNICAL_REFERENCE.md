# Technical Reference

> This document preserves the complete implementation contracts, benchmark
> history, and research log. For the reviewer-oriented project presentation,
> see the [main README](../README.md).

> Project status: the v0.1.9 challenge implementation and final 200-domain
> result are complete. The runnable CLI, evidence-bearing detector, protected
> HTTP/browser collectors, bounded resource policies, incremental output,
> resume, summary, and test suite are implemented. Experimental tier-routing
> work did not pass its development guardrails and remains optional future work;
> it is not required by, or enabled for, the submitted challenge solution.

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

## Final challenge result (v0.1.9)

The final run used clean commit
`05d94594543996a709c3cca5858c24f92d9d1c6e`, Node.js `24.19.0`, Playwright
`1.62.1`, Chromium revision `1234`, and effective catalog digest
`sha256:5aedde4f83d1ad977d646e1495b9b91d4d3b0f6f3acbd34d54906d099da18870`.
It scanned the exact 200-domain challenge input once in `full` mode, without
resume or replacement.

| Metric | Final result |
| --- | ---: |
| Processed domains | 200/200 |
| Domains with at least one detection | 165 |
| Status | 3 success, 190 partial, 7 failed |
| Technology occurrences | 2,098 direct + 167 inferred = 2,265 |
| Distinct directly evidenced names | 351 |
| Distinct names including inference | 366 |
| Challenge reference | Veridion reports 477; labels and aggregation unit are not supplied |
| Average / maximum technologies per domain | 11.325 / 37 |
| HTTP / browser requests | 1,028 / 14,601 |
| Average / p50 / p95 duration | 9,282.67 / 9,040 / 23,500 ms |

The 477 figure is a reference headline rather than a supplied labeled truth
set, so it is not used as a precision, recall, or percentage denominator.
The result deliberately favors attributable detections over inflating the count:
every direct technology includes bounded evidence, while inferred technologies
name their direct parent. A `partial` status preserves useful earlier evidence;
it usually means a later bounded browser, network, or detector stage reached a
limit, not that the record is unusable.

Final deliverables:

- [`output/results.jsonl`](../output/results.jsonl): one canonical result per input
  domain, 4,699,475 bytes,
  `sha256:e28b934763e617debc9825aab4c2cc6f27b0b4d9533350068f252ec091dfd6d7`;
- [`output/results.summary.json`](../output/results.summary.json): aggregate
  metrics and exact run context, 7,173 bytes,
  `sha256:53df7d1daa1f0f868ac3e05482a1f103fa6a82c14e861fb6d10d4807608c227b`.

Both writer-created originals are strict UTF-8 with final LF, mode `0600`, and
one filesystem link. Git deliberately records the published copies as `100644`.
All 200 JSONL records pass the production semantic validator under the embedded
configuration; their unique domain set equals the Parquet input exactly, and a
fresh accumulator rebuilds the published summary byte-for-byte.

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

## Repository layout

```text
.
├── shadow-category-ablation.v1.json
├── src/
│   ├── cli.ts
│   ├── config.ts
│   ├── domain-set.ts
│   ├── evaluation.ts
│   ├── evaluation-calibration.ts
│   ├── model.ts
│   ├── network-policy.ts
│   ├── pipeline.ts
│   ├── input/
│   │   └── parquet.ts
│   ├── crawl/
│   │   ├── transport.ts
│   │   ├── http.ts
│   │   ├── probe.ts
│   │   ├── robots.ts
│   │   ├── browser.ts
│   │   └── infrastructure.ts
│   ├── detect/
│   │   ├── catalog.ts
│   │   ├── engine.ts
│   │   ├── pool.ts
│   │   └── worker.ts
│   └── output/
│       ├── evaluation-writer.ts
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
│       ├── corrections.v1.json
│       └── technologies/ # optional original additions
├── schemas/
│   ├── domain-result.v1.schema.json
│   └── scan-config.v1.schema.json
├── test/
│   ├── fixtures/
│   ├── browser-proxy.test.ts
│   ├── browser.test.ts
│   ├── evaluation.test.ts
│   ├── evaluation-calibration.test.ts
│   ├── evaluation-writer.test.ts
│   ├── toolchain.test.ts
│   ├── catalog.test.ts
│   ├── config.test.ts
│   ├── domain-result-schema.test.ts
│   ├── engine.test.ts
│   ├── http.test.ts
│   ├── model.test.ts
│   ├── parquet.test.ts
│   ├── pool.test.ts
│   ├── probe.test.ts
│   ├── robots.test.ts
│   ├── scan-config-schema.test.ts
│   ├── target.test.ts
│   ├── transport.test.ts
│   ├── pipeline.test.ts
│   ├── summary.test.ts
│   └── writer.test.ts
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
Collect the entry page with protected HTTP
        ↓
Collect catalog-requested DNS records and the retained TLS issuer
        ↓
Freeze and reserve at most one static-only internal candidate
        ↓
Collect the reserved page with HTTP and the bounded catalog probes
        ↓
Render the entry page, complete the bounded full-page plan, and collect browsers
        ↓
Match the complete `full` observations in the isolated detector pool
        ↓
Apply requires / requiresCategory / implies / excludes relationships
        ↓
Sanitize, merge, sort, and write one complete result record
        ↓
Generate run summary
        ↓
Optionally publish the raw-free 200-domain shadow evaluation sidecar
```

The robots fetch is itself an infrastructure request and is not gated by
robots. Before every top-level redirect hop, the new destination is normalized,
resolved, and checked by the same address policy; the cached or newly fetched
robots policy for that scheme and authority is then evaluated for the new path
before the next page request. A cross-authority redirect therefore receives its
own robots policy, while a same-authority redirect still receives a new path
decision.

Catalog probe paths are validated and compiled as non-executable data. For an
HTML entry, the pipeline requests their sorted bounded prefix on the exact final
origin after `T1` infrastructure and the reserved static `T2` page, but before
any browser navigation. Probe requests use the same protected transport, robots policy,
active-domain deadline, and aggregate HTTP limits as page requests. A normal
run submits the complete observation set to the detector once; an explicitly
requested shadow run later performs two additional independent detector passes
over the already bounded `T1` and `T2` prefixes.

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

That preflight also computes an order-independent `domainSetDigest` for the
exact canonical domain set. The versioned construction hashes the UTF-8 tag
`website-technologies-scraper/domain-set/v1\0`, the unsigned 64-bit big-endian
domain count, then every canonical domain in direct UTF-16 order framed by its
unsigned 64-bit big-endian UTF-8 byte length. This digest identifies set
membership, not Parquet row order or file bytes.

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
HTTP collector and the browser collector. The shadow instrumentation below
measures exact static prefixes without skipping that work; functional tiered
routing remains a later orchestration slice.

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

Page and robots redirect `Location` values are resolved and validated lexically
by the transport helper, including canonical public IP literals, but are not
fetched automatically. The next explicit hop performs the authoritative DNS
and socket checks. A catalog-probe `3xx` is deliberately a no-follow miss, so
its `Location` is not interpreted as another probe destination. Local
adversarial tests hook Node's DNS/socket modules only inside the test process
before loading the production module. The hook lives under `test/`, is excluded
from `dist`, and the built transport exports no injectable resolver, connector,
peer metadata, or production option that disables policy.

Top-level requests use `GET`; there is no preliminary `HEAD`. Every DNS answer,
actual connection destination, and every page or robots redirect destination
which may become a new request is revalidated by the shared SSRF policy. A
followed chain may contain at most five redirects, and a cross-origin redirect
must pass the new origin's robots policy before the next top-level request.

### Static HTTP collector v1

`crawl/http.ts` receives the immutable configuration, the domain's protected
transport session, and the run-scoped robots service. The session exposes its
effective read-only abort signal, which combines the configured active-domain
deadline with caller cancellation; retry waits, decode, and extraction use that
same signal. The collector owns deterministic entry-target candidates, page
redirects, one transient retry, content admission, and static extraction. It
neither creates nor closes the session. Entry collection owns the ordered
target-alias fallback and emits `p1`; the page-aware internal operation receives
one already selected exact-origin URL plus `p2` or `p3`, never tries an alias,
and links every page error to that ID. The pipeline combines the entry page's
static links with the rendered links exposed by `crawl/browser.ts` before it
schedules those internal operations.

Robots is evaluated before every candidate request, retry, and page redirect
destination. A denial or unavailable policy stops target resolution;
an alias is never used to evade it. Only 301, 302, 303, 307, and 308 redirect,
with exactly one valid `Location`, at most five hops, and no loop. Any other 3xx
or a redirect without `Location` is `TARGET_REDIRECT_INVALID`. Access-denial
statuses 401, 403, 407, and 451 stop without an alias. Status 429 receives at
most one retry and then becomes access denied; 408, 425, 5xx, and retryable
transport failures receive at most one retry and then move to the next
candidate. Other 4xx responses move directly to the next candidate. Permanent
TLS, SSRF, target-policy, and hard-limit failures stop. Retry uses the same URL,
fresh protected transaction, `isRetry: true`, and an abortable fixed 100 ms
backoff. A single valid `Retry-After` delta-seconds or canonical IMF-fixdate on
429 is honored between 100 ms and the configured two-second cap; an absent,
invalid, or duplicate value uses 100 ms. There is no jitter in deterministic
CLI v1.

A response body is admitted as HTML only when there is exactly one syntactically
valid `Content-Type` whose ASCII-case-insensitive essence is `text/html` or
`application/xhtml+xml`. Parameters are supported; the first syntactically
valid `charset` is forwarded to Cheerio, where a recognized WHATWG label wins
and an unknown label permits BOM/meta/default detection. Missing, duplicate,
malformed, and other media types, plus 204 and 205, are terminal non-HTML
results. MIME is never inferred from body bytes.

Cheerio 1.2 `decodeStream()` receives only the already bounded transport body
and produces the DOM. The pinned implementation is also a Transform that emits
the same decoded source sent to its parser; a regression test guards this exact
version-specific behavior, and an upgrade must revalidate it. `fromURL()` is
forbidden. This keeps the decoded HTML observation without another decoder or
dependency while making the compatibility boundary explicit.

Only a selected final 2xx response contributes headers and cookies. Redirects
contribute only canonical from/to URLs and status, and observations from soft
candidate failures are discarded. Bounded robots text from the selected or a
terminal candidate remains eligible as a signal; soft-candidate robots text is
discarded. Raw observations are immutable and memory-only; sanitization and
evidence redaction happen after matching. `Set-Cookie` extraction uses the first
cookie-pair, a valid token name, and a valid quoted or unquoted cookie value.
Duplicates remain ordered. The count, name, value, and cumulative byte limits
retain a strict accepted prefix and mark it truncated on first overflow; the
cumulative total is UTF-8 bytes of admitted names plus values.

Static DOM extraction is deliberately exact: meta `name` plus `content`, or
`property` only when `name` is absent/empty; `script[src]`; `link[href]` split
into stylesheet or other link by the `rel` tokens; `img[src]`; `iframe[src]`;
and `a[href]` for later page selection. Descendants of inert `template` elements
do not contribute. Metadata pairs have their own 5,000-item prefix cap. The
first valid HTTP(S) `base[href]` sets the resolution base. Every observed URL
passes the shared URL policy,
loses its fragment, remains unfetched, is deduplicated by channel and canonical
URL, and shares the 5,000-observation prefix cap. Only final/page/redirect URLs
map to detector source `url`, and only scripts map to `script_url`; navigation
and other resource kinds remain distinct observations.

After URL and metadata extraction, `script`, `style`, `noscript`, and
`template` nodes are removed and body text collapses ASCII HTML whitespace.
The 512 KiB UTF-8 limit keeps a prefix ending on a Unicode-scalar boundary.
Cookie, metadata, URL, or text overflow preserves prior bounded observations,
emits one `HTTP_RESPONSE_LIMIT_EXCEEDED`, and marks the page `truncated`; the
bounded HTTP collector still completed and the page remains browser-eligible. Body,
decode, or DOM failure marks it `failed`, keeps already bounded final-response
signals, emits its stable transport error or non-retryable
`HTTP_REQUEST_FAILED`, and is not treated as browser-only HTTP success.

`401`, `403`, `407`, `451`, or another explicit status block is permanent:
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
Version 1 deliberately has no text-based CAPTCHA classifier: a 2xx challenge
page is collected as bounded HTML rather than guessed from vendor-specific
phrases.

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

`crawl/robots.ts` is the implemented run-scoped boundary. Its caller supplies
the same protected transport session later used for pages and probes, so robots
requests, redirects, DNS records, bytes, and the active-domain deadline share
one budget. The service coalesces concurrent misses and caches only successful
2xx policies or no-rules 4xx outcomes under the canonical owner origin plus
product token. A rejected fetch is evicted, expiry is exact, and `clear()`
releases the run cache and its bounded raw text. A robots redirect can fetch a
different authority, but its body remains a policy only for the original owner;
the redirect authority requires its own `/robots.txt` lookup when crawled.

The wrapper decodes 2xx bodies with fatal UTF-8, retains the original bounded
text only as a temporary detector signal, and sends a normalized policy to
`robots-parser`. It accepts only `User-agent`, `Allow`, and `Disallow` as
effective directives; unknown, malformed, `Crawl-delay`, `Host`, and `Sitemap`
lines do not change grouping or crawl behavior. A user-agent product token is
valid only as `*` or RFC letters, underscore, and hyphen; empty, versioned, or
otherwise malformed values are ignored. Empty rules and rules beginning with
`/` are accepted, and v1 also accepts leading `*` for compatibility with the
RFC example and reported ABNF erratum; other non-empty rule paths are ignored.
Percent escapes for ASCII unreserved octets are decoded in both rules and
checked paths, while other escapes are uppercased and remain encoded. Exact
case-insensitive `WebsiteTechScraper` groups take precedence over `*`, including
an exact group containing only empty rules or a final exact group with no rule.

Limits are applied before synchronous package matching. Physical lines are
counted after CRLF/CR/LF splitting, with one terminal line ending not creating
an extra line. The 500-rule budget counts the real expanded
`User-agent × Allow/Disallow` associations, including empty rules and duplicate
agents; the canonical pattern is capped after percent normalization. For a
checked URL, the wrapper rejects before matching when
`sum(pattern.length × (path.length + 1))` for the selected group would exceed
the configured character-state budget. It calls `isAllowed()` exactly once and
treats the package's unexpected `undefined` result as unavailable.

Version 1 does not retry a failed robots fetch inside this service: `404`, `410`,
and other non-denial non-transient 4xx responses produce an allow-all no-rules
policy, while `401`, `403`, `407`, `451`, `408`, `425`, `429`, other 3xx,
5xx, invalid UTF-8, and unusable content fail closed. Protected transport
errors retain their original DNS/TLS/SSRF/deadline diagnostics. Local robots
limits and redirect loops/overflow use `ROBOTS_LIMIT_EXCEEDED`; other local
policy failures use `ROBOTS_UNAVAILABLE`. A rule denial is the normal
`allowed: false` decision so entry-page orchestration can record
`ROBOTS_DISALLOWED`, while internal pages and probes can treat it as an
intentional skip.

The run cache is deliberately sufficient for the 200-domain challenge but has
no independent entry/byte cap yet. Before a worker scans an unbounded partition
at million-domain scale, the configuration must add a measured cache-entry and
cache-byte limit or a bounded LRU; the current code must not be presented as an
unbounded production cache.

The scanner visits at most three top-level pages:

1. the canonical `entry` page;
2. one discovered product or `detail` page;
3. one discovered collection/category/shop `listing`, or a useful `content`
   fallback.

Page-selection policy v1 never guesses a path, reads links from `p2`/`p3`, or
crawls recursively. Each candidate must parse as canonical
HTTP(S), use exactly the final entry origin (scheme, hostname, and effective
port), have empty credentials, query, and fragment, fit the configured URL
limit, and differ from both the final entry URL and the origin root. Canonical
duplicates are removed before classification.

Classification uses lowercase canonical path segments. Any segment equal to
`auth`, `login`, `log-in`, `signin`, `sign-in`, `signup`, `register`,
`account`, `admin`, `wp-admin`, `cart`, `basket`, `bag`, `checkout`, `logout`,
`search`, `legal`, `privacy`, `terms`, `policy`, `cookie`, or `cookies` rejects
the URL. A candidate is also rejected as file-like when its final non-empty
segment ends in a dot followed by one or more ASCII alphanumeric characters.
A `detail` candidate contains `product`, `products`, `item`, or `items` with at
least one following non-empty segment. Otherwise a `listing` candidate contains
`shop`, `store`, `catalog`, `category`, `categories`, `collection`,
`collections`, or `product-category`; every other eligible non-root path is a
`content` candidate.

Within each class, the token order written above is the fixed class rank, then
the shorter canonical pathname wins, then the complete canonical URL in direct
ascending UTF-16 code-unit order. The selector keeps at most one `detail` and
one `listing`; only when no listing exists may one `content` candidate occupy
the non-detail slot. An absent detail never receives a different role. Its at
most two choices are sorted by complete canonical network URL.

After entry infrastructure has completed, the orchestrator runs that selector
on a frozen copy of the static `p1` navigation links and reserves its first
choice as the only possible internal page in `T2`. The candidate receives
exactly one robots check and, if admitted, one protected HTTP collection before
probes or browser work. The reservation consumes either the detail or non-detail slot
even when denied, unavailable, skipped after sanitization, or failed; it is
never backfilled. After browser `p1`, the full plan applies the same selector to
the union of static and rendered links, preserves the reservation, and may add
at most one candidate from the opposite structural slot. That candidate also
receives no backfill, so the domain still performs at most two internal robots
checks and visits at most `topLevelPerDomain - 1` internal pages.

Admitted internal results are sanitized for publication, collisions with the
entry page or another survivor are removed, and the survivors are sorted by
public URL before receiving compact IDs `p2` and `p3`. A provisionally collected
reserved page is remapped to that final ID; therefore pre-browser collection
cannot invalidate wire order and a removed first candidate cannot leave an ID
gap.

Catalog probes do not count as pages. Their collection policy is defined below
and does not change page selection, page IDs, `pagesVisited`, or browser-prefix
semantics.

### Catalog probes v1

`crawl/probe.ts` receives only the final network URL of an HTML entry, the
probe paths from the deeply frozen catalog inspection plan, the validated
configuration, and the same protected transport session and run-scoped robots
service used by static pages. A non-HTML or unresolved entry schedules no
probes. Probe collection is sequential after T1 DNS/TLS and the reserved static
`T2` page, but before browser navigation, browser-session finalization, and
detection.

The compiler and collector both enforce at most five unique paths. Each path is
an absolute same-origin pathname beginning with one `/`, with no credentials,
backslash, query, or fragment; it must survive WHATWG URL resolution without
normalization. The collector revalidates and sorts paths by direct ascending
UTF-16 code-unit order, resolves each against the exact final origin root, and
never uses the final page pathname as a base. Both the path and the complete
composed `origin + path` URL must fit the configured URL limit; an over-limit
composed URL emits non-retryable `HTTP_LIMIT_EXCEEDED` before robots or
transport reservation and stops the stage.

Before each path, the collector evaluates robots for the resolved URL. A rule
denial skips that path without issuing a probe or recording an error, while an
unavailable robots policy fails closed, preserves its stable error, and stops
the probe stage. A successfully admitted robots body remains a bounded
`robots` detector signal and is deduplicated with bodies collected elsewhere.

Each allowed path receives exactly one protected `GET` with body purpose
`probe`. Version 1 performs no probe retry and follows no probe redirect. Only
a `2xx` response produces an observation. `204` and `205` therefore produce an
empty body observation. Ordinary `3xx` responses are not followed, and ordinary
`4xx` responses are misses which continue to the next sorted path. `401`,
`403`, `407`, and `451`
emit a non-retryable `HTTP_REQUEST_FAILED` and stop the remaining probe
stage; `408`, `425`, `429`, and `5xx` emit the same stable code as retryable and
also stop without an in-scan retry.

An admitted body uses the probe-specific 256 KiB compressed and 512 KiB
decompressed limits and is decoded as UTF-8 with deterministic replacement for
malformed byte sequences. This keeps a successful bounded response available
to a presence rule without interpreting an arbitrary legacy charset; literal
rules match only the resulting bounded string. Transport, deadline,
decompression, destination-policy, or size failures keep their stable error and
stop the stage. Probe bytes also consume the aggregate static-transfer and
decompressed-domain budgets.

The transport increments `usage.probesIssued` atomically with
`usage.httpRequests` when a `purpose: "probe"` transaction is actually
reserved, including a transaction which later fails. Robots-denied or
pre-reservation rejected work does not increment it. The transport independently
enforces both the five-probe limit and the 40-transaction domain limit.

A successful observation supplies the exact validated path as detector key and
the decoded body as its bounded value. This supports both catalog presence rules
and literal body rules without treating response headers, cookies, status, or
URL as additional probe signals. Public evidence is always
`collector: "http"`, `source: "probe"`, `pageId: null`; the path remains the
locator and every matched probe-body value is redacted.

### Browser behavior

`crawl/browser.ts` implements a bounded FIFO pool with one protected proxy and
one reusable Chromium process per `fullScans` slot (three by default). Every
slot is preflighted before domain work, and the pool freezes one runtime identity
for Playwright `1.62.1`, Chromium revision `1234`, and the common runtime version
reported by those processes. A disconnected process receives at most one
replacement; other slots continue at reduced capacity, while loss of every slot
latches the pool unavailable instead of spawning indefinitely.

The complete startup or replacement preflight for a slot is bounded by
`limits.timeMs.browserPage`. Page, context, browser-process, proxy, and canary
teardown uses a fixed one-second watchdog, so a wedged Playwright close cannot
hold FIFO admission indefinitely. A replacement that cannot complete its own
preflight is removed rather than retried in a spawn loop.

The same one-second cleanup watchdog bounds an internal drain when caller or
domain cancellation wins the race against an already-started page collection.
`collectPage()` waits for that collection to settle, or for the watchdog, before
it propagates the failure. This lets `finish()` retain the exact proxy/page
diagnostic and raw-free limit telemetry already being finalized instead of
racing the still-active collection; it neither retries the page nor extends the
domain work without a bound.

Every selected 2xx HTML page in `full` mode is rendered in a non-persistent
Chromium context dedicated to that domain. The same context is reused
sequentially for its ordered `p1` through `p3` pages and then destroyed; only
one page is active at a time, all pages use the exact selected origin, and an
aborted waiter cannot consume a pool slot. Collection waits for
`DOMContentLoaded` and a bounded two-second settle window, never unbounded
`networkidle`.

An inspection, cookie, network-observation, or script-body limit retains the
bounded browser draft, records `BROWSER_LIMIT_EXCEEDED`, marks the page
truncated, and keeps the ordered browser prefix eligible for the next selected
page. `PageRecord.collectors` therefore includes `browser` for both complete
and truncated admitted drafts. A failure before observation admission produces
no usable draft; a terminal proxy, timeout, navigation, policy, lifecycle, or
cleanup failure always closes the prefix even when the current page's earlier
bounded draft remains admissible.

A DOM inspection whose facts are all `exists` needs only one qualifying match.
It stops at that first match and emits every requested presence fact without a
false `inspection.domMatches` truncation; a zero-match selector traverses to the
end and remains an ordinary empty observation. Mixed, text, attribute, and
property inspections retain the existing per-selector match cap because their
values can differ across elements.

The collector also returns a bounded, deduplicated limit-hit list for the
evaluation boundary. Each hit is a stable category plus a DOM-selector ordinal
only for selector-specific DOM failures; public `DomainResult.errors` keeps its
existing generic sanitized error and does not expose this diagnostic detail.

The browser keeps its sandbox and CSP, has no permissions, blocks service
workers, disables downloads, and never clicks, scrolls, submits forms, accepts
consent, authenticates, or bypasses access controls. `GET`, `HEAD`, and
`OPTIONS` may continue. Other methods and WebSockets are recorded only as
attempted requests, contribute only a hostname observation, and are then
aborted; images, fonts, and media contribute their URL/hostname observations
and are aborted to conserve the budget. Popups are closed.

Context-wide Playwright routing owns initial-request method, resource, origin,
robots, observation, and logical-request accounting. A Chromium DevTools
Protocol `Fetch` gate additionally pauses both response and request stages for
automatic redirects. At the response stage it validates exactly one usable
`Location`, the URL/method/resource policy, loop and depth limits, and, for a
top-level document, the exact selected origin plus a synchronous
`allowTopLevelUrl(url) === true` robots decision. The pipeline warms that policy
through the asynchronous protected robots check before navigation; the browser
gate then uses only `RobotsPolicyService.allowsCached(url)`. A missing, pending,
expired, invalid, or unavailable cache entry returns exactly `false`: the CDP
pause path never starts network I/O, awaits a Promise, or treats an unknown
answer as permission. At the following request stage
it requires the matching `redirectedRequestId` and expected target before it
records and grants that hop exactly once. A mismatch, asynchronous/non-boolean
robots decision, or denied hop fails before the redirected target reaches the
network. The same response-stage gate admits the root document body only for an
exact 2xx HTML/XHTML response; access-denial and non-HTML bodies are stopped
before their scripts can run. Once that document is admitted, further
top-level navigations are blocked during settle and inspection so observations
cannot be attributed to a different document.

Up to 20 bounded script bodies are collected from responses the browser already
fetched, rather than downloaded a second time. Eligible script URLs are
deduplicated and ranked by page ID first, then same-origin before cross-origin,
then normalized URL in UTF-16 code-unit order; the fixed top 20 are used, and an
unavailable response is not replaced based on completion timing.

All browser HTTP(S) and CONNECT traffic passes through the project-owned local
forward proxy in `crawl/transport.ts`. The proxy resolves every authority,
rejects mixed or non-public answers, pins port 80/443 connections to the
selected public address, and verifies the connected peer. Each admitted plain
HTTP request receives one consumable proxy grant. HTTPS remains an opaque TLS
tunnel, so Playwright/CDP owns per-request logical admission and counting while
the proxy authorizes the CONNECT authority, enforces egress, and counts
downstream encrypted tunnel bytes. Chromium is configured to use the proxy
without a destination bypass, with service workers, QUIC, and non-proxied WebRTC
traffic disabled. Playwright/CDP interception is an additional
navigation/method/redirect guard, not the SSRF boundary.

Every accepted proxy TCP socket is owned by the page generation active at
accept time. A socket accepted while no page is active, including the cleanup
gap between two ordered pages, is destroyed immediately; it cannot survive into
the next page and consume that page's reset HTTP or HTTPS grants. A
syntactically valid CONNECT without a current HTTPS grant receives a local 502
without DNS or an upstream connection and does not poison the domain; malformed
method, authority, Host, port, headers, or protocol input remains a terminal
proxy failure.

For every pool slot, startup launches a loopback canary and maps one random
synthetic hostname to it through Chromium's fixed resolver rule and the proxy's
canary resolver. The proxy must reject the non-public answer and the listener
must receive zero connections. Any failed launch, control, version, proxy, or
canary preflight stops `full` mode before domain processing or output creation.
At production scale, host/container egress rules also restrict Chromium to the
local proxy. A proxy failure during a domain scan closes the context and yields
a partial result without treating the reusable Chromium process as unhealthy;
only a browser disconnect or cleanup failure consumes the slot replacement.

### DNS and TLS infrastructure signals v1

`crawl/infrastructure.ts` owns infrastructure collection policy v1. DNS queries
always use the exact canonical input domain as owner; they do not follow the
selected target alias, `www` hostname, redirect hostname, or an address learned
from page content. The compiled catalog plan supplies the set of required record
types. The collector issues only those typed `A`, `AAAA`, `CAA`, `CNAME`, `MX`,
`NS`, `PTR`, `SOA`, `SRV`, or `TXT` queries, in fixed record-type order, and
never sends `ANY` or speculative queries.

Resolver answers become one string per record using these fixed
normalizations:

- `A` and `AAAA`: canonical public address text;
- `CNAME`, `NS`, and `PTR`: lowercase hostname without a trailing dot;
- `MX`: its normalized lowercase `exchange` without a trailing dot, excluding
  priority;
- `SOA`: its normalized lowercase `nsname` without a trailing dot, excluding
  mailbox and timing fields;
- `SRV`: its normalized lowercase `name` without a trailing dot, excluding
  priority, weight, and port;
- `CAA`: the record value only, excluding its critical flag and property name;
- `TXT`: the chunks of each TXT item joined with no separator.

Every raw `A`/`AAAA` answer must pass the same canonical public-address policy
used by protected transport. The collector never keeps a public subset from a
mixed or otherwise invalid address answer. `recordsPerType` and
`recordsPerDomain` count raw resolver records before normalization,
deduplication, or sorting, and all typed queries share one session-wide DNS
record budget. Normalized observations are then deduplicated and sorted with
direct `<`/`>` comparison. TXT item and aggregate DNS text limits remain shared
across that session.

`ENODATA` and `ENOTFOUND` are ordinary absence for the requested type: they add
neither an error nor a retry. The complete DNS stage has one absolute
`dnsLookup` deadline, ten seconds by default, shared by every requested type;
timeout or upstream cancellation cancels outstanding resolver work rather than
starting a fresh per-type window. The collector performs no DNS retry.

TLS issuer evidence may come only from the already certificate-verified and
IP-pinned handshake of the selected final HTTPS transport response. The
infrastructure collector never opens a second TLS connection. If there is no
final response, the final URL is HTTP, or that verified handshake exposes no
issuer, TLS collection is skipped without an error. Issuer text is admitted
only when it fits the 4 KiB UTF-8 `issuerBytes` limit; it is never truncated,
and overflow emits non-retryable `TLS_LIMIT_EXCEEDED`. Version 1 deliberately
does not expose DNSSEC state, TLS protocol, cipher, certificate subject, SANs,
serial numbers, validity dates, or cryptographic material as detector evidence.
These rules are fixed by `policyVersions.infrastructure: 1`.

### Pipeline orchestration contract v1

`scanDomain(domain, runtimeContext)` coordinates one domain and remains
independent of the input reader and output writer. The run-owned context binds
the immutable validated configuration and provenance to the compiled catalog,
detector pool, browser pool, protected transport, and robots service. Catalog,
runtime, digest, and pool-availability mismatches fail preflight rather than
starting a partially identified scan. A domain scan closes only the transport
and browser sessions it opened; it does not close or clear run-owned pools or
the shared robots cache.

The FIFO wait for a `full` browser-scan slot happens before the active-domain
clock starts. Caller cancellation remains effective while queued, but the
`activeDomain` timer is dormant; only after slot admission does the pipeline set
`scannedAt`, start monotonic `totalMs`, arm that timer, and create the protected
transport session with the combined signal. HTTP scheduler waits, robots work,
retry backoff, browser navigation, DNS/TLS, detection, and cleanup after that
point are inside the active-domain deadline. Caller cancellation is propagated
after bounded cleanup and does not fabricate a `DOMAIN_DEADLINE_EXCEEDED`
record; that code is reserved for the pipeline-owned active timer. The proxy
and transport retain same-duration local fail-safe timers for standalone use,
but in `scanDomain()` they receive the already armed pipeline signal, which is
the first and authoritative deadline.

The admitted scan performs these bounded steps:

1. collect the selected target as HTTP `p1`, with robots checked for the
   candidate and every redirect;
2. collect catalog-requested DNS records and reuse the verified entry HTTPS
   issuer; entry plus infrastructure completes `T1` before any `T2` work can
   consume the active-domain deadline;
3. for an HTML `p1`, freeze the static links, reserve the deterministic `T2`
   candidate, perform its one robots check, collect it once with protected HTTP
   when admitted, and then collect sorted bounded probes on the exact final
   origin; denial or failure consumes the reservation without backfill, and this
   stage completes the pre-browser `T2` prefix;
4. for a complete or truncated 2xx HTML `p1`, collect the same URL in the
   browser, combine rendered and static links for the `full` plan, preserve the
   reservation, and add at most one candidate from the opposite structural
   slot;
5. collect that additional candidate with robots and HTTP when admitted, sort
   all admitted internal results by sanitized public URL, assign compact
   `p2`/`p3`, and collect their browser-eligible ordered prefix;
6. finish the browser session, then invoke the detector pool once under the
   active-domain deadline with the complete bounded HTTP `p1`–`p3`, browser,
   robots, probe, DNS, and TLS observations;
7. sanitize, deduplicate, sort, enforce result caps, and pass the authoritative
   `DomainResult` through the semantic validator;
8. only when shadow evaluation was explicitly requested, clear the pipeline
   deadline and invoke the detector independently for `T1` and `T2` under caller
   cancellation, then emit one allowlisted raw-free snapshot. These extra passes
   do not alter the validated `full` result or its timings.

Every successfully admitted robots body from entry collection, structural
prechecks, internal-page collection, or probe checks remains a detector signal
with `pageId: null`, even when the associated page or probe is later skipped or
fails. Exact duplicates are collapsed by the detector, and any retained robots
body counts as an admitted signal for `partial` versus `failed` status.

A failed static page is never presented as browser-only success. Browser pages
form an ordered prefix of eligible `p1`–`p3`; once an earlier browser page
cannot be collected, the pipeline does not create a later browser-page gap,
although already selected later pages may still contribute static HTTP
observations. A final entry 2xx non-HTML response still follows its documented
terminal partial-result path and schedules no internal pages or catalog probes.

Stage timings use the same monotonic clock. `targetMs` covers entry target
selection, `robotsMs` accumulates robots work, and `httpMs` covers static page
and probe HTTP work excluding the robots time nested inside it; `browserMs`,
`dnsMs`, `tlsMs`, and `detectMs` cover only started stages. Named stages may
overlap and are clamped to `totalMs`. A skipped stage is `null`, and a
completed sub-millisecond stage may be `0`.

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
- bounded browser request URLs and canonical public hostnames;
- validated catalog-probe paths and bounded decoded response bodies;
- DNS records and TLS issuer.

The detector consumes those observations and produces:

- technology name and categories;
- optional version;
- technology confidence from `1` to `100`; individual evidence and inference
  contributions may range from `0` to `100`;
- `direct` or `inferred` detection type;
- one or more evidence records;
- the pages on which the technology was observed.

The catalog compiler produces a deeply frozen generic inspection plan whose
shared types are owned by `src/model.ts`; `crawl` therefore does not depend on
`detect`. The browser evaluates only the requested DOM facts and safe
JavaScript-property paths under their configured caps. It emits no serialized
DOM and never enumerates, calls, or stringifies the complete `window` object.
For a DOM inspection containing only attribute facts, the per-selector match
cap counts only selector-matching elements that carry at least one requested
attribute. Irrelevant elements are traversed but do not consume the observation
budget; existence, text, property, and mixed inspections retain raw selector
match accounting.

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

At scan time `scanDomain()` supplies the non-serialized `signalAdmitted` fact
when it validates the `partial`/`failed` distinction; omitting that boolean is a
validation failure. The writer validates the exact serialized value under the
persisted-record semantics before appending it. Writer and resume validation
cannot reconstruct that collection-history fact from the v1 wire record, so
they trust its pipeline-validated status while still enforcing the fixed wire
schema, context-independent semantic invariants, configured limits, run
identity, and provenance.

Every result has exactly the top-level fields `schemaVersion`, `runId`,
`domain`, `scannedAt`, `status`, `finalUrl`, `scanMode`, `pages`,
`technologies`, `detectionStats`, `errors`, `timings`, `usage`, and
`provenance`.
`schemaVersion` is `1`; `runId` is a UUID; `scannedAt` is the exact UTC form
produced by `Date.prototype.toISOString()`; and `scanMode` is `full` in this
version. `finalUrl` is the only nullable top-level scalar. Arrays always exist,
all usage counters are non-negative integers, `totalMs` is a non-negative
integer, and each named stage timing is a non-negative integer or `null` when
that stage never started or was skipped. Provenance is complete and non-null
because missing runtime, catalog, or validated configuration identity is a
global preflight failure rather than a per-domain result.

`detectionStats` persists exactly `rawDirect`, `gatedDirect`,
`suppressedDirect`, and `retainedDirect`. `rawDirect` counts positive-confidence
direct candidates before relationships, `gatedDirect` counts those not admitted
by requirements, `suppressedDirect` counts admitted candidates removed by
exclusions, and `retainedDirect` counts the remaining direct detections before
final output materialization. Every counter is bounded by the fixed v1 catalog
technology ceiling of 20,000, and `rawDirect` is exactly the sum of the other
three. These counters remain available even when bounded output materialization
or a final record-size limit must discard the technology array.

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
  "detectionStats": {
    "rawDirect": 1,
    "gatedDirect": 0,
    "suppressedDirect": 0,
    "retainedDirect": 1
  },
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
    "httpRequests": 5,
    "browserRequests": 24,
    "retries": 0,
    "pagesVisited": 1,
    "probesIssued": 3,
    "scriptBodiesInspected": 4,
    "staticTransferredBytes": 18320,
    "browserTransferredBytes": 130000
  },
  "provenance": {
    "scannerVersion": "0.1.5",
    "runtime": {
      "node": "24.19.0",
      "playwright": "1.62.1",
      "chromiumRevision": "1234"
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
`meta`, `script_url`, `script_content`, `dom`, `javascript`, `network_url`,
`network_hostname`, `dns_record`, `tls_issuer`, `robots`, or `probe`. `collector` is `http`,
`browser`, `dns`, or `tls`; `pageId` is `null` for non-page infrastructure
signals and is required for every browser observation. `key` identifies the
header, cookie, metadata name, selector, JavaScript path, DNS record type, or
equivalent locator and is `null` for an unkeyed signal; `dns_record` always uses
a non-null uppercase record-type key, while `probe` uses its exact validated
path as a non-null key. Evidence `pageId`,
`key`, `pattern`, and `version` are the only nullable evidence scalars.
`match.value` is nullable under the redaction rules below.

`PageRecord.collectors` lists only collectors which admitted a bounded page
draft, including a truncated HTTP or browser draft; failures are linked by
`pageId`. Error `stage` is one of `target`, `robots`,
`http`, `dns`, `tls`, `browser`, or `detect`. `usage.httpRequests` excludes
browser traffic, while `usage.browserRequests` counts requests admitted or
explicitly aborted by browser policy. Every candidate, robots fetch, redirect
hop, retry, and page which reaches the HTTP transport increments
`httpRequests`; `retries` counts only additional attempts. `pagesVisited` equals
the number of emitted `PageRecord` values. `probesIssued` counts only
`purpose: "probe"` transactions reserved by the protected transport, is capped
at five, and is always less than or equal to `httpRequests`; a later network or
body failure does not undo an already reserved count. `scriptBodiesInspected`
counts bounded bodies admitted to detection.

`staticTransferredBytes` counts compressed response-body bytes read by the
protected Node transport. `browserTransferredBytes` counts downstream bytes at
the browser proxy; for HTTPS CONNECT this is conservative encrypted tunnel
traffic, not a claim about decoded response-body size. `scannedAt` is the UTC
wall-clock time at which the domain leaves the FIFO `full`-scan queue and
receives its active slot; queue wait is excluded from the active-domain
deadline and timings. `totalMs` and all seven named stage timings are
non-negative integer milliseconds measured with a monotonic clock; stage times
measure active wall time and may overlap, so they need not sum to total. A
skipped or never-started stage is `null`, while a completed sub-millisecond
stage may be `0`. Usage values are non-negative integers and remain `0` when the
corresponding work is skipped.

A technology has exactly `name`, `categories`, `version`, `confidence`, `type`,
`pageIds`, `evidence`, and `inferredFrom`; only its scalar `version` is
nullable, and its confidence is always at least `1`. A direct detection has at
least one evidence item and an empty `inferredFrom` array. An inferred
detection has no evidence or page IDs and
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
| TLS | `TLS_CONNECTION_FAILED`, `TLS_CERTIFICATE_INVALID`, `TLS_TIMEOUT`, `TLS_LIMIT_EXCEEDED` |
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
- a direct technology requires at least one matched rule whose confidence is
  greater than zero; matched `confidence:0` rules may contribute companion
  evidence or a version only after another matched rule admits that technology;
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

The fixed point uses a deterministic priority heap, and exclusion components
plus emitted inference provenance are validated iteratively rather than with
recursive graph traversal. This keeps the accepted 20,000-technology boundary
operational without quadratic queue sorting or JavaScript call-stack growth.

Evidence redaction is part of the schema contract:

- `match.value` contains only an allowlisted exact sanitized match, never the
  surrounding document, element, script, or header, and is capped at 256
  Unicode code points with deterministic truncation;
- every URL persisted anywhere in results, evidence, errors, or logs uses the
  same sanitizer: userinfo and fragments are removed, query values become
  `[redacted]`, opaque/sensitive/oversized query names also become
  `[redacted]`, and an opaque or sensitive path segment becomes `[redacted]`;
  a path segment is retained only when it is at most 64 unreserved code units
  and is not a UUID, a hexadecimal token of at least 16 characters, an
  unseparated base64url-like token of at least 24 characters, or adjacent to
  `token`, `key`, `signature`, `session`, `auth`, `password`, `secret`, or
  `code`; if those markers would expand the public URL past its configured
  bound, page/result URLs collapse deterministically to
  `origin/%5Bredacted%5D` with no query, while URL evidence from the original
  observation remains fully redacted;
- cookie values are never emitted or hashed; only a bounded non-sensitive
  cookie name remains, while an opaque/session-like name becomes `key: null`,
  and a value-dependent match uses `match.kind: "redacted"`;
- request headers are never persisted; sensitive response-header names and
  values, including authorization, cookies, tokens, secrets, signatures, API
  keys, credentials, and authentication schemes such as Basic, Bearer, Digest,
  Negotiate, NTLM, or AWS4-HMAC-SHA256 are always redacted. Authentication
  schemes are recognized at token boundaries anywhere in an allowlisted header
  or metadata value, not only at the beginning;
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
- an extracted version is emitted only from a non-redacted source, only when it
  matches `[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}`, and only when both the matched
  fragment and derived version pass the same credential/token classifier;
  a URL-derived version is allowed only when the observed URL has no userinfo,
  query, or fragment at all and its pathname survives URL sanitization
  unchanged;
  otherwise both the evidence version and that technology's candidate version
  are `null`;
- unknown values fail closed to redaction, and errors never include stack
  traces, response bodies, raw headers, cookies, or unsanitized URLs.

Raw observations are bounded and exist only in memory until detection and
sanitization finish. Version 1 does not persist HTML, DOM, script bodies,
headers, cookies, JavaScript values, network logs, or hashes of secrets.
Cookie names and bounded values may exist only long enough to evaluate the
catalog rule; values are never persisted, logged, or hashed, and a
value-dependent result exposes only a bounded non-sensitive cookie name
(otherwise `key: null`) plus a redacted match. The rendered DOM remains owned
by Chromium: Node receives only bounded facts for
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
| DNS lookup stage | 10 seconds absolute across all requested record types |
| Browser page including settle | 15 seconds |
| Canonical target candidates | 4 |
| Redirects per chain | 5 |
| Static HTTP transactions per domain | 40 total, including robots, candidates, redirects, retries, pages, and probes |
| Transient retry | 1 per eligible static-page request, still inside the 40-transaction total; robots and probes do not retry |
| Top-level pages | 3 |
| Catalog probes | 5 maximum; one sorted exact-origin `GET` per path |
| Input hostname | 2,048 UTF-16 code units |
| Any fetched or persisted URL | 2,048 UTF-16 code units |
| Header fields / total header bytes | 100 / 64 KiB |
| HTML body per page | 2 MiB compressed / 4 MiB decompressed |
| Total static decompressed bytes | 32 MiB per domain |
| Probe body | 256 KiB compressed / 512 KiB decompressed |
| Script URL candidates / bodies | 80 / 20; bodies 2 MiB each / 16 MiB total |
| Browser request URLs / unique public hostnames | at most 300 bounded URLs / 200 hostnames per domain |
| Browser requests | 150 per page / 300 per domain |
| Browser transfer | 15 MiB per page / 30 MiB per domain |
| Cookies | 100 per domain; 256-code-unit name / 4 KiB value / 64 KiB total |
| DNS | 32 records per type / 128 total; 4 KiB TXT item / 64 KiB DNS text total |
| TLS issuer | 4 KiB UTF-8, never truncated |
| robots.txt | 512 KiB; 5,000 lines; 500 rules; 512 code units per rule |
| Robots matching work | 1,000,000 pattern-path character states per checked URL |
| Extracted link/resource URLs | 5,000 per page |
| Extracted metadata pairs | 5,000 per page |
| Extracted visible text | 512 KiB per page |
| DOM inspection | 5,000 selectors; 1,024 code units each; 20 qualifying matches per selector |
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
technology materialization rather than publishing an unsupported prefix, emits
`technologies: []`, and adds one bounded terminal
`detect/RESULT_LIMIT_EXCEEDED` record: `partial` when a signal reached the
detector, otherwise `failed`. Existing JSONL lines above the configured byte cap
are rejected during resume before `JSON.parse`; the minimum configurable cap is
64 KiB so the bounded failure shape itself remains representable.

Queue wait is measured separately; the domain deadline begins only after the
job receives a full-scan slot. Reaching a limit cancels the affected work,
releases resources, records a stable error, and preserves earlier observations.
All limits live in one validated runtime configuration. CLI v1 uses the reviewed
defaults with a required real contact, or accepts one complete local JSON
`ScanConfig`; it does not add a second YAML system or dozens of partial flag
overrides.

The effective catalog currently yields 1,767 unique DOM selectors, 1,778 exact DOM
facts, 5,570 unique JavaScript paths, and 113 browser request-URL rules after
deduplication, so the inspection-plan and request caps admit the entire reviewed
baseline. A future effective upstream-plus-custom catalog which
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

## Runnable CLI v1

The built entry point is `dist/cli.js`, exposed locally as
`website-technologies-scraper`. Build and inspect it with the pinned runtime:

```sh
npm run build
./dist/cli.js --help
./dist/cli.js \
  --contact "$CRAWLER_CONTACT" \
  --input input/domains.parquet \
  --output results.jsonl
```

Set `CRAWLER_CONTACT` to the operator's real HTTPS or `mailto:` contact before
the scan; the repository deliberately provides no copyable placeholder
identity. Direct invocation keeps scan stdout empty, whereas npm may print its
own lifecycle banner around `npm start`.

`--input` defaults to `input/domains.parquet`, and `--output` defaults to
`results.jsonl`; the output parent must already exist. Exactly one configuration
source is required:

- `--contact <https://...|mailto:...>` creates the immutable reviewed default
  configuration and constructs
  `WebsiteTechScraper/<package-version> (<canonical-contact>)`; the CLI never
  ships a fictitious contact;
- `--config <path>` reads at most 1 MiB of strict UTF-8 JSON and requires one
  complete `ScanConfig` v1 whose User-Agent carries the actual package version.

Operational flags are `--resume`, `--force`, `--shadow-evaluation`,
`--shadow-candidate`, `--shadow-candidate-digest`, `--quiet`, `--help`, and
`--version`. Candidate path and digest are an inseparable pair and are valid
only with shadow evaluation. Resume and force are mutually exclusive, and
shadow evaluation is valid only in the default fresh-create mode, never with
either of them. Unknown, positional, or duplicate options fail before input,
output, browser, or network work. The CLI
validates the exact Node version, preflights the complete Parquet input, rejects
result or paired-summary aliases of input/config files, compiles the catalog,
preflights detector workers and protected Chromium, and only then opens the
writer. Resume records must all belong to the validated current input before
any domain crawl starts.

The second Parquet pass is streamed with at most
`limits.concurrency.fullScans` tasks in flight. Each task includes both
`scanDomain()` and its serialized append, so a slow output applies backpressure;
records remain completion-order. Stdout is empty during a scan. Bounded progress
uses only the canonical domain, count, and status on stderr; `--quiet` suppresses
progress but never fatal diagnostics. A completed batch exits `0` even when
individual domains are `partial` or `failed`; loss of an entire required pool or
a fatal preflight/orchestration/output error exits `1`, invalid usage exits `2`,
and graceful SIGINT/SIGTERM cleanup exits `130`/`143`. The first signal aborts
work and closes input, writer, browser, and detector resources without a false
summary; a second signal uses the operating system default termination.
`CLI_DEGRADED` identifies the unavailable `detector`, `browser`, or both pools.

### Shadow evaluation CLI

`--shadow-evaluation` is the narrow measurement entry point for protocol
revision `2026-08-20.1`. It requires the exact validated 200-domain input before
catalog, pool, writer, or network startup and keeps at most one allowlisted
snapshot per unique domain, with a hard cohort cap of 200. It does not enable
functional tier routing: every domain still receives the authoritative `full`
scan. A regular run exposes no shadow callback and retains the single detector
pass described above.

A shadow run creates three run-owned detector pools over the same compiled
catalog: the ordinary `full` pool and distinct dedicated `T1` and `T2` pools.
The two shadow pools are also distinct from one another and their passes run
concurrently after the corresponding `full` result is validated. They do not
share detector slots, worker lifecycle state, or per-worker regex objects, so a
shadow queue/failure cannot be reinterpreted as a result from another view or
consume the full pool's slots. This isolation has a deliberate cost: startup
compiles the catalog independently in every worker across three pools and holds
`3 * limits.detector.workers` worker isolates (six with the reviewed default),
while shadow matching adds CPU after each full result. The pools can still
contend for host CPU and memory, so the sidecar does not claim unchanged
wall-clock performance.

The sidecar name is derived from the canonical result path: a terminal
`.jsonl` is replaced with `.evaluation.json`, while another suffix receives an
appended `.evaluation.json`. Thus `results.jsonl` produces
`results.evaluation.json`. The CLI preflights this create-only target alongside
the result, summary, input, and optional configuration paths. Any existing
regular file, symlink, hard link, non-file, alias, or late publication race is
rejected without clobbering it. The compact UTF-8 JSON sidecar is written to an
exclusive temporary regular file with mode `0600`, synchronized, and published
without replacement as a single-link `0600` file. There is no shadow resume or
force mode.

The primary JSONL and summary finalize first. The exact 200 snapshots are then
validated and the browser-limit aggregates are built; run-owned
input/browser/detector resources close before the sidecar is published. A
regular shadow run without a candidate contains a `development-source` OOF
report and cannot publish or imply a frozen model because its own byte digest
does not exist until publication. A paired `D2` run additionally requires the
digest-pinned preregistration, development manifest, and already sealed `H1`
manifest. It publishes a `paired-development-source` envelope which binds all
three digests plus the category-projection digest before offline calibration.
The development manifest itself pins the exact sealed-`H1` manifest digest.
With the paired candidate and `H1` manifest flags, the CLI verifies the exact
file digest and scanner/config/catalog/protocol compatibility before starting
pools, then publishes a `paired-frozen-holdout` report which never trains. A
snapshot, evaluation, serialization, or sidecar I/O failure is fatal.

The candidate also pins the order-independent digest of its exact canonical
training-domain set. Immediately after Parquet preflight and candidate loading,
before catalog compilation, detector/browser pools, or network traffic, the CLI
rejects an evaluation input with that same exact set. The frozen evaluator
independently rejects either the training `runId` or the same exact set once the
completed artifact identity exists. That is the generic v0.1.7 implementation
guard, not the sampling policy of the next experiment. The v0.1.8
preregistration below requires zero canonical-domain overlap across `D1`, `D2`,
and `H1`; a cohort manifest which violates that stronger rule is invalid before
scan startup.

Before serialization, the writer rejects non-plain, cyclic, accessor-bearing,
sparse, non-finite, or unsupported structures, as well as structures deeper
than 32 levels or larger than 500,000 JSON values. It revalidates the fixed
protocol, cohort, fold, and 38+2 shapes and enforces a 64 MiB UTF-8 artifact cap
including the terminal newline (`EVALUATION_ARTIFACT_LIMIT`).
Validation and serialization failures leave the target absent; publication
races never overwrite the racing target, and cleanup removes only paths whose
file identity is still owned by the writer. The already finalized
result/summary pair is not rolled back: atomicity is guaranteed for publication
of the sidecar itself, not across all three artifacts. The CLI exits non-zero,
so a missing sidecar cannot be mistaken for a successful shadow evaluation.
If either dedicated shadow pool becomes unavailable, or any snapshot contains
an unavailable `T1` or `T2` view, the run is not calibratable and fails before
publishing the sidecar. Incremental JSONL lines and any summary already finalized before a
post-run validation failure are not deleted, but neither is relabeled as a
successful shadow evaluation.

## Incremental output and resume

JSON Lines is the selected primary output because a newline terminates one
complete domain record. A new output receives one `runId`; `--resume` reuses it
and accepts only records with the same schema version, scanner version, Node,
Playwright and Chromium versions, catalog revision/digest, scan mode, and
configuration digest. Each `(runId, domain)` appears exactly once; duplicates
and malformed middle lines are errors, not last-write wins. At most one
incomplete final fragment may be removed before append. This is process-crash
recovery at record granularity, not a claim of power-loss durability.
If no complete record remains after removing that allowed fragment, there is no
persisted identity to reuse; resume creates a new UUID and continues as an empty
run in the same validated result file.

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

The manifest scanner version is the persisted build identity for v1. Any code
change that can affect crawling, detection, validation, or output must bump that
version before producing or resuming persistent results; development artifacts
from different commits must never be merged only because their catalog and
configuration digests match.

`--resume` and `--force` are mutually exclusive. An invalid writer mode fails
before any output mutation. The writer canonicalizes the existing parent
directory once. Every existing result target must be a single-link regular
non-symlink file opened without following the final path component and verified
through its file descriptor; symlinks, directories, and hard-linked results are
rejected. A paired summary must also be a regular non-symlink file, but may have
another hard link because a crash can occur between atomic link publication and
temporary-alias cleanup. A new run treats any such existing summary as
`OUTPUT_EXISTS`; resume/force unlink only the validated summary pathname and do
not modify the inode visible through any other alias. `--resume` scans, removes
an allowed incomplete final fragment, and appends through that same validated
result descriptor. Once resume validation succeeds, it removes a validated
stale paired summary before accepting new records. `--force` removes that stale
validated summary before it truncates only the exact validated result, then
creates a new `runId`. A normal new run refuses existing targets and creates
them exclusively. Summary updates use a new exclusive temporary file in the
same canonical parent followed by an exclusive hard-link publication. The
published descriptor must retain the temporary file's exact device/inode, and
cleanup unlinks only a pathname that still names that owned inode. No mode
removes an output directory or another path implicitly.

Only one writer may own a canonical output directory in a Node.js process. A
second same-process open in that directory fails with `OUTPUT_BUSY`; closing or
finalizing the owner releases the directory for reopening. The conservative
directory-inode lock avoids filename aliases under filesystem-specific Unicode
and case folding without implementing a second collation engine; the CLI needs
only one result writer. Version 1 has no cross-process lock, so concurrent
writers in separate processes are unsupported and callers must serialize that
access.

## Run summary

`RunSummary` is a closed, deeply frozen version-1 object with exactly
`schemaVersion`, `runId`, `scanMode`, `inputDomains`, `processedDomains`,
`statusCounts`, `technologies`, `detectionStats`, `durationMs`, `usage`,
`evidenceAttribution`, `hardLimitHits`, `errors`, `provenance`, and `config`.
The paired JSON file serializes that object directly. Configuration and
provenance are copied into a fixed canonical key order, so semantically equal
contexts produce byte-stable summary JSON independent of caller insertion
order. `statusCounts` contains `success`, `partial`, and `failed`.
`technologies` contains direct, inferred, total domain-technology occurrences
and the number of distinct technology names. `detectionStats` and all eight
usage counters are sums of the exact persisted per-domain counters.

`durationMs.average` is the arithmetic mean of `timings.totalMs`, rounded to
three decimal places. `p50`, `p95`, and `p99` use nearest rank at
`ceil(p * n) - 1` after numeric ascending sort. All four values are zero when no
record was processed. Error groups have exactly `stage`, `code`, and `count`,
and sort by the fixed stage order followed by ascending UTF-16 error code.
`hardLimitHits` counts codes ending in `_LIMIT_EXCEEDED` plus
`REGEX_DOMAIN_BUDGET_EXCEEDED` and `REGEX_EXECUTION_LIMIT`.

Evidence attribution counts emitted direct domain-technology occurrences with
persisted evidence and is deliberately overlapping: every evidence item being
HTTP contributes to `directWithOnlyHttpEvidence`; any browser collector, probe
source, `p2`/`p3` page, or script-content source contributes to its corresponding
counter. These are exact descriptions of final evidence, not additive or
counterfactual lift. Measuring causal incremental lift or per-feature cost
requires subset reruns and is deferred to benchmark analysis. Summary
construction rejects duplicate domains, context/provenance mismatches, an
`inputDomains` value lower than the number processed, or either count above the
configured Parquet row cap. Every aggregate addition is preflighted as a safe
integer and an overflow rejects the entire new record without mutating prior
summary state. Aggregation is independent of JSONL completion order. The
complete validated configuration and scanner/runtime/catalog provenance are
included in canonical form.

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
- Robots status/rule semantics, fail-closed synchronous cache gating, and exact
  deterministic page-selection tests, including static/rendered union,
  exclusions, no-backfill denial, URL ordering, and compact IDs.
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
- Pipeline tests use injected deterministic collectors or controlled local
  servers, never unstable public websites, and cover the authoritative combined
  `full` detector pass, independent shadow `T1`/`T2` passes, HTTP/browser
  `p1`–`p3`, sorted exact-origin probes, DNS/TLS, queue/deadline separation,
  cleanup, partial/failed results, deterministic error merge, probe evidence,
  and transport-owned `probesIssued` accounting.
- Catalog-probe tests cover path revalidation and sorting, composed-URL limits,
  robots allow/deny/unavailable behavior, one-shot GET/no-follow/no-retry,
  2xx and empty-body presence, UTF-8 replacement, denial/transient stop
  statuses, bounded bodies, redacted literal evidence, and request accounting.
- `browser-proxy.test.ts` covers one-use HTTP grants, CONNECT authority/port
  policy, mixed and non-public DNS, peer pinning, late-DNS/page cleanup,
  request/byte limits, page-generation socket isolation, and a zero-hit
  loopback canary.
- `browser.test.ts` covers safe launch/context options, slot preflight,
  FIFO admission and cleanup, ordered per-domain pages, synchronous robots
  gating, dual-stage CDP redirect admission, deterministic top-20 script
  selection, bounded process replacement, and a real Chromium page served only
  by controlled local fixtures through the protected proxy.
- Browser-egress tests prove that private, link-local, loopback, metadata, and
  mixed DNS destinations never receive a connection; CI does not require a live
  public website.
- Output tests cover serialized append ordering, per-record and row caps,
  persisted semantic validation, fragment-only recovery, duplicate resume keys,
  target/link safety, single-process ownership, no-clobber summary publication,
  canonical aggregate ordering, percentiles, safe sums, and atomic overflow
  rejection.
- CLI tests cover bounded argument/config parsing, startup-before-mutation
  ordering, input/output alias rejection, resume membership, completion-order
  backpressure, pool loss, signal races, sanitized diagnostics, cleanup, and
  the executable build boundary.
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

The four-tier shape is provisional until the shadow evaluation below passes;
it is not yet production routing policy:

1. `T1` is the detector view over canonical-target and entry-page static HTTP,
   the robots observations needed to admit that work, and the catalog-requested
   DNS/TLS signals;
2. `T2` adds the bounded catalog probes and zero or one internal static page
   selected only from the entry page's frozen static links by the deterministic
   rule in [Provisional tiering evaluation protocol](#provisional-tiering-evaluation-protocol);
3. a later browser tier may render the entry page and retain its bounded
   script-response observations for domains selected only from `T1`/`T2`, plus
   a deterministic 1% control sample;
4. a later ecommerce tier may render a selected product page, but every domain
   which reaches either browser tier consumes the same routed-domain quota.

The 200-domain `full` run is the development dataset for shadow evaluation, not
an untouched production holdout. The original target of retaining 95% of direct
detection occurrences while rendering at most 20% of domains is infeasible on
v0.1.4. The provisional replacement therefore optimizes canonical
`(domain, technology)` pair retention, keeps canonical-name breadth as a
guardrail, and measures real browser work rather than treating routed-domain
count as a complete cost model. No target becomes a final product KPI until an
out-of-fold deployable trigger passes and a separate representative cohort is
evaluated. HTTP and browser worker counts are then sized independently from
observed p95 cost with at least 2x throughput headroom. Robots, opt-out,
retention, terms-of-service review, and an operational contact remain release
gates for a production-scale crawl.

## Debate topics

### What are the main issues, and how would I tackle them?

The largest accuracy constraint is the fingerprint catalog itself. Upstream
rules can be stale, overly generic, duplicated, or expensive to evaluate, while
the challenge does not provide a per-domain labeled truth set. I would keep the
current exact correction ledger, require positive and negative fixtures for
every changed rule, and build a small manually reviewed benchmark that records
both false positives and misses. Catalog releases would stay digest-pinned and
reproducible rather than changing silently.

Collection is also imperfect: websites disappear, block automation, return
soft-404 pages, exceed conservative budgets, or behave differently between
static HTTP and Chromium. The result model therefore preserves partial evidence
instead of converting a late failure into a total miss. The next improvements
would be driven by aggregate limit telemetry and controlled fixtures, not by
globally increasing time, body, request, or selector limits. Browser work is the
dominant cost and source of long-tail failures; the experimental routing model
did not meet its quality guardrails, so this submission correctly keeps the
reliable `full` scan instead of deploying an underperforming optimization.

### How would I scale to millions of domains in one or two months?

I would retain `scanDomain()` as the idempotent unit and place canonical domains
on a durable queue consumed by stateless workers. Results would go to object
storage and an analytical database under a stable `(run, domain)` key. Leases,
bounded retries, dead-letter queues, per-host rate limits, partitioned output,
metrics, and explicit recrawl scheduling would replace the local writer and
in-process scheduler without changing collection or evidence semantics.

Capacity should be derived from measured stage cost rather than domain count
alone. This run averaged 9.28 seconds per full domain, while browser traffic
accounted for 14,601 of 15,629 requests. I would size HTTP and Chromium pools
separately from p95 latency and transfer, add at least 2x headroom, and enforce
global plus per-origin concurrency. A staged static-first/browser-later design
could reduce cost substantially, but it should be enabled only after a frozen
router demonstrates acceptable recall on an untouched cohort. Until then,
horizontal full-scan workers are less efficient but methodologically safer.

### How would I discover new technologies?

Discovery should be a reviewed catalog pipeline, not automatic promotion from
one website. From a bounded, policy-approved sample I would aggregate unknown
public signals such as script host/path shapes, generator metadata, headers,
DOM attributes, and JavaScript globals; cluster signals that recur across
unrelated domains; and compare them with vendor documentation and release
artifacts. An analyst would then write a declarative fingerprint, validate it
on multiple positive sites and representative negative fixtures, and publish it
only in a new digest-pinned catalog revision. Version extraction, aliases,
relationships, license provenance, runtime cost, and redaction would be reviewed
at the same boundary. Raw page content would remain outside normal results and
would require a separate retention and privacy policy.

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
  custom keywords, formats, coercion, defaults, and mutation are forbidden.
  The catalog-only validator keeps strict mode enabled but sets
  `strictTypes: false`, because the immutable upstream schema omits an object
  type around one `required` block. Result and configuration validators retain
  full strict mode;
- the upstream schema is necessary but not sufficient: the catalog compiler
  must also validate supported fields, references, selectors, paths, pattern
  syntax, lengths, counts, and depth before accepting a definition;
- Playwright is an application dependency, not a test framework. Its matching
  Chromium build is provisioned explicitly, never through `postinstall`, and
  the sandbox remains enabled for untrusted pages. The browser binary is a separate third-party
  artifact: it is not committed, and its licenses/notices must be preserved if
  a future distributable bundles it.

The browser setup command is explicit and reproducible:

```sh
fnm exec --using 24.19.0 node_modules/.bin/playwright install chromium
```

For `playwright@1.62.1` this provisions Chromium revision `1234` (Chrome for
Testing `151.0.7922.34`) plus its matching headless shell and FFmpeg in the
developer-local Playwright cache. CI must run the same explicit command. No
browser artifact is written to Git or represented as an npm dependency change.
The TypeScript project includes the standard `DOM` declaration library only
because Playwright's own types expose DOM names; application execution remains
Node.js 24.

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
was inspected. Playwright 1.62.1 has no install lifecycle script, so the later
Chromium provisioning remained an explicit separate command. `node_modules`,
the browser cache, and compiled `dist` output remain local and Git-ignored.

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

## Fingerprint compiler and detector

`detect/catalog.ts` loads an exact upstream allowlist: `schema.json`,
`categories.json`, and `technologies/{_,a..z}.json`. It rejects missing or extra
upstream entries, symlinks and non-regular files, invalid UTF-8, duplicate JSON
members, excessive nesting, and all configured file/count/byte limits before
the catalog can reach a scan. Regular custom v1 files may add only new
technology names under `fingerprints/custom/technologies`; they cannot redeclare
or implicitly override an upstream definition. The only reviewed correction
boundary is the fixed `fingerprints/custom/corrections.v1.json` ledger described
below. The fixed upstream schema is validation layer one, and a semantic
compiler then closes its permissive nested shapes, validates all references and
supported locators, and produces only deeply frozen plain data. No
catalog-selected schema or executable object enters Ajv or a worker.

The pinned snapshot compiles without modification to 7,575 technologies, 109
categories, 15,496 direct declarations, 15,489 unique rules, and 2,241
relationship entries. Catalog accounting sees 8,541 regex-source declarations
before exact-rule deduplication; the worker plan compiles 8,537 unique sources
(8,033 value expressions and 504 cookie locators), alongside 1,769 DOM
selectors, 5,570 JavaScript paths, and three probe paths. The reproducible
upstream digest is
`sha256:cdcccc905a14bbc7ad35a7ea6de636a2e6e51280c6ebbe5ba14f5e55aac18c8f`.

Correction ledger revision `2026-08-20.2` has the closed schema identifier
`website-technologies-scraper/catalog-corrections-v1` and binds itself to that
exact upstream source, revision, and digest. It supports only three bounded
operations: exact upstream technology names in `dropTechnologies`, complete
upstream SHA-256 rule IDs in `dropRules`, and `replaceRules` entries containing
one complete target rule ID plus a new declarative `original`. A replacement
must retain the target's exact technology, signal source, and normalized
locator. Every rule target must resolve to exactly one upstream declaration;
missing, duplicate, cross-operation, stale-revision, wrong-digest, or
identity-changing targets reject the catalog. There are no wildcards, aliases,
name heuristics, JSON Patch, merges, config switches, or CLI-selected ledgers.
When a correction ledger is present, `compileFingerprintCatalog()` independently
recomputes the upstream digest even when called outside the filesystem loader.

Revision `2026-08-20.2` contains exactly four dropped technologies, five
dropped rules, and five exact replacements. Its raw ledger SHA-256 is
`sha256:68d702a5496f2d5c304c6608cd31c06c7679b3078b436e3ba3a1d1c4f34a8393`.
The two additions relative to revision `.1` replace the Magento
`/magento_version` rule with the literal `Magento/2.` and replace the TYPO3 CMS
probe presence rule with a distinctive bounded fragment from the official
TYPO3 SVG. Positive fixtures retain the intended signatures; negative fixtures
cover an empty successful body, generic soft-404 content, and a response which
only echoes the requested path. The historical D2 bodies were not persisted,
so these fixtures close the demonstrated mechanism without relabeling all 17
historical probe detections as proven false positives.

Dropped technologies are removed before enforcing `technologiesPerCatalog` on
the effective catalog. Replacements receive the local
`website-technologies-scraper/custom:rule-v1` namespace and a new stable rule
ID; unchanged upstream IDs and all vendored bytes remain untouched. The raw
ledger bytes participate in the effective catalog digest. Revision
`2026-08-20.2` compiles to 7,571 technologies, 109 categories, 15,481 direct
declarations, 15,474 unique rules, and 2,238 relationship entries. Catalog
accounting sees 8,529 regex-source declarations, while the worker plan contains
8,525 sources (8,022 value expressions and 503 cookie locators), alongside
1,767 DOM selectors, 5,570 JavaScript paths, and three probe paths. Its effective
digest is
`sha256:5aedde4f83d1ad977d646e1495b9b91d4d3b0f6f3acbd34d54906d099da18870`.

Every effective direct declaration counts against `patternsPerCatalog` before
exact duplicates are deduplicated, including empty presence rules. Non-empty
value regexes and cookie-locator regexes independently count toward the regex
count and total source limits. Stable direct rule IDs hash the UTF-8 JSON tuple
`[namespace, technology, signal, normalizedLocator, originalTaggedRule]`;
relationship IDs use
`[namespace, parent, "implies", target, originalTaggedValue]`. The namespaces
are `enthec/webappanalyzer:rule-v1` and
`website-technologies-scraper/custom:rule-v1`, so unchanged rules retain IDs
across a future snapshot refresh. Catalog digest paths are relative to
`fingerprints/`, use `/`, sort by UTF-8 bytes, and retain the raw file bytes in
the documented length-framed hash.

`detect/engine.ts` maps the bounded HTTP and browser observations without
creating a new network or parsing path. Final and redirect URLs become `url`;
response headers, cookies, HTML, visible text, normalized metadata, script
resource URLs, retained robots text, requested DOM/JavaScript facts, bounded
script bodies, browser request URLs, validated probe path/body pairs, DNS
records, and the retained TLS issuer map to their matching signals.
Upstream `xhr` rules match `network_url`, not only a hostname: the reviewed
snapshot has 113 such rules and 16 require a path or query component. Matching
therefore uses the complete bounded in-memory request URL, while evidence emits
only its canonical sanitized form. `network_hostname` remains a separate
bounded observation for safe public hostnames and is not presented as complete
XHR coverage. Stylesheet, image, iframe, generic link, navigation-link, and
HTTP-status observations are deliberately not detector candidates in v1.
Page-scoped HTTP observations retain their exact `p1`, `p2`, or `p3`, as
browser evidence already does. A terminal non-HTML entry response and robots
use `pageId: null`; probes also use `pageId: null` with the validated path as
key, while an already selected internal response remains linked to its assigned
`p2`/`p3`. Exact candidate duplicates are removed and HTTP candidates rank
before the additional browser tier in the stable candidate identity order. For
the authoritative `full` pass, the detector additionally marks the exact
multiset of candidates already present in the captured `T2` observation prefix.
Candidate IDs and ordinary result ordering remain unchanged, but bounded
admission and worker execution process that `T2` phase before all full-only
candidates. A checkpoint at the phase boundary confirms its matches before
remainder work may consume the active detector deadline. Remapped internal-page
IDs do not lose priority because the scheduling identity is the collector,
kind, source, key, and bounded value rather than the provisional page ID. With
no detector limit or timeout the same complete candidate set is matched; this
ordering neither raises a budget nor changes the `T1`/`T2` feature definitions.
The authoritative `full` pass submits the complete bounded
HTTP/browser/probe/infrastructure set to one detector invocation instead of
merging independently detected page results. Only an explicit shadow run adds
the separate `T1` and `T2` prefix passes described below.

Workers match raw bounded candidates, while the parent materializes only
sanitized evidence. Cookie, HTML, text, and robots matches are always redacted;
safe header and metadata rules expose only the matched fragment after the whole
observation passes the sensitive-token classifier; URL evidence exposes the
complete canonical sanitized URL or becomes redacted if it cannot fit the wire
limit. Presence evidence always has `pattern: null` and `version: null`.
Credential schemes anywhere in an otherwise allowlisted header or metadata
value fail closed. A derived version is retained only when both the version and
its raw matched fragment pass the same sensitive marker and opaque-token checks;
URL-derived versions are also rejected whenever the observed URL contains
userinfo, a query, or a fragment, or when URL sanitization changed the pathname.
Confidence and version use unique rule IDs,
then the accepted relationship fixed point and exclusion algorithm produce
deterministic direct and inferred technologies. Relationship confidence,
versions, and exclusions are resolved from all confirmed evidence before output
limits are checked. A worker, execution, or watchdog limit preserves its
deterministic confirmed prefix and adds a stable detect-stage error; an output
materialization limit instead discards the complete technology array as
described above, so a truncated evidence prefix can never change a relationship
winner.

## Regex execution policy

Fingerprint expressions use native JavaScript `RegExp` with the catalog's
case-insensitive `i` semantics, but they are never compiled or executed on the
main thread. A persistent pool of two local
[`worker_threads`](https://nodejs.org/docs/latest-v24.x/api/worker_threads.html)
compiles the validated declarative catalog and matches only bounded, normalized
candidate strings. Workers start from a fixed local module, never `eval`,
receive no runtime objects through the task protocol, perform no network or
filesystem I/O, and return rule and candidate ordinals, match spans, and a
bounded safe version rather than raw candidates or capture strings.

The catalog compiler indexes rules first by signal type and then by locator.
Header and metadata locators are exact normalized lowercase keys; DOM and
JavaScript locators remain exact selectors or paths. Cookie locators are the
catalog's anchored whole-name expressions, compiled and executed in the same
worker boundary as value regexes. One leading upstream `(?i)` marker is removed
because every worker expression already uses `i`; the original locator remains
part of the stable rule ID. Cookie-locator executions count toward the same
per-domain budget.
Unkeyed signals use the deterministic candidate caps in the resource table,
including at most 80 script URLs, 20 script bodies, three page URLs, 300 browser
request URLs, and 200 browser request hostnames. They are deduplicated and
ranked by collector, page ID, then their source URL, hostname, or locator in
UTF-16 code-unit order. Script responses use the exact browser selection rank:
page ID first, then same-origin before cross-origin, then URL.
Before dispatch, the detector calculates a conservative upper bound from
applicable rules times admitted candidates. The configured 500,000 value is
enforced as two independent ceilings: actual `RegExp` calls and total
rule-candidate work pairs. Every presence and literal comparison therefore
costs one work pair even when it costs no `RegExp` call. Candidates are admitted
atomically in stable rank order; the first candidate which would cross either
ceiling and every later candidate are omitted, and the domain records
`REGEX_EXECUTION_LIMIT`. A prefilter may remove provably inapplicable rules but
must not be required for correctness or for respecting either cap.

Worker responses are chunked so one checkpoint cannot create an unbounded
message. At most `min(executionsPerDomain, evidencePerDomain)` unique raw matches
are retained (20,000 by default), with one extra sentinel used only to detect
overflow. Reaching it terminates the attempt, preserves the deterministic
bounded prefix, replaces the worker once, and records `REGEX_EXECUTION_LIMIT`.

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
| Catalog files / one file / total bytes | 64 / 1 MiB / 16 MiB |
| Catalog JSON nesting depth | 64 |
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
| Rule-candidate work pairs per domain | 500,000 |
| RegExp executions per domain | 500,000 |
| Retained raw worker matches | 20,000, derived from the evidence/domain cap |

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

The same lifecycle monitor remains attached while a worker is idle. An idle
`error` or unexpected `exit` therefore starts exactly one bounded replacement;
queued detector work waits for that replacement, and loss of the last viable
worker latches the pool unavailable instead of surfacing an unhandled process
event or leaving a stale ready slot.

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
visible text, CSS, bounded request URLs and public hostnames, robots, bounded
probes, DNS, certificate issuer,
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
- retain the recorded source, commit, retrieval date, license, digest, and local
  modification status in `THIRD_PARTY_NOTICES.md` for every refresh;
- keep the complete `GPL-3.0-only` project `LICENSE` and the catalog notice
  synchronized with the pinned snapshot;
- validate every definition and reject unsupported or unsafe patterns before
  enabling it; a licensed catalog is still untrusted input.

The official commercial Wappalyzer catalog, website, extension, npm
placeholder, and API are not sources for this project. Mirrors or MIT-licensed
wrappers do not override the license of the catalog they copy. Additional
catalogs will be considered only after benchmark results show a concrete gap.
The approved 29-file snapshot was vendored byte-for-byte on 2026-08-17 under
`fingerprints/upstream/webappanalyzer`. It contains the fixed schema,
categories, and 27 technology files; no upstream executable code, icons,
dependencies, or branding were imported. Its provenance and unmodified status
are recorded in `THIRD_PARTY_NOTICES.md`.

## 200-domain full benchmark (v0.1.4)

The v0.1.4 reference evaluation run used the pinned catalog/configuration
recorded in its summary. It completed all 200 unique input domains, then a
resume run completed without changing either output file. The captured
artifact has verifiable provenance and bytes; live website responses are not
expected to be identical across reruns. The Git-ignored local artifacts are
`output/work/results-200-v0.1.4.jsonl` and its paired `.summary.json` file.

Integrity checks independently validated all 200 persisted results against the
embedded configuration, rebuilt the summary byte-for-byte, and confirmed the
input/output domain sets, run provenance, catalog digest, redaction invariants,
UTF-8/JSONL boundaries, and regular single-link `0600` output files. The stable
artifact hashes are:

- input Parquet: `sha256:65e77097c669c29b392f3279a93f04566ab934cf1e8acfaf1ae4046a01e97bb2`;
- result JSONL: `sha256:502a72c1ad161ed0e55c188ef7a517d975204eb1d0ef89059dfaeae1c066caa7`;
- summary JSON: `sha256:cfd022789b1fc2f9bfb9db03f498e00992d8e712bba73f505ecec4bdd6dc6ca7`.

The measured result is:

| Metric | v0.1.4 result |
| --- | ---: |
| Status | 3 success, 190 partial, 7 failed |
| Detections | 2,061 direct + 167 inferred = 2,228 |
| Unique technology names | 373 total; 360 direct |
| Direct candidate accounting | 2,120 raw - 55 gated - 4 suppressed = 2,061 retained |
| Domains with zero detections | 37 |
| HTTP / browser requests | 1,033 / 14,419 |
| Pages / probes / script bodies | 235 / 374 / 1,445 |
| Static / browser transfer | 10,777,145 / 204,825,582 bytes |
| Duration | 9,692.140 ms average; 8,969 ms p50; 25,182 ms p95; 52,972 ms p99 |

The zero-detection set does not establish 37 catalog misses: 35 domains admitted
no page and the other two ended with incomplete collection. Evidence-exclusive
support, which is descriptive and not counterfactual lift, includes 744 browser
detections across 103 domains, 33 internal-page detections across 23 domains,
70 script-content detections across 44 domains, two probe detections, 142 DNS
detections across 95 domains, and 86 TLS detections across 86 domains. These
categories overlap and must not be summed.

No pool-wide proxy or availability failure occurred in this run: it emitted no
`BROWSER_PROXY_FAILED`, `BROWSER_UNAVAILABLE`, or `DETECTOR_UNAVAILABLE`, and
admitted browser observations for 72 of 74 attempted `p2` pages. Browser
observation truncation is nevertheless systemic: 176 of 180 admitted browser
pages were truncated and the run emitted 193 `BROWSER_LIMIT_EXCEEDED` errors.
The pinned catalog still contains broad value inspections such as `div`,
`button`, `script`, and `style`; the persisted result intentionally does not
identify the exact selector/limit responsible for each truncation. The detector
also emitted 15 rule timeouts, six execution-limit errors, and six domain-budget
errors; the Liveinternet HTML rule accounts for 13 of the 15 timeouts.

Manual evidence review identified an initial, non-exhaustive correction queue
rather than a global false-positive estimate. All four Onsen UI detections
include at least one false `onsen` substring match inside `consent`; one also has
redacted evidence that cannot be adjudicated offline. Other entries are
WebsiteBuilder (9/9 Wix generator mappings), Store Vantage (3/3) and Sirvoy
(1/1) from Wix's generic `svSession`, Wix eCommerce (1/1 from a generic Wix
asset host), and 11/11 strongly suspect Lightbox evidence sets pointing to other
lightbox implementations. Four alias families also duplicate the same
technology: LiteSpeed Cache/Litespeed Cache, All in One SEO/All in One SEO Pack,
MUI/Material UI, and Adobe Fonts/Typekit.

The subsequent exact ledger revision `2026-08-20.1` removes the four duplicate
alias definitions; drops the reviewed weak WebsiteBuilder, `svSession`, generic
Wix asset, and Lightbox DOM rules; narrows Onsen UI and Lightbox script URLs to
exact basenames; and replaces the timeout-prone Liveinternet HTML expression
with the bounded `//counter\.yadro\.ru/hit` signal. Candidate-level positive and
negative fixtures retain each stronger fallback and reject the reviewed false
signals; the Liveinternet negative fixture is 4 MiB. These changes defined the
fresh v0.1.5 run and do not rewrite the historical v0.1.4 measurements above.

The original occurrence-based tiering target is infeasible on this baseline
under the optimistic evidence-based upper bound. Without browser evidence, at
most 1,317/2,061 direct occurrences remain; an oracle selecting the best 40/200
domains reaches only 1,768/2,061 (85.78%), and 95% requires at least 68/200
domains (34%). A deployable trigger may require more. A possible replacement
objective is canonical direct technology names: a post-hoc greedy selection
covers 342/360 (95%) with 25 domains and 357/360 (99.17%) with 40. That was not
a deployable policy because it used full-result knowledge. The v0.1.5
experiment below applied the targeted corrections and measured a trigger based
only on tier-1/tier-2 signals; the historical v0.1.4 measurements remain
unchanged.

## 200-domain full + shadow benchmark (v0.1.5)

The authorized fresh run built from clean commit
`b290a340355a965ec100d1c980a3653137442758` completed all 200 input domains with
scanner `0.1.5`, Node.js `24.19.0`, Playwright `1.62.1`, Chromium revision
`1234`, effective catalog digest
`sha256:614581009dc6ac2986763f8a324c656e629f63c5ecb7e46cf3ac10b121277724`,
and configuration digest
`sha256:1fdd836b195fab7f177196a6d87034dce651f845b795c7281cea967e30e6ecfb`.
The operator-supplied public contact remained runtime configuration and is not
reproduced here.

Independent checks validated all result records semantically, matched the exact
input/result domain set and run identity, rebuilt the summary byte-for-byte,
and recomputed the base snapshot plus calibration byte-for-byte. The local,
Git-ignored artifacts are:

| Artifact | SHA-256 |
| --- | --- |
| `input/domains.parquet` | `65e77097c669c29b392f3279a93f04566ab934cf1e8acfaf1ae4046a01e97bb2` |
| `output/work/results-200-v0.1.5.jsonl` | `8577b94c9dd4b777474a7bdcf963c4f718b286c1d5799f03181376e9e8c82b5e` |
| `output/work/results-200-v0.1.5.summary.json` | `c7d630748042093a1dd71d40fac163993c3f48f16cde455c1e2622a8e213e5b0` |
| `output/work/results-200-v0.1.5.evaluation.json` | `1b53023cf747e7194adc3d0261f96f93a556cba041d8ee515e9b4a8dc37ef43e` |

The authoritative `full` result is:

| Metric | v0.1.5 result |
| --- | ---: |
| Status | 2 success, 191 partial, 7 failed |
| Detections | 2,031 direct + 165 inferred = 2,196 |
| Unique technology names | 362 total; 348 direct |
| Direct candidate accounting | 2,089 raw - 54 gated - 4 suppressed = 2,031 retained |
| HTTP / browser requests | 1,021 / 14,038 |
| Pages / probes / script bodies | 231 / 368 / 1,516 |
| Static / browser transfer | 10,580,190 / 209,904,719 bytes |
| Duration | 10,132 ms average; 10,264 ms p50; 23,635 ms p95; 34,662 ms p99 |
| Hard-limit hits | 201 |

The fold-local out-of-fold deployment simulation routed exactly 38 trigger
domains plus two controls. Its provisional guardrails were:

| Guardrail | Result | Verdict |
| --- | ---: | --- |
| Canonical direct-name retention, at least 95% | 292/348 = 83.91% | fail |
| Canonical direct `(domain, technology)` retention, at least 80% | 1,609/2,031 = 79.22% | fail |
| Routed domains, at most 40 | 40/40 | pass |

The overall verdict is **REJECT**: the provisional KPI is not ratified and
functional tiering remains on hold. The 40 routed domains were 20% of the
cohort but accounted for 36.27% of attempted browser pages, 39.01% of admitted
browser pages, 41.47% of browser requests, 36.97% of browser bytes, and 40.67%
of browser milliseconds. Routed-domain share is therefore not an adequate cost
guardrail by itself. At the same budget, the deterministic random comparator
retained 276/348 names and 1,428/2,031 pairs; the post-hoc pair-first greedy
comparator retained 330/348 names and 1,735/2,031 pairs. Greedy is descriptive,
not an upper bound, so this result rejects the current deployable trigger rather
than proving that 95% name retention is impossible.

The correction ledger behaved in the intended direction on the fresh artifact.
Onsen UI changed from 4 to 0 occurrences, WebsiteBuilder 9 to 0, Store Vantage
3 to 0, Sirvoy 1 to 0, Wix eCommerce 1 to 0, and Lightbox 11 to 0. Duplicate
aliases also disappeared while their canonical names remained: Litespeed Cache
3 to 0 while LiteSpeed retained 3; All in One SEO Pack 2 to 0 while All in One
SEO retained 2; MUI 1 to 0 while Material UI retained 1; and Typekit 4 to 0
while Adobe Fonts retained 4. Detector rule timeouts fell from 15 to 2, with no
Liveinternet timeout or detection in v0.1.5.

The sidecar recorded 1,045 browser-limit hits across 106 domains and 178 pages:
802 `inspection.domMatches`, 148 `inspection.returnedValue`, and 95
`scripts.bodiesPerDomain`. There were no exists-only selector hits, confirming
the false `exists` truncation fix. Remaining pressure is concentrated in broad
property/value inspections over app/root/body descendants, `div` text/id,
`script` and `style` text, and `link` href; this supports targeted catalog or
collector work, not a global limit increase.

One historical telemetry caveat is explicit: the JSONL contains 180
`BROWSER_LIMIT_EXCEEDED` domain/page pairs, while the v0.1.5 sidecar contains
limit hits for 178 page pairs. Two protected-proxy limit hits were lost on
paths which failed before their page collection returned. The artifact must
not be described as telemetry-exact. This does not change the calibration or
KPI verdict because browser-limit telemetry is excluded from both trigger
features and labels. The historical files and hashes above remain unchanged; a
later collector fix cannot retroactively make this sidecar exact. The current
collector preserves the active raw-free page and proxy limit hits before the
pipeline classifies a thrown collection failure, so future sidecars retain this
diagnostic without changing `DomainResult`.

The next experimental slice is bounded trigger-quality work, including an
explicit real-cost guardrail and the remaining canonical-name breadth misses.
Any changed feature set, objective, or threshold must be frozen before a new
representative cohort is evaluated. This 200-domain development cohort may be
used for diagnosis and training, but not for same-cohort KPI re-ratification.
Functional routing starts only after a deployable candidate passes the frozen
guardrails on new evidence.

## Provisional tiering evaluation protocol

Protocol revision `2026-08-20.1` and its shadow instrumentation were exercised
by the fresh v0.1.5 public run above. The deployable trigger failed two of three
guardrails, so the KPI was rejected. This remains a shadow experiment, not
functional routing, a final KPI, a production capacity claim, or permission to
skip an existing safety check. All three detector views use the same validated
effective catalog, correction revision, configuration, and deterministic
matching semantics. A prefix is never approximated by filtering technologies
or evidence from the final result.

### Observation views and the static internal page

- `T1` contains the entry page's bounded static HTTP observations, including
  its final/redirect URL signals, the robots observations needed to admit entry
  work, and the catalog-requested DNS records and retained TLS issuer. It
  contains no probe, internal-page, rendered-DOM, browser-network, or browser
  script-body observation.
- `T2` contains all of `T1`, the current bounded exact-origin catalog probes and
  their robots observations, and at most one internal page collected by static
  HTTP. It contains no browser observation and no link learned from rendered
  content. A failure preserves the latest available prefix; it is not removed
  from the evaluation population.
- `full` remains a separately detected label over the complete bounded scan,
  including browser observations. `full` detections and failures are labels,
  never trigger features.

The `T2` page is selected from a frozen copy of the navigation links extracted
by static `p1` only. The existing exact-origin canonicalization, credential,
query/fragment, URL-length, excluded-path, file-like, root/final-URL, and role
classification rules are reused. Within those candidates, retain the existing
best `detail` candidate and the best `listing` candidate, or the best `content`
candidate only when no listing exists. Sort those at most two structural
choices by complete canonical network URL in direct UTF-16 code-unit order and
choose the first. This is the existing deterministic selector with one
internal-page slot and does not introduce an unmeasured role preference.

Exactly one candidate is checked with robots; denial, unavailable policy, a
publication-sanitizer collision, or the absence of an eligible link produces
zero internal pages and no backfill. Otherwise that one page is fetched once by
the protected static collector. Thus "one internal page" is a hard maximum and
a deterministic choice, not a promise to bypass policy or fabricate a URL.

The implemented order is entry HTTP, DNS/TLS infrastructure, static-only
reservation and HTTP collection, probes, browser `p1`, and then the remaining
full-page plan. Keeping infrastructure before `T2` work gives `T1` its exact
deadline prefix. The reservation occupies one of the existing two internal
slots even on denial or failure; the union of static and rendered links may
contribute at most one candidate from the opposite slot and never backfills the
reservation.
The normal three-page cap, at-most-two internal robots checks, sanitized public
URL sort, and compact `p2`/`p3` rules remain in force.

The run-owned full pipeline still admits its browser slot and disposable
context before collecting the entry page, because admission starts the single
active-domain lifecycle. A browser pre-open failure therefore records both
shadow prefixes as unavailable, and setup latency can affect whether a prefix
is captured. It cannot add browser observations to `T1` or `T2`; an unavailable
prefix is excluded fail-closed from calibration rather than treated as empty.

The authoritative `full` detector pass runs first under the active-domain
deadline. After the result has been materialized and semantically validated,
the pipeline clears its deadline and, only for a shadow run, performs independent
`T1` and `T2` detector passes concurrently under caller cancellation, each in
its own dedicated pool and separate from the `full` pool. Sharing immutable
bounded collector results is allowed; sharing a combined detection result,
worker slot, or pool failure state is not. Shadow pass duration is excluded from
`DomainResult.timings`, and neither pass can change the already validated
result. Any `detector-unavailable` shadow view invalidates calibration rather
than being scored as an empty or low-signal domain.

### Raw-free snapshot and limit telemetry

One allowlisted snapshot is produced for each domain. The top-level artifact has
`schemaVersion: 1`, protocol revision, run identity, exact input-domain count,
full provenance, domain-sorted snapshots, browser-limit aggregates, and the
calibration report. Each snapshot persists only its protocol/run/domain identity
plus:

- `T1` and `T2` availability, sorted unique direct and inferred names,
  `detectionStats`, completion state, and grouped
  `(stage, code, retryable, count)` diagnostics;
- a pre-browser feature object with entry outcome/status class, bounded entry
  HTML bytes and text code points, static-link/metadata/resource counts,
  DNS-record count, TLS-issuer presence, reserved-page selection/role/outcome,
  observed-probe count, HTTP requests, and static transferred bytes;
- the authoritative `full` direct/inferred name sets and domain status;
- actual full browser pages attempted/admitted, requests, transferred bytes,
  and browser milliseconds;
- unique browser-limit hits identified by page, stable category, and a
  catalog-plan DOM-selector ordinal only where that ordinal is meaningful.

An unavailable early prefix uses an explicit unavailable state rather than an
invented empty detection. No URL, evidence, matched value, rule ID, pattern,
error message, HTML, DOM, script, header, cookie, JavaScript value, or other raw
observation is accepted into the snapshot. Extra object properties are dropped
by construction before accumulation. Snapshots are sorted by canonical domain;
the artifact is tied to the effective catalog through provenance, so a DOM
selector ordinal is interpreted only with that catalog digest.

Before calibration, the accumulator admits at most 10,000 identity values over
the cohort. The count includes one domain identity per snapshot, every direct
and inferred name in `T1`, `T2`, and `full`, each grouped `T1`/`T2` error or the
marker for an unavailable view, and every browser-limit hit. An addition which
would reach 10,001 is rejected without inserting that snapshot. This in-memory
bound is independent of the writer's 500,000-value structural preflight and
64 MiB serialized-artifact cap.

The stable limit categories are:

- DOM/evaluation: `inspection.domMatches`, `inspection.domAccess`,
  `inspection.returnedValue`, `inspection.returnedValuesPerPage`,
  `inspection.navigationLinksCount`, and
  `inspection.navigationLinkInvalid`;
- cookies/network/scripts: `cookies.name`, `cookies.value`,
  `cookies.perDomain`, `cookies.totalBytesPerDomain`,
  `browser.networkHostnamesPerDomain`, `browser.networkUrlsPerDomain`,
  `scripts.bodyBytes`, `scripts.bodiesPerDomain`, and
  `scripts.totalBodyBytesPerDomain`;
- protected proxy: `proxy.headerFields`, `proxy.headerBytes`,
  `proxy.requestsPerPage`, `proxy.requestsPerDomain`,
  `proxy.transferBytesPerPage`, and `proxy.transferBytesPerDomain`.

Only `inspection.domMatches` and `inspection.domAccess` carry the zero-based DOM
selector ordinal. Per-page hits are deduplicated by
`(pageId, category, ordinal)`. The artifact additionally groups them by
`(category, ordinal)` and reports hit count, affected pages, and affected
domains. This telemetry diagnoses which bound was reached without weakening a
limit or exposing it in the public result schema.

### Quota, score, and comparators

For each canonical domain `d`, let `F(d)` be the set of corrected canonical
direct technology names in its `full` label. A simulated result uses its `T2`
set when `d` is not routed and `F(d)` when it is routed. Inferred technologies
are reported separately and do not enter these provisional retention scores.
Raw direct-occurrence retention remains a secondary diagnostic rather than the
optimization target.

The browser gate is at most 40 unique domains out of this fixed 200-domain set.
Every domain admitted to any browser work consumes one place even when it
fails, produces no browser page, or later receives Tier-4 work. For this OOF
evaluation, the 40 routed places are apportioned across the five held-out folds
from fold sizes alone, and exactly two of those places are apportioned as
controls. The remaining 38 are trigger places. Controls are selected only from
the non-triggered remainder of their own fold, so control traffic cannot be
presented as free coverage.

The provisional acceptance guardrails are:

- at least 95% retention of the set of corrected canonical direct technology
  names present anywhere in `full`;
- at least 80% retention of corrected canonical direct
  `(domain, technology)` pairs, treated as the primary optimization target;
- at most 40 routed domains under the accounting rule above;
- including both controls, no more than 30% of the full-cohort total for each
  real browser-cost dimension: pages attempted, pages admitted, requests,
  transferred bytes, and browser milliseconds.

Both retention values are intersections with the `full` label divided by the
corresponding non-empty `full` set. Extra shadow detections cannot increase
retention and are reported separately as disagreements for quality review.
Pair retention is also reported as macro recall across domains with a non-empty
`F(d)` and across technologies with at least one `full` domain; empty-label
domain counts remain explicit rather than being assigned a convenient recall.
The report includes absolute and relative browser pages, requests, transferred
bytes, and summed browser milliseconds, as well as routed-domain count.

A deployable trigger may use only the `T1`/`T2` direct names and controlled
states, completion/errors/detection counts, plus the allowlisted pre-browser
features above. Inferred names are retained for reporting but are not feature
tokens. `full`, browser costs, and browser-limit telemetry are excluded from the
feature function; changing those fields for a held-out domain cannot change its
fold, tokens, or score.

Calibration uses five deterministic folds. A domain's fold is the first
unsigned 32-bit big-endian word of
`SHA-256(foldSalt + NUL + canonicalDomain) mod 5`. Each held-out fold is scored
by a model trained on the other four, and the five held-out prediction sets are
concatenated once. The frozen salts are:

| Purpose | Salt |
| --- | --- |
| Fold | `website-technologies-scraper/shadow/2026-08-20.1/fold/v1` |
| Score tie | `website-technologies-scraper/shadow/2026-08-20.1/score-tie/v1` |
| Control | `website-technologies-scraper/shadow/2026-08-20.1/control/v1` |
| Random comparator | `website-technologies-scraper/shadow/2026-08-20.1/random/v1` |
| Greedy tie | `website-technologies-scraper/shadow/2026-08-20.1/greedy-tie/v1` |

The model target is the count of incremental direct `(domain, technology)`
pairs in `full` relative to `T2`. Features are deterministic tokens for the
allowlisted values; numeric counts use fixed zero/one/power-of-two bins. For
each token, its empirical target mean is smoothed toward the training-fold
global mean with prior weight four. A domain score is the arithmetic mean of
that global mean and all estimates for its matched tokens. This deliberately
small `smoothed-empirical-token-lift-v1` model is descriptive, not a calibrated
probability or a generic machine-learning framework.

Fold quotas use Hamilton's largest-remainder rule. For a fold of size `n`, the
initial routed quota is `floor(40 * n / 200)`; remaining routed places go by
descending fractional remainder, then lower fold number. The two control places
are apportioned by the same rule and tie-break, bounded by each fold's routed
quota; that fold's trigger quota is routed minus control. Impossible
distributions fail closed. Within each fold, only its held-out scores are
ranked with the frozen score tie-break. Controls are then chosen by the control
salt only among the non-triggered domains in that same fold. The unions contain
exactly 38 trigger and two control domains. Consequently, changing every
`full` label in a held-out fold cannot change routed membership in that fold,
even though it may alter models trained for other folds.

Equal-budget comparators are a 40-domain deterministic label-blind hash sample
and a 40-domain post-hoc label-aware greedy selection which maximizes
incremental pair lift, then newly covered canonical names, with its own frozen
tie-break. The latter is reported as greedy, never as an oracle or mathematical
upper bound. The historical v0.1.5 report trained a full-cohort deployment
model after OOF evaluation. Revision v0.1.7 replaces that ambiguous lifecycle
with the separate `development-source`, `development-oof`, and `frozen-holdout`
boundary below.

### KISS+ multi-objective candidate and frozen holdout

Calibration revision `2026-08-20.2` does not reweight the failed v0.1.5 scalar
score. It keeps the same raw-free `T1`/`T2`/pre-browser feature surface and adds
only the minimum set-aware targets required by the observed failure:

- a pair head estimates the number of direct `(domain, technology)` pairs in
  `full` but absent from `T2`;
- a bounded binary head is learned for each incremental canonical name which
  appears on at least two training domains;
- one aggregate rare-name head estimates the count of incremental canonical
  names whose training support is exactly one. A name seen only in a held-out
  fold is never inserted into that fold's model.

All heads reuse the fixed smoothing prior of four and the existing deterministic
feature tokens. During selection, recurring-name probability receives
diminishing marginal credit after another selected domain already predicts the
same name. Names already present anywhere in the candidate cohort's `T2` union
receive no breadth credit. The frozen utility is:

```text
predicted pair lift / training pair deficit
+ marginal canonical-name lift / training name deficit
```

The deficits are computed only from the corresponding training partition as
the positive gains still required to reach 80% pair retention and 95% canonical
name retention; each denominator has an explicit minimum of one. No fitted
weight search, browser-cost feature, generic model framework, or new raw signal
is introduced.

Development evaluation remains five-fold and fold-local: models, name support,
deficits, trigger ranking, and controls for a held-out fold use no `full`, cost,
or browser-limit field from that fold. After development GO/NO-GO, one model is
trained on all development snapshots and serialized as a standalone canonical
candidate. The candidate records the immutable development-sidecar digest,
training provenance/config digest, the order-independent digest of the exact
canonical training-domain set, snapshot and calibration revisions, catalog
identity, and the exact scanner/config identity expected for its future
evaluation. Its file digest is pinned independently by the operator.

A prospective holdout run receives that standalone candidate and never receives
the development snapshots or invokes training. It ranks the new cohort globally
for exactly 38 trigger domains, then chooses two deterministic controls from the
remainder. Mutating any holdout `full` label, browser cost, or browser-limit hit
must leave every prediction, greedy step, trigger, and control byte-identical.
Only `T1`, `T2`, or allowlisted pre-browser features may affect membership.
The candidate cannot be evaluated against its training `runId` or the same exact
canonical domain set. This narrow generic guard prevents exact cohort reuse but
does not define the stricter v0.1.8 experiment: the preregistered cohort
manifests must prove zero canonical overlap across `D1`, `D2`, and `H1` before
any `D2` scan.

Real cost is deliberately an evaluation veto, not a predicted score term. All
five selected/full ratios use exact integer comparison against `3/10`; a zero
full total is valid only with a zero selected total. Controls are included in
the numerator. Passing breadth or pair retention cannot compensate for any cost
dimension above 30%.

The existing v0.1.5 sidecar is the pinned development input; its historical
calibration report is not treated as the new candidate. A bounded offline step
canonicalizes its base snapshots and writes the separate candidate before any
holdout traffic. If the KISS+ candidate misses any development guardrail, the
experiment stops: the next action is more training signal/data or a separately
approved raw-free feature, not weight tuning on these same 200 labels.

Every sidecar includes absolute/intersection retention, macro recall, extra
shadow disagreements, actual browser-cost ratios, all bounded scalar
predictions, and a machine-readable `provisional-shadow-challenge` guardrail
verdict. A `development-source` sidecar intentionally contains no candidate.
The offline `development-oof` report can contain a candidate only after a full
PASS, while a `frozen-holdout` report records the pinned candidate and training
identity but never a training result. No per-domain recurring-name probability
vectors are persisted. The two development report modes also include the
equal-budget deterministic-random and label-aware-greedy comparators;
`frozen-holdout` evaluates only the frozen deployable selection and does not
recompute a label-aware comparator on the prospective cohort. The guardrail
boolean is not a ratification by itself.

The pinned v0.1.5 development artifact was evaluated offline with calibration
revision `2026-08-20.2`. The set-aware trigger routed the exact 38+2 domains but
retained only 294/348 canonical direct names (84.48%) and 1,595/2,031
domain-technology pairs (78.53%). Its selected/full browser-cost ratios were
35.78% attempted pages, 37.36% admitted pages, 39.07% requests, 36.64%
transferred bytes, and 39.67% browser milliseconds. It therefore failed both
retention guardrails and every real-cost guardrail. The result is `NO-GO`, the
candidate is `null`, and no new public cohort is authorized by this result.

The 95% and 80% values are provisional challenge guardrails. This cohort has
already informed catalog fixes and metric design, so even out-of-fold results
are descriptive development evidence rather than a production generalization
claim. A final KPI requires a deployable trigger which passes this protocol and
then a fresh representative cohort.

### Preregistered direct-category ablation (v0.1.8)

`shadow-category-ablation.v1.json` is the immutable protocol artifact for the
next experiment, revision `2026-08-20.3`. Its canonical serialization is hashed
before any cohort is instantiated; its frozen digest is
`sha256:bf924836872efc40ee30b92ae51eb456d08ce3172b19de25b401be422107f849`.
The v0.1.5 dataset is named `D1` and is
hypothesis-generation evidence only: it motivated this single feature, but it
cannot train either arm, select the winner, change a threshold, or ratify a KPI.
The preregistration pins its raw sidecar digest
`sha256:1b53023cf747e7194adc3d0261f96f93a556cba041d8ee515e9b4a8dc37ef43e`
and domain-set digest
`sha256:4bd010e4fae36d5f50d468e4e0e47e377040281fa38be0be9dd1d97c48c7c523`.

The paired experiment has exactly two arms over the same snapshots, folds,
labels, quotas, and control-selection rule:

| Feature set | Frozen definition |
| --- | --- |
| `baseline-v2` | The exact raw-free v0.1.7 multi-objective trigger, pinned to its implementation commit. |
| `baseline-v2+t2-direct-category-id-v1` | The baseline plus tokens with the exact form `t2.directCategoryId=<decimal>`. |

For the category arm, each canonical name in `T2.directNames` must resolve to
its technology in the pinned compiled catalog. The feature is the sorted,
deduplicated union of that technology's numeric category IDs. A missing or
ambiguous technology mapping invalidates evaluation instead of silently
dropping a name. The category projection and catalog are digest-bound. No `T1`
name, inferred name, `full` field, browser field, category name/group, or
explicit category-count token is admitted. This is the only new feature family;
there is no weight search, new raw signal, or collector/routing change.

`D2` is a new exact-200 development cohort and `H1` is a distinct exact-200
sealed holdout. Both are frozen from the same named immutable source frame
before the first `D2` scan, with zero canonical-domain overlap among `D1`, `D2`,
and `H1`. Source identity and exact source digest belong to the cohort manifest,
so this preregistration does not claim that any currently considered mirror is
an official source. Candidate domains are normalized and deduplicated using the
static hostname contract only. DNS, HTTP, browser availability, technology
signals, or eventual scan success cannot pre-screen the sample, and a failed or
unavailable domain is never replaced after the manifests are frozen.

Sampling is one deterministic unstratified draw without replacement. Eligible
canonical domains are ordered by
`SHA-256(sampleSalt + NUL + canonicalDomain)`, then by canonical domain as the
collision tie-break. After excluding `D1`, the first 200 become `D2` and the
next 200 become `H1`. The single frozen salt is
`website-technologies-scraper/shadow/2026-08-20.3/cohort-sample/v1`. Sampling is
not stratified and no website probe may influence eligibility.

Each cohort instance has a separate immutable canonical manifest, and both are
frozen before the first `D2` scan. Each binds the preregistration digest, source
name/revision/digest, sampling mode and salt, the ordered input count, the
canonical domain-set digest, and the SHA-256 digest of the exact Parquet input
bytes. The `D2` manifest additionally pins the exact sealed-`H1` manifest
digest. The live `D2` CLI requires both manifests before catalog or pool startup,
and its `paired-development-source` sidecar binds the preregistration, both
manifest digests, and the category projection. The eventual candidate preserves
the same `D2` and `H1` pins; `H1` evaluation accepts only that exact manifest and
also pins the frozen candidate digest. A digest mismatch, overlap, wrong count,
post-freeze replacement, or unbound artifact invalidates the experiment before
interpretation.

The concrete `D2`/`H1` instance was frozen on 2026-08-20 from the official
CrUX BigQuery table `chrome-ux-report.all.202606`, published on 2026-07-14.
The bounded source query lowercases `NET.HOST(origin)`, keeps only ASCII
hostname candidates, deduplicates before applying the frozen SHA-256 rank, and
returns the first 5,000 rows. The completed BigQuery job processed 718,235,611
bytes under a 50,000,000,000-byte billing cap. Its exact query, job receipt,
and CSV are retained locally with these pins:

| Source artifact | SHA-256 |
| --- | --- |
| Query (`output/work/crux-202606-ranked-5000.sql`) | `57e00de2a713402e6260ab6960027870c463ca263e0498280803b3c95466f884` |
| BigQuery job receipt (`output/work/crux-202606-export-job.json`) | `aae01d5c754c14f7f52918dd0f166a2f7d4464d65d40ba5bc0d55aca609f11e3` |
| Ranked source CSV (`output/work/crux-202606-ranked-5000.csv`) | `a17f2dc551d8efd7bc070a619aaf6a0814c775159b78dcd61df316fbb6b49201` |

All 5,000 rows pass the scanner's static hostname contract unchanged; there are
no raw or canonical duplicates and no `D1` overlap. No DNS, HTTP, browser,
technology, reachability, or scan-success signal influenced eligibility. The
first 200 rows are the frozen `D2` input and rows 201–400 are the sealed `H1`
input:

| Cohort artifact | File SHA-256 | Domain-set digest | Manifest digest |
| --- | --- | --- | --- |
| `output/work/d2-crux-202606.parquet` | `2b5b804d933461830d526171552faba4b105487119224d405727bca1ade48f2d` | `sha256:8fa28cd236c0896491714c16df179d36a9d2bde49b75fdbe1917ebfcc545c7b4` | `sha256:1e4c0793f6954988fdaa7c3838e2f1c3db201fedeb0e9642a2d7244b19b4b24e` |
| `output/work/h1-crux-202606.parquet` | `f0bda7f40af62702dddaa6ae428d5b5f6d8100a884de7bc2751f8b4c6331a418` | `sha256:d69b0d4e73c8ee8300943c1376e51be19e3cc49f20945e1bd0edceeb9c5c54ed` | `sha256:f5115d197216ac819a7a8faed7e5ce09a359cee5abd419af9f04876d3d02487f` |

Both Parquet files contain exactly one required UTF-8 `root_domain` column and
200 rows in frozen rank order. They pass the production two-pass reader; all
source, input, and manifest files are single-link regular files with mode
`0600`. The `D2` manifest pins the exact `H1` manifest digest above, and the
three-way canonical overlap is zero. These local artifacts freeze membership;
they do not authorize either public scan.

All v0.1.7 calibration constants remain fixed: five folds, smoothing prior
four, recurring-name support two, 38 trigger domains plus two controls, minimum
95% canonical direct-name retention, minimum 80% canonical direct pair
retention, and at most 30% of each real browser-cost total. Every fold must have
a positive trigger quota or the experiment is invalid. Fold wins compare only
the trigger members; controls are excluded from this comparison but included
in every full-cohort retention, quota, and cost guardrail.

For a domain `d`, let `F(d)` be its canonical direct `full` names and `T2(d)` its
canonical direct `T2` names. Let `U_T2` be the `T2` union over all 200 `D2`
domains, shared by both arms. Within fold `f`, an arm's trigger-only pair lift is
`sum(|F(d) - T2(d)|)` and its novel-name coverage is
`|union(F(d)) - U_T2|` over the fold's selected trigger domains. The category
arm wins the fold only when neither value regresses versus baseline and at
least one is strictly larger. It must win at least four of five folds. This is
a preregistered stability heuristic, not a statistical significance test.

The decision is deliberately baseline-first. If baseline passes every global
guardrail, baseline wins and the extra feature is rejected as unnecessary.
Otherwise the category arm wins only if it passes every global guardrail and
also wins at least four folds. Every other outcome is `NO-GO`; a failed arm is
not ranked into a candidate and the thresholds, salts, folds, quota, or feature
definition are not retuned on `D2`.

Only a passing winner is trained on all `D2` snapshots and frozen as the single
candidate. `H1` is then evaluated once, without training, feature changes,
threshold changes, or retraining after inspection. If that one-shot check
fails, `H1` becomes development evidence and a later claim requires a new
sealed `H2`. Preregistration and manifests do not themselves authorize public
traffic. Functional tier routing remains `HOLD` until the frozen winner passes
the distinct holdout and a later implementation slice is explicitly approved.

### D2 paired-development verdict and bounded v0.1.9 remediation

The authorized fresh D2 run was built from clean commit
`29ccc4ff3577a5cb80fae86c46e6cd643182b014` with scanner `0.1.8`, Node.js
`24.19.0`, Playwright `1.62.1`, Chromium revision `1234`, catalog digest
`sha256:614581009dc6ac2986763f8a324c656e629f63c5ecb7e46cf3ac10b121277724`,
and configuration digest
`sha256:9bd1d4ab621075abdc669f6caf1393a6fc5d36e69e6a5297eb35f2c57ee79584`.
It completed all 200 frozen domains without cohort replacement or resume: 9
`success`, 182 `partial`, and 9 `failed`, with 2,305 direct and 234 inferred
occurrences.
The summary was reconstructed byte-for-byte. The Git-ignored local artifacts
are pinned as follows:

| Artifact | SHA-256 |
| --- | --- |
| `output/work/d2-crux-202606.results.jsonl` | `90242459ed4fc7a88601911a057a7951d2562388cd3fbcf1db188407493b40d1` |
| `output/work/d2-crux-202606.results.summary.json` | `d8ec4532b585a57c4c769ee33e0d0b5a5352371077ae9301a48343e22bc79f3f` |
| `output/work/d2-crux-202606.results.evaluation.json` | `054b14bf7109823775cb2b3aa422ca1983df8d619584e874d66554293c135bb4` |
| `output/work/d2-crux-202606.paired.report.json` | `e8f53b9eb75d23254a55e97efb6e6e96dfc5cc8bbf4809b2608cfc1c93ff0a8d` |

The preregistered decision is `NO-GO`:

| Arm | Canonical names | Domain-technology pairs | Cost dimensions at or below 30% | Category fold wins |
| --- | ---: | ---: | ---: | ---: |
| `baseline-v2` | 302/388 = 77.84% | 1,748/2,305 = 75.84% | 2/5 | not applicable |
| `baseline-v2+t2-direct-category-id-v1` | 302/388 = 77.84% | 1,757/2,305 = 76.23% | 3/5 | 1/5 |

Both arms fail the 95% name and 80% pair guardrails. Baseline also exceeds the
30% ceiling for admitted pages, requests, and browser milliseconds; category
exceeds it for requests and browser milliseconds. The category arm wins only
fold 4, below the required four folds. The machine decision is therefore
`selectedFeatureSet: null`, `reason: "no-arm-eligible"`, and `candidate: null`.
No model was frozen. The H1 evaluation branch is closed as not applicable; its
manifest and Parquet remain sealed, archived, unused, and unscanned.

The bounded diagnosis identified three implementation defects without changing
the frozen weights, folds, salts, quota, thresholds, or global limits:

1. All 17 direct occurrences with probe evidence were probe-only: 13 TYPO3 CMS
   and four Magento. Because raw bodies were intentionally not persisted, the
   run cannot prove that all 17 were false. Local fixtures demonstrate that the
   old presence/generic-literal rules admitted empty, soft-404, or path-echo
   responses; ledger revision `2026-08-20.2` replaces both rules with exact
   stronger literals and covers the mechanism with positive and negative
   fixtures.
2. Nineteen direct T2 pairs disappeared from the authoritative `full` result on
   11 domains; every affected full pass ended with
   `REGEX_EXECUTION_LIMIT` or `REGEX_DOMAIN_BUDGET_EXCEEDED`. Version 0.1.9
   schedules the exact T2 candidate multiset as the first detector phase and
   checkpoints that phase before full-only work, without raising either limit.
3. All 24 historical `BROWSER_UNAVAILABLE` errors co-occur with
   `BROWSER_NAVIGATION_FAILED`. Thirteen have causal proxy telemetry
   (12 `proxy.requestsPerPage`, one `proxy.requestsPerDomain`); one has only an
   earlier unrelated DOM hit, and ten have no limit hit. For those latter 11,
   the exact terminal cause is historically unrecoverable from the raw-free
   artifact because abort won the race against the still-active collection and
   `finish()` emitted the false unavailable. Version 0.1.9 boundedly drains the
   collection first; local fixtures reproduce both a causal limit hit and a
   proxy failure without a hit.

D2 has now informed these fixes and cannot ratify them. The next prospective
experiment therefore requires a fresh development cohort `D3` and a separately
sealed holdout `H2`, with a new digest-bound preregistration and manifests for
the v0.1.9 scanner/catalog identity. Neither cohort, source frame, artifact
chain, nor public traffic is currently frozen or authorized. H1 is not recycled
as H2, and functional tier routing remains `HOLD`.

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
- [x] Implement the bounded fail-closed robots policy and local adversarial
  tests.
- [x] Implement the static HTTP observation collector.
- [x] Implement the fingerprint catalog compiler and HTTP/browser detector.
- [x] Implement the protected browser collector and bounded Chromium pool.
- [x] Add bounded DNS/TLS infrastructure signals.
- [x] Implement `scanDomain()`, deterministic internal-page selection, and
  combined HTTP/browser/DNS/TLS detection.
- [x] Add bounded declarative catalog-probe collection.

Remaining implementation slices:

- [x] Add incremental output, resume, and summary generation.
- [x] Add the runnable CLI that connects Parquet input, the bounded local
  worker pool, `scanDomain()`, and incremental output.

Completion and evaluation gates:

- [x] Run deterministic tests and a small real-site smoke test.
- [x] Scan all 200 domains and analyze misses and false positives.
- [x] Freeze the provisional shadow protocol and exact `T1`/`T2` observation
  views without adopting a final KPI.
- [x] Correct false browser `exists` truncation and add bounded aggregate limit
  telemetry.
- [x] Add the exact catalog-correction ledger with positive and negative
  fixtures.
- [x] Implement independent shadow `T1`/`T2` detector views without functional
  routing or raw-observation persistence.
- [x] Release v0.1.5 and run one fresh 200-domain `full` plus shadow evaluation.
- [x] Calibrate and evaluate the deployable trigger with a frozen deterministic
  out-of-fold split and equal-budget random/label-aware comparators.
- [x] Reject the provisional KPI after the deployable trigger failed canonical
  name and pair retention guardrails.
- [x] Implement and audit the set-aware KISS+ development model, standalone
  digest-pinned candidate, and no-training frozen-holdout evaluator.
- [x] Run the offline development GO/NO-GO against the exact pinned v0.1.5
  sidecar and freeze a candidate only if all retention, quota, and real-cost
  guardrails pass. The result was `NO-GO`, so no candidate was frozen.
- [x] Preregister the paired `baseline-v2` versus direct-`T2` category-ID
  ablation, its 4/5 fold rule, baseline-first decision, immutable artifact
  chain, and sealed-holdout policy.
- [x] Freeze exact-200 `D2` and exact-200 sealed `H1` manifests simultaneously
  from one named immutable source frame, with zero `D1`/`D2`/`H1` overlap and
  no network prescreen or post-freeze replacement.
- [x] Run the two frozen arms once on `D2`. Both failed the global guardrails,
  category won only 1/5 folds, and the result is `NO-GO` with
  `candidate: null`.
- [x] Close the H1 branch as not applicable because D2 produced no eligible
  winner; H1 remains sealed, archived, unused, and unscanned.
- [x] Implement the bounded D2 remediations in v0.1.9: exact Magento/TYPO3
  probe literals with fixtures, T2-first detector work under unchanged limits,
  and bounded draining of the browser collection cleanup race.
- [x] Produce and validate the final v0.1.9 result for all 200 challenge domains
  and answer the three debate topics.

Optional post-challenge research, not submission completion gates:

- [ ] Preregister, freeze, and separately authorize a fresh `D3` development
  cohort and sealed `H2` holdout. No source frame, manifest, or traffic for
  these cohorts is currently approved.
- [ ] Implement functional tiered orchestration only after a frozen deployable
  trigger passes a new representative cohort; this slice is on hold and has no
  reserved version.

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

The readiness gate, application foundation, protected HTTP/browser transports,
robots policy, static and rendered observation collectors, fingerprint
compiler, isolated detector, bounded Chromium pool, catalog probes, DNS/TLS
infrastructure collector, pipeline orchestration, incremental output, resume,
summary generation, runnable local CLI, exact correction ledger, bounded limit
telemetry, raw-free shadow evaluator, bounded set-aware trigger, standalone
candidate boundary, and no-training frozen-holdout evaluator are complete in
versions 0.1.7–0.1.9. Both the v0.1.7 offline development run and the paired
v0.1.8 D2 experiment produced `NO-GO`; D2 published `candidate: null`, so H1
was never scanned and its branch is closed as not applicable. Version 0.1.9
contains only the three bounded remediations recorded above and does not claim
that they pass a prospective cohort. Functional routing remains a later slice
with no reserved version. A fresh `D3`/`H2` chain is neither frozen nor
authorized, and none of the development rejections authorizes lower guardrails,
same-cohort ratification, or public traffic.
