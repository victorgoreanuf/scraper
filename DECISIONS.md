# Decizii proiect

## Ce am decis

- Proiectul va fi un CLI batch scraper, nu o extensie de browser.
- Inputul este fișierul Parquet cu cele 200 de domenii.
- Fiecare domeniu trebuie să aibă un rezultat, chiar dacă scanarea eșuează parțial sau complet.
- Fiecare tehnologie detectată direct trebuie să aibă o dovadă clară.
- Detecțiile directe și cele deduse vor fi marcate separat.
- Crawlerul doar colectează informații, iar detectorul decide ce tehnologii există.
- Regulile de detecție vor fi ținute în fișiere JSON, nu împrăștiate prin cod.
- Un website cu probleme nu trebuie să oprească întregul batch.
- Procesarea trebuie să poată continua după o întrerupere.
- Structura proiectului trebuie să rămână mică și clară, fără directoare sau abstracții inutile.
- Nu vom implementa queue-uri, microservicii sau infrastructură cloud pentru varianta locală.
- Funcția principală va fi `scanDomain()`, astfel încât aceeași logică să poată fi folosită ulterior de workeri distribuiți.
- Runtime-ul proiectului va fi Node.js 24.19.0 LTS, fixat în `.node-version`.
- Package managerul va fi npm 11.17.0, versiunea inclusă în runtime-ul ales.
  Vom comite `package-lock.json` versiunea 3 și vom folosi `npm ci` în medii
  automatizate.
- Dependențele runtime directe vor fi `hyparquet@1.28.2`, `cheerio@1.2.0`,
  `ajv@8.20.0`, `robots-parser@3.0.1` și `playwright@1.62.1`.
- Dependențele de dezvoltare directe vor fi `typescript@7.0.2` și
  `@types/node@24.13.3`.
- Catalogul de bază va fi `enthec/webappanalyzer`, fixat la commitul
  `5e7c47b1d441ded0bd476b252261e87634349f96` din 2026-08-12.
- Vom trata prudent catalogul WebAppAnalyzer ca `GPL-3.0-only`. Codul proiectului
  și fingerprinturile originale vor fi publicate sub `GPL-3.0-only`, iar
  materialele terțe își vor păstra termenii proprii.
- Vom importa doar schema, categoriile și fișierele JSON cu tehnologii. Nu vom
  importa codul, dependențele, iconurile sau brandingul upstream.
- Snapshotul upstream va rămâne nemodificat și separat de fingerprinturile
  create de noi. Sursa, commitul și modificările vor fi documentate în
  `THIRD_PARTY_NOTICES.md` înainte de primul import.
- Wappalyzer comercial, API-ul său, pachetul npm oficial deprecated și înlocuit
  cu un placeholder, precum și copiile cu proveniență sau licență neclară nu
  vor fi surse pentru proiect.
- Regulile permanente pentru Codex și alți agenți de coding vor fi ținute în `AGENTS.md` la rădăcina repository-ului.
- Commiturile vor grupa câte o schimbare logică și vor folosi un mesaj Conventional Commits scurt, cu tip și scope apropiat de sursa modificării.
- Pentru benchmark folosim modul `full`: maximum trei pagini determinate
  reproductibil, scanate HTTP și în browser dacă sunt eligibile și permise.
- Outputul principal este JSONL cu `schemaVersion: 1`, câte un rezultat complet
  pentru fiecare `(runId, domain)` și dovezi sanitizate pentru detecțiile directe.
- Observațiile brute sunt temporare, numai în memorie; nu persistăm HTML, DOM,
  scripturi, headere, cookies sau valori JavaScript brute în versiunea 1.
- Regexurile catalogului rulează cu semantica JavaScript nativă doar într-un pool
  de workeri supravegheat; nu rulează niciodată în threadul principal.
- Inputul Parquet v1 este validat complet înainte de rețea sau output; orice
  rând invalid ori domeniu duplicat după normalizare oprește batchul.
- Hostname-urile au o singură normalizare IDNA strictă, iar fiecare socket HTTP
  și browser este rezolvat, validat ca public și pin-uit la adresa verificată.
- Contractele wire v1 sunt scheme JSON 2020-12 locale pentru `DomainResult` și
  `ScanConfig`; configurația comportamentală folosește digest JCS + SHA-256.
- Domeniile sunt programate în ordinea Parquet, dar liniile JSONL sunt scrise în
  ordinea finalizării; ordinea globală nu face parte din contract.

## Structura proiectului

```text
src/
├── cli.ts
├── config.ts
├── model.ts
├── network-policy.ts
├── pipeline.ts
├── input/
│   └── parquet.ts
├── crawl/
│   ├── transport.ts
│   ├── http.ts
│   ├── robots.ts
│   ├── browser.ts
│   └── infrastructure.ts
├── detect/
│   ├── catalog.ts
│   ├── engine.ts
│   ├── pool.ts
│   └── worker.ts
└── output/
    ├── writer.ts
    └── summary.ts

fingerprints/
├── upstream/
│   └── webappanalyzer/
│       ├── schema.json
│       ├── categories.json
│       └── technologies/
└── custom/
    └── technologies/

schemas/
├── domain-result.v1.schema.json
└── scan-config.v1.schema.json

test/
├── fixtures/
├── toolchain.test.ts
├── domain-result-schema.test.ts
└── scan-config-schema.test.ts
```

Nu vom adăuga foldere generale precum `services`, `repositories`, `helpers`, `common` sau `utils` dacă nu apare o nevoie reală.

## Cum va funcționa scanarea

```text
Parquet
  ↓
preflight complet: schemă, limite, domenii și duplicate
  ↓
normalizare domeniu + candidat target + DNS/SSRF
  ↓
robots protejat + decizie pentru path
  ↓
homepage HTTP + browser izolat
  ↓
maximum două pagini interne determinate reproductibil
  ↓
HTTP + browser + DNS/TLS + scripturi/probe limitate
  ↓
fingerprints în workeri regex terminabili
  ↓
tehnologii + dovezi sanitizate
  ↓
JSONL incremental + summary
```

Scanarea HTTP va colecta:

- URL-ul final și redirect-urile;
- headerele;
- numele și valorile limitate ale cookie-urilor, numai temporar în memorie
  pentru matching;
- HTML și meta tags;
- scripturi și alte resurse externe.

Browserul va colecta:

- numai faptele DOM cerute de planul validat al catalogului, fără serializarea
  sau enumerarea întregului DOM;
- proprietăți JavaScript cunoscute;
- request-uri făcute de pagină;
- semnale randate care nu apar în răspunsul HTML inițial și pot fi interpretate ulterior de detector.

Fetch-ul `robots.txt` nu este el însuși condiționat de robots. Înaintea fiecărui
request top-level și redirect, validăm întâi destinația efectivă, apoi aplicăm
politica robots a schemei/autorității pentru noul path. Redirecturile către altă
autoritate primesc propria politică; cele de pe aceeași autoritate reevaluează
pathul.

## Ce rămâne de confirmat înainte de publicare sau scanare reală

- URL-ul sau emailul real de contact care intră în User-Agent înainte de a
  accesa domenii publice.
- Dacă Veridion permite republicarea fișierului `input/domains.parquet`; până
  confirmăm, acesta rămâne local și ignorat de Git.

Aceste puncte nu blochează scheletul de cod. Valorile de performanță și
trigger-ele modului tiered vor fi ajustate numai după benchmark; contractele de
siguranță, rezultat și redacție nu se relaxează pentru a crește numărul de
detecții.

## Decizia contractului Parquet v1

Acceptăm exact un câmp primitiv top-level `root_domain`, fizic `BYTE_ARRAY` cu
`LogicalType.STRING` sau echivalentul legacy `ConvertedType.UTF8`. Dacă există
ambele adnotări, trebuie să fie coerente. Câmpul poate fi `REQUIRED` sau
`OPTIONAL`, dar fiecare rând trebuie să conțină un string nenul; `REPEATED`,
binary neadnotat, nested sau două câmpuri cu același nume sunt invalide. Coloane
suplimentare sunt permise și ignorate fără decodare. Pentru coloana selectată
acceptăm numai `UNCOMPRESSED` și `SNAPPY`.

Facem două treceri pe row groups: preflight complet și apoi emitere cu
backpressure în ordinea rândurilor. Nu facem trim, coercion sau deduplicare.
Orice valoare invalidă ori duplicat după normalizare respinge întregul input
înainte de output și trafic. Fișierul gol este invalid. Limitele sunt 1.000.000
de rânduri, 65.536 rânduri per row group, 16 MiB metadata/footer și 32 MiB atât
comprimat, cât și necomprimat pentru chunkul `root_domain`. Codurile globale
sunt `INPUT_OPEN_FAILED`, `INPUT_PARQUET_INVALID`, `INPUT_SCHEMA_INVALID`,
`INPUT_LIMIT_EXCEEDED`, `INPUT_DOMAIN_INVALID` și `INPUT_DOMAIN_DUPLICATE`; ele
nu intră în `DomainResult.errors`. Contractul implementabil complet este în
[`Parquet input contract v1`](README.md#parquet-input-contract-v1).

Implementarea proiectează câte un singur row group și coloana selectată la
fiecare apel `hyparquet`, pentru lucru liniar în numărul de grupuri, și nu
decodează statisticile coloanelor ignorate cu parserul strict de string.
Acceptăm numai versiunile de metadata Parquet 1 și 2; `ColumnChunk.file_offset`
este deprecated și nu este folosit, iar offseturile efectiv citite sunt
validate separat. Limitele de chunk și decomprimarea Snappy sunt enforceable,
dar API-ul public `hyparquet@1.28.2` nu permite preflight pentru fiecare count
de page header/RLE înaintea decoderului. Un input Parquet arbitrar încărcat din
exterior va necesita decoder izolat terminabil sau un pre-parser revizuit;
această întărire nu blochează benchmarkul local actual.

## Decizia normalizării hostname și a SSRF

Nu facem trim. Acceptăm un string Unicode limitat, fără whitespace, controls,
surrogate invalid sau sintaxă URL, îl convertim cu `domainToASCII()`, eliminăm
maximum un root dot și folosim lowercase ASCII. Cerem 2–127 labels, maximum 253
caractere, 1–63 caractere per label, numai alfanumeric și hyphen fără hyphen la
margini, iar ultimul label trebuie să conțină o literă. Respingem IDNA invalid,
underscore, IP literal, IPv4 legacy, single-label și toate domeniile IANA
Special-Use plus descendenții lor. Nu adăugăm Public Suffix List în v1.

Pentru fiecare socket și fiecare retry/redirect rezolvăm toate răspunsurile
A/AAAA, respingem orice răspuns nepublic sau set mixt și pin-uim conexiunea la
setul validat. Verificăm `remoteAddress`, dar păstrăm hostname-ul original pentru
Host, SNI și certificat. HTTP și proxy-ul browserului folosesc aceeași politică.
IPv4 blochează registrul special IANA, multicast și endpointul Azure explicit;
IPv6 permite numai `2000::/3` minus intervalele speciale fixate. Tabelele
effective, versiunea și regulile complete sunt contractul unic din
[`Public-address and connection contract`](README.md#public-address-and-connection-contract),
nu date descărcate la runtime.

## Decizia transportului HTTP protejat

Transportul v1 execută o singură tranzacție `GET` și nu urmărește automat
redirecturi sau retry-uri. Orchestratorul robots/HTTP decide următorul pas, iar
fiecare apel repetă validarea URL-ului, rezolvarea DNS completă, verificarea SSRF
pentru toate răspunsurile, pinning și verificarea peer-ului. Alegem primul IP
valid în ordinea `verbatim`, deschidem un
socket nou per tranzacție și păstrăm hostname-ul logic pentru Host, SNI și
certificat. Nu există keep-alive, proxy implicit sau opțiune de producție care
poate dezactiva aceste verificări.

Rezervăm bugetul după preflight-ul URL/anulare și înainte de DNS. Rezolvarea are
un scheduler separat, apoi destinația validată intră în coada HTTP
global/per-origin. Deadline-ul domeniului include cozile, iar timeoutul absolut
al requestului acoperă DNS până la trailers. Deoarece `dns.lookup()` nu poate anula operația
libuv, rezultatele târzii sunt ignorate și un scheduler separat limitează
lookup-urile rămase în fundal fără să țină sloturile HTTP permanent. Bugetul DNS
cumulativ numără IP-uri canonice unice, dar fiecare lookup este limitat la 128
de răspunsuri brute înainte de deduplicare.

Blocul final de headere folosește `maxHeaderSize` nativ și plafonul nostru de
câmpuri. În v1 respingem orice răspuns informațional și orice trailer nenul,
deoarece API-ul high-level Node normalizează whitespace-ul și nu mai permite
reconstrucția exactă a dimensiunii wire cumulative. Body-ul este admis numai după
status și headere: redirecturile, non-2xx, `204` și `205` sunt distruse, iar
apelantul poate respinge și un alt 2xx non-HTML. Acceptăm exact o codare dintre
identity/gzip/deflate/br și limităm streaming bytes wire, decomprimați per body
și decomprimați per domeniu. Retry pairing și backoff aparțin orchestratorului;
transportul păstrează plafonul agregat compatibil cu un retry per request.

## Decizia politicii inițiale de scanare

Primul mod implementat este `full`, ca să obținem un baseline bun pe cele 200 de
domenii. Încercăm determinist HTTPS pe domeniu și `www`, apoi HTTP pe aceleași
hosturi. Folosim numai porturile 80/443, maximum cinci redirecturi și aceeași
validare DNS/adresă efectiv conectată pentru orice request. Un răspuns explicit
de access denial nu este o invitație să încercăm alt alias, browserul sau alte
retry-uri. Un 2xx non-HTML păstrează semnalele HTTP sigure, nu încearcă pagini,
browser, probe sau alias și produce `partial` cu eroarea terminală
`http/UNSUPPORTED_CONTENT_TYPE`, `retryable: false`.

Înaintea paginilor top-level și a probelor citim și aplicăm `robots.txt` pentru
product tokenul `WebsiteTechScraper`. `robots-parser@3.0.1` furnizează gruparea
și wildcard matching numai pe text deja descărcat și limitat de transportul
nostru; wrapperul proiectului deține normalizarea percent-encoding, limitele și
testele relevante din RFC 9309. Nu susținem că pachetul singur implementează
toate detaliile RFC. Un contact real în User-Agent este precondiție pentru
scanarea publică.

Scanăm maximum trei pagini cu roluri wire exacte: `entry`, o pagină `detail` și
o pagină `listing` sau fallback `content`. Linkurile vin numai din homepage-ul
static sau randat, rămân pe originul final, trec robots și exclud auth, account, admin,
cart, checkout, search, legal, query-uri și fișiere. Rankingul și tie-break-ul
sunt fixe. Slotul `detail` rămâne gol dacă nu are candidat; numai slotul
`listing` poate primi fallback `content`, fără două roluri interne duplicate. Nu
facem crawl recursiv și nu ghicim pathuri. Maximum cinci probe declarative
validate rămân în afara numărului de pagini.

În `full`, fiecare pagină HTML 2xx eligibilă primește HTTP și browser. Folosim un
context Chromium nepersistent per domeniu, maximum o pagină activă, sandbox și
CSP active, service workers și downloads dezactivate și fără clickuri, formulare
sau autentificare. Metodele mutabile și WebSocket sunt observate ca tentative,
apoi blocate. Tot traficul browserului trece fără bypass prin proxy-ul local
validant al proiectului; acesta rezolvă și validează destinația efectivă și
deține bugetele. Un canary de startup trebuie să demonstreze că o destinație
nepublică nu primește conexiunea, iar producția adaugă și restricții egress la
nivel de host/container. Interceptionarea Playwright singură nu este considerată
protecție SSRF.
Această acoperire este justificată de snapshotul ales: 785 tehnologii au reguli
pentru script content, 1.609 pentru DOM, 3.326 pentru JavaScript și 109 pentru
requesturi XHR; benchmarkul ne va spune cât lift real aduce fiecare sursă.

Bugetele exacte și failure semantics sunt contractul unic din secțiunile
[`Initial scan policy`](README.md#initial-scan-policy) și
[`Initial resource budget`](README.md#initial-resource-budget). La scară mare,
HTTP rulează pentru toate domeniile, iar probele, paginile interne și browserul
cu scripturile deja descărcate de el sunt tier-uri selective măsurate împotriva
baseline-ului `full`.

## Decizia rezultatului și a dovezilor

Outputul principal este UTF-8 JSONL. Fiecare linie terminată cu newline este un
`DomainResult` complet, iar cheia logică este `(runId, domain)`. Resume acceptă
numai aceeași versiune de schemă și scanner, aceleași versiuni Node,
Playwright/Chromium, catalog, mod și configurație; un fragment final incomplet
poate fi eliminat, însă o linie invalidă în mijloc sau un duplicat oprește
operația. `--retry-failed` nu este promis până când poate rescrie sigur printr-un
fișier temporar și rename atomic.

Contractele wire normative sunt `schemas/domain-result.v1.schema.json` și
`schemas/scan-config.v1.schema.json`, JSON Schema 2020-12 local, fără referințe
remote și cu `additionalProperties: false` la fiecare obiect. Toate câmpurile
fixe există. La top-level numai `finalUrl` este nullable; timpii etapelor
nepornite sunt nullable, counters rămân întregi nenegativi, iar provenance este
complet. Page roles sunt exact `entry`, `detail`, `listing`, `content`, iar
collector arrays sunt exact `[]`, `["http"]` sau `["http", "browser"]`.
Evidence permite `null` pentru `pageId`, `key`, `pattern`, `version` și valoarea
redactată; error permite `null` pentru `pageId`, `ruleId`, `signal`, `limit` și
`catalogRevision`.

JSON Schema închide forma wire și variantele locale, dar nu pretinde să verifice
singur URL/timestamp canonic, sanitizerul, referințele, sortarea, calculele sau
sensul statusului. `src/model.ts` implementează validatorul semantic unic, leagă
digestul de configurația validată și cere explicit contextul boolean
`signalAdmitted`; omiterea lui este invalidă. Writerul și viitorul resume reader
vor aplica acest validator înainte de a accepta recordul.

`success` cere `errors: []`; `partial` cere minimum un semnal admis și o eroare
terminală; `failed` nu are semnale utilizabile, are `technologies: []` și minimum
o eroare terminală. Detecția directă are minimum o dovadă și zero inferences;
cea dedusă are zero evidence/page IDs și minimum un părinte. Codurile de eroare
respectă `^[A-Z][A-Z0-9_]*$` și un registry TypeScript append-only; un cod nou
este compatibil cu schema v1, dar eliminarea sau schimbarea sensului nu este.
Registrul non-regex inițial și toate detaliile implementabile sunt în
[`Result and evidence contract v1`](README.md#result-and-evidence-contract-v1).

Domeniile sunt programate în ordinea Parquet, însă workerii scriu fiecare record
complet când termină. Ordinea globală JSONL este nespecificată/completion-order;
resume păstrează ordinea existentă și doar adaugă. Determinismul este garantat în
interiorul rezultatului, exceptând timestampurile și timings, iar testele și
consumatorii compară după `(runId, domain)`, nu după poziția liniei.

Schema v1 păstrează domeniul și statusul, paginile, tehnologiile, erorile,
timpii, consumul de resurse și provenance pentru scanner, catalog și
configurație. O detecție directă are cel puțin o dovadă; una dedusă nu pretinde
observație și indică părintele/regula. Dacă există ambele, varianta directă are
prioritate. Confidence-ul direct însumează o singură dată contribuția fiecărei
reguli până la 100; repetarea pe alte pagini nu îl umflă. Confidence-ul dedus
folosește cea mai puternică relație validă fără însumarea căilor. O egalitate
între versiuni diferite produce `null`, nu o alegere arbitrară.

Dovada conține locatorul, regula, patternul și numai matchul exact sanitizat,
limitat la 256 code points. Query values, segmentele URL opace, cookies și
headere/valori sensibile sunt redactate; valorile cookie nu sunt nici hash-uite.
O versiune este publicată numai dintr-o sursă neredactată și dacă trece gramatica
sigură fixată. Observațiile brute rămân în memorie doar până la detecție și nu
intră în rezultate, cache, fixtures sau logs. Contractul complet, ordinea,
digesturile și cheile de deduplicare sunt în
[`Result and evidence contract v1`](README.md#result-and-evidence-contract-v1).

`ScanConfig` conține numai comportamentul: identity și policy versions,
concurrency, Parquet, target, robots, HTTP, pages, browser, DNS/TLS,
detection/regex, evidence, redaction și limitele outputului. Input/output paths,
`--resume`, `--force`, log verbosity și progress sunt opțiuni operaționale și nu
intră în digest. Configurația validată și imutabilă se canonizează RFC 8785/JCS,
apoi se hash-uiește SHA-256 ca `sha256:<hex>` lowercase; schema order și
insertion order nu influențează rezultatul. Runtime-ul și catalogul rămân separat
în provenance.

Schema fixează plafoane catalog/output: nume tehnologie 256 code points, nume
categorie 128, ID categorie 1–1.000.000, 32 categorii per tehnologie și 1.024
total; per domeniu maximum 20.000 tehnologii, 128 erori, 256 dovezi sau părinți
per tehnologie și 20.000 din fiecare total. O linie JSONL are maximum 16 MiB
UTF-8. Depășirea produce un record bounded `detect/RESULT_LIMIT_EXCEEDED`, iar
resume respinge o linie peste cap înainte de parsarea JSON.

Relațiile se rezolvă determinist per domeniu. `requires` și
`requiresCategory` formează un singur gate OR care poate fi satisfăcut de o
detecție directă sau dedusă deja admisă și se procesează împreună cu `implies`
până la fixed point, fără autosatisfacere. Gate-ul este condiție de admitere și
nu se revalidează după exclusions, deoarece snapshotul conține variante
specializate care cer apoi exclud tehnologia de bază. `implies` folosește
widest-path, adâncime minimă și provenance aciclic; confidence și versiunea
literală sigură se propagă, iar o detecție directă are prioritate.

O excludere unilaterală își păstrează direcția. Procesăm întâi nodurile cu
indegree zero; numai când rămâne un ciclu alegem winner-ul prin direct înainte
de inferred, confidence descrescător și nume UTF-16. Nodurile eliminate nu își
mai aplică excluderile și nu reapar. La final recalculăm implies și provenance
numai din directele păstrate, fără tehnologiile suprimate și fără să redeschidem
gates sau exclusions; astfel fiecare părinte dedus este și el emis. Referințele
inexistente, self-`requires` nominal, self-`excludes` și tagurile de relație
nesuportate invalidează catalogul înainte de crawl. Un `requiresCategory` egal
cu propria categorie rămâne valid, dar nu se poate autosatisface. Detaliile
implementabile sunt în
[`Relationship resolution`](README.md#relationship-resolution).

## Decizia izolării regex

Păstrăm `RegExp` nativ cu flagul `i`, compatibil cu specificația catalogului,
dar îl compilăm și executăm exclusiv în doi `worker_threads` persistenți.
Threadul principal supraveghează progresul prin `SharedArrayBuffer`, termină un
worker blocat, îl înlocuiește și reia de la ultimul checkpoint confirmat. Regula
care a expirat este omisă numai pentru domeniul curent, ca rezultatul să nu
depindă de ordinea concurentă a domeniilor.

Înainte de dispatch, regulile sunt indexate după signal și locator, iar
candidații fără locator au cap-uri și ranking determinist. Detectorul calculează
limita superioară a execuțiilor și nu trimite un plan inițial care poate depăși
500.000 de apeluri RegExp. Un contor cumulativ deținut de parent include apelul
blocat și orice replay după checkpoint, supraviețuiește înlocuirii workerului și
oprește înaintea execuției 500.001. Pragul de 50 ms este verificat de watchdog,
nu pretins ca plafon real-time exact. După timeout sau crash încercăm o singură
înlocuire; dacă mai există un worker sănătos continuăm degradat și marcăm
domeniul parțial. Dacă întregul pool devine indisponibil, domeniile rămase nu
mai sunt crawl-uite, primesc rezultate `failed` cu `DETECTOR_UNAVAILABLE`, iar
batchul scrie summary complet și iese cu cod nenul.

În auditul snapshotului fixat am separat metadata `confidence/version` și am
găsit 8.037 surse regex ne-goale: toate compilează cu flagul `i` în Node 24.19.0,
lungimea maximă este 1.115 code units, iar 20 folosesc lookaround. Acest audit
confirmă compatibilitatea actuală, nu demonstrează că inputurile adversariale nu
pot produce backtracking catastrofic.

Catalogul are limite de număr, lungime și dimensiune totală, iar fiecare worker
are prag de watchdog pentru compilare și limite V8. Runtime-ul are prag pe
regulă, buget și număr maxim de timeouturi per domeniu și limită de execuții.
După depășire păstrăm matchurile confirmate, emitem o eroare stabilă fără
valoarea observată și marcăm domeniul `partial`. Sintaxa invalidă sau un catalog
care nu poate fi compilat oprește batchul înainte de crawl.

Nu adăugăm `safe-regex`, RE2 sau `re2-wasm`: analiza statică nu poate dovedi
absența ReDoS, iar RE2 ar schimba compatibilitatea pentru unele reguli. Limitele
și protocolul complet sunt în [`Regex execution policy`](README.md#regex-execution-policy).

## Decizia package managerului și a dependențelor

Am ales npm 11.17.0 deoarece vine împreună cu Node.js 24.19.0 și proiectul este
un singur CLI, nu un monorepo. pnpm și Yarn nu aduc acum un avantaj care să
justifice încă un instrument. `package-lock.json` va fixa arborele și
integritatea artefactelor, va fi comis, iar instalările reproductibile vor
folosi `npm ci`. Nu folosim `npm-shrinkwrap.json`, workspaces, Corepack sau o
actualizare separată a npm.

În `package.json` salvăm versiunile directe exact, declarăm
`packageManager: npm@11.17.0`, `private: true` și verificăm prin `devEngines`
perechea exactă Node/npm. Manifestul, `tsconfig.json` și lockfile-ul v3 au fost
create în etapa de fundație aprobată, cu npm 11.17.0. Testele de fundație verifică
automat coerența runtime-ului, manifestului, versiunilor directe, lockfile-ului,
modului ESM, protecției `private` și licenței proiectului.

Cele cinci dependențe runtime au câte o singură responsabilitate:

- `hyparquet@1.28.2` citește inputul Parquet. Are tipuri TypeScript, zero
  dependențe runtime și suportă Snappy direct, deci nu adăugăm
  `hyparquet-compressors`, Arrow, DuckDB sau un writer;
- `cheerio@1.2.0` parsează HTML static și aplică selectori CSS fără să execute
  JavaScript. Primește doar conținut deja descărcat și limitat de transportul
  nostru; nu folosim `cheerio.fromURL()`;
- `robots-parser@3.0.1` aplică regulile robots pe text deja descărcat și validat.
  Are zero dependențe runtime și nu deschide o cale proprie de rețea;
- `ajv@8.20.0`, prin varianta pentru JSON Schema 2020-12, validează catalogul cu
  schema locală fixată și revizuită. Nu acceptă scheme sau referințe remote și
  nu adăugăm `ajv-formats`. Validarea semantică proprie rămâne obligatorie,
  deoarece schema upstream nu restrânge suficient toate câmpurile;
- `playwright@1.62.1` colectează semnalele care apar numai după randare. Este
  dependență runtime, nu `@playwright/test`; instalăm explicit doar Chromium în
  etapa de setup și păstrăm sandboxul activ. Binarele browserului nu intră în
  Git și vor avea licențele/notificările lor păstrate dacă le distribuim.

Pentru dezvoltare folosim numai `typescript@7.0.2` și
`@types/node@24.13.3`. Nu adăugăm `tsx`, `ts-node`, Jest, Vitest, ESLint,
Prettier sau Biome înainte să existe o nevoie măsurată. `tsc` face verificarea
strictă de tipuri, testele folosesc `node:test` și `node:assert`, iar
`tsconfig.build.json` compilează numai `src` în `dist`, fără testele proiectului.
Buildul curăță mai întâi numai directorul generat și ignorat `dist`, astfel încât
fișierele sursă redenumite să nu lase artefacte executabile vechi.

Node.js acoperă nativ argumentele CLI, HTTP(S), URL/DNS/TLS, timeouturile,
decompresia, controlul concurenței, streamurile JSONL, hashingul și testele. De
aceea nu adăugăm Commander, Axios, Undici direct, `p-limit`, dotenv, logger sau
Zod. Toate dependențele directe alese sunt MIT sau Apache-2.0. La generarea
lockfile-ului am verificat arborele tranzitiv, integritatea, scripturile de
instalare, licențele și advisories: fiecare intrare registry are integrity,
licențele declarate în arbore sunt MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause
sau ISC, iar npm a raportat zero vulnerabilități cunoscute la 2026-08-17.
Instalarea inițială a rulat cu lifecycle scripts dezactivate. Playwright 1.62.1
nu are install script și Chromium nu a fost descărcat; instalarea browserului
rămâne un pas ulterior explicit.

Nu adăugăm `safe-regex`, RE2 sau o alternativă. Workerii nativi terminabili și
limitele acceptate mai sus păstrează semantica catalogului și opresc o expresie
blocată fără să blocheze procesul principal.

## Decizia catalogului de fingerprints

La 2026-08-17 am verificat direct repository-ul
[`enthec/webappanalyzer`](https://github.com/enthec/webappanalyzer), licența sa
GPLv3 și revizia aleasă
[`5e7c47b1d441ded0bd476b252261e87634349f96`](https://github.com/enthec/webappanalyzer/commit/5e7c47b1d441ded0bd476b252261e87634349f96).
Snapshotul are 7.575 tehnologii, 109 categorii și semnale potrivite pentru
arhitectura noastră declarativă.

Am ales varianta hibridă: WebAppAnalyzer este baseline-ul nemodificat, iar
regulile originale rămân separat în `fingerprints/custom`. Nu combinăm acum
WhatWeb, HTTP Archive sau alte cataloage suprapuse; facem asta doar dacă
benchmarkul arată un gol concret. WhatWeb conține pluginuri Ruby executabile,
ceea ce nu respectă modelul nostru de date neexecutabile.

Repository-ul upstream declară GPLv3 și nu am găsit o licență sau excepție
separată pentru fișierele JSON. De aceea, ca interpretare prudentă pentru un
proiect self-contained, tratăm catalogul ca `GPL-3.0-only` și folosim aceeași
licență pentru codul proiectului și regulile originale. Materialele terțe își
păstrează licența și notificările proprii. Înainte de a importa catalogul am
adăugat textul complet al licenței și
`THIRD_PARTY_NOTICES.md`. Aceasta este o decizie de conformitate tehnică, nu
consultanță juridică. În această etapă nu am copiat încă niciun fișier din
catalogul terț; notice-ul va fi actualizat la import.

## Ce trebuie măsurat

- domenii procesate cu succes, parțial sau eșuate;
- timpul total și timpul mediu per domeniu;
- throughput și p95;
- numărul total de detecții;
- numărul de tehnologii unice;
- detecții directe și deduse;
- candidați direcți blocați de requirements sau eliminați de exclusions;
- domenii fără tehnologii detectate;
- detecții obținute doar din HTTP;
- detecții suplimentare obținute cu browserul;
- detecții suplimentare obținute din pagini interne sau scripturi externe;
- numărul de request-uri și cantitatea de date descărcată;
- cele mai frecvente erori;
- reguli care par să producă false positives.

## Probleme posibile

- fingerprints incomplete sau învechite;
- false positives și false negatives;
- tehnologii ascunse în bundle-uri JavaScript;
- website-uri care blochează crawlerul;
- timeout-uri, DNS sau certificate invalide;
- pagini diferite în funcție de locație, cookies sau consent banner;
- o singură pagină poate să nu arate întregul stack;
- Playwright poate consuma cea mai mare parte din timp și resurse;
- versiunile tehnologiilor nu sunt întotdeauna vizibile;
- baza de fingerprints poate avea restricții de licențiere.

## Scalare la milioane de domenii

- Fiecare domeniu va fi un job independent și idempotent.
- Tier 1 rulează pentru toate domeniile: target, robots, homepage HTTP, DNS/TLS,
  headere, meta și URL-uri de resurse.
- Tier 2 adaugă probe și o pagină internă statică pentru site-uri ecommerce/CMS,
  pagini HTML subțiri sau zero detecții directe.
- Tier 3 rulează browserul pe homepage și folosește script bodies din răspunsurile
  deja descărcate pentru site-uri relevante obiectivului, dinamice sau
  necunoscute și pentru un sample de control determinist de 1%.
- Tier 4 adaugă product page și scripturile sale numai pentru subsetul ecommerce
  unde homepage-ul nu oferă suficiente semnale.
- Domeniile vor fi împărțite într-o coadă durabilă.
- Un run distribuit `full` poate păstra câte un job idempotent per domeniu; modul
  tiered va persista rezultatul fiecărei etape și va ruta selectiv joburile între
  pool-uri HTTP și browser, fără să schimbe contractele collector/detector/output.
- Workerii de etapă vor fi stateless și vor putea fi porniți în paralel.
- Vom avea retry cu backoff, deduplicare și dead-letter queue.
- Vom limita concurența globală și per hostname.
- Rezultatele vor fi scrise incremental și partiționate.
- Vom monitoriza durata, erorile, throughput-ul și dimensiunea cozilor.
- Numărul de workeri va fi calculat după ce măsurăm costul scanării HTTP și al scanării cu browserul.
- Ținta inițială pentru tiering este minimum 95% din detecțiile directe ale
  baseline-ului `full`, cu browser pe maximum 20% dintre domenii; nu tratăm
  aceste procente ca adevăr înainte de benchmark.

## Descoperirea tehnologiilor noi

1. Versiunea 1 nu persistă observații fără match. O etapă viitoare poate agrega
   numai semnale sanitizate și explicit aprobate după o decizie separată de
   retenție, redacție și scop; nu va păstra cookies sau conținut brut.
2. Vedem ce semnale apar pe mai multe website-uri.
3. Investigăm manual semnalele care par să aparțină unei tehnologii.
4. Găsim mai multe website-uri despre care știm că folosesc tehnologia.
5. Verificăm și exemple negative, ca să evităm reguli prea generale.
6. Adăugăm fingerprint-ul și testele aferente.
7. Versionăm regulile și urmărim dacă apar detecții greșite.

Nu adăugăm o regulă nouă doar pentru că funcționează pe un singur website.

## Notițe pe parcurs

Pentru deciziile importante voi nota simplu:

```text
Data:
Ce am observat:
Ce variante am încercat:
Ce am ales:
De ce:
Ce rezultat am obținut:
```
