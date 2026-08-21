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
- Colectorul browser folosește un pool FIFO bounded de procese Chromium
  reutilizabile, fiecare cu proxy validant propriu, preflight canary obligatoriu
  și cel mult o înlocuire după pierderea procesului.
- Colectorul de infrastructură interoghează numai tipurile DNS cerute de
  catalog pentru domeniul input canonic și reutilizează exclusiv issuerul TLS
  din handshake-ul HTTPS final deja verificat și pin-uit.
- `scanDomain()` unește într-o singură scanare bounded HTTP `p1`–`p3`, browser,
  robots, probe declarative și DNS/TLS, apoi apelează detectorul o dată pentru
  rezultatul `full`; numai evaluarea shadow explicită mai rulează două pass-uri
  independente peste prefixele `T1` și `T2`.
- Coada FIFO pentru slotul `full` rămâne în afara deadline-ului activ al
  domeniului; anularea callerului rămâne activă și în coadă.
- Colectorul de probe revalidează maximum cinci pathuri sortate din planul
  catalogului și emite body observations bounded numai prin originul final,
  robots și transportul protejat comun.
- Instrumentația tiered destinată runului v0.1.5 este numai shadow: rezervă
  static candidatul `T2` și colectează prefixul înainte de browser, dar nu
  rutează lucru și nu schimbă rezultatul `full`. Persistă doar snapshotul
  allowlisted raw-free și agregatele lui; observațiile brute rămân în memorie.
  Pragurile 95%/80%/20% descrise mai jos sunt guardrails provizorii pentru
  experiment, nu KPI final de produs.
- `--shadow-evaluation` este create-only, cere exact 200 de domenii și publică
  sidecarul compact `.evaluation.json` separat de JSONL/summary; nu există resume,
  force sau atomicitate tranzacțională între cele trei artefacte.
- Numai acest mod pornește trei pool-uri detector distincte peste același catalog:
  `full`, `T1` și `T2`. Nu împart slots, workeri sau failure state; orice
  indisponibilitate shadow invalidează calibrarea și sidecarul fail-closed.
- Runul fresh v0.1.5 a respins KPI-ul provizoriu: triggerul deployabil a păstrat
  292/348 nume directe canonice și 1.609/2.031 perechi pe 40/40 domenii rutate.
  Routingul tiered funcțional rămâne `HOLD`; nu coborâm pragurile și nu ratificăm
  o ajustare pe același cohort de dezvoltare.
- Modelul set-aware v0.1.7 separă development de holdout: development source nu
  conține candidat, un candidat standalone poate fi publicat numai după PASS
  complet, iar holdoutul pin-uit prin digest nu antrenează. Candidatul leagă și
  digestul setului canonic exact de domenii folosit la training; același `runId`
  sau exact același set este respins de guardul generic.
  GO/NO-GO offline pe sidecarul v0.1.5 a eșuat retenția numelor, retenția
  perechilor și toate cele cinci costuri; `candidate=null`, fără cohort public
  nou.
- Pentru experimentul paired v0.1.8, setul v0.1.5 devine `D1`, folosit numai la
  generarea ipotezei. Comparăm exact baseline v2 cu baseline plus category IDs
  directe din `T2` pe un `D2` nou de 200 de domenii; `D1`, `D2` și holdoutul
  sigilat `H1` au overlap canonic zero. Regula baseline-first, pragurile,
  foldurile, salts și cota 38+2 sunt preregistrate în
  `shadow-category-ablation.v1.json`. Tieringul funcțional rămâne `HOLD`.
- Runul D2 v0.1.8 a produs `NO-GO`: baseline a păstrat 302/388 nume și
  1.748/2.305 perechi, category 302/388 și 1.757/2.305, iar category a câștigat
  numai 1/5 folds. `candidate=null`; H1 nu a fost scanat, rămâne sigilat și
  arhivat, iar ramura sa de evaluare este închisă ca neaplicabilă.
- Versiunea 0.1.9 remediază bounded exact trei defecte diagnosticate pe D2:
  regulile probe Magento/TYPO3 devin reguli literale exacte în ledgerul
  `2026-08-20.2`, detectorul procesează faza exactă T2 înaintea candidaților
  full-only sub aceleași limite, iar browserul drenează bounded colecția activă
  înainte să propage failure-ul. Nu mărim limitele și nu schimbăm triggerul.
- D2 este acum evidence de dezvoltare și nu poate ratifica aceste corecții.
  Dacă cercetarea tiered continuă, următorul experiment necesită `D3` fresh plus
  `H2` sigilat, cu preregistrare, source frame, manifeste și autorizare noi;
  niciunul nu este înghețat sau autorizat, iar H1 nu este reciclat drept H2.
  Acest experiment este opțional și nu mai blochează submitul challenge-ului.
- Deliverable-ul final folosește pass-ul autoritar `full` v0.1.9 peste exact cele
  200 de domenii originale: 2.098 detecții directe, 167 inferred și 366 nume
  distincte. JSONL-ul
  `sha256:e28b934763e617debc9825aab4c2cc6f27b0b4d9533350068f252ec091dfd6d7`
  și summary-ul
  `sha256:53df7d1daa1f0f868ac3e05482a1f103fa6a82c14e861fb6d10d4807608c227b`
  au setul de input exact, validează semantic integral, iar summary-ul se
  reconstruiește byte-identic. Cercetarea tiered rămâne `HOLD`, nu este activată
  în soluția trimisă.

## Structura proiectului

```text
src/
├── cli.ts
├── config.ts
├── domain-set.ts
├── evaluation.ts
├── evaluation-calibration.ts
├── model.ts
├── network-policy.ts
├── pipeline.ts
├── input/
│   └── parquet.ts
├── crawl/
│   ├── transport.ts
│   ├── http.ts
│   ├── probe.ts
│   ├── robots.ts
│   ├── browser.ts
│   └── infrastructure.ts
├── detect/
│   ├── catalog.ts
│   ├── engine.ts
│   ├── pool.ts
│   └── worker.ts
└── output/
    ├── evaluation-writer.ts
    ├── writer.ts
    └── summary.ts

fingerprints/
├── upstream/
│   └── webappanalyzer/
│       ├── schema.json
│       ├── categories.json
│       └── technologies/
└── custom/
    ├── corrections.v1.json
    └── technologies/ # adăugiri originale opționale

schemas/
├── domain-result.v1.schema.json
└── scan-config.v1.schema.json

test/
├── fixtures/
├── browser-proxy.test.ts
├── browser.test.ts
├── evaluation.test.ts
├── evaluation-calibration.test.ts
├── evaluation-writer.test.ts
├── probe.test.ts
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
robots protejat + homepage HTTP
  ↓
DNS/TLS cerut de catalog
  ↓
rezervare/pagină `T2` statică + probe declarative bounded
  ↓
browser izolat pe homepage + completarea planului `full`
  ↓
HTTP/browser pentru maximum încă un candidat intern
  ↓
scripturi deja observate de browser
  ↓
fingerprints în workeri regex terminabili
  ↓
tehnologii + dovezi sanitizate
  ↓
JSONL incremental + summary
```

Scanarea HTTP colectează:

- URL-ul final și redirect-urile;
- headerele;
- numele și valorile limitate ale cookie-urilor, numai temporar în memorie
  pentru matching;
- HTML și meta tags;
- scripturi și alte resurse externe;
- pathurile validate și body-urile bounded ale probelor declarative.

Browserul colectează:

- numai faptele DOM cerute de planul validat al catalogului, fără serializarea
  întregului DOM sau returnarea unei enumerări a acestuia;
- proprietăți JavaScript cunoscute;
- URL-uri bounded ale requesturilor făcute de pagină și hostname-uri publice
  canonice, în canale separate;
- semnale randate care nu apar în răspunsul HTML inițial și pot fi interpretate ulterior de detector.

Fetch-ul `robots.txt` nu este el însuși condiționat de robots. Înaintea fiecărui
request top-level și redirect, validăm întâi destinația efectivă, apoi aplicăm
politica robots a schemei/autorității pentru noul path. Redirecturile către altă
autoritate primesc propria politică; cele de pe aceeași autoritate reevaluează
pathul.

## Ce rămâne de confirmat înainte de republicare sau crawl la scară de producție

- Fiecare crawl public primește la runtime un contact real în User-Agent;
  benchmarkul v0.1.4 a folosit contactul autorizat de operator, fără să îl
  hardcodăm în repository.
- Politicile finale de robots, opt-out, retenție și terms-of-service trebuie
  revizuite înaintea unui crawl la scară de producție.
- Dacă Veridion permite republicarea fișierului `input/domains.parquet`; până
  confirmăm, acesta rămâne local și ignorat de Git.

Aceste puncte nu blochează scheletul de cod. Evaluarea v0.1.5 a respins
triggerul shadow curent. Un candidat schimbat se îngheață înaintea unui cohort
reprezentativ nou; cohortul curent rămâne descriptiv/de dezvoltare și nu poate
ratifica o ajustare post-hoc. Contractele de siguranță, rezultat și redacție nu
se relaxează pentru a crește numărul de detecții.

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
[`Parquet input contract v1`](docs/TECHNICAL_REFERENCE.md#parquet-input-contract-v1).

Preflightul calculează și un `domainSetDigest` independent de ordinea rândurilor
pentru setul exact de domenii canonice: SHA-256 peste tagul UTF-8 versionat
`website-technologies-scraper/domain-set/v1\0`, numărul de domenii uint64
big-endian, apoi domeniile sortate direct UTF-16, fiecare prefixat cu lungimea
sa UTF-8 uint64 big-endian. Digestul identifică membershipul setului, nu bytes
Parquet sau ordinea lor.

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
[`Public-address and connection contract`](docs/TECHNICAL_REFERENCE.md#public-address-and-connection-contract),
nu date descărcate la runtime.

## Decizia transportului HTTP protejat

Transportul v1 execută o singură tranzacție `GET` și nu urmărește automat
redirecturi sau retry-uri. Orchestratorul robots/HTTP decide următorul pas;
pentru `purpose: "probe"`, un `3xx` este miss și transportul nu interpretează
`Location` drept un nou target. Fiecare apel repetă validarea URL-ului,
rezolvarea DNS completă, verificarea SSRF pentru toate răspunsurile, pinning și
verificarea peer-ului. Alegem primul IP
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

## Decizia colectorului HTTP static

`crawl/http.ts` primește aceeași sesiune protejată și același serviciu robots
pentru toate paginile. Semnalul efectiv read-only expus de sesiune combină
deadline-ul configurat cu anularea callerului și este folosit și pentru
backoff/decode/extracție. Colectorul nu creează și nu închide transport.
Operația entry deține fallbackul aliasurilor și emite `p1`; operația internă
primește exact URL-ul same-origin deja selectat plus `p2` sau `p3`, nu încearcă
aliasuri și leagă erorile de acel ID. Aplică robots înaintea candidatului și a
fiecărui redirect, păstrează
maximum cinci hopuri și un singur retry tranzitoriu cu backoff abortable fix de
100 ms. Pentru 429, singurul `Retry-After` valid este plafonat la două secunde;
denial, 3xx unsupported, TLS permanent, SSRF, target invalid și hard limits
opresc fără alias.

HTML necesită exact un `Content-Type` valid cu essence `text/html` sau
`application/xhtml+xml`; nu facem MIME sniffing. Cheerio 1.2 `decodeStream()`
primește exclusiv body-ul deja limitat. Păstrăm DOM-ul și source-ul decodat emis
de Transform-ul implementării pin-uite, cu test de regresie obligatoriu la
upgrade; nu folosim `fromURL()` și nu adăugăm încă alt decoder. Numai chainul
candidatului selectat intră în observații: redirecturile dau URL/status, iar
headerele și cookies provin doar din finalul 2xx.

Extragem exact meta name/property, script, stylesheet/link, image, iframe,
navigation links și text static normalizat. Toate URL-urile embedded trec
politica comună, nu sunt fetch-uite și împart capul de 5.000. Limitele cookie,
metadata, URL și text păstrează prefixul bounded, emit o singură eroare
`HTTP_RESPONSE_LIMIT_EXCEEDED` și marchează pagina `truncated`, dar nu blochează
browserul. Body/decode/DOM failure este starea distinctă `failed` și nu poate fi
prezentată ca succes HTTP browser-only. Metadata are cap separat de 5.000 și
descendenții `template` sunt inerți. În v1 nu există classifier CAPTCHA pe text.
După entry, pipeline-ul colectează mai întâi infrastructura `T1`, apoi clasifică
snapshotul static pentru rezervarea `T2`; numai după această colectare și după
browser `p1` clasifică reuniunea static + randat pentru candidatul `full`
suplimentar.

## Decizia implementării robots

`crawl/robots.ts` este un serviciu per run, fără stare globală, iar callerul îi
dă aceeași sesiune de transport protejat folosită ulterior pentru pagini și
probe. Cache-ul folosește cheia origin canonical + product token, coalescează
missurile concurente, păstrează numai politici 2xx și rezultate 4xx fără reguli,
expiră conform configurației și se golește explicit la final. Erorile nu sunt
cache-uite. Un redirect cross-authority este fetch-uit protejat, dar textul
definește politica numai pentru originul inițial.

Body-ul 2xx se decodează UTF-8 strict. Păstrăm temporar textul original bounded
ca semnal pentru detector, dar parserul primește numai liniile normalizate
`User-agent`, `Allow` și `Disallow`; celelalte directive nu schimbă comportamentul
v1 și nu separă grupurile. Acceptăm numai product token RFC (`*`, litere,
underscore, hyphen), ignorăm tokenuri goale/versionate, iar rule path poate fi
gol sau începe cu `/`; acceptăm și `*` inițial pentru compatibilitate cu exemplul
RFC și errata ABNF raportată. Normalizăm escape-urile percent pentru octeții
ASCII unreserved în reguli și path, fără să decodăm escape-uri rezervate.
Tokenul exact `WebsiteTechScraper`, case-insensitive, are prioritate față de `*`,
inclusiv pentru un grup exact gol la final.

Înainte de `robots-parser` aplicăm limite enforceable pentru bytes, linii,
pattern canonical și lucru de matching. Plafonul de 500 reguli numără
asocierile efective `User-agent × Allow/Disallow`, inclusiv reguli goale și agenți
duplicați, ca expansionarea internă a pachetului să rămână bounded. Pentru un
URL, formula conservativă este suma
`pattern.length × (path.length + 1)` pe grupul relevant; peste plafon eșuăm
înaintea apelului sincron. Folosim o singură evaluare `isAllowed()`.

Un disallow este o decizie normală, nu o excepție: entry orchestration îl poate
materializa ca `ROBOTS_DISALLOWED`, iar paginile interne/probele îl pot trata ca
skip intenționat. `404`, `410` și celelalte 4xx non-denial/non-transient înseamnă
fără reguli. Denial, `408`, `425`, `429`, alte 3xx, 5xx, UTF-8 invalid și conținut
inutilizabil sunt fail-closed. Modulul nu face retry intern în v1; erorile
transportului păstrează codurile DNS/TLS/SSRF/deadline, iar limitele și
indisponibilitatea locală folosesc codurile robots stabile.

Cache-ul actual este potrivit benchmarkului cu 200 domenii, dar nu are încă un
plafon separat de entries/bytes. Înainte ca un worker să primească o partiție
nebounded la scară de milioane vom adăuga un cap măsurat sau LRU în configurația
digestată; nu inventăm acum o valoare fără benchmark.

Browserul nu poate aștepta un fetch robots din request/redirect interception.
Pipeline-ul încălzește politica prin `check()` înainte de navigare, iar gate-ul
sincron folosește numai `allowsCached(url)`. Un entry lipsă, pending, expirat,
invalid ori indisponibil întoarce exact `false`; această cale nu face rețea, nu
returnează Promise și nu transformă necunoscutul în allow.

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
o pagină `listing` sau fallback `content`. Candidații sunt exclusiv linkurile de
navigare din `p1`: snapshotul static înghețat pentru rezervarea `T2`, apoi
reuniunea deduplicată static + randat pentru maximum încă un candidat `full`.
Nu ghicim pathuri, nu folosim linkuri din paginile interne și nu facem crawl
recursiv.
Acceptăm numai HTTP(S) canonic pe exact originul final, fără credentials, query
sau fragment, diferit de root și de URL-ul final și în limita URL configurată.

Pe segmentele path lowercase excludem exact `auth`, `login`, `log-in`, `signin`,
`sign-in`, `signup`, `register`, `account`, `admin`, `wp-admin`, `cart`,
`basket`, `bag`, `checkout`, `logout`, `search`, `legal`, `privacy`, `terms`,
`policy`, `cookie` și `cookies`. Excludem și un URL file-like când ultimul segment
nenul se termină cu punct plus minimum un caracter ASCII alfanumeric. `detail`
înseamnă segment `product`, `products`, `item` sau `items` urmat de încă un
segment nenul. În lipsa acestei clase, `listing` înseamnă un segment `shop`,
`store`, `catalog`, `category`, `categories`, `collection`, `collections` sau
`product-category`; restul pathurilor eligibile sunt `content`.

Ordinea tokenurilor de mai sus este rangul fix în fiecare clasă, urmat de
pathname canonic mai scurt și apoi URL canonic în ordine directă UTF-16. Alegem
maximum un `detail` și un `listing`; numai dacă nu există listing alegem un
`content` cu un singur rang fix pentru acel slot. Slotul detail absent rămâne
gol, iar alegerile structurale se sortează după URL-ul canonic de rețea.

După ce entry + infrastructura au completat `T1`, rulăm selectorul numai pe
linkurile statice `p1` înghețate și rezervăm prima alegere pentru `T2`. Îi facem
un singur check robots și, dacă este admisă, o singură colectare HTTP înainte de
probe și browser. Rezervarea consumă
slotul detail sau non-detail chiar la denial, unavailable, coliziune sanitizată,
skip ori failure și nu primește backfill. După browser `p1`, planul `full`
păstrează rezervarea și poate adăuga din reuniunea static + randat maximum un
candidat din slotul opus. Facem deci maximum două checks robots interne.

Sanitizăm rezultatele admise pentru publicare, eliminăm coliziunile cu entry-ul
sau între ele, le resortăm după URL-ul public și abia apoi atribuim IDs compacte
`p2`/`p3`, fără goluri. Rezultatul HTTP rezervat provizoriu este remapat la ID-ul
public final; ordinea colectării nu devine ordine wire.

Maximum cinci pathuri de probe declarative sunt validate și sortate în planul
catalogului, rămân în afara numărului de pagini și sunt colectate prin politica
separată de mai jos. Un entry non-HTML nu pornește probe.

În `full`, fiecare pagină HTML 2xx eligibilă primește HTTP și browser.
`crawl/browser.ts` implementează un pool FIFO cu un proxy protejat și un proces
Chromium reutilizabil per slot `fullScans` (trei implicit). Toate sloturile trec
preflight înaintea domeniilor; runtime identity fixează Playwright `1.62.1`,
revizia Chromium `1234` și aceeași versiune raportată de fiecare proces. Un
proces pierdut primește maximum o înlocuire; pool-ul continuă degradat cât timp
mai există un slot sănătos și devine indisponibil fără spawn loop când le pierde
pe toate.

Preflightul complet al unui slot inițial sau replacement este bounded de
`limits.timeMs.browserPage`. Cleanup-ul paginii, contextului, procesului,
proxy-ului și canary-ului are watchdog fix de o secundă, astfel un apel
Playwright blocat nu poate ține coada FIFO nelimitat. Un replacement care nu-și
termină preflightul este eliminat, nu relansat într-un spawn loop. Abortul local
al domeniului produs de o limită sau eroare proxy închide contextul, dar nu
consumă replacement-ul procesului; numai disconnectul Chromium ori cleanup-ul
eșuat marchează slotul nesănătos.

Același watchdog de o secundă limitează drain-ul intern când abortul callerului
sau al domeniului devansează o colecție de pagină deja pornită. `collectPage()`
așteaptă ca promisiunea internă să se finalizeze ori ca watchdogul să expire
înainte să propage failure-ul. Astfel `finish()` poate păstra diagnosticul exact
proxy/pagină și telemetry raw-free deja în curs de finalizare, fără retry,
fereastră nelimitată sau transformarea race-ului într-un fals
`BROWSER_UNAVAILABLE`.

Fiecare domeniu primește un context Chromium nepersistent, reutilizat secvențial
pentru `p1`–`p3`, cu maximum o pagină activă și exact același origin. Sandboxul
și CSP rămân active, service workers și downloads sunt dezactivate și nu există
clickuri, formulare sau autentificare. Planul generic de inspecție este compilat
din catalog, are tipurile comune deținute de `src/model.ts` și cere numai fapte
DOM și pathuri JavaScript bounded; `crawl` nu importă `detect`, nu emite o
enumerare a DOM-ului și nu enumeră `window` complet.

Pentru o inspecție formată exclusiv din fapte attribute, capul per selector
numără numai elementele care corespund selectorului și au cel puțin unul dintre
atributele cerute. Elementele irelevante sunt traversate streaming, dar nu
consumă bugetul de observații; inspecțiile existence, text, property și mixte
păstrează contabilizarea match-urilor brute ale selectorului.

Pentru un selector ale cărui fapte sunt exclusiv `exists`, primul match eligibil
este suficient: traversalul se oprește acolo, emite toate presence facts cerute
și nu mai declară fals depășirea `domMatches`. Zero match rămâne observație goală
după traversal complet. Inspecțiile mixte/value păstrează capul per selector,
fiindcă elementele pot avea valori diferite.

Colectorul întoarce intern, pe lângă eroarea publică sanitizată, hits bounded și
deduplicate de forma `(category, domSelectorOrdinal|null)`. Ordinalul apare numai
pentru `inspection.domMatches` și `inspection.domAccess`; celelalte limite DOM,
cookie, network, script și proxy au `null`. Evaluatorul le leagă de `pageId` și
catalog digest, apoi agregă `(category, ordinal)` în hits, pagini și domenii
afectate fără să adauge acest diagnostic în schema publică `DomainResult`.

Metodele mutabile și WebSocket sunt observate ca tentative, apoi blocate.
Playwright routing decide și numără requesturile inițiale. Pentru redirecturile
automate, un gate CDP `Fetch` oprește atât response stage, cât și următorul
request stage: validează `Location`, URL-ul, metoda, resursa, loop/depth, originul
top-level și decizia robots sincronă exact `true`, apoi corelează
`redirectedRequestId` înainte să numere și să autorizeze hopul o singură dată.
Orice rezultat robots Promise/non-boolean sau corelare invalidă eșuează înainte
ca targetul redirectat să ajungă în rețea. Același response-stage gate permite
body-ul documentului root numai pentru un răspuns exact 2xx HTML/XHTML; denial
și non-HTML sunt oprite înainte de executarea scripturilor. După admiterea
documentului, navigările top-level noi rămân blocate pe durata settle/inspection.

Tot traficul browserului trece fără bypass de destinație prin proxy-ul local
validant al proiectului; acesta rezolvă toate răspunsurile, respinge adresele
mixte/nepublice, pin-uiește conexiunea 80/443 și verifică peer-ul. Pentru HTTP,
fiecare request admis primește un grant consumabil o singură dată. Pentru HTTPS,
tunelul TLS este opac: Playwright/CDP deține admiterea și contorul logic per
request, iar proxy-ul autorizează authority-ul CONNECT, aplică egress și numără
bytes criptate downstream. Interceptionarea Playwright/CDP rămâne strat de
politică, nu boundary-ul SSRF.

Fiecare socket TCP acceptat de proxy aparține generației de pagină active în
acel moment. Dacă nu există o pagină activă — inclusiv în intervalul de cleanup
dintre două pagini ordonate — socketul este distrus imediat și nu poate ajunge
în generația următoare cu granturile ei HTTP/HTTPS resetate. Un CONNECT valid
sintactic, dar fără grant HTTPS curent, primește local 502 fără DNS sau conexiune
upstream și nu otrăvește domeniul; metoda, authority, Host, portul, headerele ori
protocolul malformate rămân failure terminal al proxy-ului.

Fiecare slot trece un canary de startup cu hostname sintetic mapat la un listener
loopback atât prin regula resolverului Chromium, cât și prin resolverul canary al
proxy-ului. Proxy-ul trebuie să înregistreze respingerea adresei nepublice, iar
listenerul trebuie să primească zero conexiuni. Producția adaugă și restricții
egress la nivel de host/container.

Script bodies provin numai din răspunsurile deja descărcate de browser, maximum
20, selectate determinist după `pageId`, apoi same-origin înainte de
cross-origin, apoi URL. Requesturile HTTP(S) produc separat URL-uri canonice
bounded (`network_url`) și hostname-uri publicabile (`network_hostname`). Cele
113 reguli upstream `xhr` se aplică URL-ului complet păstrat numai în memorie,
nu doar hostname-ului: 16 cer path sau query. Dovada publică numai forma URL
sanitizată/redactată. Această acoperire este justificată de snapshotul ales: 785
tehnologii au reguli pentru script content, 1.609 pentru DOM, 3.326 pentru
JavaScript și 109 tehnologii au reguli XHR; benchmarkul ne va spune cât lift
real aduce fiecare sursă.

Testele `browser-proxy.test.ts` folosesc servere și hookuri locale controlate
pentru grants HTTP consumabile, CONNECT, DNS mixt/nepublic, peer mismatch,
cleanup, limite și canary zero-hit. `browser.test.ts` verifică opțiunile sigure,
preflightul de slot, coada FIFO, paginile ordonate, gate-ul robots/CDP,
rankingul top-20, replacement/cleanup și o pagină reală Chromium care trece
numai prin proxy-ul protejat. CI nu depinde de website-uri publice.

Bugetele exacte și failure semantics sunt contractul unic din secțiunile
[`Initial scan policy`](docs/TECHNICAL_REFERENCE.md#initial-scan-policy) și
[`Initial resource budget`](docs/TECHNICAL_REFERENCE.md#initial-resource-budget). La scară mare,
HTTP rulează pentru toate domeniile, iar probele, paginile interne și browserul
cu scripturile deja descărcate de el sunt tier-uri selective măsurate împotriva
baseline-ului `full`.

## Decizia colectării probelor declarative

Politica v1 este implementată în `crawl/probe.ts`. Colectorul primește URL-ul
final de rețea numai pentru un entry HTML, maximum cinci pathuri din planul
catalogului, configurația validată, sesiunea de transport protejat și serviciul
robots al runului. Rulează secvențial după infrastructura `T1` și colectarea HTTP
a rezervării statice `T2`, dar înainte de orice navigare browser, finalizarea
sesiunii browser și detecție.

Compilatorul și collectorul validează independent pathurile. Ele trebuie să fie
unice, să înceapă cu exact un `/`, să nu conțină backslash, query, fragment sau
o schimbare de origin și să supraviețuiască rezolvării WHATWG fără normalizare.
Colectorul le sortează direct după code units UTF-16 și construiește fiecare URL
de la rădăcina originului final exact, nu relativ la pathname-ul paginii finale.
Atât pathul, cât și URL-ul complet `origin + path` respectă capul URL configurat;
un URL compus prea lung emite `HTTP_LIMIT_EXCEEDED` non-retryable înainte de
robots sau rezervarea transportului și oprește stage-ul.

Înaintea fiecărui path aplicăm robots pe URL-ul compus. Denialul este un skip
intenționat fără request sau eroare; indisponibilitatea robots păstrează eroarea
stabilă, eșuează fail-closed și oprește stage-ul. Orice body robots admis rămâne
semnal bounded `robots` cu `pageId: null` și este deduplicat ulterior.

Un path permis primește exact un `GET` protejat cu `purpose: "probe"`, fără
retry și fără urmărirea redirecturilor. Numai `2xx` produce observație; `204` și
`205` produc body gol. Un `3xx` nu este urmat, iar un `4xx` obișnuit este miss și
permite următorul path. `401`, `403`, `407` și `451` emit
`HTTP_REQUEST_FAILED` non-retryable și opresc probele rămase. `408`, `425`,
`429` și `5xx` emit același cod cu `retryable: true` și opresc fără retry în
scanarea curentă. Erorile transportului, deadline-ului, decomprimării, politicii
de destinație sau limitelor își păstrează codurile și opresc stage-ul.

Body-ul admis folosește maximum 256 KiB comprimat și 512 KiB decomprimat, plus
bugetul static decomprimat per domeniu, și este decodat UTF-8 cu replacement
determinist pentru secvențe invalide. Nu interpretăm charseturi legacy din
`Content-Type`. Astfel, un răspuns bounded rămâne disponibil regulilor presence,
iar regulile literale se aplică numai stringului rezultat. Observația conține
doar pathul validat și body-ul decodat; headerele, cookies, statusul și URL-ul
probe-ului nu devin semnale suplimentare.

Transportul deține accountingul: la rezervarea efectivă a unei tranzacții
`purpose: "probe"` incrementează atomic atât `httpRequests`, cât și
`probesIssued`, înainte de DNS. O eroare ulterioară nu scade contorul, iar un
denial robots sau un reject înainte de rezervare nu îl crește. Același boundary
enforcează capul de cinci probe, totalul de 40 tranzacții, deadline-ul și
bugetele de bytes; `staticTransferredBytes` include body bytes citiți pentru
probe.

Detectorul primește probele în aceeași invocare cu toate celelalte observații.
Pathul exact devine locatorul/key, iar body-ul bounded este valoarea pentru
reguli presence sau literale. Evidence este întotdeauna
`collector: "http"`, `source: "probe"`, `pageId: null`; valoarea body-ului este
redactată și probele nu creează `PageRecord`, nu schimbă `pagesVisited` și nu
afectează prefixul paginilor browser.

## Decizia colectării semnalelor DNS/TLS

Politica este fixată prin `policyVersions.infrastructure: 1` și implementată în
`crawl/infrastructure.ts`. Ownerul DNS este întotdeauna domeniul input canonic,
nu aliasul `www`, hostname-ul final ori un hostname extras din pagină. Planul
compilat al catalogului cere explicit tipurile necesare, iar colectorul emite
numai query-uri typed pentru `A`, `AAAA`, `CAA`, `CNAME`, `MX`, `NS`, `PTR`,
`SOA`, `SRV` și `TXT`, în ordine fixă. Nu folosim `ANY`, query-uri speculative
sau DNSSEC în v1.

Normalizarea DNS produce un string per record. `A`/`AAAA` folosesc adresa
publică în forma canonică. `CNAME`/`NS`/`PTR` folosesc hostname lowercase fără
punct terminal; `MX` păstrează numai `exchange` normalizat, `SOA` numai
`nsname`, iar `SRV` numai `name`. `CAA` păstrează numai value-ul, iar fiecare
item `TXT` își unește chunkurile fără separator. Toate răspunsurile brute
`A`/`AAAA` trebuie să treacă politica adreselor publice; nu păstrăm subsetul
public al unui răspuns mixt sau invalid.

Limitele de 32 records per tip și 128 per domeniu se consumă pe răspunsurile
brute, înainte de deduplicare, iar toate query-urile sesiunii folosesc același
buget. După normalizare, valorile se deduplică și se sortează cu comparație
directă `<`/`>`. Bugetele TXT de 4 KiB per item și 64 KiB text DNS total sunt
tot comune sesiunii. `ENODATA` și `ENOTFOUND` înseamnă absență normală pentru
tipul cerut, fără eroare sau retry. Întregul stage are un singur deadline absolut
`dnsLookup` de maximum 10 secunde; timeoutul sau anularea din exterior anulează
resolverul și nu pornește ferestre noi per tip. Colectorul DNS nu face retry.

Issuerul TLS se preia numai din handshake-ul răspunsului HTTPS final deja
validat de transport: certificat verificat, hostname/SNI păstrat și conexiune
pin-uită la IP-ul admis. Nu deschidem o a doua conexiune TLS. Lipsa unui răspuns
final, un final HTTP ori lipsa issuerului în handshake înseamnă skip fără
eroare. Issuerul are limita `issuerBytes` de maximum 4 KiB UTF-8, nu se
trunchiază, iar depășirea emite `TLS_LIMIT_EXCEEDED` non-retryable. Nu expunem
DNSSEC, versiunea protocolului TLS, cipherul, subjectul, SAN-urile, serialul,
validitatea sau material criptografic ca semnale de detecție în v1.

## Decizia orchestrării pipeline v1

`scanDomain(domain, runtimeContext)` este boundary-ul per domeniu și nu cunoaște
sursa inputului sau destinația outputului. Contextul per run leagă configurația
și provenance validate de catalogul compilat, transport, serviciul robots și
pool-urile browser/detector. Mismatchurile de digest, catalog ori runtime și
pool-urile obligatorii indisponibile eșuează la preflight. Scanarea închide doar
sesiunile per domeniu; nu închide pool-urile și nu golește cache-ul robots al
runului.

Așteptarea FIFO pentru slotul `full` are caller cancellation, dar nu consumă
deadline-ul activ. După admitere fixăm `scannedAt`, pornim `totalMs` monotonic,
armăm `activeDomain` și creăm sesiunea HTTP cu semnalul combinat. Toate cozile și
operațiile ulterioare, retry/backoff și cleanup intră în acel deadline. Anularea
callerului se propagă după cleanup bounded și nu este convertită în
`DOMAIN_DEADLINE_EXCEEDED`; codul rămâne exclusiv timerului activ al
pipeline-ului. Proxy-ul și sesiunea transport își păstrează timerele locale
same-duration ca fail-safe pentru folosirea standalone, dar în `scanDomain()`
primesc semnalul pipeline deja armat, primul și autoritativ.

Ordinea bounded este: HTTP/robots `p1`; DNS cerut de catalog și issuerul TLS
reutilizat, care închid prefixul `T1`; înghețarea și rezervarea candidatului
static `T2`; checkul robots și HTTP-ul rezervării; probele sortate pe originul
final, care închid prefixul `T2`; browser `p1` numai pentru
HTML 2xx complete sau truncated; completarea planului `full` din reuniunea
static + randat cu maximum încă un candidat; check/HTTP pentru acel candidat;
sortarea publică și browserul prefixului compact `p2`/`p3`; finalizarea sesiunii
browser; apoi pass-ul detector `full` cu toate observațiile HTTP, browser,
robots, probe, DNS și TLS. Relațiile și excluderile se rezolvă o dată pe setul
combinat autoritativ.

Într-un run obișnuit acesta este singurul pass. Cu callback shadow explicit,
după materializarea și validarea `DomainResult` oprim deadline-ul activ și
rulăm concurrent detectorul pe prefixele imutabile `T1` și `T2`, numai sub
caller cancellation, în două pool-uri dedicate distincte între ele și de pool-ul
`full`. Timpii acestor două pass-uri nu intră în `DomainResult`, iar snapshot
sink-ul nu poate modifica rezultatul `full` deja validat. Pool-urile nu împart
cozi, slots, regex objects sau lifecycle failures; rămâne totuși costul comun de
CPU/memorie al hostului.

Orice body robots admis cu succes în entry, precheck structural, colectarea unei
pagini interne sau verificarea unui probe rămâne semnal de detector cu
`pageId: null`, inclusiv când lucrul asociat este ulterior omis ori eșuează.
Detectorul deduplică valorile identice, iar existența unui astfel de semnal
participă la alegerea `partial`/`failed`.

O pagină statică eșuată nu poate deveni browser-only. Navigările browser formează
un prefix ordonat: după un gap nu deschidem o pagină browser ulterioară, deși un
`p2`/`p3` deja selectat poate păstra observațiile HTTP. Un entry final non-HTML
urmează terminalul `partial` deja decis și nu pornește pagini interne.
O limită de observație browser păstrează draftul bounded, eroarea și statusul
`partial`, dar nu creează un gap: pagina primește collectorul browser, iar
`p2`/`p3` rămân eligibile. Admiterea draftului decide provenance-ul paginii,
separat de reutilizarea contextului: o eroare terminală de navigare, timeout,
proxy, policy, lifecycle ori cleanup închide prefixul chiar dacă draftul bounded
al paginii curente rămâne admis.

`targetMs` măsoară selecția entry, `robotsMs` acumulează lucrul robots, iar
`httpMs` include paginile și probele, dar exclude robots inclus în colectarea
statică. Celelalte stages măsoară numai lucrul pornit, pot overlap și sunt
plafonate la `totalMs`; un stage nepornit este `null`. Pipeline-ul deduplică și
sortează erorile, construiește usage din sesiunile efective, sanitizează
rezultatul și îl trece prin validatorul semantic înainte să-l returneze.

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
`signalAdmitted`; omiterea lui este invalidă. Pipeline-ul aplică această
validare cu factul real înainte să returneze rezultatul. Writerul și resume
readerul validează valoarea serializată sub semantica persisted-record: au
încredere numai în statusul deja validat, dar reaplică schema, invariants
semantice independente de istoria colectării, limitele și identitatea completă
a runului.

`success` cere `errors: []`; `partial` cere minimum un semnal admis și o eroare
terminală; `failed` nu are semnale utilizabile, are `technologies: []` și minimum
o eroare terminală. Detecția directă are minimum o dovadă și zero inferences;
cea dedusă are zero evidence/page IDs și minimum un părinte. Codurile de eroare
respectă `^[A-Z][A-Z0-9_]*$` și un registry TypeScript append-only; un cod nou
este compatibil cu schema v1, dar eliminarea sau schimbarea sensului nu este.
Registrul non-regex inițial și toate detaliile implementabile sunt în
[`Result and evidence contract v1`](docs/TECHNICAL_REFERENCE.md#result-and-evidence-contract-v1).

Fiecare rezultat persistă `detectionStats` cu exact `rawDirect`, `gatedDirect`,
`suppressedDirect` și `retainedDirect`. Primul numără candidatele directe cu
confidence pozitiv înainte de relații, al doilea pe cele respinse de gates, al
treilea pe cele eliminate de exclusions, iar ultimul pe cele directe păstrate
înainte de materializarea bounded. Toate sunt întregi bounded și
`rawDirect = gatedDirect + suppressedDirect + retainedDirect`.

Domeniile sunt programate în ordinea Parquet, însă workerii scriu fiecare record
complet când termină. Ordinea globală JSONL este nespecificată/completion-order;
resume păstrează ordinea existentă și doar adaugă. Determinismul este garantat în
interiorul rezultatului, exceptând timestampurile și timings, iar testele și
consumatorii compară după `(runId, domain)`, nu după poziția liniei.
După eliminarea fragmentului final permis, un fișier fără niciun record complet
nu are identitate persistată; resume generează un UUID nou și continuă ca run
gol în același fișier validat.

În v1, `scannerVersion` din manifest este identitatea buildului persistată de
resume. Orice schimbare de cod care poate modifica crawl, detectare, validare sau
output cere bump de versiune înaintea unui run persistent; artefactele de
dezvoltare produse de commituri diferite nu se combină doar pentru că au același
catalog și același config digest.

Writerul validează modul înainte de orice mutație și acceptă ca rezultat
existent numai un fișier regular, non-symlink, cu un singur hard link, verificat
și prin descriptor. Summary-ul pereche trebuie să fie regular și non-symlink,
dar poate avea încă un hard link: un crash poate surveni între publicarea prin
`link(temp, summary)` și ștergerea aliasului temporar. Create îl tratează ca
existent, iar resume/force șterg numai aliasul summary validat, fără să modifice
inode-ul vizibil prin alt hard link. Resume face asta numai după validarea
completă a prefixului; force înainte să trunchieze rezultatul validat. Într-un
proces poate exista un singur writer în directorul output canonic; o a doua
deschidere în același inode de director dă `OUTPUT_BUSY`, iar close/finalize
eliberează ownership-ul. Lock-ul conservator pe director evită aliasurile de
filename produse de regulile Unicode/case ale filesystemului fără un al doilea
motor de collation; CLI-ul are nevoie de un singur result writer. V1 nu
implementează locking între procese: writeri concurenți din procese diferite sunt
unsupported, iar apelantul trebuie să îi serializeze.

Publicarea summary-ului folosește un temp exclusiv și sincronizat, apoi un hard
link exclusiv. Writerul verifică după link că device/inode-ul publicat este exact
cel validat prin descriptor și șterge temp-ul numai dacă pathname-ul încă indică
acel inode; un replacement concurent nu este publicat și nu este șters.

Summary-ul v1 este un obiect TypeScript închis și deep-frozen cu exact
`schemaVersion`, `runId`, `scanMode`, `inputDomains`, `processedDomains`,
`statusCounts`, `technologies`, `detectionStats`, `durationMs`, `usage`,
`evidenceAttribution`, `hardLimitHits`, `errors`, `provenance` și `config`.
Numără tehnologiile ca apariții domeniu-tehnologie, iar `unique` ca nume
distincte. Media duratei este rotunjită la trei zecimale; p50/p95/p99 folosesc
nearest-rank `ceil(p*n)-1`, cu zero pentru un run fără rezultate. Erorile sunt
grupate după stage/code și sortate în ordinea fixă a stages, apoi după cod UTF-16.
Hard-limit hits sunt codurile terminate în `_LIMIT_EXCEEDED` plus
`REGEX_DOMAIN_BUDGET_EXCEEDED` și `REGEX_EXECUTION_LIMIT`.

Atribuirea evidence este direct-only, exactă și neaditivă: numără separat
aparițiile domeniu-tehnologie directe emise cu evidence persistat: cele cu toate
dovezile HTTP și cele cu orice dovadă browser, probe, pagină internă `p2`/`p3`
sau script content. Acești counteri descriu dovezile finale și nu pretind lift
cauzal. Counterfactual lift și costul per feature cer rerulări pe subseturi și
rămân pentru analiza benchmarkului. Accumulatorul respinge duplicatele,
nepotrivirile de context/provenance, orice input/processed count peste capul
`limits.parquet.rows` și un input count sub processed count. Fiecare sumă este
preflighted ca safe integer înainte de orice mutație; overflow-ul respinge
atomic noul record. Configurația și provenance sunt copiate în ordine canonică
fixă, astfel încât JSON-ul summary este byte-stable pentru contexte semantic
egale indiferent de insertion order. Outputul rămâne independent de completion
order.

Schema v1 păstrează domeniul și statusul, paginile, tehnologiile, erorile,
timpii, consumul de resurse și provenance pentru scanner, catalog și
configurație. O detecție directă are cel puțin o dovadă; una dedusă nu pretinde
observație și indică părintele/regula. Dacă există ambele, varianta directă are
prioritate. Confidence-ul direct însumează o singură dată contribuția fiecărei
reguli până la 100; repetarea pe alte pagini nu îl umflă. O tehnologie directă
trebuie însă admisă de cel puțin o regulă potrivită cu `confidence > 0`;
regulile `confidence:0` pot furniza doar evidence/version companion după acea
admitere și nu pot porni singure relații. Confidence-ul dedus
folosește cea mai puternică relație validă fără însumarea căilor. O egalitate
între versiuni diferite produce `null`, nu o alegere arbitrară.

Dovada conține locatorul, regula, patternul și numai matchul exact sanitizat,
limitat la 256 code points. Query values, query names sensibile/opace/oversized,
segmentele URL opace, cookies și headere/valori sensibile sunt redactate. Dacă
redacția detaliată ar depăși limita URL, URL-ul public de pagină/rezultat se
reduce determinist la `origin/%5Bredacted%5D` fără query, iar evidence-ul URL
original rămâne complet redactat;
valorile cookie nu sunt nici hash-uite, iar un nume de cookie opac sau sensibil
devine `key:null` în evidence.
O versiune este publicată numai dintr-o sursă neredactată și dacă trece gramatica
sigură fixată. Observațiile brute rămân în memorie doar până la detecție și nu
intră în rezultate, cache, fixtures sau logs. Contractul complet, ordinea,
digesturile și cheile de deduplicare sunt în
[`Result and evidence contract v1`](docs/TECHNICAL_REFERENCE.md#result-and-evidence-contract-v1).

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
UTF-8. Relațiile se rezolvă din setul complet confirmat înainte de aceste
plafoane; depășirea elimină întreaga materializare `technologies`, nu publică un
prefix care i-ar schimba confidence-ul sau exclusions, și produce un record
bounded `detect/RESULT_LIMIT_EXCEEDED`. Resume respinge o linie peste cap înainte
de parsarea JSON.

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
[`Relationship resolution`](docs/TECHNICAL_REFERENCE.md#relationship-resolution).

Closure-ul folosește un priority heap și traversări iterative pentru fixed point,
SCC și provenance. Astfel limita acceptată de 20.000 tehnologii nu depinde de
call stack și nu rescanează/sortează quadratic întreaga coadă.

## Decizia CLI-ului executabil v1

CLI-ul construit este `dist/cli.js`, declarat ca bin local
`website-technologies-scraper`; Node `util.parseArgs` rămâne parserul unic și nu
adăugăm Commander, logger, YAML sau un pool generic. `--input` și `--output` au
defaulturile `input/domains.parquet` și `results.jsonl`. Exact una dintre
`--contact` și `--config` este obligatorie: contactul HTTPS/mailto validat
construiește User-Agent-ul cu versiunea reală din manifest, iar config citește
maximum 1 MiB de JSON UTF-8 strict și cere un `ScanConfig` v1 complet cu aceeași
versiune. Opțiunile operaționale rămase sunt `--resume`, `--force`, `--quiet`,
`--help` și `--version`; duplicatele, poziționalele și opțiunile necunoscute sunt
invalide, iar resume/force sunt mutual exclusive.

Startup-ul validează runtime-ul, configurația și întregul Parquet înainte de
catalog, pool-uri sau output mutabil. Inputul pregătit păstrează count-ul și
membership-ul primei treceri, apoi expune o singură a doua trecere streaming.
Configul și Parquetul sunt deschise nonblocking pe ținta canonizată, refuză un
symlink schimbat în timpul deschiderii și acceptă numai descriptor regular.
Resultul și summary-ul pereche nu pot aliasa inputul sau configul, iar resume
validează fiecare domeniu persistat în membership-ul inputului înainte să
repare fragmentul final ori să elimine summary-ul stale. Catalogul și workerii
detectorului sunt pregătiți înaintea transportului și canary-ului Chromium; abia
după toate preflighturile writerul creează/reia `runId` pe calea output deja
canonizată și verificată. Configul trebuie să includă exact același contact
canonic HTTPS/mailto pe care l-ar accepta `--contact`, nu doar un prefix de
User-Agent cu versiunea corectă.

Schedulerul direct ține maximum `limits.concurrency.fullScans` taskuri, fiecare
incluzând scanarea și appendul, astfel încât writerul aplică backpressure și
JSONL rămâne completion-order. Progresul canonic merge numai în stderr, iar
stdout este rezervat help/version. Exit `0` înseamnă că toate rândurile au un
record și summary, chiar dacă unele domenii sunt partial/failed; un pool global
devenit indisponibil sau un failure fatal dă `1`, usage invalid `2`, iar
SIGINT/SIGTERM după cleanup bounded dau `130`/`143`. Primul signal face abort
graceful fără summary fals complet; al doilea revine la terminarea implicită a
sistemului de operare. V1 nu creează automat directoare output și nu adaugă un
lock cross-process peste writerul deja decis.

## Decizia izolării regex

Păstrăm `RegExp` nativ cu flagul `i`, compatibil cu specificația catalogului,
dar îl compilăm și executăm exclusiv în doi `worker_threads` persistenți.
Threadul principal supraveghează progresul prin `SharedArrayBuffer`, termină un
worker blocat, îl înlocuiește și reia de la ultimul checkpoint confirmat. Regula
care a expirat este omisă numai pentru domeniul curent, ca rezultatul să nu
depindă de ordinea concurentă a domeniilor.

Înainte de dispatch, regulile sunt indexate după signal și locator, iar
candidații fără locator au cap-uri și ranking determinist. Detectorul aplică
independent plafonul 500.000 atât apelurilor RegExp, cât și perechilor totale
regulă–candidat; `presence` și `literal` consumă astfel work chiar fără RegExp.
Candidații sunt admiși atomic în ordinea stabilă, iar raw matches sunt bounded
de capul evidence/domain, cu un singur sentinel de overflow și mesaje IPC
chunked. Un contor cumulativ deținut de parent include apelul
blocat și orice replay după checkpoint, supraviețuiește înlocuirii workerului și
oprește înaintea execuției 500.001. Pragul de 50 ms este verificat de watchdog,
nu pretins ca plafon real-time exact. După timeout sau crash încercăm o singură
înlocuire; dacă mai există un worker sănătos continuăm degradat și marcăm
domeniul parțial. Dacă întregul pool devine indisponibil, domeniile rămase nu
mai sunt crawl-uite, primesc rezultate `failed` cu `DETECTOR_UNAVAILABLE`, iar
batchul scrie summary complet și iese cu cod nenul.

Listener-ele `error`/`exit` rămân active și când workerul este idle. O pierdere
idle pornește o singură înlocuire bounded, joburile așteaptă replacement-ul, iar
pierderea ultimului worker viabil latches pool-ul indisponibil fără unhandled
event sau slot `ready` stale.

În auditul snapshotului fixat am separat metadata `confidence/version` și am
găsit 8.037 declarații regex de valoare ne-goale înainte de deduplicare; după
deduplicare, worker plan-ul conține 8.033 expresii de valoare unice plus 504
locatori regex pentru cookie. Toate compilează cu flagul `i` în Node 24.19.0,
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
și protocolul complet sunt în
[`Regex execution policy`](docs/TECHNICAL_REFERENCE.md#regex-execution-policy).

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
  schema locală fixată și revizuită. Instanța exclusivă catalogului păstrează
  `strict: true`, dar folosește `strictTypes: false`, deoarece schema upstream
  nemodificată omite `type: object` în jurul unui bloc `required`; validatorii
  configurației și rezultatului rămân complet stricti. Nu acceptăm scheme sau
  referințe remote și nu adăugăm `ajv-formats`. Validarea semantică proprie
  rămâne obligatorie, deoarece schema upstream nu restrânge suficient toate
  câmpurile;
- `playwright@1.62.1` colectează semnalele care apar numai după randare. Este
  dependență runtime, nu `@playwright/test`; Chromium revision `1234` a fost
  provisionat explicit, separat de npm lifecycle, iar sandboxul rămâne activ.
  Binarele browserului nu intră în Git și vor avea licențele/notificările lor
  păstrate dacă le distribuim.

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
nu are install script; Chromium a fost provisionat ulterior prin comanda
explicită `fnm exec --using 24.19.0 node_modules/.bin/playwright install
chromium`. Revizia potrivită este `1234` (Chrome for Testing `151.0.7922.34`),
rămâne în cache-ul local Playwright și nu modifică manifestul sau lockfile-ul.

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
păstrează licența și notificările proprii. Înainte de import am adăugat textul
complet al licenței și `THIRD_PARTY_NOTICES.md`. La 2026-08-17 am vendorizat
byte-for-byte numai schema, categoriile și cele 27 de fișiere cu tehnologii la
revizia fixată, fără cod upstream, iconuri sau branding; notice-ul consemnează
sursa, revizia, data și faptul că snapshotul este nemodificat. Aceasta este o
decizie de conformitate tehnică, nu consultanță juridică.

Compilatorul acceptă numai allowlistul upstream exact și fișiere custom regulate
care adaugă nume noi fără redeclarare. Singura excepție de corecție este ledgerul
fix `fingerprints/custom/corrections.v1.json`, cu schema închisă
`website-technologies-scraper/catalog-corrections-v1` și revizia
`2026-08-20.2`. Ledgerul se leagă de source, revision și digestul upstream exact
și admite numai `dropTechnologies` cu nume upstream exacte, `dropRules` cu rule
ID SHA-256 complet și `replaceRules` cu target exact plus un `original`
declarativ nou. Replacementul păstrează obligatoriu aceeași tehnologie, sursă
și locator normalizat, intră în namespace-ul local și primește un rule ID nou.

Fiecare target trebuie să rezolve exact o declarație upstream. Targeturile
lipsă, duplicate, folosite în două operații, stale, cu digest greșit sau cu
identity schimbată invalidează catalogul. Nu acceptăm wildcarduri, alias engine,
name heuristics, JSON Patch, merge generic, config switch, CLI ledger sau date
executabile. Când ledgerul există, chiar și apelul direct
`compileFingerprintCatalog()` recalculează digestul complet al byte-ilor
upstream înainte să aplice corecțiile; loaderul păstrează aceeași verificare.
Byte-ii upstream și ID-urile regulilor neschimbate rămân intacte, iar byte-ii
ledgerului intră în digestul catalogului efectiv.

Revizia `2026-08-20.2` conține exact patru `dropTechnologies`, cinci
`dropRules` și cinci `replaceRules`; SHA-256 al ledgerului brut este
`sha256:68d702a5496f2d5c304c6608cd31c06c7679b3078b436e3ba3a1d1c4f34a8393`.
Față de `.1`, regula probe Magento cere literalul `Magento/2.`, iar TYPO3 CMS
cere un fragment distinctiv bounded din SVG-ul oficial în loc de simpla
prezență a răspunsului. Fixtures pozitive păstrează semnăturile, iar negativele
resping 2xx gol, soft-404 și body-ul care reflectă numai pathul. Nu declarăm
retroactiv toate cele 17 detecții probe-only D2 false, deoarece body-urile brute
nu au fost persistate.

`dropTechnologies` se aplică înainte de limita `technologiesPerCatalog`, astfel
încât limita descrie catalogul efectiv. Revizia acceptată produce 7.571
tehnologii, 109 categorii, 15.481 declarații directe, 15.474 reguli unice și
2.238 relații. Accountingul are 8.529 surse regex declarate, iar planul
workerilor 8.525 surse (8.022 value și 503 locatoare cookie), 1.767 selectori
DOM, 5.570 pathuri JavaScript și trei probe. Digestul efectiv este
`sha256:5aedde4f83d1ad977d646e1495b9b91d4d3b0f6f3acbd34d54906d099da18870`;
digestul upstream rămâne
`sha256:cdcccc905a14bbc7ad35a7ea6de636a2e6e51280c6ebbe5ba14f5e55aac18c8f`.

Înainte de parsare se aplică limite de 64 fișiere, 1 MiB per fișier, 16 MiB
total și adâncime JSON 64, iar duplicatele de membri JSON, symlinkurile și
intrările neașteptate sunt respinse. Toate declarațiile directe efective,
inclusiv presence și duplicatele care vor fi deduplicate, consumă limita de
20.000. Header/meta folosesc locatoare exacte lowercase; locatoarele cookie sunt
regexuri whole-name ancorate, executate în worker și incluse în bugetul regex.
Rule ID-urile folosesc namespace-uri versionate stabile, fără commit, în timp ce
provenance păstrează separat revizia upstream și digestul catalogului efectiv.

Detectorul admite numai observațiile deja limitate ale collectorilor HTTP și
browser: URL final/redirecturi, headere, cookie-uri, HTML, text, metadata,
script URLs, robots, probe declarative, fapte DOM/JavaScript cerute de plan,
script bodies și request URLs. Regulile upstream `xhr` folosesc `network_url`;
canalul separat
`network_hostname` nu este prezentat drept acoperire XHR completă. Nu
reinterpretăm statusuri, stylesheet-uri, imagini, iframe-uri, linkuri sau
navigation links ca semnale v1. Observațiile HTTP page-scoped păstrează exact
`p1`, `p2` sau `p3`, la fel ca browserul; non-HTML entry și robots rămân cu
`pageId: null`, probele folosesc tot `pageId: null` și pathul drept key, iar un
răspuns intern deja selectat păstrează `p2`/`p3`. Pass-ul autoritativ `full`
trimite o singură dată setul combinat HTTP/browser/probe/DNS/TLS și nu unește
rezultate detectate separat pe pagini; numai modul shadow explicit adaugă
pass-urile independente pe prefixele `T1` și `T2`. Matchingul regex rulează pe
valoarea raw bounded în worker; parentul primește doar spanul și versiunea sigură
și construiește dovada prin sanitizerul comun. URL-urile se publică numai
integral, canonic și sanitizat;
header/meta publică doar matchul după clasificarea întregii observații, iar
cookie/HTML/text/robots/probe/DOM/JavaScript/script content rămân redacted.
Ordinea identităților candidat rămâne stabilă și neschimbată. Pentru pass-ul
`full`, pipeline-ul furnizează separat multisetul exact al observațiilor din
prefixul T2; detectorul îl identifică după collector, kind, source, key și
valoarea bounded, fără `pageId`, astfel încât remaparea provizorie `p2`/`p3` nu
pierde prioritatea. Admiterea bounded și work items rulează întâi faza T2, apoi
candidații full-only, cu checkpoint explicit la frontieră. Un deadline sau cap
consumat de remainder nu mai poate elimina matchurile T2 încă neconfirmate.
Candidate IDs, ordinea rezultatului, limits, views și setul complet în cazul
fără limită/timeout nu se schimbă. Confidence și version se calculează din rule
ID-uri unice, apoi se
aplică fixed point-ul relațiilor și excluderile deterministe deja decise.

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

## Rezultatul benchmarkului full v0.1.4

Runul public autorizat v0.1.4 a terminat 200/200 domenii, iar resume nu a
modificat artefactele. Validarea independentă a confirmat setul exact de input,
toate cele 200 de rezultate, provenance/config/catalog, summary-ul reconstruit
byte-identic și redacția. Rezultatul are 3 success, 190 partial și 7 failed,
2.061 detecții directe, 167 deduse și 373 nume unice total. În acest run nu a
existat un failure proxy sau de disponibilitate la nivelul întregului pool:
zero `BROWSER_PROXY_FAILED`, `BROWSER_UNAVAILABLE` și `DETECTOR_UNAVAILABLE`;
72/74 pagini interne încercate în browser au admis un draft bounded.

Baseline-ul arată însă două limite de calitate care nu trebuie ascunse prin
mărirea tăcută a bugetelor sau reinterpretarea dovezilor:

- 176/180 pagini browser admise sunt trunchiate și există 193
  `BROWSER_LIMIT_EXCEEDED`; catalogul pin-uit conține în continuare selectori
  value foarte largi, iar outputul redacted nu dovedește offline cauza exactă a
  fiecărei limite;
- review-ul evidențelor a produs o coadă inițială, neexhaustivă, de
  reguli/aliasuri de corectat: toate cele patru detecții Onsen UI includ cel
  puțin un match fals `onsen` în `consent`; WebsiteBuilder este mapat din Wix;
  `svSession` susține Store Vantage/Sirvoy; Wix eCommerce folosește un host
  generic; familia Lightbox este puternic suspectă; există patru perechi de
  aliasuri duplicate.

Am închis această coadă punctuală prin ledgerul exact `2026-08-20.1`: eliminăm
cele patru definiții alias, regulile slabe WebsiteBuilder, Store Vantage,
Sirvoy, Wix eCommerce și DOM Lightbox; restrângem Onsen UI și scriptul Lightbox
la basename-uri exacte; iar regula Liveinternet care a produs 13 timeouturi este
înlocuită cu semnalul bounded `//counter\.yadro\.ru/hit`. Fixtures la nivel de
candidat au câte un negativ pentru fiecare regulă eliminată și un pozitiv pentru
fallbackul puternic păstrat, plus negativele `consent`, `dmm-consent`,
Breakdance și un HTML Liveinternet negativ de 4 MiB. Această decizie s-a aplicat
runului fresh v0.1.5; nu rescrie statisticile istorice v0.1.4.

Ținta inițială pe occurrence-uri, 95% din detecțiile directe cu browser pe
maximum 20% dintre domenii, este infirmată de date: fără browser rămân cel mult
1.317/2.061; chiar un oracle care alege cele mai productive 40 de domenii ajunge
numai la 1.768/2.061 (85,78%), iar 95% cere minimum 68/200 domenii (34%). Nu mai
folosim această țintă drept criteriu de acceptare implicit.

Pentru experimentul v0.1.5 am acceptat varianta KISS+ numai ca protocol
provizoriu: breadth-ul numelor directe canonicalizate a fost guardrail, iar
retenția perechilor canonicalizate `(domain, technology)` este obiectivul
principal. Retenția occurrence-urilor raw rămâne diagnostic secundar. Acest
lucru nu a ratificat un KPI de produs: triggerul deployabil bazat exclusiv pe
semnale `T1`/`T2` a fost evaluat și respins. Nu adăugăm un framework generic de
override, nu schimbăm capul browser și nu coborâm pragurile după rezultat.

## Rezultatul benchmarkului full + shadow v0.1.5

Runul public fresh autorizat, construit din commitul curat
`b290a340355a965ec100d1c980a3653137442758`, a terminat 200/200 domenii cu
scanner `0.1.5`, Node.js `24.19.0`, Playwright `1.62.1` și Chromium revision
`1234`. Contactul real al operatorului a rămas exclusiv configurație runtime și
nu este reprodus în documentație. Provenance folosește digestul catalogului
`sha256:614581009dc6ac2986763f8a324c656e629f63c5ecb7e46cf3ac10b121277724`
și config digestul
`sha256:1fdd836b195fab7f177196a6d87034dce651f845b795c7281cea967e30e6ecfb`.

Artefactele locale Git-ignored și hashurile lor sunt:

- `input/domains.parquet`:
  `sha256:65e77097c669c29b392f3279a93f04566ab934cf1e8acfaf1ae4046a01e97bb2`;
- `output/work/results-200-v0.1.5.jsonl`:
  `sha256:8577b94c9dd4b777474a7bdcf963c4f718b286c1d5799f03181376e9e8c82b5e`;
- `output/work/results-200-v0.1.5.summary.json`:
  `sha256:c7d630748042093a1dd71d40fac163993c3f48f16cde455c1e2622a8e213e5b0`;
- `output/work/results-200-v0.1.5.evaluation.json`:
  `sha256:1b53023cf747e7194adc3d0261f96f93a556cba041d8ee515e9b4a8dc37ef43e`.

Validarea independentă a confirmat toate cele 200 de rezultate, setul exact de
domenii și run identity, contractele semantice, summary-ul reconstruit
byte-identic și recalcularea byte-identică a snapshotului de bază și calibrării.
Rezultatul `full` are 2 success, 191 partial și 7 failed; 2.031 detecții directe,
165 deduse, 2.196 total și 362 nume unice total. Accountingul direct este
2.089 raw - 54 gated - 4 suppressed = 2.031 retained.

Selecția OOF fold-local a rutat exact 38 trigger + 2 control. Verdictul
`provisional-shadow-challenge` este **REJECT**:

- nume directe canonice: 292/348 = 83,91%, sub guardrailul de 95%;
- perechi canonice `(domain, technology)`: 1.609/2.031 = 79,22%, sub
  guardrailul de 80%;
- domenii rutate: 40/40, guardrail trecut.

Cele 40 de domenii au reprezentat 20% din cohort, dar 36,27% din paginile
browser încercate, 39,01% din paginile admise, 41,47% din requesturile browser,
36,97% din bytes browser și 40,67% din `browserMs`. Costul real cere deci un
guardrail explicit, nu numai cota de domenii. Comparatorul random la același
buget a păstrat 276/348 nume și 1.428/2.031 perechi; greedy-ul post-hoc pair-first
a păstrat 330/348 și 1.735/2.031. Greedy-ul nu este upper bound, deci respingem
triggerul curent fără să declarăm imposibil pragul de 95%.

Ledgerul exact a avut rezultatul urmărit în cohortul fresh: Onsen UI 4→0,
WebsiteBuilder 9→0, Store Vantage 3→0, Sirvoy 1→0, Wix eCommerce 1→0 și
Lightbox 11→0. Aliasurile duplicate au dispărut, iar numele canonice au rămas:
Litespeed Cache 3→0 / LiteSpeed 3, All in One SEO Pack 2→0 / All in One SEO 2,
MUI 1→0 / Material UI 1 și Typekit 4→0 / Adobe Fonts 4. Timeouturile de regulă
au scăzut de la 15 la 2; Liveinternet nu a produs timeout sau detecție.

Sidecarul istoric conține 1.045 limit hits pe 106 domenii și 178 pagini: 802
`inspection.domMatches`, 148 `inspection.returnedValue` și 95
`scripts.bodiesPerDomain`. Nu există hit pentru selectori exclusiv `exists`,
deci corecția trunchării false funcționează. Presiunea rămasă provine din
inspecții property/value largi pe app/root/body descendants, `div` text/id,
`script`/`style` text și `link` href; nu mărim global limitele.

Acest sidecar nu este telemetry-exact: JSONL are 180 perechi domeniu/pagină cu
`BROWSER_LIMIT_EXCEEDED`, dar sidecarul are hits pentru 178. Două limit hits de
proxy protejat s-au pierdut pe căi care au eșuat înainte să returneze colecția
paginii. Gap-ul nu afectează features, labels, selecția sau verdictul KPI,
deoarece telemetry browser este exclusă explicit din calibrare. Fișierele și
hashurile istorice rămân neschimbate; o corecție ulterioară a collectorului nu
face retroactiv sidecarul exact. Collectorul curent păstrează hit-urile raw-free
active ale paginii și proxy-ului înainte ca pipeline-ul să clasifice un failure
aruncat de colecție, astfel încât sidecarurile viitoare rețin diagnosticul fără
să schimbe `DomainResult`.

Decizia este să păstrăm routingul funcțional pe `HOLD`. Experimentul set-aware
v0.1.7 a diagnosticat breadth-ul și costul real, dar a produs `NO-GO`. Nu
folosim deci încă un cohort public; următorul pas este mai mult semnal/date de
training sau aprobarea separată a unei feature raw-free. Cele 200 de domenii
actuale pot servi la diagnostic și training, nu la re-ratificarea aceluiași
candidat ajustat post-hoc.

## Protocolul provizoriu de evaluare tiered

Protocolul `2026-08-20.1` și instrumentația lui shadow au fost exercitate în
runul public fresh v0.1.5. Triggerul deployabil a eșuat două dintre cele trei
guardrails, iar KPI-ul provizoriu a fost respins. Nu este routing funcțional,
KPI final sau afirmație de capacitate la scară de producție. Toate views folosesc
același catalog efectiv validat, aceeași revizie de corecții, configurație și
semantică deterministă a detectorului. Nu obținem un view intermediar filtrând
dovezile din rezultatul final; detectorul rulează separat pe fiecare prefix.

Views sunt exacte:

- `T1` conține targetul și observațiile HTTP statice bounded ale entry page,
  inclusiv URL final/redirecturi, observațiile robots necesare admiterii acestui
  lucru, DNS-ul cerut de catalog și issuerul TLS reținut. Nu conține probe,
  pagină internă sau observații browser.
- `T2` conține `T1`, toate probele declarative bounded pe originul exact și
  observațiile robots aferente, plus maximum o pagină internă colectată static.
  Nu conține linkuri randate, DOM, browser network sau script bodies din browser.
  Un failure păstrează prefixul disponibil și rămâne în populația evaluată.
- `full` este labelul detectat separat peste scanarea bounded completă. Niciun
  rezultat sau failure `full` nu poate deveni feature al triggerului.

Pagina `T2` se alege numai din copia înghețată a linkurilor de navigare extrase
static din `p1`. Refolosim exact filtrarea existentă pentru origin canonic,
credentials, query/fragment, lungime URL, pathuri excluse, fișiere, root/URL
final și clasificarea rolurilor. Păstrăm cel mai bun `detail` și cel mai bun
`listing`, sau cel mai bun `content` numai când listingul lipsește, cu rankingul
existent pe token, pathname mai scurt și URL canonic. Sortăm cele maximum două
alegeri structurale după URL-ul canonic de rețea în ordine directă UTF-16 și o
alegem pe prima. Astfel capul de o pagină nu introduce o preferință de rol nouă.

Facem un singur check robots pentru candidatul ales. Denial, unavailable,
coliziunea după sanitizer sau lipsa unui candidat produc zero pagini și fără
backfill; altfel colectăm exact acea pagină prin HTTP protejat. „O pagină” este
deci maximumul determinist, nu o promisiune de a ocoli policy sau de a inventa
un URL.

Pipeline-ul implementat colectează DNS/TLS imediat după HTTP `p1`, închizând
prefixul `T1` înainte ca lucrul `T2` să-i consume deadline-ul. Apoi îngheață și
rezervă candidatul static `T2`, îl colectează înainte de probe, iar toate acestea
precedă browserul. După browser `p1`, planul `full` păstrează rezervarea într-unul
dintre cele două sloturi interne și permite maximum încă un candidat din slotul
opus. Capul total de trei pagini, sanitizarea și regulile IDs publice rămân
neschimbate. Observațiile bounded sunt reutilizate, dar detectorul primește trei
seturi imutabile independente; `full` rulează sub deadline, apoi, după validarea
rezultatului și oprirea acelui timer, `T1` și `T2` rulează separat sub semnalul
callerului, concurrent și în pool-uri detector dedicate distincte. Timpul
shadow nu intră în timings și nu modifică labelul `full`. Un view
`detector-unavailable` invalidează cohortul; nu îl calibrăm ca zero semnale.

Lifecycle-ul `full` admite totuși slotul și contextul browser înaintea HTTP
`p1`, deoarece admission pornește unicul deadline activ al domeniului. Un eșec
de pre-open face ambele prefixuri shadow explicit unavailable, iar latența de
setup poate influența disponibilitatea capturii. Nu permite însă niciunei
observații browser să intre în `T1`/`T2`; prefixul indisponibil invalidează
calibrarea fail-closed în loc să fie convertit într-un set gol.

Artefactul top-level are `schemaVersion: 1`, protocol/run, numărul exact de
domenii, provenance complet, snapshoturi sortate, agregatele limitelor și
raportul de calibrare. Snapshotul per domeniu este un allowlist raw-free:
protocol/run/domain; pentru
`T1`/`T2`, state disponibil/indisponibil, nume direct/inferred sortate,
`detectionStats`, completed și erori grupate numai după
`(stage, code, retryable, count)`; features pre-browser bounded pentru outcome și
status entry, mărimea HTML/text, numărul de linkuri statice, metadata, resurse,
DNS, prezența issuerului TLS, selecția/rolul/outcome `T2`, probe, requesturi HTTP
și bytes statici; labelul `full` cu nume/status; costurile browser; și hits de
limită `(pageId, category, domSelectorOrdinal|null)`. Un prefix care nu a putut
fi capturat este explicit unavailable, nu o detecție goală inventată.

Nu admitem URL, evidence, rule ID, pattern, message, valoare matched, HTML, DOM,
script, header, cookie, JavaScript value sau altă observație brută; proprietățile
extra sunt eliminate înainte de acumulare. Snapshoturile sunt sortate după
domeniu și provenance leagă ordinalele selectorilor de digestul catalogului.
Hits per pagină se deduplică după `(pageId, category, ordinal)`, apoi artefactul
agregă după `(category, ordinal)` numărul de hits, pagini și domenii afectate.
Numai `inspection.domMatches` și `inspection.domAccess` poartă ordinal; celelalte
categorii de inspection, cookie, network, script și proxy folosesc `null`.
Allowlistul exact este `inspection.domMatches`, `inspection.domAccess`,
`inspection.returnedValue`, `inspection.returnedValuesPerPage`,
`inspection.navigationLinksCount`, `inspection.navigationLinkInvalid`,
`cookies.name`, `cookies.value`, `cookies.perDomain`,
`cookies.totalBytesPerDomain`, `browser.networkHostnamesPerDomain`,
`browser.networkUrlsPerDomain`, `scripts.bodyBytes`,
`scripts.bodiesPerDomain`, `scripts.totalBodyBytesPerDomain`,
`proxy.headerFields`, `proxy.headerBytes`, `proxy.requestsPerPage`,
`proxy.requestsPerDomain`, `proxy.transferBytesPerPage` și
`proxy.transferBytesPerDomain`.

Înainte de calibrare, acumulatorul admite cumulativ maximum 10.000 identity
values: câte o identitate de domeniu, toate numele directe și inferred din
`T1`/`T2`/`full`, fiecare grup de erori `T1`/`T2` sau markerul unui view
indisponibil și fiecare browser-limit hit. O adăugare care ar produce 10.001
este respinsă atomic, fără inserarea snapshotului. Limita protejează cohortul în
memorie și este independentă de preflightul structural de 500.000 valori JSON și
capul UTF-8 de 64 MiB ale writerului.

Bugetul provizoriu este maximum 40 de domenii unice din 200 care ajung la orice
lucru browser. Un domeniu consumă un loc chiar dacă browserul eșuează, nu admite
o pagină sau primește ulterior Tier 4. Pentru evaluarea OOF, cele 40 de locuri
sunt repartizate între folds numai din mărimea lor, iar exact două dintre aceste
locuri sunt repartizate drept control. Restul de 38 sunt locuri trigger.
Controlul se alege numai din restul netriggerat al aceluiași fold, deci nu este
prezentat drept trafic gratuit.

Pentru fiecare domeniu canonic `d`, `F(d)` este setul numelor directe
canonicalizate din labelul `full`. Simularea folosește `T2(d)` pentru domeniul
nerutat și `F(d)` pentru cel rutat. Inferred rămâne separat. Guardrails sunt:

- minimum 95% din setul global de nume directe canonicalizate din `full`;
- minimum provizoriu 80% din perechile canonicalizate
  `(domain, technology)`, acesta fiind obiectivul principal de optimizare;
- maximum 40 de domenii rutate după contabilizarea de mai sus;
- maximum 30% din totalul `full` pentru fiecare dintre pagini browser
  attempted, pagini admitted, requesturi, bytes transferați și `browserMs`, cu
  cele două controale incluse integral în numerator.

Ambele retenții sunt intersecții cu labelul `full` împărțite la setul `full`
nenul corespunzător. Detecțiile shadow suplimentare nu pot mări scorul și sunt
raportate separat ca disagreements. Raportăm și macro recall pe domeniile cu
`F(d)` nenul, macro recall pe tehnologiile cu minimum un domeniu `full`, plus
numărul explicit al domeniilor fără label. Costul include valori absolute și
relative pentru domenii și pagini browser, requesturi, bytes transferați și
suma `browserMs`; procentul domeniilor nu este proxy suficient pentru cost.

Feature function-ul triggerului vede numai state/completed, nume directe,
`detectionStats`, erorile controlate din `T1`/`T2` și features pre-browser de mai
sus. Numele inferred se păstrează pentru raport, dar nu sunt tokens. Labelul
`full`, costul browser și telemetry browser nu intră în features.

Calibrarea folosește cinci folds determinate prin primul uint32 big-endian din
`SHA-256(salt + NUL + domain) mod 5`. Pentru fiecare fold antrenăm pe celelalte
patru și concatenăm o singură dată predicțiile held-out. Modelul direct
`smoothed-empirical-token-lift-v1` țintește numărul de perechi directe
incrementale din `full` față de `T2`. Valorile bounded devin tokens deterministe,
counters folosesc bins fixe zero/unu/puteri de doi, iar media empirică a fiecărui
token este netezită spre media globală a foldului cu prior weight 4. Scorul este
media dintre global mean și estimările tokenurilor matched; nu îl prezentăm ca
probabilitate sau framework ML generic.

Salturile înghețate sunt
`website-technologies-scraper/shadow/2026-08-20.1/fold/v1`,
`website-technologies-scraper/shadow/2026-08-20.1/score-tie/v1`,
`website-technologies-scraper/shadow/2026-08-20.1/control/v1`,
`website-technologies-scraper/shadow/2026-08-20.1/random/v1` și
`website-technologies-scraper/shadow/2026-08-20.1/greedy-tie/v1`.

Cotele fold-local folosesc regula Hamilton/largest-remainder. Pentru un fold de
mărime `n`, cota routed inițială este `floor(40 * n / 200)`; locurile rămase se
dau după restul fracționar descrescător, apoi numărul foldului. Cele două cote
control se distribuie prin aceeași regulă și același tie-break, bounded de cota
routed; cota trigger a foldului este routed minus control. Distribuțiile
imposibile sunt respinse fail-closed. În fiecare fold rankăm numai scorurile lui
held-out, iar controlul se alege cu saltul control numai dintre domeniile
netriggerate ale acelui fold. Uniunile au exact 38 trigger și două control.
Astfel schimbarea tuturor labelurilor `full` dintr-un fold nu poate schimba
membership-ul routed în acel fold, chiar dacă poate modifica modelele celorlalte
folds.

Comparatorii de buget egal sunt un sample hash label-blind de 40 și un greedy
post-hoc label-aware de 40, care maximizează întâi liftul de perechi și apoi
numele canonice noi; îl numim greedy, nu oracle sau upper bound. Revizia
istorică v0.1.5 a inclus un deployment model în același raport. Revizia v0.1.7
elimină acea ambiguitate: sidecarul live este doar development source, iar
candidatul standalone se construiește offline și se publică numai după PASS.

Candidatul KISS+ v0.1.7 nu este o căutare de ponderi peste scorul scalar care a
eșuat în v0.1.5. Păstrăm aceeași suprafață raw-free de features și adăugăm exact
trei targets bounded: liftul de perechi, câte un head binar pentru numele
incrementale cu support de minimum două domenii în training și un head agregat
pentru numele rare cu support exact unu. Supportul, priorurile, deficitul până la
80% perechi și deficitul până la 95% nume se calculează exclusiv din partiția de
training. Un nume prezent numai în foldul held-out nu poate intra în modelul
acelui fold.

Selecția este set-aware. Creditul marginal al unui nume recurent scade după ce
alt candidat îl prezice, iar numele deja prezente în uniunea `T2` a cohortului
nu primesc credit de breadth. Utilitatea înghețată este suma dintre pair-liftul
prezis normalizat cu deficitul de perechi și breadth-ul marginal normalizat cu
deficitul de nume; denominatoarele au minimum unu. Păstrăm priorul patru,
tokens, folds și salts existente. Nu adăugăm costul browser drept feature sau
head predictiv în această primă revizie.

Costul real este un veto independent după evaluare. Fiecare dintre cele cinci
rapoarte selected/full trebuie să fie `<= 3/10`, comparat exact pe integers;
`full=0` este valid numai cu `selected=0`. Niciun rezultat bun pe breadth sau
pairs nu compensează un cost peste plafon. Pragul 30% este înghețat înaintea
cohortului nou ca toleranță de 1,5x față de cota de 20% a domeniilor, nu ales
pentru a trece datele deja observate.

Separăm explicit development de holdout. Artefactul public v0.1.5, pin-uit prin
digestul consemnat mai sus, rămâne development input; folosim snapshoturile lui
canonice, nu raportul său vechi ca nou model. Un pas offline produce un candidat
standalone canonic care păstrează digestul sursei, provenance/configul de
training, digestul independent de ordine al setului canonic exact de domenii,
protocolul, catalogul și identitatea exactă scanner/config a viitorului run.
Digestul fișierului candidat este pin-uit separat de operator.

Evaluatorul holdout primește numai candidatul standalone și snapshoturile
cohortului nou; nu primește development snapshots și nu apelează training.
Rulează global exact 38 trigger plus două controale deterministe. Schimbarea
oricărui label `full`, cost sau browser-limit hit din holdout nu poate schimba
predicțiile ori membership-ul 38+2. Dacă GO/NO-GO offline nu trece simultan
breadth, pairs, cota și toate cele cinci costuri, nu lansăm cohortul public și nu
retunăm ponderile pe aceleași 200 labels.

Evaluatorul respinge același `runId` de training sau exact același set canonic
de domenii. Egalitatea setului este detectată de CLI imediat după preflightul
Parquet și citirea candidatului, înainte de catalog, pool-uri ori trafic; `runId`
este reverificat de evaluator când identitatea artefactului complet există.
Acesta este guardul generic v0.1.7, nu regula experimentului următor.
Preregistrarea v0.1.8 cere disjuncție canonică totală între `D1`, `D2` și
`H1`; un manifest cu orice overlap este invalid înainte de scanare.

Versiunea 0.1.7 implementează acest model și boundary-ul development versus
frozen holdout. Nu conține routing funcțional; acel slice rămâne `HOLD` până la
un PASS prospectiv pe cohort nou.

Implementarea v0.1.7 este exclusiv shadow: nu schimbă routingul și rezultatul
`full` rămâne autoritativ. `--shadow-evaluation` este create-only, incompatibil
cu `--resume` și `--force`, cere exact 200 de domenii și ține în memorie maximum
un snapshot allowlisted per domeniu, cu cap fix 200. Modului shadow îi aparțin
trei pool-uri peste același catalog (`full`, `T1`, `T2`), fiecare cu
`limits.detector.workers`: implicit șase worker isolates în loc de două și trei
seturi distincte de compilări worker-local. Separarea împiedică o coadă sau un
lifecycle failure să contamineze alt view, dar nu elimină competiția CPU/memorie
la nivelul hostului. Orice pool shadow indisponibil sau snapshot cu view `T1`
sau `T2` indisponibil oprește fail-closed înainte de calibrare/publicare. După finalizarea
JSONL/summary și închiderea resurselor runului publică un JSON compact: sufixul
terminal `.jsonl` devine `.evaluation.json`, iar alt sufix primește
`.evaluation.json` appended. Writerul folosește temporary file exclusiv, mode
`0600`, sync și no-clobber atomic pentru sidecar. Înainte de serializare
revalidează forma fixă protocol/cohort/folds/38+2, respinge structuri
non-plain/ciclice/cu accessors sau excesive, cu maximum 500.000 de valori JSON,
și aplică un cap UTF-8 fix de 64 MiB inclusiv newline
(`EVALUATION_ARTIFACT_LIMIT`). Orice target existent/alias/race este respins; nu
promitem atomicitate între result, summary și sidecar și nu anulăm
artefactele principale deja finalizate dacă evaluarea eșuează. Failure-ul rămâne
exit non-zero, iar sidecarul nu are resume sau force.

Fără alte flaguri, `--shadow-evaluation` publică numai raportul
`development-source`. Pentru holdout, `--shadow-candidate <path>` și
`--shadow-candidate-digest <sha256:...>` sunt obligatorii împreună. Candidatul
este citit UTF-8 strict și bounded, pin-uit exact, respins dacă este symlink,
hard link sau alias de input/output și verificat contra scanner/config/catalog/
protocol înainte să pornească pool-urile sau traficul. După preflightul
inputului, CLI-ul compară și digestul setului exact de domenii cu identitatea de
training și respinge egalitatea la aceeași frontieră timpurie. Raportul rezultat
este `frozen-holdout` și nu apelează training.

Toate rapoartele includ selecțiile/predicțiile scalare bounded, retențiile prin
intersecție, macro recall, disagreements extra, costurile reale și verdictul
machine-readable `provisional-shadow-challenge`. Modurile de development includ
și comparatorii cu buget egal random determinist și greedy label-aware; raportul
`frozen-holdout` evaluează numai selecția deployabilă înghețată și nu recalculează
un comparator label-aware pe cohortul prospectiv. Fără candidat, modul
`development-source` nu persistă modelul standalone; pasul offline
`development-oof` îl produce numai după PASS. Cu candidat, modul
`frozen-holdout` pin-uiește digestul și training identity, dar nu antrenează.
Câmpul `passed` nu ratifică singur nimic.

GO/NO-GO v0.1.7 a folosit exact sidecarul v0.1.5 cu digest
`sha256:1b53023cf747e7194adc3d0261f96f93a556cba041d8ee515e9b4a8dc37ef43e`.
Selecția set-aware 38+2 a păstrat 294/348 nume canonice (84,48%) și
1.595/2.031 perechi (78,53%). Costurile selected/full au fost 35,78% pagini
încercate, 37,36% pagini admise, 39,07% requesturi, 36,64% bytes și 39,67%
browser milliseconds. Toate cele cinci costuri depășesc 30%; verdictul este
`NO-GO`, candidatul este `null`, iar cohortul public nou nu pornește.

Cele 200 de domenii sunt set descriptiv/de dezvoltare, deoarece v0.1.4 a
influențat corecțiile și metrica. Out-of-fold reduce leakage-ul calibrării, dar
nu transformă setul într-un holdout de producție. Un trigger schimbat se
îngheață înainte să fie evaluat pe un cohort nou reprezentativ; nu ratificăm o
ajustare folosind din nou acest set.

### Preregistrarea ablației category-ID v0.1.8

Am înghețat în `shadow-category-ablation.v1.json` experimentul paired cu
revizia `2026-08-20.3`. Digestul serializării canonice a acestui protocol se
calculează înaintea manifestelor de cohort și este
`sha256:bf924836872efc40ee30b92ae51eb456d08ce3172b19de25b401be422107f849`.
Setul public v0.1.5 este `D1` și are
rol exclusiv `hypothesis-generation`: pin-uim sidecarul brut
`sha256:1b53023cf747e7194adc3d0261f96f93a556cba041d8ee515e9b4a8dc37ef43e`
și domain-set digestul
`sha256:4bd010e4fae36d5f50d468e4e0e47e377040281fa38be0be9dd1d97c48c7c523`,
dar nu folosim labelurile lui la training, comparația brațelor, alegerea
câștigătorului, praguri sau ratificare.

Brațele sunt exact:

1. `baseline-v2`, implementarea KISS+ v0.1.7 pin-uită prin commit;
2. `baseline-v2+t2-direct-category-id-v1`, aceeași implementare plus familia
   exactă de tokens `t2.directCategoryId=<decimal>`.

Al doilea braț proiectează numai `T2.directNames` în tehnologiile catalogului
compilat pin-uit și ia reuniunea sortată/deduplicată a ID-urilor numerice de
categorie. Orice nume fără mapping unic invalidează evaluarea. Digestul
proiecției și digestul catalogului sunt parte din preregistrare. Nu folosim
`T1`, inferred, `full`, browser, nume sau grupuri de categorii și nici token
explicit de count. Nu adăugăm alt feature, alt semnal raw, ponderi, collector
sau routing.

`D2` este un development cohort nou de exact 200 de domenii, iar `H1` este un
holdout sigilat distinct de exact 200. Le înghețăm simultan, înaintea primului
scan `D2`, din același source frame numit și imuabil. `D1`, `D2` și `H1` au
overlap canonic zero. Sursa exactă, revizia și digestul ei apar numai
în manifestul concret; protocolul nu descrie un mirror drept bytes oficiali.
Eligibilitatea folosește numai normalizarea statică și deduplicarea. Nu facem
DNS/HTTP/browser prescreen, nu folosim tehnologiile observate și nu înlocuim
domenii după freeze pentru timeout, block, failure sau label gol.

Selecția este un singur sample ne-stratificat fără replacement, sortat după
`SHA-256(sampleSalt + NUL + canonicalDomain)`, apoi domeniu canonic la o
coliziune. După excluderea `D1`, primele 200 sunt `D2`, iar următoarele 200
sunt `H1`. Saltul unic este
`website-technologies-scraper/shadow/2026-08-20.3/cohort-sample/v1`. Samplingul
nu este stratificat și nicio probă de website nu poate influența eligibilitatea.

Fiecare instanță de cohort are un manifest canonic imuabil, iar ambele sunt
înghețate înainte de primul scan `D2`. Fiecare manifest leagă
`preregistrationDigest`, source name/revision/digest, metoda, saltul, countul
ordonat, `domainSetDigest` și SHA-256 al bytes-ilor Parquet exacți. Manifestul
`D2` pin-uiește suplimentar digestul manifestului `H1` deja sigilat. CLI-ul `D2`
cere ambele manifeste înainte de catalog/pool-uri și publică un envelope
`paired-development-source` care fixează preregistrarea, ambele manifeste și
proiecția category. Candidatul păstrează pin-urile `D2` și `H1`, iar evaluatorul
`H1` acceptă numai manifestul sigilat exact și pin-uiește separat digestul
candidatului. Preregistrarea nu conține `cohortManifestDigest`, fiindcă
manifestele sunt create ulterior și conțin digestul preregistrării. Orice
mismatch, overlap, count greșit, replacement sau artefact nelegat invalidează
experimentul.

Instanța concretă a fost înghețată pe 2026-08-20 din tabela oficială CrUX
BigQuery `chrome-ux-report.all.202606`, publicată pe 2026-07-14. Query-ul static
`LOWER(NET.HOST(origin))` + filtrul ASCII + deduplicarea aplică apoi rankingul
SHA-256 înghețat și reține un prefix de 5.000. Jobul `DONE` a procesat
718.235.611 bytes sub capul de 50.000.000.000 bytes. Pin-urile sursei sunt:

- query `sha256:57e00de2a713402e6260ab6960027870c463ca263e0498280803b3c95466f884`;
- receipt BigQuery `sha256:aae01d5c754c14f7f52918dd0f166a2f7d4464d65d40ba5bc0d55aca609f11e3`;
- CSV 5.000 rows `sha256:a17f2dc551d8efd7bc070a619aaf6a0814c775159b78dcd61df316fbb6b49201`.

Toate cele 5.000 de domenii sunt canonice și unice, fără transformare sau
overlap cu `D1`. Nu s-a făcut DNS/HTTP/browser/technology/reachability
prescreen. Primele 200 sunt `D2`, următoarele 200 sunt `H1`, iar toate cele trei
seturi au overlap zero. Identitățile înghețate sunt:

- `D2`: Parquet `sha256:2b5b804d933461830d526171552faba4b105487119224d405727bca1ade48f2d`,
  domain set `sha256:8fa28cd236c0896491714c16df179d36a9d2bde49b75fdbe1917ebfcc545c7b4`,
  manifest `sha256:1e4c0793f6954988fdaa7c3838e2f1c3db201fedeb0e9642a2d7244b19b4b24e`;
- `H1`: Parquet `sha256:f0bda7f40af62702dddaa6ae428d5b5f6d8100a884de7bc2751f8b4c6331a418`,
  domain set `sha256:d69b0d4e73c8ee8300943c1376e51be19e3cc49f20945e1bd0edceeb9c5c54ed`,
  manifest `sha256:f5115d197216ac819a7a8faed7e5ce09a359cee5abd419af9f04876d3d02487f`.

Ambele Parquet-uri au exact 200 de rânduri și un singur câmp required
`root_domain`, trec readerul de producție și păstrează ordinea rankului.
Manifestul `D2` pin-uiește digestul manifestului `H1`; toate artefactele locale
sunt regular, single-link și `0600`. Freeze-ul nu autorizează trafic public.

Păstrăm exact cinci folds, priorul patru, supportul recurent minimum doi,
38 trigger plus două controls și pragurile globale 95% nume, 80% perechi și
30% pentru fiecare dintre cele cinci costuri browser reale. Fiecare fold trebuie
să primească o cotă trigger pozitivă; altfel experimentul este invalid.
Comparația foldurilor exclude controls, dar toate guardrails globale includ
integral cele două controls.

Notăm cu `F(d)` setul numelor directe canonice `full`, cu `T2(d)` setul direct
`T2` și cu `U_T2` reuniunea `T2` peste toate cele 200 de domenii `D2`, comună
ambelor brațe. Într-un fold, pair lift-ul trigger-only este
`sum(|F(d) - T2(d)|)`, iar novel-name coverage este
`|union(F(d)) - U_T2|` peste triggerii selectați ai acelui fold. Feature-ul
category câștigă foldul numai dacă ambele valori sunt cel puțin egale cu
baseline și minimum una este strict mai mare. Cerem minimum patru victorii din
cinci. Este o euristică de stabilitate preregistrată, nu un test de
semnificație statistică.

Decizia este baseline-first. Dacă baseline trece simultan toate guardrails
globale, el este câștigătorul și feature-ul suplimentar nu este acceptat. Altfel
acceptăm category numai dacă trece toate guardrails globale și câștigă minimum
patru folds. Orice alt rezultat este `NO-GO`; nu publicăm candidat pentru un
braț eșuat și nu reglăm pragurile, salts, foldurile, cota sau feature-ul după
ce vedem `D2`.

Numai câștigătorul eligibil se antrenează apoi pe toate snapshoturile `D2` și
se îngheață. Îl evaluăm o singură dată pe `H1`, fără training, retraining,
feature sau prag schimbat. Un eșec transformă `H1` în development evidence și
o nouă afirmație cere `H2` sigilat. Documentul și manifestele nu autorizează
singure trafic public. Tieringul funcțional rămâne `HOLD` până la PASS pe
holdout și un slice de implementare autorizat separat.

## Verdictul paired D2 v0.1.8 și remedierea bounded v0.1.9

Runul public D2 autorizat a fost construit din commitul curat
`29ccc4ff3577a5cb80fae86c46e6cd643182b014` cu scanner `0.1.8`, Node
`24.19.0`, Playwright `1.62.1`, Chromium `1234`, catalog
`sha256:614581009dc6ac2986763f8a324c656e629f63c5ecb7e46cf3ac10b121277724`
și config
`sha256:9bd1d4ab621075abdc669f6caf1393a6fc5d36e69e6a5297eb35f2c57ee79584`.
A terminat exact 200/200 domenii fără înlocuire a cohortei sau resume: 9
success, 182 partial și 9 failed, cu 2.305 apariții directe și 234 inferred.
Summary-ul a fost reconstruit byte-identic. Artefactele locale Git-ignored sunt:

| Artefact | SHA-256 |
| --- | --- |
| `output/work/d2-crux-202606.results.jsonl` | `90242459ed4fc7a88601911a057a7951d2562388cd3fbcf1db188407493b40d1` |
| `output/work/d2-crux-202606.results.summary.json` | `d8ec4532b585a57c4c769ee33e0d0b5a5352371077ae9301a48343e22bc79f3f` |
| `output/work/d2-crux-202606.results.evaluation.json` | `054b14bf7109823775cb2b3aa422ca1983df8d619584e874d66554293c135bb4` |
| `output/work/d2-crux-202606.paired.report.json` | `e8f53b9eb75d23254a55e97efb6e6e96dfc5cc8bbf4809b2608cfc1c93ff0a8d` |

Rezultatul preregistrat este:

| Braț | Nume canonice | Perechi domeniu-tehnologie | Costuri `<=30%` | Fold wins category |
| --- | ---: | ---: | ---: | ---: |
| baseline v2 | 302/388 = 77,84% | 1.748/2.305 = 75,84% | 2/5 | neaplicabil |
| baseline + T2 category IDs | 302/388 = 77,84% | 1.757/2.305 = 76,23% | 3/5 | 1/5 |

Baseline are ratios 28,97% pages attempted, 30,37% pages admitted, 31,86%
requesturi, 28,88% bytes și 31,39% browser milliseconds. Category are 28,57%,
29,91%, 32,74%, 29,99% și 31,12% în aceeași ordine. Ambele eșuează pragurile
95%/80%; category câștigă numai foldul 4, nu minimum patru. Raportul fixează
`selectedFeatureSet=null`, `reason=no-arm-eligible` și `candidate=null`.
Nu antrenăm și nu înghețăm model. Ramura H1 este închisă ca neaplicabilă;
Parquetul și manifestul rămân sigilate, arhivate, nefolosite și nescanate.

Diagnosticul D2 a autorizat numai aceste trei remedieri bounded:

1. Cele 17 apariții directe cu probe sunt exclusiv probe: 13 TYPO3 CMS și patru
   Magento. Body-urile brute nu au fost persistate, deci nu le etichetăm pe toate
   retrospectiv drept false. Ledgerul `.2` închide mecanismul demonstrat de
   presence/generic literal prin semnături exacte și fixtures soft-404/path-echo.
2. 19 perechi T2 lipsesc din `full` pe 11 domenii; fiecare full pass afectat are
   `REGEX_EXECUTION_LIMIT` sau `REGEX_DOMAIN_BUDGET_EXCEEDED`. Faza T2 primește
   prioritate și checkpoint înainte de full-only sub plafoanele neschimbate.
3. Toate cele 24 `BROWSER_UNAVAILABLE` coapar cu
   `BROWSER_NAVIGATION_FAILED`. 13 au telemetry proxy cauzală
   (12 `proxy.requestsPerPage`, una `proxy.requestsPerDomain`); una are numai un
   hit DOM anterior fără cauzalitate demonstrată, iar zece nu au limit hit.
   Pentru ultimele 11, cauza terminală exactă este istoric nerecuperabilă din
   artefactul raw-free: abortul a devansat promisiunea colecției, iar `finish()`
   a emis falsul unavailable. Drain-ul bounded v0.1.9 reproduce local atât
   cazul cu hit cauzal, cât și proxy failure fără hit și păstrează diagnosticul
   finalizat.

Nu mărim limite, nu schimbăm triggerul și nu reinterpretăm D2 după fixuri. D2 a
devenit development evidence. Următorul experiment trebuie să înghețe și să
autorizeze separat un `D3` fresh și un `H2` sigilat, cu preregistrare și
manifeste legate de scannerul/catalogul v0.1.9. Nici source frame-ul, cohorturile,
artefactele și nici traficul nu sunt încă înghețate sau autorizate. H1 nu devine
H2, iar routingul funcțional rămâne `HOLD`.

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
- Forma tiered rămâne provizorie până trece protocolul shadow: `T1` este view-ul
  entry HTTP static + robots + DNS/TLS, iar `T2` adaugă probele și zero sau o
  pagină internă statică selectată numai din linkurile statice `p1` prin regula
  exactă de mai sus.
- Un Tier 3 viitor rulează browserul pe entry numai pentru domeniile selectate
  din `T1`/`T2` și pentru controlul determinist de 1%.
- Un Tier 4 viitor poate adăuga product page pentru subsetul ecommerce, dar
  domeniul consumă același buget browser indiferent de tier sau outcome.
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
- Ținta inițială de 95% din occurrence-urile directe cu browser pe maximum 20%
  a fost infirmată de benchmarkul v0.1.4. Protocolul v0.1.5 a folosit provizoriu
  breadth canonicalizat >=95%, retenția perechilor canonicalizate >=80% și
  maximum 40/200 domenii browser. Triggerul v0.1.5 a eșuat; routingul funcțional
  rămâne `HOLD`, iar un KPI final cere un candidat înghețat și un cohort
  reprezentativ nou.

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
