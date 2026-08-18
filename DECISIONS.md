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
- Colectorul browser folosește un pool FIFO bounded de procese Chromium
  reutilizabile, fiecare cu proxy validant propriu, preflight canary obligatoriu
  și cel mult o înlocuire după pierderea procesului.
- Colectorul de infrastructură interoghează numai tipurile DNS cerute de
  catalog pentru domeniul input canonic și reutilizează exclusiv issuerul TLS
  din handshake-ul HTTPS final deja verificat și pin-uit.
- `scanDomain()` unește într-o singură scanare bounded HTTP `p1`–`p3`, browser,
  robots, probe declarative și DNS/TLS, apoi apelează detectorul exact o dată pe
  setul complet de observații.
- Coada FIFO pentru slotul `full` rămâne în afara deadline-ului activ al
  domeniului; anularea callerului rămâne activă și în coadă.
- Colectorul de probe revalidează maximum cinci pathuri sortate din planul
  catalogului și emite body observations bounded numai prin originul final,
  robots și transportul protejat comun.

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
├── browser-proxy.test.ts
├── browser.test.ts
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
robots protejat + decizie pentru path
  ↓
homepage HTTP + browser izolat
  ↓
maximum două pagini interne determinate reproductibil
  ↓
HTTP + browser + probe declarative bounded
  ↓
DNS/TLS + scripturi deja observate
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
Pipeline-ul unește linkurile statice și randate ale `p1` înainte să clasifice și
să fetch-uiască paginile interne.

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
o pagină `listing` sau fallback `content`. Candidații sunt exclusiv reuniunea
deduplicată a linkurilor de navigare statice și randate din `p1`; nu ghicim
pathuri, nu folosim linkuri din paginile interne și nu facem crawl recursiv.
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
gol. Sortăm alegerile structurale după URL-ul canonic de rețea și păstrăm
prefixul permis de `topLevelPerDomain - 1`. Apoi facem maximum două checks
robots; denial sau unavailable elimină candidatul fără backfill. Sanitizăm
supraviețuitorii pentru publicare, eliminăm coliziunile cu entry-ul sau între ei,
îi resortăm după URL-ul public și abia apoi atribuim IDs compacte `p2`/`p3`, fără
goluri.

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

Fiecare domeniu primește un context Chromium nepersistent, reutilizat secvențial
pentru `p1`–`p3`, cu maximum o pagină activă și exact același origin. Sandboxul
și CSP rămân active, service workers și downloads sunt dezactivate și nu există
clickuri, formulare sau autentificare. Planul generic de inspecție este compilat
din catalog, are tipurile comune deținute de `src/model.ts` și cere numai fapte
DOM și pathuri JavaScript bounded; `crawl` nu importă `detect`, nu emite o
enumerare a DOM-ului și nu enumeră `window` complet.

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
[`Initial scan policy`](README.md#initial-scan-policy) și
[`Initial resource budget`](README.md#initial-resource-budget). La scară mare,
HTTP rulează pentru toate domeniile, iar probele, paginile interne și browserul
cu scripturile deja descărcate de el sunt tier-uri selective măsurate împotriva
baseline-ului `full`.

## Decizia colectării probelor declarative

Politica v1 este implementată în `crawl/probe.ts`. Colectorul primește URL-ul
final de rețea numai pentru un entry HTML, maximum cinci pathuri din planul
catalogului, configurația validată, sesiunea de transport protejat și serviciul
robots al runului. Rulează secvențial după toate colectările HTTP/browser
`p1`–`p3` și înainte de DNS/TLS, finalizarea sesiunii browser și singura
invocare a detectorului.

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

Ordinea bounded este: HTTP/robots `p1`; browser `p1` numai pentru HTML 2xx
complete sau truncated; reuniunea linkurilor statice și randate; selecția v1 și
maximum două checks robots; HTTP apoi browser pentru `p2`/`p3` eligibile;
probele sortate pe originul final pentru un entry HTML; DNS cerut de catalog și
issuerul TLS reutilizat numai după toate requesturile HTTP statice; finalizarea
sesiunii browser; apoi o singură invocare a detectorului cu toate observațiile
HTTP `p1`–`p3`, browser, robots, probe, DNS și TLS. Relațiile și excluderile se
rezolvă astfel o singură dată pe setul combinat.

Orice body robots admis cu succes în entry, precheck structural, colectarea unei
pagini interne sau verificarea unui probe rămâne semnal de detector cu
`pageId: null`, inclusiv când lucrul asociat este ulterior omis ori eșuează.
Detectorul deduplică valorile identice, iar existența unui astfel de semnal
participă la alegerea `partial`/`failed`.

O pagină statică eșuată nu poate deveni browser-only. Navigările browser formează
un prefix ordonat: după un gap nu deschidem o pagină browser ulterioară, deși un
`p2`/`p3` deja selectat poate păstra observațiile HTTP. Un entry final non-HTML
urmează terminalul `partial` deja decis și nu pornește pagini interne.

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
[`Result and evidence contract v1`](README.md#result-and-evidence-contract-v1).

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
[`Relationship resolution`](README.md#relationship-resolution).

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
care adaugă nume noi; v1 nu definește merge sau override. Înainte de parsare se
aplică limite de 64 fișiere, 1 MiB per fișier, 16 MiB total și adâncime JSON 64,
iar duplicatele de membri JSON, symlinkurile și intrările neașteptate sunt
respinse. Toate declarațiile directe, inclusiv presence și duplicatele care vor
fi deduplicate, consumă limita de 20.000. Header/meta folosesc locatoare exacte
lowercase; locatoarele cookie sunt regexuri whole-name ancorate, executate în
worker și incluse în bugetul regex. Rule ID-urile folosesc namespace-uri
versionate stabile, fără commit, în timp ce provenance păstrează separat
revizia și digestul snapshotului.

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
răspuns intern deja selectat păstrează `p2`/`p3`. Pipeline-ul trimite o singură
dată setul combinat HTTP/browser/probe/DNS/TLS, nu unește rezultate detectate
separat pe pagini. Matchingul regex rulează pe valoarea raw bounded în worker;
parentul primește doar spanul și versiunea sigură și construiește dovada prin
sanitizerul comun. URL-urile se publică numai integral, canonic și sanitizat;
header/meta publică doar matchul după clasificarea întregii observații, iar
cookie/HTML/text/robots/probe/DOM/JavaScript/script content rămân redacted.
Candidații HTTP au prioritate înaintea tierului browser când bugetul admite doar
un prefix. Confidence și version se calculează din rule ID-uri unice, apoi se
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
