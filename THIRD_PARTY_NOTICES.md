# Third-Party Notices

This file records third-party material approved for this project and its
provenance. Third-party material retains its own copyright and license.

## WebAppAnalyzer fingerprint catalog

Status: approved baseline; no catalog files have been vendored yet.

- Source: <https://github.com/enthec/webappanalyzer>
- Pinned revision:
  [`5e7c47b1d441ded0bd476b252261e87634349f96`](https://github.com/enthec/webappanalyzer/commit/5e7c47b1d441ded0bd476b252261e87634349f96)
- Revision date: 2026-08-12
- License: GNU General Public License, version 3; treated conservatively by
  this project as `GPL-3.0-only`
- License text:
  <https://github.com/enthec/webappanalyzer/blob/5e7c47b1d441ded0bd476b252261e87634349f96/LICENSE>
- Intended files: `schema.json`, `src/categories.json`, and
  `src/technologies/*.json`
- Excluded files: upstream executable code, dependencies, icons, and branding
- Local modifications: none; the files are not present in this repository yet

When the pinned snapshot is imported, this notice must be updated with the
retrieval date and any local modifications. Vendored files remain separate
from original definitions in `fingerprints/custom` and are not edited in place.

The current commercial Wappalyzer catalog, website, extension, npm placeholder,
and API are not sources for this project.

## Direct npm dependencies

Status: resolved exactly in `package-lock.json`; Chromium has not been
downloaded or bundled.

| Package | Version | Declared license |
| --- | ---: | --- |
| `ajv` | 8.20.0 | MIT |
| `cheerio` | 1.2.0 | MIT |
| `hyparquet` | 1.28.2 | MIT |
| `playwright` | 1.62.1 | Apache-2.0 |
| `robots-parser` | 3.0.1 | MIT |
| `@types/node` | 24.13.3 | MIT |
| `typescript` | 7.0.2 | Apache-2.0 |

The complete resolved dependency tree, source URLs, integrity hashes, and
declared licenses are recorded in `package-lock.json`. Installed package copies
retain their own license files. If a future distributable bundles dependency
code or a Playwright browser, its corresponding license and notices must be
included with that artifact.

## Veridion challenge domain list

Status: present locally as `input/domains.parquet`; excluded from Git until
redistribution permission is confirmed.

- Challenge page:
  <https://veridion.com/company/careers/challenges/internship>
- Supplied file link:
  <https://drive.google.com/file/d/1JeyDbO7TOeLPS_FsXf8YFsdENnmwlCJm/view?usp=sharing>
- License: no separate redistribution license was found in the challenge text
- Local modifications: none

The project `GPL-3.0-only` license does not claim copyright in or relicense this
input file. Before publishing the repository, confirm that the file may be
redistributed or keep it excluded and document how applicants obtain it from
the challenge source.
