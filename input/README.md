# Challenge Input

The benchmark input is supplied by Veridion for the
[Website Technologies Scraper challenge](https://veridion.com/company/careers/challenges/internship).
Download the linked Parquet file from the challenge page and save it locally as:

```text
input/domains.parquet
```

Direct domain-list link published with the challenge:

<https://drive.google.com/file/d/1JeyDbO7TOeLPS_FsXf8YFsdENnmwlCJm/view?usp=sharing>

The file used for the submitted run has:

```text
SHA-256  65e77097c669c29b392f3279a93f04566ab934cf1e8acfaf1ae4046a01e97bb2
Rows     200
Column   root_domain (UTF-8 string)
```

Verify it on macOS with:

```sh
shasum -a 256 input/domains.parquet
```

The source Parquet is intentionally ignored by Git because it is challenge
input rather than project-authored material. The submitted per-domain output is
tracked because it is an explicit expected deliverable and necessarily names
the domains whose results it contains.

The scanner performs a complete fail-fast schema, limit, normalization, and
duplicate preflight before it creates output or starts network traffic. See the
[Parquet input contract](../docs/TECHNICAL_REFERENCE.md#parquet-input-contract-v1)
for the complete accepted schema and safety limits.
