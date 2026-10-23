---
title: Scanner reports
description: The report formats Specht reads and the limits to check before uploading.
---

Specht accepts the reports your scanners produce. Choose the scanner that wrote
the file. A mismatched file is refused, with a message that names the scanner
it resembles.

## Supported formats

| Scanner                | Accepted report                                    |
| ---------------------- | -------------------------------------------------- |
| Trivy                  | JSON from filesystem, image or configuration scans |
| OSV-Scanner            | JSON                                               |
| Semgrep                | Native JSON or SARIF                               |
| Checkov                | JSON, including output with several frameworks     |
| OWASP Dependency-Check | JSON                                               |
| Grype                  | Native JSON                                        |
| Gitleaks               | JSON, including redacted reports                   |
| tfsec                  | JSON                                               |
| Nuclei                 | JSON Lines (`.jsonl` or `.ndjson`)                 |
| SARIF tools            | SARIF 2.1.0, including CodeQL, Gosec and Hadolint  |
| SBOM                   | CycloneDX 1.x JSON or SPDX 2.x JSON                |

The repository's [generated scanner table](https://github.com/minh-tg/specht#supported-scanners)
records example commands and the versions tested by each parser.

## Produce a report

For a Trivy filesystem scan:

```bash
trivy fs --format json -o trivy.json .
```

For a Semgrep scan:

```bash
semgrep scan --json -o semgrep.json
```

Upload the output, not terminal text or a screenshot of the scan. The manual
upload form accepts files up to 10 MiB; the HTTP API accepts request bodies up to
25 MiB. Finding limits and ingest memory settings also apply.

## Scope and repeat scans

Send replacement reports with the same scanner, target, branch and other scan
metadata. Findings are matched across scans, and evidence from different scopes
can remain active independently. A clean scan of one target does not establish
that every other target is clean.

A manual upload through the web form does not add CI branch or revision
metadata. Use the adapter or API for [change-linked gates](../ci-gates/).

## Limits worth knowing

- Checkov's open-source report does not provide severity. Those findings appear
  with unknown severity.
- The SBOM reader records package identity and supplied vulnerabilities. It does
  not normalize dependency graphs, licenses, hashes or signatures.
- Select the SBOM reader for Grype's CycloneDX output. Native Grype JSON uses the
  Grype reader.
- A report can finish processing without proving complete coverage of a target.
  Only comparable, complete scan evidence can retire older scope evidence.

A tool or format not listed here needs a parser and test fixtures before Specht
can read it.
