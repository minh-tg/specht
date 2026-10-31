---
title: CI gates and change evidence
description: Send a scanner report with change metadata and understand the gate that CI evaluates.
---

Specht evaluates reports against a project's policy. A failed check links to the
report and decision it evaluated, rather than a generic project overview.

## Choose the gate

An introduced-findings gate asks whether the report introduced blocking findings.
A project-wide gate considers current blocking findings, including existing debt.
The mode and severity floor belong to the decision; links preserve both.

The change view keeps introduced blockers separate from existing debt. Do not
interpret a passing introduced-findings gate as proof that the project has no
other findings.

## Configure the integration

The project CI setup page generates instructions for your installation. Create a
project-scoped API key and keep it in your CI secret store. The adapter uploads
the scanner report with branch, commit and scan metadata, then evaluates the gate.

:::caution[No tagged release yet]
The GitHub Action downloads and verifies a release artifact. Before the first
release is published, use an adapter built from the same checkout as your server.
A placeholder release tag is not an installable version.
:::

After a release exists, pin the action and server to the same release. The
repository includes [complete GitHub Actions and GitLab examples](https://github.com/minh-tg/specht/tree/main/examples/ci).

The adapter exits with:

| Code | Meaning                                               |
| ---- | ----------------------------------------------------- |
| `0`  | The selected gate passes.                             |
| `1`  | The selected gate is blocked.                         |
| `2`  | A runtime or configuration error prevented the check. |

Do not convert a runtime error into a passing security check. An incomplete
report is not a completed gate decision.

## Declare a filtered scan

Trivy with `--severity HIGH,CRITICAL` or `--ignore-unfixed`, and Grype with
`--only-fixed`, write a report that looks like a full scan. The file does not
record the flags. Without a declaration, every medium, low or unfixed finding
missing from the report would count as fixed.

Declare the filter when you upload the report. A filtered report closes only the
findings inside its filter. A finding outside the filter stays open when the
report omits it, and verifying such a finding by hand stays inconclusive.

| Adapter flag | `specht reports upload` flag | Action input | Meaning |
| --- | --- | --- | --- |
| `-scan-severities=high,critical` | `--scan-severities` | `scan-severities` | The severities the scan kept. |
| `-fixable-only` | `--fixable-only` | `fixable-only` | The scan kept only findings that have a fix. |

For `-tool=trivy`, the adapter and `specht reports upload` read `TRIVY_SEVERITY`
(for example `HIGH,CRITICAL`) and `TRIVY_IGNORE_UNFIXED=true` when the flags are
absent, so a step that sets Trivy's own variables needs nothing more. An explicit
flag wins over the variable. The API takes the same declaration as the
`scan_filter` object of the ingest request, with `severities` and `fixable_only`;
a severity other than `critical`, `high`, `medium`, `low` or `unknown` is refused
with `400 invalid_field`. The report API returns it as `scan_filter`.

Uploading the same file with a different filter creates a separate report. Only
the same file with the same filter, commit and scan scope is treated as a replay.

## Read the result

The check's link opens the exact report. Each blocker identifies the finding and
its evidence. Findings from older work appear separately as existing debt.

A severity badge is not itself a gate verdict. A finding can be high severity
without blocking the selected gate, while a lower-severity finding can block a
gate with a lower floor. The **Blocks gate** marker follows the server's decision.

## Verify a fix

Re-run your CI scan, or submit a replacement through the API with matching scan
metadata. A configured watcher can provide its next scan for the scope it watches.
A checklist records your progress; it does not change a gate decision.

The newest received report may still be processing or may have failed. The
application shows the latest completed report separately. **Page data fetched**
describes the browser's request, not when the scanner ran.
