---
title: CI gates and change evidence
description: Send a scanner report with change metadata and understand the gate that CI evaluates.
---

Specht evaluates reports against a project's policy. A failed check links to the
report and decision it evaluated, rather than a generic project overview.

## Start without breaking your default branch

The pipeline also scans your default branch, so existing findings can fail its first run. Set the
project's gate mode first, on its CI setup or Policy page. **Block new findings only** fails a pull
request that introduces a blocking finding and only reports what is already there. **Report only**
fails nothing. Turn on **Block** once the backlog is under control.

## Choose the gate

An introduced-findings gate asks whether the report introduced blocking findings.
A project-wide gate considers current blocking findings, including existing debt.
The mode and severity floor belong to the decision; links preserve both.

The change view keeps introduced blockers separate from existing debt. Do not
interpret a passing introduced-findings gate as proof that the project has no
other findings.

The project-wide gate answers for the default branch. A finding seen only on
change branches stays out of it until the default branch reports it, so an open
pull request or an abandoned branch does not turn `main` red. The findings list
labels these findings and can filter to them. A project-wide gate run on another
branch also counts that branch's own findings. A report without a branch counts,
because nothing shows it is off the default branch.

In a pipeline with one step per scanner, the adapter's exit code on a
project-wide gate counts only the findings that scanner reported. A Semgrep step
does not fail on Trivy findings, which the Trivy step reports and can close on
its own. The log still prints the project total across all scanners, and the
project verdict (`GET /api/v1/projects/{slug}/gate` without `scanner`) and the
UI still count every scanner. So does the check the adapter publishes on the
commit: every step writes the same check, and the last one to finish must leave
the whole project's verdict, not only its own scanner's.

The introduced-findings gate compares the report with a baseline: the newest
full report of the same scanner for `base_revision`, a commit or a branch name.
Only a report on a trunk can be the baseline. Once the project names its
default branch, that branch is the only trunk: a report on any other branch, or
a report without a branch, is never a baseline. Without the setting, a trunk is
a branch whose reports never named a `base_revision` other than the branch
itself, such as a default branch that only gets push builds, and a report
without a branch is accepted. A `base_revision` that resolves to a report of the
uploading branch, by its name or an earlier commit, or to a report of a branch
that is itself a pull or merge request head, is not used.

A report of a change with no usable baseline counts a finding as pre-existing
only when the trunk still has it: a trunk scan observed it and no later complete
scan of that trunk scope found it gone. Every other finding the report observes
is introduced. A report is a change when it names a `base_revision` other than
its branch, or its branch did before. Once the project names its default branch,
every report off that branch is a change, with or without a branch name. The
branch name, environment and artifact name are the uploader's choice, so changing
them between pushes does not turn a blocker into existing debt. A project that
never scans its trunk has no trunk debt: each change counts every finding it
observes as introduced. Scan the default branch, or waive or accept the shared
findings, to keep pull requests from blocking on them.

A project admin sets the default branch under **Settings** on the project, or
with `default_branch` on `PUT /api/v1/projects/{slug}`. Reports on it count as
the baseline for pull requests even if the branch was once the head of a pull
request, for example a `main` that was merged into a release branch, and its own
push builds never carry introduced findings forward. No other branch is a trunk
then, so a `develop` or release branch is a baseline only if it is the one you
set. Set the default branch: without it, an ingest key can upload a report
without a branch, or on a branch name nobody used, and name it as the base.
Without the setting, a
default branch that was once the head of a pull request is a change branch: it
is no baseline and no trunk, so a pull request against it counts the default
branch's own findings as introduced. Without the setting, a push build of a
branch that never named a base also counts as a trunk build. The server never
takes the default branch from an upload.

A baseline declared filtered (see below) cannot show that a finding its filter
may have hidden is absent. For such a finding, the newest earlier full scan of
the same branch that could have seen it answers instead, among the 20 newest. If
none could, the finding is pre-existing when the trunk still has it, so trunk
debt hidden by the filter never counts as introduced.

A trunk that scans several images or targets with one scanner has a newest
report for each. The baseline is the newest trunk report of the same scan scope
as the uploaded report: the same scanner, target, artifact name and environment.
When the trunk has no report in that scope, the newest trunk report of the
scanner is used. The earlier scans that answer for a filtered baseline come from
the baseline's own scope, so a scan of one image never says a finding of another
image is gone.

## Configure the integration

The project CI setup page generates instructions for your installation. Create a
project-scoped API key and keep it in your CI secret store. The adapter uploads
the scanner report with branch, commit and scan metadata, then evaluates the gate.

:::caution[No tagged release yet]
The GitHub Action downloads and verifies a release artifact. Before the first
release is published, use an adapter built from the same checkout as your server.
A placeholder release tag is not an installable version.
:::

On GitHub Actions and GitLab CI the adapter also sends where the report came
from: the repository's web address, the pull or merge request number and title,
and the address of the run. The change view uses them to link back to the pull
request, the run and each file at the scanned commit. Elsewhere, set
`-repo-url`, `-pull-request` and `-run-url`. A URL with a user name or password
is never sent, so GitLab's `CI_REPOSITORY_URL`, which carries the job token, is
not read; the adapter uses `CI_PROJECT_URL` instead.

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

A matrix that runs one scanner in several jobs, such as one job per lockfile or
URL, must give each job its own `-artifact` (the `artifact` input on the GitHub
Action). Without it the jobs share a scan scope, and a clean scan in one job
would close the findings of the others. When a full report finds another report
of its scope at the same commit with the same declared scan filter and different
content, it closes nothing and
the adapter prints a warning that says to set `-artifact`. A rerun whose output
changes between runs looks the same, so it closes nothing until the next commit.

## Declare a filtered scan

Trivy with `--severity HIGH,CRITICAL` or `--ignore-unfixed`, and Grype with
`--only-fixed`, write a report that looks like a full scan. The file does not
record the flags. Without a declaration, every medium, low or unfixed finding
missing from the report would count as fixed.

Declare the filter when you upload the report. A report filtered by severity
closes no finding it omits: the scanner may have re-rated the finding below the
filter since the last scan, and the report cannot show which happened. Run an
unfiltered scan of the same scope to close fixed findings. A fixable-only report
closes an omitted finding only when the finding has a fixed version. A finding
the report cannot vouch for stays open, and verifying it by hand stays
inconclusive.

- **Severities the scan kept:** `-scan-severities=high,critical` on the
  adapter, `--scan-severities` on `specht reports upload`, or the
  `scan-severities` Action input.
- **Only findings that have a fix:** `-fixable-only` on the adapter,
  `--fixable-only` on `specht reports upload`, or the `fixable-only` Action
  input.

For `-tool=trivy`, the adapter and `specht reports upload` read `TRIVY_SEVERITY`
(for example `HIGH,CRITICAL`) and `TRIVY_IGNORE_UNFIXED=true` when the flags are
absent, so a step that sets Trivy's own variables needs nothing more. An explicit
flag wins over the variable. The adapter cannot see the flags Trivy actually
ran with, so it trusts the variable and prints
`declaring scan filter: severities=..., fixable_only=...` on stderr with the
source of each value. A variable that is set for another step of the same job,
or a `--severity` flag that differs from it, makes that declaration wrong, and a
declaration wider than the real scan lets the server close findings the scan
never examined. Check the line in the job log. The API takes the same declaration as the
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
