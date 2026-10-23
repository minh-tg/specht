---
title: Triage and waivers
description: Work open findings, record analysis and request time-limited policy exceptions.
---

## Find the work

The **Needs triage** shortcut selects open or reopened findings whose analysis is
unanalyzed or in triage. The counter and the linked list use the same predicate.
**Open critical/high** selects open or reopened findings at those severities.

A shortcut replaces older filters and resets pagination. You can refine the
result with the existing filters and keep the URL for later.

## Keep severity and impact separate

Severity describes a finding. The current gate, its floor and its policy decide
whether it blocks. An explicit **Blocks gate** marker identifies actual blockers.

Record analysis and reachability decisions on the finding, individually or in
bulk. Triage state is not the same as an approved policy exception. Use the
finding's history to see how scans and decisions changed it.

## Waivers

A waiver request records its targets, a reason and an expiry date. Approval is a
separate step, with permissions enforced by the server. Submitting a request does
not by itself grant an exception.

Use the project's **Waivers** page to review requests and decisions. When an
approved exception expires, evaluate the finding against the active policy again.

## Project configuration

The daily tabs are **Findings**, **Reports**, **Waivers** and **Insights**.
Open **Configuration** for **Policy**, **Watcher** and **Access & Members**.
Members retain their existing read access; **Settings** appears only for users
with the required administrative permission.
