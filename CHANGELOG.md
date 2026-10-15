# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Specht is an early preview: schemas, settings, and the API may change between
releases.

## [Unreleased]

### Added

- Report ingestion for Trivy, OSV-Scanner, Grype, OWASP Dependency-Check,
  Semgrep, SARIF 2.1.0 (CodeQL and others), Checkov, tfsec, Gitleaks, Nuclei,
  and CycloneDX or SPDX SBOMs.
- A finding ledger: findings persist across scans, track when they first
  appeared, and move through triage (open, fixed, returned, waived).
- Bulk triage from the findings list, with selection, sorting, filtering, and
  server-side search.
- Policy per project, with organization-wide policy templates and a severity
  floor that a project can override.
- Waivers with an expiry date, explicit scope, and a request and approval flow.
- A CI gate in `specht-adapter` that fails a build on blocked findings and
  explains the block: a why-it-blocks panel in the web UI and annotations and
  check runs in CI.
- A GitHub Action (`minh-tg/specht`) that verifies the adapter release
  signature before it runs the gate, and a GitLab merge request gate for
  findings introduced by the change.
- Teams and project access: project members and teams. Team rosters show
  member names to anyone signed in.
- Single-use project invite links, and an invite dialog for teammates.
- First-run setup with a one-time setup token; self-service registration is
  off by default.
- Single sign-on over OpenID Connect, with ID-token verification, optional
  domain allowlisting, and admin groups.
- API keys per project, managed by project managers and admins.
- Account recovery from the host: `specht` commands that restore access to a
  locked-out instance.
- A readiness endpoint at `GET /api/v1/ready` that checks the database, next
  to the liveness endpoint at `/api/v1/health`.
- A CVE feed watcher that checks tracked packages against OSV, with Slack and
  webhook notifications signed with HMAC-SHA256 (opt-in per project).
- Tracker dispatch for finding lifecycle events (created, verified fixed,
  regression) to a webhook, off by default.
- Threat intelligence on finding detail pages: EPSS scores and CISA KEV status.
- Docker Compose deployment with Postgres 17, rate limiting on by default,
  and a published server image.
- Web UI pages for findings, reports, policy, waivers, insights, the watcher,
  access, and administration, with a command palette.
- A profile page to change your name and password, and a one-time password
  reset link an administrator can hand to someone who is locked out.
- Project settings to rename, describe and delete a project.
- Evidence, reviewer sign-off, a fix check, and a way back to "not triaged"
  on the finding page; report deletion; waiver editing, deletion and history.
- API key expiry, and project managers can manage their project's keys.
- Add a project or team member by email address.
- An inventory of environments, scan targets and artifacts on the Insights
  page.
- Audit log entries for membership, team, policy, waiver, evidence, sign-off
  and retention changes, including refused attempts.
- A published-image compose file with a source-build override, backup and
  restore instructions, and a CI check that restores a dump.
- Project admins can classify an environment (tier, reachable from the
  internet, data sensitivity) from the Insights page. Scans create an
  environment with a tier guessed from its name and never overwrite what an
  admin set.
- The report upload page takes `.jsonl` and `.ndjson` files, such as Nuclei
  output, and names the line that is not valid JSON.

### Changed

- The server validates all of its settings at startup and reports every
  problem in one message.
- Request logs carry a request ID that matches the `X-Request-Id` response
  header.
- The server waits for the database at startup, up to `DB_CONNECT_TIMEOUT`.
- The database pool size comes from `DB_MAX_CONNS` and `DB_MIN_CONNS`.
- A stop waits for in-flight requests up to `SHUTDOWN_TIMEOUT`.
- A report left in processing by a stopped server is marked failed after 15
  minutes, so the scan can be uploaded again.
- Report history pages through older reports, and a finding's history shows
  every event instead of the newest 20.
- Roles granted through a linked team now show the controls they allow.
- Fonts are served as files, which the Content-Security-Policy allows.

### Security

- Self-service registration is closed unless `REGISTRATION_ENABLED=true`.
- Forwarding headers are trusted only from the CIDRs in `TRUSTED_PROXIES`.
- Request bodies are size-capped, and ingest rejects oversized reports with
  413.
- The MCP bridge hides state-changing tools unless `MCP_ALLOW_MUTATIONS=true`.
