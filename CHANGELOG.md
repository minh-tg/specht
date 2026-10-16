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
- Ingest keeps every CVSS vector a Trivy, Grype, OSV-Scanner, Dependency-Check
  or CycloneDX report states (all versions, with the scoring source), and the
  EPSS percentile and the KEV due date and ransomware use are read from the
  feeds. `INTEL_ENABLED=false` turns the EPSS and KEV feeds off, so an
  air-gapped install makes no feed calls.
- Restore a revoked waiver from the Closed list of the waivers page (project managers and
  admins). `POST /waivers/{id}/revoke` and `/restore` name the wanted state, so a repeat changes
  nothing, and an optional `expected_updated_at` answers 409 `waiver_changed` when someone else
  wrote the waiver first. The Undo on the revoke toast uses it, so it no longer overrides a
  restore and revoke made in between. A waiver past its expiry cannot come back until its expiry
  is extended (409 `waiver_expired`), shows as Expired instead of Revoked, and no longer counts
  in the project's waiver total. History and the audit log record who revoked or restored a
  waiver and when. `POST /waivers/{id}/toggle` still works for approved waivers but is
  deprecated, and it refuses pending, rejected, withdrawn and expired ones.
- `GET /api/v1/findings/{id}/cve` returns the CVE evaluation details of a
  finding: every CVSS vector its scan reports carry with score, severity and
  each metric, EPSS and KEV, CWEs, dates and references, each with its source.
  When a report lacks a CVSS v3 or v4 vector, or both a CWE and a published
  date, the server can fetch the rest from NVD, VulnCheck or OSV
  (`CVE_DETAIL_PROVIDERS`, off by default). Only the CVE identifier is sent;
  answers are cached in PostgreSQL and the admin status lists each provider.
- A bare `?` opens the keyboard shortcut sheet, and a "Single-key shortcuts"
  switch in the account menu turns it off together with the findings list keys
  `j`, `k` and `x`. The findings list and the finding page now refresh every
  30 seconds while the tab is visible, show when they were last updated, and
  a Ctrl+K pressed with a list row focused opens the command palette.
- A "CVE details" section on the finding page: every CVSS version with its
  score, severity word and each metric in plain language, the vector with a
  copy button, EPSS as a percentage, KEV dates, CWE links and references. Each
  value says whether the scan report, the CVE watcher, a provider or a feed
  supplied it. The section is folded to a one-line summary until opened.
- A scan report only scopes the gate of the project it belongs to: asking for
  another project's report answers 403 and never evaluates its findings.
  Deleting a finding's evidence now requires the evidence to belong to that
  finding, so a mismatched pair, a missing finding and a missing evidence id
  all answer 404.
- The API key list carries `creator_is_member`, which is `false` for a key
  whose creator is no longer a direct or team member of the project. Removing
  a person never revokes their keys, so a CI key can outlive them on purpose;
  the field lets a manager see which keys to review.

### Changed

- Stored Gitleaks and Nuclei evidence no longer keeps a secret under a key written in another
  case (`secret`, `sEcReT`, `Request`, `RESPONSE`) or inside a nested object. Both scanners'
  redaction now matches key names without regard to case, at any depth. A Nuclei JSON Lines
  report with a line over 1 MiB is refused as unreadable instead of losing the later events.
- A report can no longer copy megabytes of scanner text into the database through a target
  name, scan scope value, artifact metadata or a finding's extra data. Target names are cut
  at 1024 bytes and kinds at 64, scope values at 1024 bytes, and one finding's extra data at
  16 KiB (whole keys are dropped, largest first, and `_truncated` is set). NUL bytes in extra
  data, which PostgreSQL refuses, are removed. An oversized target name used to make the
  target record fail without an error.
- A Semgrep report with an extremely long rule id no longer fails the whole ingest. The
  finding's fingerprint is now capped at 512 bytes like every other scanner's, and NUL
  bytes are removed. Fingerprints of normal findings do not change.
- Semgrep SARIF reports parse in linear time. Looking up the rule of each result scanned every
  rule, so a report with 40,000 rules and 40,000 results took several seconds and a larger one
  held an ingest slot for minutes.
- A report that would produce more than 100,000 findings and packages is refused with a
  422 `too_many_findings` that names the limit and asks you to split the report. The parser
  stops at the limit instead of converting the whole file, so one oversized upload can no
  longer exhaust the server's memory. Set `INGEST_MAX_FINDINGS` to change the limit; see
  `deploy/README.md` for the memory it costs.
- The finding limit can no longer be bypassed with padding. A report whose finding arrays
  hold `null`, strings, numbers or empty arrays instead of objects, whose array names are
  spelled in another case or with a JSON escape (`"RESULTS"`), or whose fields hold millions
  of scalar entries is refused with `422 too_many_findings` before it is decoded. Such a
  20 MB upload used to be accepted and cost the server about 1.5 GiB of memory.
- Report ingests share a memory budget. Before it decodes a report, an ingest reserves 64
  bytes per byte of the report out of `INGEST_MEMORY_BUDGET` (default 2 GiB, for example
  `512MiB`). A report that does not fit waits up to 15 seconds and then gets
  `503 ingest_busy`, so a few large uploads can no longer decode side by side and exhaust
  the server's memory. `deploy/README.md` now gives the real arithmetic instead of the earlier
  1.1 GB estimate.
- Secrets are no longer stored when redaction cannot read a report. A Gitleaks or Nuclei
  report with a number that does not fit a double (`1e400`) in an ignored field made the
  redaction step give up and store the report as it came, with the secret or the request
  and response in `reports.raw_data`. Redaction now reads any valid JSON. When it still
  cannot read a report, the stored evidence is `{"redaction":"failed"}` and the server logs
  a warning with the scanner and size. The report's findings are still ingested.
- A NUL character (`\u0000`) in a report no longer fails the whole ingest with a generic
  `ingest_failed`. The database cannot store it, so it is dropped from the strings of the
  report and its stored evidence, and the report is ingested. A NUL in a field name is
  refused with `malformed_report`, because dropping it would rename the field. A NUL in a
  request field such as `branch`, `commit_sha` or `environment` is refused with
  `400 invalid_field` naming the field.
- Undo after a triage change works for every earlier state. The server keeps a snapshot of
  the analysis it replaced (state, reason, expiry, source, manual and review flags) in the
  triage event, and `POST /api/v1/findings/{id}/analysis/undo` puts it back as a new event.
  Only the finding's newest change can be undone; older events and bulk triage answer 409
  `undo_unavailable`. `PATCH /api/v1/findings/{id}` accepts `expected_state`, answers 409
  `analysis_conflict` when the finding changed, and returns the new `event_id`. The finding
  response now carries `analysis_reason`, `analysis_expires_at`, `analysis_source`,
  `manual_override` and `review_required`.
- A report that is not the named scanner's output is refused with a 422 that
  names the scanner it looks like (`unrecognized_format`), instead of being
  recorded as a clean scan with no findings. A report that cannot be read is
  `malformed_report`, and an unknown scanner is `unknown_scanner`.
- A clean OSV-Scanner run, with no vulnerabilities, can now be ingested.
- `specht-mcp`, the MCP bridge, is built into every release next to `specht`
  and `specht-adapter`, reports the release version, answers `-version` and
  `-help`, and has a setup guide in `docs/mcp.md` that a test keeps in step
  with the tools it registers.
- The `specht` command can triage findings (`findings triage`, `bulk-triage`,
  `events`) and manage waivers (`waivers list`, `get`, `create`, `request`,
  `approve`, `reject`, `withdraw`, `toggle`, `delete`, `events`). The new
  commands honour `--format json`.
- Bulk triage no longer reports a decode error after the server has applied it.
- The Add Direct Member dialog suggests people as you type (three characters or more, at most
  eight, by email or the start of a name word). Only project managers and admins get
  suggestions, a limit of 30 requests a minute applies per person, and the list stays empty
  while open sign-up or SSO with unverified emails could let someone register under a
  colleague's name. Typing a full address still works. The team roster dialog suggests from
  the account list it already loads.
- The server compresses its own web app files (gzip), so the main script is about 250 kB on
  the wire instead of 830 kB. API responses are never compressed.
- A password must not be on a list of about 2,000 commonly used passwords or match the account's
  email address, the part before the @, or its display name, and it needs a visible character.
  Setting a password shows a strength bar (loaded only when a password field is used) with one
  line of advice. The minimum counts characters, the maximum counts bytes (72, the limit of the
  hash), and the message now says bytes. The new refusals answer `password_too_common` and
  `password_matches_account`.
- The Docker image carries `LICENSE` and `THIRD_PARTY_NOTICES` in `/usr/share/doc/specht`.
- The top bar uses the same button look as the rest of the app: links have a hover and a
  current-page fill, and Profile and Sign out moved into an account menu. The scan file
  field on the upload page is a drop area that also takes a dragged file, and the remaining
  hand-built buttons, inputs and text links use the shared components. A test now fails
  when a page declares its own input, textarea, select or button look.
- `--format json` now applies to `projects`, `findings`, `stats`, `teams`, `project-teams`,
  `policy` and `watcher` as well. They printed their table before. A command with nothing
  to list prints `[]`, not `null`.
- `specht findings events --type` and the MCP `finding_events` tool now filter by event
  type. The server ignored the filter before.
- `specht reports upload` drops a UTF-8 byte order mark, says when a file is UTF-16 (what
  PowerShell's `>` writes) or empty, and `--limit` values too large for the API are refused
  instead of wrapping to a small number. The MCP tools refuse them the same way.
- The `specht` command can upload a scanner's file (`reports upload`, which also reads standard
  input and line-based `.jsonl`), list, show and delete reports, change an environment's
  exposure and data sensitivity (`environments set`), and list targets, artifacts and the
  scanners Specht reads (`scanners list`).
- The `specht` command can create, rename and delete projects (`projects create`,
  `update`, `delete`, which needs `--yes`) and manage `members`, `api-keys`,
  `users` and `invites`. Account and invite commands need a signed-in session
  token in `API_KEY`, not a project key.
- `specht-mcp` also offers projects, stats, aging, reports, environments, targets,
  artifacts and a finding's history, and `scanners_list` for a signed-in session.
  With `MCP_ALLOW_MUTATIONS=true` it can record a triage decision, request a
  waiver, withdraw a request and reclassify an environment. It has no tool to approve or reject a waiver
  request, which stays with a person.
- A Semgrep finding keeps its identity when the code above it moves. The line
  is no longer part of it: a finding is the rule, the file and what was
  matched (Semgrep's own match id when the run is logged in, otherwise the
  message), and two alike in one file are told apart by their order.
- The upload page names scanners the way people know them ("Trivy", "SARIF (any
  tool)") and, once one is chosen, shows the files it reads, the command that
  produces each, and the tool version it was checked with. It accepts `.sarif`
  files. The same information is in `GET /api/v1/scanners` and in the README,
  where it is generated from the parsers.
- Semgrep reports are read from `semgrep --json` as well as `--sarif`. Both
  formats give the same findings, so switching keeps a project's history.
- A Checkov run over a directory with several kinds of files (Terraform,
  Kubernetes, Dockerfile), which Checkov writes as one report per framework,
  is ingested as one report. It used to be refused.
- A CycloneDX file that lists vulnerabilities (Grype writes one with
  `-o cyclonedx-json`) is ingested as findings, with the same identity Grype's
  own JSON gives them. It used to be read as a bare inventory with none.
- Two different secrets of one rule in one file (a `.env` with two keys) are
  two findings. A finding's identity is the rule, the file and a keyed hash of
  the credential, so it stays put when its line moves, a rotated credential is
  a new finding, and the credential itself is never stored. The key is made on
  first use and kept in the database, so it travels with a backup.
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
- The rate limiters hold at most 100,000 client buckets each. When that is
  full, clients without a bucket share one, so a flood of new addresses is
  throttled without evicting anyone already tracked.
- Every per-IP rate limit counts an IPv6 client by its /64 prefix instead of
  its full address, so rotating through addresses in one network no longer
  gives a fresh login budget each time. IPv4 stays per address, and an
  IPv4-mapped IPv6 address counts as the IPv4 address.
- Repeated failed password logins for one email now slow that account down,
  whichever address they come from. After three failures in a row the account
  waits 1 second, then 2, 4 and so on up to 60 seconds. Sign-in attempts during
  the wait get `429` with `Retry-After` and are not checked against the
  password. A successful sign-in resets the count, and it clears on its own
  after 15 minutes without a failure. There is no lockout, and unknown emails
  are counted the same way so the wait does not reveal which accounts exist.
- The per-account sign-in delay no longer shares one counter between emails
  when its table is full. Before, a flood of made-up emails could push every
  other account onto one shared counter and refuse real users' sign-ins with
  `429`. Now a new email takes the place of the stalest entry that has not
  started waiting yet, and if every entry is waiting the new email is only
  limited by the per-IP login bucket.
- Behind a trusted proxy, every `X-Forwarded-For` line is read, not just the
  first. A proxy that adds its own line (HAProxy `option forwardfor`) used to
  leave the client's line first, which let a client pick the address its rate
  limit bucket was keyed on. The client is now the rightmost entry that is not
  a trusted proxy, and `X-Real-IP` is used only when `X-Forwarded-For` gives no
  usable address.
- `PUT /api/v1/me/password` now slows wrong current passwords per account, the
  same way sign-in does, and both count together. Before, a stolen access token
  could guess the current password from many addresses. After three failures
  in a row the answer is `429` `too_many_attempts` with `Retry-After`, and the
  password is not checked during the wait. A correct current password resets
  the count.
- First-run setup stays available until a global admin exists. A stranger who
  registers before you no longer closes it. If the address you enter at setup
  already belongs to an account, setup answers 409 and you pick another one.
- `ADMIN_EMAILS` promotes only accounts that proved the address: the account
  first-run setup created, or one that signed in through SSO while the identity
  provider reported the email as verified. A password-registered account is
  never promoted, and neither is a deactivated one. If you relied on
  registering a listed address and restarting, create the admin with first-run
  setup, sign in with SSO, or run `specht grant-admin`. At startup the server
  logs one warning for each listed address whose account is not promoted.
- An API key whose stored scopes include anything other than `ingest` and
  `read` is refused with 401, like an unknown key. The API never mints an
  `admin` scope, and a key given one directly in the database used to pass the
  route check and then fail with 500 on most reads. Project management routes
  are for people with a role on the project, and every API key gets 403 there.
- Deactivating an account revokes every API key it created, in every project,
  and writes one audit line per key. Reactivating the account does not bring
  the keys back. A key whose creator is deactivated is also refused at
  authentication, with the answer an unknown key gets.
- Signing in through SSO for the first time into an account that already
  existed revokes every API key that account created before the link, in the
  same transaction as the link. Someone who registered the address first can
  no longer keep a key to the account the owner then takes over.
- A password reset link no longer works for an account that is deactivated or
  that has no local password because it signs in through SSO. The link answers
  the same "not valid" error an expired one gives. Before, such a link could
  still set a password on the account.
- Deactivating an account, setting its password again and clearing its password
  now end every password reset link the account had pending, in the same
  transaction. Before, a link issued earlier still worked after any of these,
  and reactivating a deactivated account brought it back. Issuing a link also
  waits for a deactivation in flight and then refuses the account.
- Linking an existing account to a first SSO sign-in now clears its password,
  ends its sessions and refresh tokens, retires its pending password reset
  links and revokes the API keys it created, all in one transaction with the
  link. Before, a failure between those steps could leave a linked account that
  still had the previous holder's password and refresh tokens, and an old reset
  link could give that holder a password again.
- Creating an API key now serialises with the deactivation of its creator. A
  key request that had passed sign-in just before the deactivation used to be
  able to commit after the deactivation revoked the account's keys, and that key
  worked again once the account was reactivated. The request now gets `403` when
  the creator is deactivated, and a key stored a moment earlier is revoked with
  the rest.
- Email addresses are now lower-cased for ASCII letters only, and an address
  with another character that has a different lower case (for example the Kelvin
  sign U+212A, which Go and some PostgreSQL locales fold to a plain `k`) is
  refused as an invalid address at registration, invites, member lookups and
  recovery commands, and matches no account at sign-in or SSO. Before, an
  identity provider that vouched for `Kate@corp` spelled with the Kelvin sign
  could link to the account `kate@corp`. An `ADMIN_EMAILS` entry written that
  way is skipped with a warning.
- A password reset link stops working when the account is deactivated, when its password
  changes, and when a single sign-on link removes the password. It is also refused for a
  deactivated account and for an account that signs in through single sign-on. A link a
  previous owner of the address kept can no longer set a password after the real owner
  signed in.
- Linking an existing password account to single sign-on now ends the previous owner's
  password, sessions, refresh tokens, reset links and API keys in one step, so a failure
  halfway cannot leave a linked account with the old credentials.
- Creating an API key checks that its creator is still active and holds the creator's row
  while it does, so a key created while the account is being deactivated no longer
  survives it.
- Email addresses are matched with ASCII case folding only. An address that contains a
  non-ASCII letter with a lower-case form (for example an upper-case accented letter or the
  Kelvin sign) is refused at registration and sign-in, because it could match a different
  account than the one shown. Type such an address in lower case.
- A sign-in now ends after an absolute lifetime, 30 days by default
  (`SESSION_MAX_AGE`, for example `720h`). Before, a client that kept
  refreshing renewed its session a week at a time forever, so a deactivated or
  stolen session never expired. A refresh after the limit answers `401`
  `refresh_failed`, like an expired token, and the user signs in again.
  Sessions that already exist get 30 days counted from their latest token.
- A refresh token is single-use, and reusing one only ends the sign-in it
  belongs to, not the user's other devices. Any second use of a rotated token,
  however soon after the first, answers `401` `refresh_reused` and revokes that
  sign-in's tokens, successor included. Logging out with a rotated token does
  the same. The web client keeps one refresh in flight at a time and shows a
  message on the sign-in page when the server ended its session this way. A
  script that refreshes the same token from two processes at once now loses
  its session and has to sign in again.
- A password change and the host `reset-password` command now end the
  account's refresh tokens in the same transaction that starts the new token
  generation, and a refresh locks the account row when it stores its
  successor. Before, a refresh that was in flight during the change could
  store a token that the change had already passed over, and that token kept
  the old session alive.
- Expired refresh tokens, and ones revoked more than 7 days ago, are now
  deleted. The `refresh_tokens` table used to grow by a row on every sign-in
  and every refresh, forever. The sweep runs at startup and then every
  `LIFECYCLE_SWEEP_INTERVAL`, and deletes at most 50,000 rows per run.
- The email address an SSO provider sends on a first login now has to pass the
  checks registration applies: at most 254 bytes, no control characters and a
  bare address. A claim that fails is refused with `403` and a message that
  names the provider's address, and no account is looked up or created.
- Email addresses are capped at 254 bytes and display names at 100 characters
  on registration, first-run setup, invite links, adding a member by email and
  the profile update. Before, only the 1 MiB request body limited them. A name
  over the cap is refused with `400` `invalid_display_name` on the profile
  update, and with the usual credential error on setup and invite acceptance.
- Audit lines for sign-in and registration now carry the masked email
  (`a***@example.com`) instead of the address as typed, on success and on
  failure. The audit logger also escapes control characters, such as a newline
  or an ANSI escape sequence, in the project, target, request id and error
  fields, and cuts those fields at 512 bytes, so a crafted value cannot forge a
  second event or repaint an operator's terminal.
- Outbound requests (the SSO provider, CVE detail providers, tracker and watcher webhooks)
  now also refuse addresses in 0.0.0.0/8, 6to4 (2002::/16), IPv4-compatible (::/96), Teredo
  (2001::/32), site-local (fec0::/10), 100::/64 and the ORCHID ranges. A hostname that
  resolved into one of them could reach an internal IPv4 host through a relay or a DNS64
  gateway.
- Outbound requests also refuse the SIIT IPv4-translated range (`::ffff:0:0:0/96`),
  6to4 relay anycast (192.88.99.0/24), 2001:2::/48, 3fff::/20 and 5f00::/16. A hostname that
  resolved into the SIIT range could reach an internal IPv4 host through a translator. The
  deploy guide now also says that behind a TLS proxy missing from `TRUSTED_PROXIES` the SSO
  sign-in cookie is sent without `Secure` and no HSTS header is set.
- With `SSO_ENABLE=true` the server now checks the SSO settings at startup and refuses to
  start, naming every problem, when the issuer, client id or redirect URI is missing, when
  the issuer or redirect URI is not an absolute `https` URL (`http` is accepted for a
  loopback host only), or when the client secret is empty. A public identity provider
  client can set `SSO_PUBLIC_CLIENT=true` to allow the empty secret. Before, an empty
  secret was accepted and silently switched PKCE off.
- The web app no longer accepts a session token from the URL fragment (`#sso_token=...`). The
  server stopped sending one when single sign-on moved to a one-time exchange code, but the
  page still installed any token it found there while an SSO sign-in was pending, so a crafted
  link could sign the visitor into the sender's account. Only the exchange code is read now.
- A single sign-in is now bound to the browser that started it. Before, the PKCE verifier
  and the OIDC nonce were computed from the `state` value that also appears in the callback
  URL, so anyone who obtained an unused callback URL (from a log, a browser extension or a
  shared device) could set a cookie of their own and finish the victim's login. Each login
  now gets a signed `sso_state_<id>` cookie with a random secret, the verifier and nonce are
  derived from that secret, and a callback without the matching cookie is refused before the
  code is sent to the identity provider. Several tabs can sign in at once, a browser keeps at
  most four pending logins, and a login cookie expires after 10 minutes. PKCE is now also sent
  when no client secret is configured, and the `redirect` return path is limited to 1024 bytes.
  The cookie is signed with a key derived from `JWT_SECRET`. Sign-ins in flight during the
  upgrade fail once and succeed on retry.
- Updating or deleting a waiver now writes an audit line with the person, the project and
  the waiver. Deleting a waiver keeps a copy of the waiver, its scope and its event history
  in an append-only record, so a change that lets findings through the gate cannot be erased.
- A waiver context written with the documented `environment_id`, `target_id` and
  `artifact_id` keys now keeps those ids. The server used to ignore them and store a context
  that named nothing, so the waiver covered only findings without an environment. A context
  that names no environment, target or artifact is now refused, and an old one stops matching
  instead of applying to every finding. A waiver with no environment in its contexts applies
  in every environment.
- A waiver scoped to one environment no longer covers a finding that another environment
  also reported. The gate used the environment of the newest scan, so a dev scan after a
  production scan of the same code let a dev waiver cover the production finding. The waiver
  now has to cover every environment that reported the finding.
- Creating or updating a waiver checks that every finding, environment, target and artifact
  it names belongs to the project. An id from another project used to be accepted and a
  missing id answered 500. Both now answer the same 404, and a malformed id answers 400.
- The pull-request check answered 500 for a `report_id` that does not exist but 403 for one
  that belongs to another project, which let a caller probe for report ids. Both now answer
  403 `project_access_denied`. A malformed `report_id` on the pull-request check and on the
  introduced-only gate answers 400 `invalid_id` instead of 500.
- With rate limiting on, an API key now has its own request budget. Before, all keys
  made by one person and that person's browser session shared one, so a busy CI key could
  lock out other projects' keys and the web UI.
- With rate limiting on, requests with an invalid or non-bearer `Authorization` header
  now count against the per-address limit and get `429` once it is used up. Before, any
  such header skipped the per-address limit, so made-up keys could be tried without limit.
- Report ingest now checks its metadata. `commit_sha` may hold at most 64 letters, digits,
  `.`, `_` and `-`. `branch` and `base_revision` may be at most 255 bytes, `environment` 64,
  and `owner`, `digest` and the `artifact_*` fields 255. `changed_files` may list at most
  5000 files of at most 1024 bytes each. A value over a limit, or one with a control
  character such as a newline, is refused with `400 invalid_field` that names the field.
- A failed ingest no longer leaves environment, target or artifact rows behind. Before, a
  report that failed after those rows were created kept them, and made-up names piled up in
  the environment list and the waiver pickers.
- An ingest no longer stops halfway when the client hangs up. The write phase now runs to
  its end, still bounded by the server's own time limit, and a report that fails is marked
  failed even if the request was cancelled. Before, a CI job that timed out left a report
  stuck in `processing` and findings with no occurrence that no later scan could close.
- The stale-report sweep now marks a report that has been `processing` for more than 10
  minutes (it was 15) as failed and removes the findings that report created and no
  occurrence supports. Findings it only brought back from archive, or that someone had
  already triaged, are archived instead.
- A signed-in user with no access to a project can no longer hold every ingest slot and make
  every tenant's CI get `503 ingest_busy`. Report ingest now reads only the start of the body
  (64 KiB) to find `project`, checks that the caller may ingest into it, and answers `403`
  before it reads or decodes the rest. Put `project` before `raw_data` in the JSON body: a
  body that names its project later is refused with `400 missing_field`. A body that repeats
  `project` with another value is refused with `400 invalid_field`.
- A slow upload no longer holds an ingest slot. The slot is taken only after the whole body
  has arrived, and the body has 30 seconds (`408 request_timeout` otherwise). One user or API
  key may use at most half of the ingest slots and half of the ingest memory budget at once;
  its further requests wait in their own queue and get `503 ingest_busy` with `Retry-After`,
  and other callers are not delayed.
- One project can no longer hold every ingest slot. The limit was per caller, so a project
  manager's session plus one API key (or two keys) could together fill all 8 slots and the
  whole memory budget, and another project's CI got `503 ingest_busy`. A project is now held
  to half of `INGEST_MAX_CONCURRENCY` (4 at the default, at least 1), whatever the number of
  callers behind it, and its ingests share an allowance of half of `INGEST_MEMORY_BUDGET`.
  The allowance does not lower one ingest's charge against the whole budget, so a single
  large report can still hold more than half of it. A single-project install
  runs at most 4 ingests at once at the default; raise `INGEST_MAX_CONCURRENCY` if its CI
  needs more.
- A password sign-in whose password check was still running when the account changed no
  longer gets a session. Signing in through SSO for the first time into an account
  (which clears its password), changing the password, and deactivating the account each
  used to be able to commit inside the check, and the sign-in then returned a working
  access token and a refresh token that the change never saw. The server now confirms
  under a row lock that the account is active, has the same password hash and the same
  token generation, and otherwise answers the same "invalid email or password" as a wrong
  password.
- Creating an API key now also checks the creator's token generation under the row lock.
  A key request that had passed sign-in just before the creator's first SSO sign-in
  used to commit after the link revoked the account's keys, and the key stayed live on
  the account the owner now holds. The request now gets `403`, the same answer as for a
  deactivated creator.
- Linking an existing account to a first SSO sign-in now locks the account row and checks
  again that it is not deactivated. A deactivation that committed between the check and
  the link used to leave a deactivated account with a proven email, and its SSO sign-in
  then received tokens. The link now answers the same "not provisioned" refusal as any
  other deactivated account and changes nothing.
- A deactivated account no longer counts as a project admin. The last admin who
  can sign in cannot leave or step down just because a deactivated admin still
  holds a row, and a deactivated admin can be removed from the roster.
  Deactivating an account that is the only active admin of a project now
  answers 409 `sole_project_admin` and lists the projects; send `{"force":
  true}` (or `specht users deactivate --force`) to go ahead.
- A person whose manager or admin rank on a project comes only from a linked
  team can no longer grant manager or admin through a member row, a team link
  or an invite. Before, they could write a direct admin row for themselves and
  keep admin after the team was unlinked. Granting member level is unchanged,
  and a direct manager or admin keeps their own role as the limit.
- A project manager can no longer undo an admin's promotion by changing or
  removing the same person at the same moment. The rule that a manager may not
  touch an admin is now checked on the person's role as it is when the change
  is saved, not on an earlier read.
- Updating or deleting a project, listing, linking and unlinking its teams, and
  setting its policy or policy overrides answered differently for a project that
  exists and one that does not, which let any signed-in account find out which
  project slugs exist. They now answer 403 `project_access_denied` in both
  cases (a global admin still gets 404 for a missing project). A missing slug
  no longer answers 400 or 500 on these routes.
- Behavior change: the team directory is limited to the teams a person belongs to
  and the teams linked to a project they can reach. `GET /api/v1/teams` no
  longer lists every team of the instance to anyone with one project, and a
  team outside that set answers 404 on `GET /api/v1/teams/{id}/members` and on
  adding or removing members, the same as a team that does not exist. Global
  admins still see every team. A project manager now links a team from the ones
  they can see; a global admin can link any team. See "Who sees which teams" in
  `deploy/README.md`.
- Changing a password, and resetting one from the server's recovery command, now write the
  new hash, start a new token generation and revoke the refresh tokens and pending reset
  links in one transaction under the account row lock. They used to revoke first and write
  second as separate statements, so a password sign-in that stored its session between the
  two kept a refresh token that the new password never ended. A password change also
  refuses to write if the account was linked to SSO (which clears its password) after the
  current password was checked, instead of giving the account a password again.
- A password change now stores the caller's own new session against the hash and token
  generation the change wrote, the way a password sign-in stores its session. An SSO link
  that committed right after the change used to leave that session alive under a
  generation the link never expected. The change now answers 409 `account_changed`, issues
  no session, and the caller signs in again.
