# Self-hosting Specht with Docker Compose

Specht is an early preview and is not production-ready. Docker Compose
(`deploy/docker-compose.yml`) is the documented single-node self-hosting path
for evaluation: Postgres 17 + the Specht server. Migrations run automatically
at startup (`DB_MIGRATE=true`). The `specht` and `specht-adapter` binaries are
attached to each GitHub Release. No Helm deployment is provided.

## 1. Secrets

```bash
cp deploy/.env.prod.example deploy/.env.prod
# Fill in POSTGRES_PASSWORD and JWT_SECRET (min 32 random bytes):
head -c 48 /dev/urandom | base64
```

`deploy/.env.prod` must never be committed. The server refuses to start with
a missing or short `JWT_SECRET`; Postgres refuses an empty password — both
fail fast instead of running insecure.

For production, add `POSTGRES_SSLMODE=require` (or `verify-full` when the
Postgres certificate and hostname are configured) to `deploy/.env.prod`. The
Compose file's `disable` fallback is intentionally for its localhost-bound
development database only; never use that fallback for a remote database.
Keep `DB_MIGRATE=true` for the simple deployment path, or set it to `false`
and run `specht migrate` as a separately controlled release step.

## 2. Start

```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env.prod up -d
curl -fsS http://localhost:8080/api/v1/health   # liveness: the process is up
curl -fsS http://localhost:8080/api/v1/ready    # readiness: the database answers
curl -fsS http://localhost:8080/api/v1/version
```

The server service pulls `ghcr.io/minh-tg/specht:${SPECHT_VERSION}` (default
`latest`). Set `SPECHT_VERSION` in `deploy/.env.prod` to a release tag such as
`v0.1.0` so a restart never moves you to a new build. The GHCR package is
private after its first push: open the package settings on GitHub and change
its visibility to public once, or hosts cannot pull it without a login.

### Build from source

The override file replaces the pulled image with a local build from the
repository root. Run it from the checkout:

```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.build.yml \
  --env-file deploy/.env.prod up -d --build
```

Without the override file, compose only pulls the image and never builds it.
Until the first release is published there is no image to pull, so use the
override for a first start.

## 3. Configuration reference

The server reads its settings from the environment. Compose forwards every
variable below from `deploy/.env.prod`; for a bare-metal run, export them or
use your service manager. Defaults are the server's own, except where the
compose defaults differ, which is noted.

### Core

| Variable | Default | Purpose |
|----------|---------|---------|
| `SERVER_ADDR` | `:8080` | HTTP listen address. |
| `DATABASE_URL` | *required* | Postgres DSN. Append `?sslmode=require` or `verify-full` for a remote database. |
| `JWT_SECRET` | *required* | HMAC signing key, at least 32 random bytes. Startup fails without it. |
| `DB_MIGRATE` | `true` | Run migrations at startup. Set `false` to run `specht migrate` as a separately controlled step. |
| `DB_CONNECT_TIMEOUT` | `30s` | How long startup waits for Postgres to answer, retrying with a growing delay, before the server exits. `0s` tries once. A rejected login fails at once. |
| `DB_MAX_CONNS` | `20` | The most database connections the server opens. Keep it below Postgres `max_connections` (100 by default), which every client of that database shares. |
| `DB_MIN_CONNS` | `2` | Connections kept open when idle. Capped at `DB_MAX_CONNS`. |
| `SHUTDOWN_TIMEOUT` | `150s` | How long a stop (SIGTERM) waits for in-flight requests before closing. Longer than the two minutes an ingest may run. If you run the container yourself, give it a stop grace period above this value; the Compose file sets 165s. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |
| `CORS_ORIGINS` | *(empty)* | Comma/space-separated origins allowed to call the API from a browser. Empty allows none: the bundled UI is same-origin and needs no entry. Set it only when the UI is hosted elsewhere (use exact `https://` origins). |
| `ADMIN_EMAILS` | *(empty)* | Comma-separated emails promoted to global admin at startup. Idempotent; unknown addresses are skipped with a warning. Matching ignores case. While `REGISTRATION_ENABLED` is on, an address not yet registered can be claimed by anyone before promotion; keep signup closed during admin bootstrapping or create accounts only after restricting registration. |
| `SETUP_TOKEN` | *(random)* | Proof of access for first-run setup. While the database has no accounts the server logs a random token at startup (`setup_token=...`); set this variable to choose it instead (at least 16 characters, never logged). Ignored once an account exists. |
| `REGISTRATION_ENABLED` | `false` | Allow self-service `POST /api/v1/auth/register`. Unset or empty is closed; set `true` only when open signup is intended. The endpoint answers `403 registration_disabled` while closed. First-run setup and invite links keep working, and invalid values fail startup. |
| `TRUSTED_PROXIES` | *(empty)* | Comma/space-separated CIDRs of proxy hops allowed to set `X-Forwarded-For` / `X-Real-IP` / `X-Forwarded-Proto`. Empty trusts nobody. |
| `INVENTORY_TTL` | `2160h` | How long a scanned package stays in the watcher's active inventory. |
| `INGEST_MAX_CONCURRENCY` | `8` | Report ingests processed at once. Each parse holds several times the request body in memory (bodies are capped at 25 MiB), so this bounds the worst case. Further ingests wait up to 15 s for a slot and then get `503 ingest_busy` with `Retry-After`. An ingest may take up to two minutes, upload included. Must be a positive integer. |
| `LIFECYCLE_SWEEP_INTERVAL` | `5m` | Period of the analysis-expiry and waiver-expiry sweeps; must be a positive duration. |

Registration does not verify email addresses: an account holds whatever address
its creator typed, so keep `REGISTRATION_ENABLED` closed unless you accept that.

### Rate limiting

| Variable | Default | Purpose |
|----------|---------|---------|
| `RATE_LIMIT_ENABLED` | `false` (`true` in compose) | Token-bucket limiting on public and authenticated routes. |
| `RATE_LIMIT_RPS` | `10` | Per-IP rate for unauthenticated entry points. |
| `RATE_LIMIT_BURST` | `20` | Burst for the unauthenticated bucket. |
| `RATE_LIMIT_AUTH_RPS` | `1000` | Per-caller rate behind authentication. |
| `RATE_LIMIT_AUTH_BURST` | `2000` | Burst for the authenticated bucket. |
| `RATE_LIMIT_LOGIN_PER_MINUTE` | `5` | Per-IP refill rate for login and register, the endpoints that accept guessable credentials. |
| `RATE_LIMIT_LOGIN_BURST` | `5` | Burst for that bucket: attempts allowed before the per-minute refill applies. |

The login and register bucket applies even when `RATE_LIMIT_ENABLED` is
`false`, and a request cannot opt out of it by sending an `Authorization`
header. Token refresh and logout are not charged to it. Behind a reverse proxy,
set `TRUSTED_PROXIES` so each client is counted by its own address instead of
the proxy's; otherwise every user shares one bucket.

### SSO / OIDC

Off unless `SSO_ENABLE=true`, which then requires the client credentials,
issuer, and redirect URI.

| Variable | Default | Purpose |
|----------|---------|---------|
| `SSO_ENABLE` | `false` | Mounts the SSO login and callback routes. |
| `SSO_CLIENT_ID` | *(empty)* | OAuth client id. |
| `SSO_CLIENT_SECRET` | *(empty)* | **Secret.** OAuth client secret. |
| `SSO_ISSUER_URL` | *(empty)* | Must be `https`; plain `http` is accepted only for a loopback host, for a local IdP. |
| `SSO_REDIRECT_URI` | *(empty)* | Must match the IdP's registered redirect URI. |
| `SSO_GROUPS_CLAIM` | `groups` | Claim carrying IdP group membership. |
| `SSO_ALLOWED_DOMAINS` | *(empty)* | Comma/space-separated email domains that may auto-provision. Empty refuses every unknown subject. |
| `SSO_ADMIN_GROUPS` | *(empty)* | IdP groups granting admin to a *newly provisioned* account. Existing accounts never change role from IdP groups. |
| `SSO_ALLOW_USERINFO_ONLY` | `false` | Insecure compatibility downgrade for an IdP that returns no ID token. |
| `SSO_ALLOW_UNVERIFIED_EMAIL` | `false` | Let a first SSO login link or provision by an email the IdP did not mark `email_verified`. Only for IdPs that never send the claim and whose emails administrators control. See "SSO account linking". |

### CVE feed watcher

| Variable | Default | Purpose |
|----------|---------|---------|
| `WATCHER_ENABLE` | `false` | Runs the OSV poll loop. |
| `WATCHER_POLL_INTERVAL` | `6h` | Time between polls. |
| `WATCHER_OSV_ENDPOINT` | `https://api.osv.dev/v1/querybatch` | Batch query endpoint. |
| `WATCHER_OSV_VULN_ENDPOINT` | `https://api.osv.dev/v1/vulns/{id}` | Full-advisory template; `{id}` is substituted. Keep it inside the same trust boundary as the batch endpoint. |
| `WATCHER_BATCH_SIZE` | `0` (unlimited; compose sets `100`) | Identifiers per batch. |
| `WATCHER_COLD_START_WINDOW` | `full` | `full` for full-history cold start, or a Go duration to backfill since. |
| `WATCHER_SLACK_URL` | *(empty)* | Slack webhook for new advisories. Empty disables the channel. |
| `WATCHER_SLACK_SIGNING_SECRET` | *(empty)* | **Secret.** Signs Slack deliveries. |
| `WATCHER_WEBHOOK_URL` | *(empty)* | Generic webhook for new advisories. |
| `WATCHER_WEBHOOK_SIGNING_SECRET` | *(empty)* | **Secret.** Signs both this webhook and tracker deliveries. |

### Tracker dispatch

Finding lifecycle events (created, verified fixed, regression) can be pushed to
an external issue tracker. Disabled by default.

| Variable | Default | Purpose |
|----------|---------|---------|
| `TRACKER_PROVIDER` | `noop` | `noop`, `inprocess`, or `webhook`. |
| `TRACKER_BASE_URL` | *(empty)* | Tracker API base URL. |
| `TRACKER_PROJECT_ID` | *(empty)* | Destination project. |
| `TRACKER_API_TOKEN` | *(empty)* | **Secret.** Tracker API token. |
| `WATCHER_WEBHOOK_URLS` | *(empty)* | Comma-separated endpoints fanned out to when `TRACKER_PROVIDER=webhook`. |

### Threat intel

| Variable | Default | Purpose |
|----------|---------|---------|
| `INTEL_TTL` | `1h` | Cache lifetime for both feeds. A feed outage serves the last record, flagged stale. |
| `INTEL_EPSS_ENDPOINT` | `https://api.first.org/data/v1/epss` | EPSS feed. |
| `INTEL_KEV_ENDPOINT` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | CISA KEV catalog. |

### Client (adapter and CLI)

Read by `specht-adapter` and `specht`, not by the server.

| Variable | Default | Purpose |
|----------|---------|---------|
| `API_URL` | `http://localhost:8080` | Specht base URL. |
| `API_KEY` | *required* | A project API key, or a session token for admin operations. |
| `SPECHT_PROJECT` | *(empty)* | Adapter only: project slug, used when the report and `-project` give none. |
| `SPECHT_API_URL`, `SPECHT_API_KEY` | *(empty)* | Aliases for `API_URL` and `API_KEY`, for runners where those names collide with other tools. |
| `SPECHT_OWNER` | *(derived)* | Adapter only: repository owner recorded on the report. Defaults to the owner of `GITHUB_REPOSITORY` or `CI_PROJECT_PATH`. |
| `SPECHT_ENVIRONMENT` | *(empty)* | Adapter only: deployment environment (for example `production`) recorded on the report. |

The adapter also reads the CI provider's own variables when its flags are not
set: `GITHUB_REPOSITORY`, `GITHUB_SHA`, `GITHUB_REF_NAME`, `GITHUB_BASE_REF`,
`GITHUB_STEP_SUMMARY`, `GITHUB_EVENT_NAME` and `GITHUB_EVENT_PATH` on GitHub
Actions, and `CI_PROJECT_PATH`, `CI_COMMIT_SHA`, `CI_COMMIT_REF_NAME` and
`CI_MERGE_REQUEST_TARGET_BRANCH_NAME` on GitLab CI. A pull request from a fork
has no secrets, so with an empty API key the adapter logs a notice and exits 0.

### Compose-only

| Variable | Default | Purpose |
|----------|---------|---------|
| `POSTGRES_PASSWORD` | *required* | Postgres password. |
| `POSTGRES_SSLMODE` | `disable` | Appended to the generated `DATABASE_URL`. |
| `SERVER_PORT` | `8080` | Host port published for the server. |

See `.env.example` for a commented starting point.

## 4. Verify release images

Published images are signed with keyless Sigstore signing from the tagged
release workflow. Install `cosign`, then verify an image before deployment:

```bash
IMAGE=ghcr.io/minh-tg/specht:v0.1.0
cosign verify \
  --certificate-identity-regexp 'https://github.com/minh-tg/specht/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$IMAGE"
```

The command verifies the certificate issuer and that the signing workflow ran
from this repository's release tag; replace the image with the exact version
you intend to deploy.

## 5. First admin

Self-service registration is closed by default. Use first-run setup to create
an administrator; setup remains available while registration is closed.
Tenant isolation is enforced: every project needs members, and project
administration needs a global admin.

1. On the first start, read the setup token from the server log
   (`docker compose logs server | grep setup_token`), open the app and create
   the first administrator with it. Or set `SETUP_TOKEN` in `deploy/.env.prod`
   and use that value. Setup closes as soon as the account exists.
2. To promote more accounts, add their emails to `ADMIN_EMAILS` in
   `deploy/.env.prod` and restart (`up -d` again — promotion is idempotent).
3. Create projects in the UI, then add members from the project's Access page
   (or `POST /projects/:slug/members`).
4. Bring teammates in with invite links (Access page, or
   `POST /projects/:slug/invites`; valid 1 to 30 days, single use). The link
   works while `REGISTRATION_ENABLED` is `false`, so registration can stay
   closed.

### Recovering access

If the only administrator has forgotten a password, or an account has to be
promoted while no admin can sign in, run one of these inside the server
container. They act on the database directly, so access to the host is the
credential:

```bash
docker compose -f deploy/docker-compose.yml exec server specht reset-password ada@example.com
docker compose -f deploy/docker-compose.yml exec server specht grant-admin ada@example.com
```

`reset-password` prints a generated 24-character password once and ends every
session of the account. Add `--password-stdin` to set a password you chose
instead; it is read from standard input and never printed. A deactivated
account stays deactivated, and the command says so. `grant-admin` makes the
account a global admin; a session the person already has picks the role up at
the next sign-in. Neither command touches the seeded `system@specht.local`
account. Anyone signed in can change their own password, and the name others
see, on the Profile page (the API is `PUT /api/v1/me/password`).

### Changing or deactivating an account

Global admins manage accounts from the admin area or the API:

- `PUT /api/v1/users/{id}/role` changes the global role. The account's token
  generation advances, so its open sessions stop working and the person signs
  in again to get the new role.
- `POST /api/v1/users/{id}/deactivate` ends access without deleting history or
  memberships: open sessions stop at their next request, refresh tokens are
  revoked, and sign-in is refused until `POST /api/v1/users/{id}/reactivate`.

The last active admin, the signed-in admin themselves (for deactivation) and
the seeded `system@specht.local` account cannot be demoted or deactivated;
those requests answer 409. Specht has no endpoint that deletes an account.
Removing someone from a project or a team takes effect on their next request.

## 6. Reverse proxy

Terminate TLS at the proxy and forward plain HTTP. Set `TRUSTED_PROXIES` to
only the proxy-hop CIDRs. Configure the nearest proxy to append the observed
client address to `X-Forwarded-For` and overwrite `X-Real-IP` and
`X-Forwarded-Proto`; the server walks the forwarded chain from the right and
skips trusted proxy hops. Otherwise, forwarding headers are ignored and
`Secure` cookies follow the direct connection. `CORS_ORIGINS` stays empty
unless the UI is served from a different origin than the API.

## SSO ID-token requirement

The SSO authorization-code callback requires a signed ID token by default and
verifies its signature and claims before accepting identity. For an IdP that
cannot return an ID token, `SSO_ALLOW_USERINFO_ONLY=true` explicitly enables
an insecure compatibility downgrade: identity then comes from the UserInfo
endpoint without a signed subject to verify. Prefer configuring the IdP to
return ID tokens; enable this only after assessing the reduced assurance.
This option never bypasses validation when an ID token is present.

## SSO login protections

Each SSO login sends the provider a state, an OIDC `nonce`, and (when
`SSO_CLIENT_SECRET` is set) a PKCE `code_challenge` (S256). The callback
rejects a state that carries no nonce and an ID token whose nonce does not
match, and the token request proves possession of the PKCE verifier. The
verifier is derived from the state and the client secret, so nothing extra is
stored and any replica can complete a login another one started. Providers
that do not support PKCE ignore the extra parameters. Logins that were
already in flight when you upgrade fail once and succeed on retry.

After a successful login the SPA receives a single-use code in the URL
fragment, valid for 60 seconds, and trades it for an access and a refresh token
at `POST /api/v1/auth/sso/exchange`. The fragment is never sent to the server
or in a `Referer` header, and a replayed or expired code answers 401.

## SSO account linking

An SSO login is matched to an account by the provider's stable identity, the
pair of issuer and subject (`sub`), which is stored in `user_identities` after
the first login. Later logins use only that pair, so a changed or unverified
`email` claim cannot redirect them to a different account.

The first login of a new subject needs a verified email: the ID token or
UserInfo response must carry `email_verified: true`. That email then either
links the existing account with the same address or, when its domain is in
`SSO_ALLOWED_DOMAINS`, provisions a new one. An account that is already linked
to a different subject at the same provider is never re-linked by email.

Linking an existing account removes its password and revokes all of its
refresh tokens, because whoever registered that address first may not be the
person the provider vouches for. The user signs in through the provider from
then on. Accounts created by SSO never had a password.

Existing SSO users have no link yet; their next login creates it, which needs
the verified email above. If your provider never sends `email_verified` (Azure
AD v2 does not by default) and its emails are controlled by your
administrators, set `SSO_ALLOW_UNVERIFIED_EMAIL=true` for that first login. The
server logs a warning at startup while it is on.

## 7. Backup and restore

Postgres holds all state; the server keeps nothing on disk. Dump in custom
format (`-Fc`): `pg_restore` can read it selectively and restores faster than
plain SQL. The `-T` flag turns off the TTY so the redirect gets clean binary:

```bash
docker compose -f deploy/docker-compose.yml exec -T db \
  pg_dump -U specht -Fc specht > specht-$(date +%F).dump
```

A nightly cron entry that keeps 14 days of dumps. In a crontab, `%` must be
escaped as `\%`. Create the directory first with `mkdir -p /var/backups/specht`.

```cron
30 2 * * * cd /opt/specht && docker compose -f deploy/docker-compose.yml exec -T db pg_dump -U specht -Fc specht > /var/backups/specht/specht-$(date +\%F).dump && find /var/backups/specht -name 'specht-*.dump' -mtime +14 -delete
```

A dump on the same disk as the database protects against a bad migration or
a deleted row, not against losing the host. Copy each dump off the host in the
same job (for example `rsync` to another machine or `aws s3 cp` to a bucket),
and check that the copy arrived.

### Restore into an empty database

Restore with migrations off, so the server cannot touch the schema while the
dump loads. Set `DB_MIGRATE=false` in `deploy/.env.prod`, then start only the
database:

```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env.prod up -d db
docker compose -f deploy/docker-compose.yml cp specht-YYYY-MM-DD.dump db:/tmp/specht.dump
docker compose -f deploy/docker-compose.yml exec db \
  pg_restore -U specht -d specht --no-owner /tmp/specht.dump
docker compose -f deploy/docker-compose.yml exec db rm /tmp/specht.dump
```

Read the `pg_restore` output for errors before you continue. Then remove
`DB_MIGRATE=false` (or set it back to `true`) and start the server normally.
Any migrations newer than the dump run at that start:

```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env.prod up -d
curl -fsS http://localhost:8080/api/v1/ready
```

## 8. Upgrades

Migrations are forward-only and run when the server starts. A rollback
therefore depends on a backup taken before the upgrade, so take one first
(section 7).

1. Set `SPECHT_VERSION` in `deploy/.env.prod` to the new tag.
2. Pull the new image and recreate the server:

   ```bash
   docker compose -f deploy/docker-compose.yml --env-file deploy/.env.prod pull server
   docker compose -f deploy/docker-compose.yml --env-file deploy/.env.prod up -d
   curl -fsS http://localhost:8080/api/v1/ready
   ```

   Pending migrations run before the new server takes traffic. Check
   `docker compose -f deploy/docker-compose.yml logs server` if `ready` does
   not answer 200.

   From a source checkout, add the override and `--build` instead of `pull`:
   `docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.build.yml --env-file deploy/.env.prod up -d --build`.

### Rolling back

An older server cannot read a schema that a newer migration changed, so a
rollback restores the pre-upgrade dump:

1. Stop the server and drop the database: `docker compose -f deploy/docker-compose.yml stop server`, then
   `docker compose -f deploy/docker-compose.yml exec db dropdb -U specht specht`
   and `... exec db createdb -U specht specht`.
2. Set `SPECHT_VERSION` back to the previous tag.
3. Follow the restore steps above with the pre-upgrade dump, then start the
   previous version.

## 9. Hardening checklist

- `RATE_LIMIT_ENABLED=true` (compose default) — strict per-IP buckets on
  unauthenticated routes, generous per-caller budgets behind auth. Login and
  register always get their own 5-per-minute per-IP bucket.
- Request bodies are size-capped; ingest rejects oversized scans with 413.
- `GET /api/v1/ready` answers 200 while the database is reachable and 503
  when it is not, with no detail in the body. The image's HEALTHCHECK uses it,
  and so should a load balancer or uptime monitor. `GET /api/v1/health` only
  says the process is up. Both are public, and readiness reuses its answer for
  one second so probing it cannot load the database.
- `LOG_LEVEL=info` (or `warn`); audit events go to structured logs. Every
  response carries an `X-Request-Id` header, and the access log line and any
  audit line for that request carry the same `request_id`, so a report that
  quotes the header leads straight to the log. The access log names the route
  pattern (`/api/v1/invites/{token}`), never the raw path or query, so tokens
  stay out of it; the health and readiness probes log at `debug`.
- Keep the image updated; rebuilds pull a fresh Alpine + `go mod` pins.
- Watcher (`WATCHER_ENABLE`) and SSO stay off unless configured.
- Database TLS: the compose default `POSTGRES_SSLMODE=disable` is for a
  database on the same host. For anything else set `require` or `verify-full`;
  at startup the server logs a warning when `DATABASE_URL` reaches a non-local
  host with `sslmode` of `disable`, `allow`, `prefer`, or unset.
