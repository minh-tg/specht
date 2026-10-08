# Self-hosting Specht with Docker Compose

Specht is an early preview and is not production-ready. Docker Compose
(`deploy/docker-compose.yml`) is the documented single-node self-hosting path
for evaluation: Postgres 17 + the Specht server. Migrations run automatically
at startup (`DB_MIGRATE=true`). The web UI is unfinished; use the API and CLI
for now. No Helm deployment or standalone binary package is currently
provided.

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
docker compose -f deploy/docker-compose.yml --env-file deploy/.env.prod up -d --build
curl -fsS http://localhost:8080/api/v1/health
curl -fsS http://localhost:8080/api/v1/version
```

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
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma/space-separated UI origins allowed to call the API. |
| `ADMIN_EMAILS` | *(empty)* | Comma-separated emails promoted to global admin at startup. Idempotent; unknown addresses are skipped with a warning. Matching ignores case. |
| `REGISTRATION_ENABLED` | `true` | Allow self-service `POST /api/v1/auth/register`. Open by default because the first administrator has to register before anyone can be promoted. Set `false` once your admins exist (and always for SSO-only deployments); the endpoint then answers `403 registration_disabled`. Anything other than a boolean fails startup. |
| `TRUSTED_PROXIES` | *(empty)* | Comma/space-separated CIDRs of proxy hops allowed to set `X-Forwarded-For` / `X-Real-IP` / `X-Forwarded-Proto`. Empty trusts nobody. |
| `INVENTORY_TTL` | `2160h` | How long a scanned package stays in the watcher's active inventory. |
| `LIFECYCLE_SWEEP_INTERVAL` | `5m` | Period of the analysis-expiry and waiver-expiry sweeps; must be a positive duration. |

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
| `SPECHT_PROJECT` | *(empty)* | Adapter only: project slug, overriding the one in the report. |

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

Tenant isolation is enforced: every project needs members, and project
administration needs a global admin.

1. Register an account in the UI (or `POST /api/v1/auth/register`).
2. Add its email to `ADMIN_EMAILS` in `deploy/.env.prod` and restart
   (`up -d` again — promotion is idempotent).
3. Create projects and grant membership via `POST /projects/:slug/members`.

## 6. Reverse proxy

Terminate TLS at the proxy and forward plain HTTP. Set `TRUSTED_PROXIES` to
only the proxy-hop CIDRs. Configure the nearest proxy to append the observed
client address to `X-Forwarded-For` and overwrite `X-Real-IP` and
`X-Forwarded-Proto`; the server walks the forwarded chain from the right and
skips trusted proxy hops. Otherwise, forwarding headers are ignored and
`Secure` cookies follow the direct connection. Set `CORS_ORIGINS` to the
public UI origin(s).

## SSO ID-token requirement

The SSO authorization-code callback requires a signed ID token by default and
verifies its signature and claims before accepting identity. For an IdP that
cannot return an ID token, `SSO_ALLOW_USERINFO_ONLY=true` explicitly enables
an insecure compatibility downgrade: identity then comes from the UserInfo
endpoint without a signed subject to verify. Prefer configuring the IdP to
return ID tokens; enable this only after assessing the reduced assurance.
This option never bypasses validation when an ID token is present.

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

Existing SSO users have no link yet; their next login creates it, which needs
the verified email above. If your provider never sends `email_verified` (Azure
AD v2 does not by default) and its emails are controlled by your
administrators, set `SSO_ALLOW_UNVERIFIED_EMAIL=true` for that first login. The
server logs a warning at startup while it is on.

## 7. Backup and restore

Postgres holds everything (the server is stateless). Nightly logical backup:

```bash
docker compose -f deploy/docker-compose.yml exec db \
  pg_dump -U specht specht | gzip > specht-$(date +%F).sql.gz
```

Restore into a fresh stack:

```bash
gunzip -c specht-YYYY-MM-DD.sql.gz | docker compose -f deploy/docker-compose.yml exec -T db \
  psql -U specht specht
```

## 8. Upgrades

```bash
git pull
docker compose -f deploy/docker-compose.yml --env-file deploy/.env.prod up -d --build
```

Migrations are forward-only and run at startup. To roll back, restore a
compatible database backup and redeploy a compatible revision. Schema
migrations never migrate down automatically.

## 9. Hardening checklist

- `RATE_LIMIT_ENABLED=true` (compose default) — strict per-IP buckets on
  unauthenticated routes, generous per-caller budgets behind auth. Login and
  register always get their own 5-per-minute per-IP bucket.
- Request bodies are size-capped; ingest rejects oversized scans with 413.
- `LOG_LEVEL=info` (or `warn`); audit events go to structured logs.
- Keep the image updated; rebuilds pull a fresh Alpine + `go mod` pins.
- Watcher (`WATCHER_ENABLE`) and SSO stay off unless configured.
