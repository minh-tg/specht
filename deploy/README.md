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

## 3. Verify release images

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

## 4. First admin

Tenant isolation is enforced: every project needs members, and project
administration needs a global admin.

1. Register an account in the UI (or `POST /api/v1/auth/register`).
2. Add its email to `ADMIN_EMAILS` in `deploy/.env.prod` and restart
   (`up -d` again — promotion is idempotent).
3. Create projects and grant membership via `POST /projects/:slug/members`.

## 5. Reverse proxy

Terminate TLS at the proxy and forward plain HTTP. Set `TRUSTED_PROXIES` to
only the proxy-hop CIDRs. Configure the nearest proxy to append the observed
client address to `X-Forwarded-For` and overwrite `X-Real-IP` and
`X-Forwarded-Proto`; the server walks the forwarded chain from the right and
skips trusted proxy hops. Otherwise, forwarding headers are ignored and
`Secure` cookies follow the direct connection. Set `CORS_ORIGINS` to the
public UI origin(s).

## 6. Backup and restore

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

## 7. Upgrades

```bash
git pull
docker compose -f deploy/docker-compose.yml --env-file deploy/.env.prod up -d --build
```

Migrations are forward-only and run at startup. To roll back, restore a
compatible database backup and redeploy a compatible revision. Schema
migrations never migrate down automatically.

## 8. Hardening checklist

- `RATE_LIMIT_ENABLED=true` (compose default) — strict per-IP buckets on
  login/register, generous per-caller budgets behind auth.
- Request bodies are size-capped; ingest rejects oversized scans with 413.
- `LOG_LEVEL=info` (or `warn`); audit events go to structured logs.
- Keep the image updated; rebuilds pull a fresh Alpine + `go mod` pins.
- Watcher (`WATCHER_ENABLE`) and SSO stay off unless configured.
