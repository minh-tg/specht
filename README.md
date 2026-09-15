# Specht

Specht is a small, watchful vulnerability management platform. It ingests scan results from Trivy, OSV-Scanner, Semgrep, Checkov, and other tools into a PostgreSQL-backed API. CI/CD pipelines can gate on findings with dimension-based filtering and waiver support.

> **Experimental / playtest project:** Specht is under active development and heavy change. APIs, database schemas, configuration, scanner normalization, and deployment behavior may change without notice. It is not production-ready and should not be used as the sole basis for critical security decisions.

## What It Does

- Normalizes SCA, SAST, IaC, secret, vulnerability, and SBOM reports.
- Maintains finding lifecycle, package inventory, triage, waivers, and remediation context.
- Exposes an HTTP API and embedded React UI backed by PostgreSQL.
- Provides CI/CD adapter commands for gate checks and report ingestion.
- Supports optional OSV feed watching, Slack notifications, SSO, and issue-tracker dispatch.

Supported input formats are implemented under `internal/parser/`; committed examples and parser tests are the compatibility reference while the project is experimental.

## Quick Start

```bash
cp .env.example .env
docker compose -f deploy/docker-compose.yml up -d db
set -a
source .env
set +a
go run ./cmd/server
```

The API starts at `http://localhost:8080`. Health check:

```bash
curl http://localhost:8080/api/v1/health
```

## Self-Hosting

The supported single-node Docker Compose path, production environment guidance,
TLS, backups, upgrades, and hardening notes are documented in
[deploy/README.md](deploy/README.md).

## Project Layout

```
cmd/server/      API server (chi router, embedded SPA, watcher daemon)
cmd/specht/      CLI client (specht)
cmd/adapter/     CI/CD gate-check CLI (specht-adapter)
cmd/mcp/         MCP bridge
internal/        Go packages (handlers, usecases, repos, auth, scanners)
frontend/        React SPA (Vite, shadcn/ui)
migrations/      SQL migrations (golang-migrate)
sqlc/            Type-safe SQL queries
deploy/          Docker Compose + Helm chart
```

## Development

```bash
nix develop            # enter the dev shell (Go 1.26, sqlc, prek, frontend toolchain)
prek install           # enable commit hooks: format/lint/vet/secrets + conventional commits
```

Commits are checked automatically once hooks are installed: gofumpt, staticcheck, `go vet`, `go mod tidy`, dprint/oxlint (frontend), hadolint, gitleaks, and conventional-commit message validation.

Run the test suite with `go test ./... -count=1 -short` (unit) or `go test -tags integration ./internal/repo/ -count=1` (needs Docker for testcontainers). Frontend checks run with `pnpm -C frontend test`, `pnpm -C frontend exec tsc -b`, `pnpm -C frontend exec dprint check`, and `pnpm -C frontend lint`.

Changes that add scanner kinds, alter normalized contracts, change database schemas, or change gate policy require an accepted RFC under `rfcs/`.

## Project Status

There is no stable release or compatibility promise yet. Expect incomplete features, breaking changes, migration churn, and rough edges. Feedback and playtest reports are welcome through GitHub issues; security reports should follow [SECURITY.md](SECURITY.md).

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0)

Contributions follow the [Developer Certificate of Origin](CONTRIBUTING.md#developer-certificate-of-origin).
