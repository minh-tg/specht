# Specht 🐦

Small, watchful vulnerability management platform. Ingest scan results from Trivy, OSV-Scanner, Semgrep, Checkov, and more into a single PostgreSQL-backed API. Gate CI/CD pipelines on findings with dimension-based filtering and waiver support.

## Quick Start

```bash
cp .env.example .env
docker compose -f deploy/docker-compose.yml up -d db
set -a
source .env
set +a
go run ./cmd/server
```

API starts at `http://localhost:8080`. Health check: `curl http://localhost:8080/api/v1/health`.

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

Run the test suite with `go test ./... -count=1 -short` (unit) or `go test -tags integration ./internal/repo/ -count=1` (needs Docker for testcontainers).

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0)

Contributions are accepted under the project's [Developer Certificate of Origin](CONTRIBUTING.md#contributor-license-agreement).
