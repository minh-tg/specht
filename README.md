# Specht 🐦

Small, watchful vulnerability management platform. Ingest scan results from Trivy, OSV-Scanner, Semgrep, Checkov, and more into a single PostgreSQL-backed API. Gate CI/CD pipelines on findings with dimension-based filtering and waiver support.

## Quick Start

```bash
cp .env.example .env
go run ./cmd/server
```

API starts at `http://localhost:8080`. Health check: `curl http://localhost:8080/api/v1/health`.

## Documentation

See [docs/](docs/) for architecture, data model, API reference, roadmap, and development guide.

## Project Layout

```
cmd/specht/      API server
cmd/adapter/     CI/CD gate-check CLI (specht-adapter)
internal/        Go packages (handlers, usecases, repos, auth, scanners)
frontend/        React SPA (Vite, shadcn/ui)
migrations/      SQL migrations (golang-migrate)
sqlc/            Type-safe SQL queries
deploy/          Docker Compose + Helm chart
```

## License

MIT
