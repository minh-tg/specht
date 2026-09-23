# Specht

[![ci](https://github.com/minh-tg/specht/actions/workflows/ci.yml/badge.svg)](https://github.com/minh-tg/specht/actions/workflows/ci.yml) [![CodeQL](https://github.com/minh-tg/specht/actions/workflows/codeql.yml/badge.svg)](https://github.com/minh-tg/specht/actions/workflows/codeql.yml) [![Go 1.26](https://img.shields.io/badge/Go-1.26.0-00ADD8?logo=go&logoColor=white)](go.mod) [![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

Specht is a vulnerability management platform. It takes scan output from Trivy,
OSV-Scanner, Semgrep, Checkov (and seven other parsers), puts everything in
Postgres, and gives you one place to triage findings, waive the noise, and fail
CI when the gate says so.

> This is a side project that's still changing quickly. Schemas, APIs, and
> config may change. It is not production-ready and should not be your only
> security control.

## What it does

- Normalizes SCA, SAST, IaC, secret and SBOM reports into a single finding
  model, built from 11 parsers: Trivy, OSV-Scanner, Grype, Semgrep, Checkov,
  tfsec, Gitleaks, Dependency-Check, Nuclei, SARIF, and CycloneDX/SPDX SBOMs.
- Tracks the whole lifecycle (new, fixed, reopened, triaged, waived), with
  package inventory, gate effects and remediation context attached.
- HTTP API plus a `specht` CLI, and `specht-adapter` for CI: exits non-zero
  when the gate is breached, prints annotations, publishes GitHub check runs.
  Drop-in pipeline templates for GitHub Actions and GitLab are in
  [`examples/ci/`](examples/ci/).
- Optionally watches the OSV feed for new CVEs against your inventory and pings
  Slack or a webhook.
- SSO, teams, org-wide policy baselines, waivers with conditions and expiry.

Parsers live in `internal/parser/`; the fixtures in
`internal/parser/*/testdata/` together with their tests are what "supported"
actually means.

## Quick start

You need Go 1.26 and Docker:

```bash
cp .env.example .env
docker compose -f deploy/docker-compose.yml up -d db
set -a
source .env
set +a
go run ./cmd/server
```

The API comes up on `http://localhost:8080`. Check it:

```bash
curl http://localhost:8080/api/v1/health
```

The quickstart serves a placeholder page at `/` until you run `make build`.
That builds and embeds the React frontend from `frontend/`. The UI is still
rough, and there is no dashboard yet, so the API and CLI are the useful
interfaces for now.

## Self-Hosting

[`deploy/README.md`](deploy/README.md) covers the supported Docker Compose
path: production environment, TLS, backups, upgrades, hardening.

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
examples/ci/     Ready-made GitHub Actions / GitLab CI pipelines
```

## Development

```bash
nix develop            # enter the dev shell (Go 1.26, sqlc, prek, frontend toolchain)
prek install           # commit hooks: format/lint/vet/secrets + conventional commits
```

After that every commit you make gets checked: gofumpt, staticcheck,
`go vet`, `go mod tidy`, dprint/oxlint (frontend), hadolint, gitleaks, and
conventional-commit validation. Useful commands:

```bash
go test ./... -count=1 -short                     # unit tests
go test -tags integration ./internal/repo/ -count=1   # integration, needs Docker
pnpm -C frontend test                             # frontend tests
pnpm -C frontend exec tsc -b
pnpm -C frontend exec dprint check
pnpm -C frontend lint
```

## How development works

- Touching scanner kinds, the normalized contract, database schemas, or gate
  policy means writing an RFC first and getting it accepted (see
  [`rfcs/`](rfcs/)). This adds a review step, but helps avoid breaking
  everyone's ingest.
- CI repeats the test/lint/frontend checks on every push
  ([ci.yml](.github/workflows/ci.yml)), CodeQL runs separately
  ([codeql.yml](.github/workflows/codeql.yml)), and Dependabot opens dependency
  PRs with a cooldown window
  ([dependabot.yml](.github/workflows/dependabot.yml)).
- Around 1,400 Go tests (unit plus testcontainers-backed integration) and a
  frontend suite. We expect tests for code changes.
- Contributions follow the
  [Developer Certificate of Origin](CONTRIBUTING.md#developer-certificate-of-origin).
- Push a `v*` tag and [release.yml](.github/workflows/release.yml) builds and
  publishes a versioned container image.

## Project Status

No releases or tags exist yet. Once they do, the release workflow above
starts publishing images. The API works, but the web UI is unfinished and
there is no dashboard yet. Expect breaking changes. Bug reports and playtest feedback are welcome via
[GitHub issues](https://github.com/minh-tg/specht/issues); security reports
should follow [SECURITY.md](SECURITY.md).

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).
