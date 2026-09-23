# Specht

[![ci](https://github.com/minh-tg/specht/actions/workflows/ci.yml/badge.svg)](https://github.com/minh-tg/specht/actions/workflows/ci.yml) [![CodeQL](https://github.com/minh-tg/specht/actions/workflows/codeql.yml/badge.svg)](https://github.com/minh-tg/specht/actions/workflows/codeql.yml) [![Go 1.26](https://img.shields.io/badge/Go-1.26.0-00ADD8?logo=go&logoColor=white)](go.mod) [![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

Specht collects reports from security scanners in one place. It tracks findings
across scans and lets teams apply project rules in CI, so they can see what
changed and decide whether a change should pass.

> This side project is changing quickly. APIs, database schemas, and settings
> may change. It is not production-ready and should not be your only security
> control.

## What it does

- Tracks findings as they appear, are fixed, return, or are waived. It keeps
  package inventory and remediation details with them.
- Provides an HTTP API, a `specht` CLI, and `specht-adapter` for CI. The adapter
  can fail a build when policy blocks a change, print annotations, and publish
  GitHub check runs. Pipeline examples for GitHub Actions and GitLab are in
  [`examples/ci/`](examples/ci/).
- Can check tracked packages against OSV for newly published advisories and
  send notifications to Slack or a webhook.
- Supports single sign-on, teams, shared organization policies, and waivers
  with conditions and expiry dates.

## Supported inputs

| Area | Inputs |
| --- | --- |
| Dependencies and container images | Trivy, OSV-Scanner, Grype, OWASP Dependency-Check |
| Source-code findings | Semgrep; SARIF 2.1.0 reports from compatible tools such as CodeQL |
| Infrastructure checks | Trivy, Checkov, tfsec |
| Secrets | Trivy, Gitleaks |
| Web application checks | Nuclei |
| Software bills of materials (SBOMs) | CycloneDX 1.x JSON and SPDX 2.x JSON |

SARIF input is treated as source-code findings. The SBOM parser records package
identity, but does not currently normalize every SBOM field, such as dependency
graphs, licenses, hashes, or signatures. Tools that emit compatible SARIF or
SBOM JSON can use the shared adapters; other formats need a Go parser with
fixtures and tests under `internal/parser/`.

## Where Specht fits

[Dependency-Track](https://docs.dependencytrack.org/) focuses on SBOMs and
risk from software components. [DefectDojo](https://docs.defectdojo.com/) is a broad
platform for importing and managing findings from many tools. Specht is an
early, smaller project that brings several kinds of scanner reports together
and focuses on team policy and CI decisions. It overlaps with both, but is not
a drop-in replacement.

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

The server shows a placeholder at `/` until you run `make build`, which builds
and embeds the React frontend from `frontend/`. The UI is unfinished; use the
API and CLI for now.

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

- Changes to supported scanner kinds, the finding format, database schemas, or
  CI policy need an approved RFC first (see [`rfcs/`](rfcs/)). This adds a
  review step, but helps avoid breaking report ingestion.
- CI repeats the test/lint/frontend checks on every push
  ([ci.yml](.github/workflows/ci.yml)), CodeQL runs separately
  ([codeql.yml](.github/workflows/codeql.yml)), and Dependabot opens dependency
  PRs with a cooldown window
  ([dependabot.yml](.github/workflows/dependabot.yml)).
- About 1,500 Go tests, including integration tests that run against
  PostgreSQL in Docker, plus a frontend test suite. We expect tests for code
  changes.
- Contributions follow the
  [Developer Certificate of Origin](CONTRIBUTING.md#developer-certificate-of-origin).
- Push a `v*` tag and [release.yml](.github/workflows/release.yml) builds and
  publishes a versioned container image.

## Project Status

No releases or tags exist yet. Once they do, the release workflow above
starts publishing images. The API works, but the web UI is unfinished and
there is no dashboard yet.
Expect breaking changes. Bug reports and general feedback are welcome via
[GitHub issues](https://github.com/minh-tg/specht/issues); security reports
should follow [SECURITY.md](SECURITY.md).

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).
