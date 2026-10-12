# Specht

[![CI](https://github.com/minh-tg/specht/actions/workflows/ci.yml/badge.svg)](https://github.com/minh-tg/specht/actions/workflows/ci.yml) [![CodeQL](https://github.com/minh-tg/specht/actions/workflows/codeql.yml/badge.svg)](https://github.com/minh-tg/specht/actions/workflows/codeql.yml) [![Go 1.26](https://img.shields.io/badge/Go-1.26.0-00ADD8?logo=go&logoColor=white)](go.mod) [![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

Self-hosted vulnerability management for security scanner reports.

Specht brings software composition analysis (SCA), static application security
testing (SAST), infrastructure-as-code (IaC), and secret findings into one
place. Track findings across scans, triage them in the dashboard, and apply
project policies in CI to decide whether a change should pass.

> [!WARNING]
> **Experimental preview.** Specht is not production-ready; APIs, database
> schemas, and settings may change. Do not use it as your only security control.

## What you can do

- Filter findings, review report history, triage issues, upload reports, and
  manage project access and API keys in the web UI.
- Track findings as they appear, are fixed, return, or are waived, alongside
  package inventory and remediation details.
- Use the HTTP API, `specht` CLI, or `specht-adapter` for CI. The adapter
  can fail a build when policy blocks a change, print annotations, and publish
  GitHub check runs. On GitHub, the `minh-tg/specht` action downloads the
  adapter for a release tag, verifies its signature, and runs the gate.
  Pipeline examples for GitHub Actions and GitLab are in
  [`examples/ci/`](examples/ci/).
- Check tracked packages against OSV for newly published advisories and send
  notifications to Slack or a webhook.
- Set up single sign-on, teams, shared organization policies, and waivers with
  conditions and expiry dates.

## Supported inputs

| Report category | Supported tools and formats |
| --- | --- |
| **Dependencies & container images** | Trivy · OSV-Scanner · Grype · OWASP Dependency-Check |
| **Source-code findings** | Semgrep · SARIF 2.1.0 (for example, CodeQL) |
| **Infrastructure checks** | Trivy · Checkov · tfsec |
| **Secrets** | Trivy · Gitleaks |
| **Web application checks** | Nuclei |
| **Software bills of materials** | CycloneDX 1.x JSON · SPDX 2.x JSON |

> [!NOTE]
> **SARIF is classified as source-code findings.** The SBOM adapter records
> package identity, but does not currently normalize every SBOM field—for
> example, dependency graphs, licenses, hashes, or signatures.

Tools that emit compatible SARIF or SBOM JSON can use the shared adapters.
Other formats need a Go parser with fixtures and tests under
[`internal/parser/`](internal/parser/).

## Try it locally

You need Go 1.26, Node.js 26, pnpm, Make, and Docker. The optional
`nix develop` shell supplies the build tools; Docker still needs to be running.
Run these commands from the repository root in Bash:

```bash
cp .env.example .env
set -a
source .env
set +a
# The example secret is a placeholder and is rejected by the server.
export JWT_SECRET="$(head -c 48 /dev/urandom | base64 | tr -d '\n')"
docker compose --env-file .env -f deploy/docker-compose.yml up -d db
pnpm --dir frontend install --frozen-lockfile
make build
./bin/server
```

The server applies database migrations on startup. On a database with no
accounts it logs a one-time setup token (`setup_token=...`). Open
<http://localhost:8080>, enter that token and create the first administrator.
Set `SETUP_TOKEN` (at least 16 characters) to choose the token yourself for a
scripted install. In another terminal, check the API:

```bash
curl --fail http://localhost:8080/api/v1/health
```

The setup screen is available only until the first account exists. After that
`POST /api/v1/setup` answers 404. To promote further accounts to global admin,
restart the server with their emails in `ADMIN_EMAILS`.

Create a project in the UI, then follow its CI setup page to create an API key and connect a scanner. Pipeline
examples are also available in [`examples/ci/`](examples/ci/).

For API-only development, skip the frontend installation and build, and run
`go run ./cmd/server` instead. Without a frontend build, `/` shows a placeholder.

[`openapi.yaml`](openapi.yaml) documents the HTTP routes, required roles and API
key scopes, parameters, and responses.

## Self-host

For evaluation deployments, follow [`deploy/README.md`](deploy/README.md).
It covers Docker Compose, persistent secrets, TLS, backups, and upgrades.
The local defaults above are not suitable for an internet-facing deployment.

## Project layout

```
cmd/server/      API server (chi router, embedded SPA, watcher daemon)
cmd/specht/      CLI client (specht)
cmd/adapter/     CI/CD gate-check CLI (specht-adapter)
cmd/mcp/         MCP bridge
internal/        Go packages (handlers, usecases, repos, auth, scanners)
frontend/        React SPA (Vite, shadcn/ui)
migrations/      SQL migrations (golang-migrate)
openapi.yaml     HTTP API description (all routes, scopes, and shapes)
sqlc/            Type-safe SQL queries
deploy/          Docker Compose deployment files
examples/ci/     Ready-made GitHub Actions / GitLab CI pipelines
```

## Development

```bash
nix develop            # enter the dev shell (Go 1.26, gopls, SonarQube scanner, frontend toolchain)
prek install           # commit hooks: format/lint/vet/secrets + conventional commits
```

After that every commit you make gets checked: gofumpt, staticcheck,
`go vet`, `go mod tidy`, dprint/oxlint (frontend), hadolint, gitleaks, and
conventional-commit validation. Useful commands:

### Tests

```bash
go test ./... -count=1 -short  # Go unit tests
pnpm --dir frontend test      # frontend unit tests

# Integration and full-stack tests (Docker required)
go test -tags integration ./... -count=1 -timeout 20m
make e2e     # API, adapter, and CLI
make e2e-ui  # browser journeys and accessibility

make coverage  # coverage report; Docker required
```

Browser tests need Chromium. Install it with
`pnpm --dir frontend exec playwright install chromium`, or set
`CHROMIUM_BIN` to a system Chromium executable. The harness builds the UI and
server, starts a temporary database, and tests sign-in, findings, triage,
report uploads, project setup, and more. If its default port is occupied, use
`E2E_UI_PORT=18082 make e2e-ui`.

For Docker-compatible runtimes that cannot run the testcontainers cleanup
helper, prefix Go integration and E2E commands with
`TESTCONTAINERS_RYUK_DISABLED=true`.

### Other checks

```bash
make lsp-check
pnpm --dir frontend exec tsc -b
pnpm --dir frontend exec dprint check
pnpm --dir frontend lint
SONAR_ADMIN_PASSWORD=admin make sonar  # disposable local SonarQube scan; needs Docker/Podman
```

## Contribute

- Changes to supported scanner kinds, the finding format, database schemas, or
  CI policy need an approved RFC first (see [`rfcs/`](rfcs/)). This adds a
  review step, but helps avoid breaking report ingestion.
- CI runs test/lint/frontend checks on pull requests and pushes to `main`
  ([ci.yml](.github/workflows/ci.yml)), CodeQL runs separately
  ([codeql.yml](.github/workflows/codeql.yml)), and Dependabot opens dependency
  PRs with a cooldown window
  ([dependabot.yml](.github/dependabot.yml)).
- Include tests for code changes. The suites cover Go packages, PostgreSQL
  integration, the API and command-line tools, and browser journeys.
- Contributions follow the
  [Developer Certificate of Origin](CONTRIBUTING.md#developer-certificate-of-origin).
- Pushing a `vMAJOR.MINOR.PATCH` tag runs [release.yml](.github/workflows/release.yml).
  It builds the server and adapter images, signs them with cosign, boots the
  server image before tagging it, cross-compiles the `specht` and
  `specht-adapter` binaries, and publishes a GitHub Release with a signed
  `SHA256SUMS`. A tag with a suffix (`v1.2.0-rc.1`) is marked as a prerelease.

## Project status

Specht is an experimental preview. The web UI covers project setup, the change
view that explains a blocked build, findings and report history, triage and
bulk triage, reachability decisions, waivers, policy and templates, insights,
API keys, access management, the CVE watcher, and administration. The API and
CLI cover the same workflows plus a few that have no screen yet.

Releases publish version-tagged images and binaries only, with no mutable
`latest` image. Expect breaking changes before 1.0.

Bug reports and general feedback are welcome via
[GitHub issues](https://github.com/minh-tg/specht/issues); security reports
should follow [SECURITY.md](SECURITY.md).

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).
