# Contributing to Specht

Thanks for considering a contribution. This project is licensed under the
[GNU Affero General Public License v3.0](LICENSE).

## Developer Certificate of Origin

Contributions follow the [Developer Certificate of Origin, version
1.1](https://developercertificate.org/). By signing off a commit, you certify
that you have the right to submit the work and that it may be distributed
under this project's AGPL-3.0 license.

Sign off each commit with:

```bash
git commit -s -m "type(scope): description"
```

The commit must contain a trailer like this:

```text
Signed-off-by: Your Name <you@example.com>
```

All commits in a pull request must be signed off. Do not sign off a
contribution you did not author or do not have permission to submit.

The `dco` check on every pull request fails when a commit has no
`Signed-off-by` trailer whose email matches the commit's author or committer.
Commits by bot accounts such as Dependabot are exempt. To sign off a branch
that is missing it:

```bash
git rebase --signoff origin/main
git push --force-with-lease
```

Installing the hooks with `prek install` also signs off for you: the
`dco-signoff` hook adds the trailer from your git identity when you commit, so
`-s` becomes optional. The sign-off still certifies the statement above, so
review what you commit.

Maintainers: squash merges keep each commit's sign-off because the repository
builds the squash message from the commit messages. Leave that setting as is.

## Development

You need Go 1.26, Node.js 26, pnpm, Make and Docker. The optional `nix develop` shell
supplies the build tools (Go, gopls, the SonarQube scanner and the frontend toolchain);
Docker still needs to be running. Run `prek install` once to enable the commit hooks.

Every commit is checked by those hooks: gofumpt, staticcheck, `go vet`, `go mod tidy`,
dprint and oxlint for the frontend, hadolint, gitleaks, conventional-commit message
validation, and an automatic DCO sign-off. Keep pull requests focused and reasonably sized.

### Run from source

Run these commands from the repository root in Bash:

```bash
cp .env.example .env
set -a
source .env
set +a
# The example secret is a placeholder and the server rejects it.
export JWT_SECRET="$(head -c 48 /dev/urandom | base64 | tr -d '\n')"
docker compose --env-file .env -f deploy/docker-compose.yml up -d db
pnpm --dir frontend install --frozen-lockfile
make build
./bin/server
```

The server applies database migrations on startup. On a database with no accounts it
logs a one-time setup token (`setup_token=...`). Open <http://localhost:8080>, enter the
token and create the first administrator. Set `SETUP_TOKEN` (at least 16 characters) to
choose the token yourself for a scripted install. Check the API with
`curl --fail http://localhost:8080/api/v1/health`.

The setup screen stays available until the first global admin exists, and accounts that
registered earlier do not close it. After that `POST /api/v1/setup` answers 404. To make
further admins, change an account's role in the Admin area, or list the email of an account
that signed in through SSO with a verified address in `ADMIN_EMAILS` and restart. A
password-registered account is never promoted that way.

For API-only development, skip the frontend install and build and run
`go run ./cmd/server`. Without a frontend build, `/` shows a placeholder.

### Repository layout

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
examples/ci/     Ready-made GitHub Actions and GitLab CI pipelines
```

### Tests

```bash
go test ./... -count=1 -short  # Go unit tests
pnpm --dir frontend test       # frontend unit tests

# Integration and full-stack tests (Docker required)
go test -tags integration ./... -count=1 -timeout 20m
make e2e     # API, adapter and CLI
make e2e-ui  # browser journeys and accessibility

make coverage  # coverage report; Docker required
```

Browser tests need Chromium. Install it with
`pnpm --dir frontend exec playwright install chromium`, or set `CHROMIUM_BIN` to a system
Chromium executable. The harness builds the UI and server, starts a temporary database, and
tests sign-in, findings, triage, report uploads, project setup and more. If its default port
is occupied, use `E2E_UI_PORT=18082 make e2e-ui`.

For Docker-compatible runtimes that cannot run the testcontainers cleanup helper, prefix
Go integration and e2e commands with `TESTCONTAINERS_RYUK_DISABLED=true`.

Other checks:

```bash
make lsp-check
pnpm --dir frontend exec tsc -b
pnpm --dir frontend exec dprint check
pnpm --dir frontend lint
SONAR_ADMIN_PASSWORD=admin make sonar  # disposable local SonarQube scan; needs Docker or Podman
```

### Changes that need an RFC

Changes to supported scanner kinds, the finding format, database schemas or CI policy need
an approved RFC first (see [`rfcs/`](rfcs/)). This adds a review step and protects report
ingestion from breaking changes.

### Continuous integration and releases

CI runs the test, lint and frontend checks on pull requests and pushes to `main`
([ci.yml](.github/workflows/ci.yml)). CodeQL runs weekly
([codeql.yml](.github/workflows/codeql.yml)), and Dependabot opens dependency pull
requests with a cooldown window ([dependabot.yml](.github/dependabot.yml)).

Pushing a `vMAJOR.MINOR.PATCH` tag runs [release.yml](.github/workflows/release.yml). It
builds the server and adapter images, signs them with cosign, boots the server image before
tagging it, cross-compiles the `specht`, `specht-adapter` and `specht-mcp` binaries, and
publishes a GitHub Release with a signed `SHA256SUMS`. A tag with a suffix (`v1.2.0-rc.1`)
is marked as a prerelease.

### Reproducible CI inputs

The Nix development environment uses the committed `flake.lock` for its
`nixos-unstable` input. Refresh it deliberately with `nix flake lock` during
quarterly dependency maintenance (or sooner for a security fix), then review
the resulting input changes; do not update the lock opportunistically in
unrelated pull requests.
