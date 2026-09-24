.PHONY: dev-api dev-web db-up db-down migrate-up migrate-down sqlc test test-race e2e e2e-ui lsp-check sonar coverage build clean

dev-api:
	go run ./cmd/server

dev-web:
	cd frontend && npm run dev

db-up:
	docker compose -f deploy/docker-compose.yml up -d db

db-down:
	docker compose -f deploy/docker-compose.yml down

migrate-up:
	go run ./cmd/server migrate

migrate-down:
	go run ./cmd/server migrate-down

sqlc:
	sqlc generate -f sqlc.yaml

test:
	go test ./... -count=1 -short

test-race:
	go test -race ./... -count=1 -short

# Full-stack E2E: real Postgres (testcontainers), real server/adapter/CLI
# binaries, HTTP + exit-code contracts. Needs Docker; ~1-3 minutes.
e2e:
	TESTCONTAINERS_RYUK_DISABLED=true go test -tags e2e ./e2e/ -count=1 -timeout 15m

# Browser smoke: boots the real server (embedded React build) against a
# throwaway PostgreSQL, then drives register → login → dashboard in
# Chromium. Needs Docker plus a Playwright Chromium:
#   pnpm --dir frontend exec playwright install chromium
# or CHROMIUM_BIN=/path/to/chromium (e.g. NixOS system Chromium).
e2e-ui:
	./scripts/e2e-ui.sh

lsp-check:
	gopls check $$(git ls-files --cached --others --exclude-standard -- '*.go')

sonar:
	./scripts/sonar-scan.sh

coverage:
	mkdir -p .coverage
	go test ./... -count=1 -short -coverpkg=./... -coverprofile=.coverage/go-unit.out
	TESTCONTAINERS_RYUK_DISABLED=true go test -tags integration ./internal/repo/ -count=1 -coverpkg=./... -coverprofile=.coverage/go-integration.out
	pnpm --dir frontend run test:coverage
	python3 scripts/coverage_report.py --go-profile .coverage/go-unit.out --go-profile .coverage/go-integration.out --frontend-json frontend/coverage/coverage-final.json

build:
	cd frontend && npm run build
	# Copy into cmd/server/dist/dist/ (not over the committed placeholder
	# index.html): the placeholder must stay byte-identical so go:embed and
	# clean-checkout builds work; the nested dist/ is git-excluded.
	rm -rf cmd/server/dist/dist
	cp -r frontend/dist cmd/server/dist/
	go build -ldflags "$(LDFLAGS)" -o bin/server ./cmd/server
	go build -ldflags "$(LDFLAGS)" -o bin/adapter ./cmd/adapter

# Version wiring: VERSION defaults to a dev marker; the release workflow
# builds with VERSION=vX.Y.Z so the health endpoint reports the tagged build.
VERSION ?= dev
LDFLAGS = -X github.com/minh-tg/specht/internal/version.Version=$(VERSION) -X github.com/minh-tg/specht/internal/version.Commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

clean:
	rm -rf bin/ frontend/dist/ cmd/server/dist/dist/
