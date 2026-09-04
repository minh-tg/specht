.PHONY: dev-api dev-web db-up db-down migrate-up migrate-down sqlc test build clean

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
LDFLAGS = -X github.com/xMinhx/specht/internal/version.Version=$(VERSION) -X github.com/xMinhx/specht/internal/version.Commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

clean:
	rm -rf bin/ frontend/dist/ cmd/server/dist/dist/
