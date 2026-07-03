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
	cp -r frontend/dist cmd/server/dist
	go build -o bin/server ./cmd/server
	go build -o bin/adapter ./cmd/adapter

clean:
	rm -rf bin/ frontend/dist/ cmd/server/dist/
