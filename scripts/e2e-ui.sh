#!/usr/bin/env bash
# Browser smoke: boots the real release artifact — Go server with the
# embedded React build — against a throwaway PostgreSQL, then drives the
# auth journey in Chromium via Playwright.
#
# Requirements: Docker, Go, pnpm, and a Playwright Chromium
#   pnpm --dir frontend exec playwright install chromium
# or a system Chromium via CHROMIUM_BIN=/path/to/chromium (NixOS).
#
# Optional env: E2E_UI_PORT (default 18081), E2E_UI_DB_PORT (default 54331),
#   CHROMIUM_BIN, plus any Playwright env (E2E_BASE_URL is set for you).
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${E2E_UI_PORT:-18081}"
DB_PORT="${E2E_UI_DB_PORT:-54331}"
DB_NAME="specht_e2e_ui"
CONTAINER="specht-e2e-ui-db"
BIN_DIR="$(mktemp -d)"
SERVER_PID=""

cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$BIN_DIR" cmd/server/dist/dist
}
trap cleanup EXIT

echo "== postgres ==" >&2
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run --rm -d --name "$CONTAINER" \
  -e POSTGRES_USER=specht -e POSTGRES_PASSWORD=specht -e POSTGRES_DB="$DB_NAME" \
  -p "127.0.0.1:$DB_PORT:5432" postgres:17-alpine >/dev/null
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" pg_isready -U specht >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! docker exec "$CONTAINER" pg_isready -U specht >/dev/null 2>&1; then
  echo "postgres did not become ready" >&2
  exit 1
fi

echo "== build frontend and embed it ==" >&2
pnpm --dir frontend build
# Copy into cmd/server/dist/dist/ (not over the committed placeholder
# index.html) — the same layout `make build` uses for go:embed.
rm -rf cmd/server/dist/dist
cp -r frontend/dist cmd/server/dist/

echo "== build server ==" >&2
go build -o "$BIN_DIR/specht-server" ./cmd/server

echo "== start server ==" >&2
DATABASE_URL="postgres://specht:specht@127.0.0.1:$DB_PORT/$DB_NAME?sslmode=disable" \
JWT_SECRET="$(head -c 48 /dev/urandom | base64)" \
SERVER_ADDR="127.0.0.1:$PORT" \
DB_MIGRATE=true \
LOG_LEVEL=warn \
"$BIN_DIR/specht-server" >>"$BIN_DIR/server.log" 2>&1 &
SERVER_PID=$!

healthy=""
for _ in $(seq 1 90); do
  if curl -fsS "http://127.0.0.1:$PORT/api/v1/health" >/dev/null 2>&1; then
    healthy=1
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "server exited during startup:" >&2
    cat "$BIN_DIR/server.log" >&2
    exit 1
  fi
  sleep 1
done
if [ -z "$healthy" ]; then
  echo "server never became healthy:" >&2
  cat "$BIN_DIR/server.log" >&2
  exit 1
fi

echo "== browser smoke ==" >&2
E2E_BASE_URL="http://127.0.0.1:$PORT" pnpm --dir frontend exec playwright test "$@"
