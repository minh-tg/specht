#!/usr/bin/env bash
# Release-image verification: boots a Specht container image against a
# throwaway PostgreSQL and exercises the API end to end — migrations,
# SPA delivery, registration, the two-phase admin promotion (same as the
# dev harness), project creation, and a real report ingest.
#
# Usage: scripts/verify-image.sh <image-ref>
#   scripts/verify-image.sh ghcr.io/minh-tg/specht:v0.1.0-rc.1
#
# The image must be present locally (pull or build it first).
# Requirements: Docker-compatible CLI, curl, jq, network host mode (Linux).
#
# Optional env: VERIFY_PORT (default 18090), VERIFY_DB_PORT (default 54332).
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="${1:?usage: scripts/verify-image.sh <image-ref>}"
PORT="${VERIFY_PORT:-18090}"
DB_PORT="${VERIFY_DB_PORT:-54332}"
DB_NAME="specht_verify"
DB_CONTAINER="specht-verify-db"
APP_CONTAINER="specht-verify-app"
ADMIN_EMAIL="release-check@example.com"
ADMIN_PASSWORD="release-check-password-123"
FIXTURE="e2e/testdata/high.sarif.json"

cleanup() {
  docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true
  docker rm -f "$DB_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  echo "--- app logs (tail) ---" >&2
  docker logs "$APP_CONTAINER" 2>&1 | tail -40 >&2 || true
  exit 1
}

# api <METHOD> <path> [data] [token] -> "$code" + body in $body
api() {
  local method="$1" path="$2" data="${3:-}" token="${4:-}"
  local args=(-sS -X "$method" -D /tmp/verify-headers.txt -o /tmp/verify-body.txt
    -H "Content-Type: application/json")
  [ -n "$token" ] && args+=(-H "Authorization: Bearer $token")
  [ -n "$data" ] && args+=(--data "$data")
  curl "${args[@]}" "http://127.0.0.1:$PORT$path" || return 1
  CODE=$(awk 'NR==1{print $2}' /tmp/verify-headers.txt)
  body=$(cat /tmp/verify-body.txt)
}

start_app() { # optional NAME=VALUE env args (e.g. ADMIN_EMAILS=...)
  local extra=()
  local kv
  for kv in "$@"; do extra+=(-e "$kv"); done
  docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true
  # --network host: the app reaches the host-published Postgres port and
  # serves on the loopback port the checks below use.
  docker run -d --name "$APP_CONTAINER" --network host \
    -e DATABASE_URL="postgres://specht:specht@127.0.0.1:$DB_PORT/$DB_NAME?sslmode=disable" \
    -e JWT_SECRET="$(head -c 48 /dev/urandom | base64)" \
    -e SERVER_ADDR="127.0.0.1:$PORT" \
    -e DB_MIGRATE=true \
    -e LOG_LEVEL=info \
    "${extra[@]}" "$IMAGE" >/dev/null
}

wait_healthy() {
  local i
  for i in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:$PORT/api/v1/health" >/dev/null 2>&1; then
      return 0
    fi
    if [ "$(docker inspect -f '{{.State.Running}}' "$APP_CONTAINER" 2>/dev/null)" != "true" ]; then
      fail "app container exited during startup"
    fi
    sleep 1
  done
  fail "server never became healthy"
}

echo "== image: $IMAGE ==" >&2
docker image inspect "$IMAGE" >/dev/null 2>&1 || fail "image not present locally: $IMAGE"

echo "== postgres ==" >&2
docker rm -f "$DB_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$DB_CONTAINER" \
  -e POSTGRES_USER=specht -e POSTGRES_PASSWORD=specht -e POSTGRES_DB="$DB_NAME" \
  -p "127.0.0.1:$DB_PORT:5432" docker.io/library/postgres:17-alpine >/dev/null
for _ in $(seq 1 60); do
  if docker exec "$DB_CONTAINER" pg_isready -U specht >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$DB_CONTAINER" pg_isready -U specht >/dev/null 2>&1 || fail "postgres did not become ready"

echo "== boot (phase 1: register) ==" >&2
start_app
wait_healthy
api POST /api/v1/auth/register \
  "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" || fail "register request failed"
[ "$CODE" = "201" ] || fail "register expected 201, got $CODE: $body"
docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true

echo "== boot (phase 2: ADMIN_EMAILS promotion) ==" >&2
start_app "ADMIN_EMAILS=$ADMIN_EMAIL"
wait_healthy

echo "== SPA ==" >&2
curl -fsS "http://127.0.0.1:$PORT/" | grep -q '<div id="root"' || fail "embedded SPA did not serve the app shell"
echo "== login + identity ==" >&2
api POST /api/v1/auth/login "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" \
  || fail "login request failed"
[ "$CODE" = "200" ] || fail "login expected 200, got $CODE: $body"
TOKEN=$(echo "$body" | jq -r '.token // empty')
[ -n "$TOKEN" ] || fail "login returned no token"
api GET /api/v1/me "" "$TOKEN" || fail "me request failed"
[ "$(echo "$body" | jq -r .email)" = "$ADMIN_EMAIL" ] || fail "me returned wrong identity: $body"
[ "$(echo "$body" | jq -r .role)" = "admin" ] || fail "ADMIN_EMAILS did not promote the account: $body"

echo "== project + ingest round trip ==" >&2
api POST /api/v1/projects '{"name":"release-verify","slug":"release-verify"}' "$TOKEN" \
  || fail "create project request failed"
[ "$CODE" = "201" ] || fail "create project expected 201, got $CODE: $body"
RAW_DATA=$(jq -c . "$FIXTURE")
api POST /api/v1/reports "{\"project\":\"release-verify\",\"scanner\":\"sarif\",\"raw_data\":$RAW_DATA}" "$TOKEN" \
  || fail "ingest request failed"
[ "$CODE" = "201" ] || fail "ingest expected 201, got $CODE: $body"
echo "$body" | jq -e '.report_id' >/dev/null || fail "ingest returned no report_id: $body"
api GET "/api/v1/projects/release-verify/findings?limit=50" "" "$TOKEN" || fail "findings request failed"
[ "$(echo "$body" | jq 'length')" = "1" ] || fail "expected 1 finding after ingest, got: $body"

echo "OK: $IMAGE boots, migrates, serves the SPA, and completes the API round trip" >&2
