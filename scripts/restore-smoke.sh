#!/usr/bin/env bash
# Restore smoke: proves the backup and restore procedure in deploy/README.md
# (section "Backup and restore") works end to end. Seeds a throwaway source
# database through the real server, dumps it in custom format, restores the
# dump into an empty database, then boots the server on the restored data
# with migrations off and on.
#
# Requirements: Docker, Go, curl, python3.
#
# Optional env: RESTORE_SMOKE_PORT (default 18082), RESTORE_SMOKE_DB_PORT
#   (default 54332).
# SPECHT_TEST_POSTGRES_IMAGE replaces the Postgres image (CI points it at a mirror).
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${RESTORE_SMOKE_PORT:-18082}"
DB_PORT="${RESTORE_SMOKE_DB_PORT:-54332}"
CONTAINER="specht-restore-smoke-db"
SRC_DB="specht_src"
DST_DB="specht_restored"
BIN_DIR="$(mktemp -d)"
SERVER_PID=""
EMAIL="restore@example.test"
PASSWORD="restore-smoke-123"
SETUP_TOKEN="restore-smoke-setup-token"
PROJECT_SLUG="restore-me"
BASE="http://127.0.0.1:$PORT/api/v1"

cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$BIN_DIR"
}
trap cleanup EXIT

fail() {
  echo "restore smoke: FAILED: $*" >&2
  echo "--- server log ---" >&2
  cat "$BIN_DIR/server.log" >&2 2>/dev/null || true
  exit 1
}

echo "== postgres ==" >&2
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
# The official image starts a socket-only server to run its init scripts, then restarts. Probing
# over TCP waits for the final server, which is the one that has the database.
docker run -d --name "$CONTAINER" \
  -e POSTGRES_USER=specht -e POSTGRES_PASSWORD=specht -e POSTGRES_DB="$SRC_DB" \
  -p "127.0.0.1:$DB_PORT:5432" "${SPECHT_TEST_POSTGRES_IMAGE:-docker.io/library/postgres:17-alpine}" >/dev/null
ready=0
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" pg_isready -h 127.0.0.1 -U specht -d "$SRC_DB" >/dev/null 2>&1; then
    ready=1
    break
  fi
  state=$(docker inspect --format '{{.State.Status}}' "$CONTAINER" 2>/dev/null || true)
  if [ "$state" != "running" ]; then
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  docker logs "$CONTAINER" >&2 || true
  fail "postgres did not become ready"
fi
docker exec "$CONTAINER" psql -U specht -d "$SRC_DB" -q -c "CREATE DATABASE $DST_DB" >/dev/null

echo "== build server ==" >&2
go build -o "$BIN_DIR/specht-server" ./cmd/server

# start_server DB_NAME DB_MIGRATE [NAME=VALUE ...]
start_server() {
  local db="$1" migrate="$2"
  shift 2
  env \
    DATABASE_URL="postgres://specht:specht@127.0.0.1:$DB_PORT/$db?sslmode=disable" \
    JWT_SECRET="$(head -c 48 /dev/urandom | base64)" \
    SERVER_ADDR="127.0.0.1:$PORT" \
    DB_MIGRATE="$migrate" \
    REGISTRATION_ENABLED=true \
    LOG_LEVEL=warn \
    RATE_LIMIT_LOGIN_PER_MINUTE=100000 \
    RATE_LIMIT_LOGIN_BURST=100000 \
    "$@" "$BIN_DIR/specht-server" >>"$BIN_DIR/server.log" 2>&1 &
  SERVER_PID=$!
}

wait_healthy() {
  for _ in $(seq 1 90); do
    if curl -fsS "$BASE/health" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      fail "server exited during startup"
    fi
    sleep 1
  done
  fail "server never became healthy"
}

stop_server() {
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
}

# json_field FILE KEY: prints a top-level string field from a JSON file.
json_field() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}

# login_token: logs in and prints the session token.
login_token() {
  local code
  code=$(curl -s -o "$BIN_DIR/login.out" -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" \
    "$BASE/auth/login")
  if [ "$code" != "200" ]; then
    fail "login returned HTTP $code"
  fi
  json_field "$BIN_DIR/login.out" token
}

echo "== seed source database ==" >&2
start_server "$SRC_DB" true "SETUP_TOKEN=$SETUP_TOKEN"
wait_healthy
code=$(curl -s -o "$BIN_DIR/setup.out" -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$SETUP_TOKEN\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" \
  "$BASE/setup")
[ "$code" = "201" ] || fail "first-run setup returned HTTP $code"
TOKEN=$(login_token)
code=$(curl -s -o "$BIN_DIR/project.out" -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"name\":\"restore-me\",\"slug\":\"$PROJECT_SLUG\"}" \
  "$BASE/projects")
[ "$code" = "201" ] || fail "create project returned HTTP $code"
stop_server

echo "== dump source database (custom format) ==" >&2
DUMP="$BIN_DIR/dump.pgdump"
docker exec "$CONTAINER" pg_dump -U specht -Fc "$SRC_DB" > "$DUMP" \
  || fail "pg_dump failed"
[ -s "$DUMP" ] || fail "pg_dump produced an empty file"

echo "== restore into empty database ==" >&2
docker exec -i "$CONTAINER" pg_restore -U specht -d "$DST_DB" --no-owner < "$DUMP" \
  || fail "pg_restore exited non-zero"

echo "== start restored database with migrations off ==" >&2
start_server "$DST_DB" false
wait_healthy
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/ready")
[ "$code" = "200" ] || fail "ready returned HTTP $code on restored database"
TOKEN=$(login_token)
code=$(curl -s -o "$BIN_DIR/get-project.out" -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE/projects/$PROJECT_SLUG")
[ "$code" = "200" ] || fail "GET project returned HTTP $code after restore"
stop_server

echo "== normal start on restored database (migrations on) ==" >&2
start_server "$DST_DB" true
wait_healthy
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/ready")
[ "$code" = "200" ] || fail "ready returned HTTP $code after migrating start"
stop_server

echo "restore smoke: ok"
