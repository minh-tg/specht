#!/usr/bin/env bash
# Upgrade smoke: proves a database written by an older release migrates and keeps working. For each
# reference in UPGRADE_FROM it builds that revision, lets it create and fill a database through its
# own API (an account, a project, a scan, a triage decision, an API key), then starts the current
# build on the same database and checks that everything is still there and still works.
#
# Requirements: Docker, Go, git (with the old revisions in its history), curl, python3.
#
# Optional env:
#   UPGRADE_FROM            space-separated git refs to upgrade from. Defaults to the newest v* tag
#                           when one exists, and to a pinned revision otherwise.
#   UPGRADE_SMOKE_PORT      (default 18084)
#   UPGRADE_SMOKE_DB_PORT   (default 54333)
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${UPGRADE_SMOKE_PORT:-18084}"
DB_PORT="${UPGRADE_SMOKE_DB_PORT:-54333}"
CONTAINER="specht-upgrade-smoke-db"
BIN_DIR="$(mktemp -d)"
BASE="http://127.0.0.1:$PORT/api/v1"
EMAIL="upgrade@example.test"
PASSWORD="upgrade-smoke-123"
SLUG="upgrade-me"
SERVER_PID=""
CURRENT_LOG=""

# A pinned fallback from before the account-token generation (migration 40), so the run crosses
# several migrations. Once a release is tagged the default becomes the newest tag instead.
PINNED_FROM="0720cfe"
if [ -z "${UPGRADE_FROM:-}" ]; then
  tag="$(git tag --list 'v*' --sort=-v:refname | head -1)"
  UPGRADE_FROM="${tag:-$PINNED_FROM}"
fi

cleanup() {
  stop_server
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  for wt in "$BIN_DIR"/src-*; do
    [ -d "$wt" ] && git worktree remove --force "$wt" >/dev/null 2>&1 || true
  done
  rm -rf "$BIN_DIR"
}
trap cleanup EXIT

stop_server() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
  fi
}

fail() {
  echo "upgrade smoke: FAILED: $*" >&2
  echo "--- server log ($CURRENT_LOG) ---" >&2
  tail -60 "$BIN_DIR/$CURRENT_LOG.log" >&2 2>/dev/null || true
  exit 1
}

start_server() { # binary label [NAME=VALUE...]
  local bin="$1" label="$2"
  shift 2
  CURRENT_LOG="$label"
  env \
    DATABASE_URL="postgres://specht:specht@127.0.0.1:$DB_PORT/$DB_NAME?sslmode=disable" \
    JWT_SECRET="upgrade-smoke-secret-upgrade-smoke-secret-1234" \
    SERVER_ADDR="127.0.0.1:$PORT" \
    DB_MIGRATE=true \
    REGISTRATION_ENABLED=true \
    LOG_LEVEL=warn \
    RATE_LIMIT_LOGIN_PER_MINUTE=100000 \
    RATE_LIMIT_LOGIN_BURST=100000 \
    "$@" "$bin" >>"$BIN_DIR/$label.log" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 60); do
    if curl -fsS "$BASE/health" >/dev/null 2>&1; then return 0; fi
    kill -0 "$SERVER_PID" 2>/dev/null || fail "$label exited during startup"
    sleep 1
  done
  fail "$label never became healthy"
}

json() { python3 -c 'import json,sys; print(json.load(sys.stdin)'"$1"')'; }

call() { # method path token [body]
  local method="$1" path="$2" token="$3" body="${4:-}"
  curl -sS -X "$method" -w '\n%{http_code}' \
    ${token:+-H "Authorization: Bearer $token"} -H 'Content-Type: application/json' \
    ${body:+-d "$body"} "$BASE$path"
}

echo "== postgres ==" >&2
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" \
  -e POSTGRES_USER=specht -e POSTGRES_PASSWORD=specht -e POSTGRES_DB=postgres \
  -p "127.0.0.1:$DB_PORT:5432" docker.io/library/postgres:17-alpine >/dev/null
for _ in $(seq 1 60); do
  docker exec "$CONTAINER" pg_isready -U specht >/dev/null 2>&1 && break
  sleep 1
done

echo "== build the current server ==" >&2
go build -o "$BIN_DIR/current-server" ./cmd/server

n=0
for ref in $UPGRADE_FROM; do
  n=$((n + 1))
  DB_NAME="upgrade_$n"
  echo "== upgrade from $ref ==" >&2
  git rev-parse --verify --quiet "$ref^{commit}" >/dev/null || fail "$ref is not in this repository's history"
  docker exec "$CONTAINER" psql -U specht -d postgres -c "CREATE DATABASE $DB_NAME" >/dev/null

  git worktree add --detach "$BIN_DIR/src-$n" "$ref" >/dev/null 2>&1 || fail "cannot check out $ref"
  (cd "$BIN_DIR/src-$n" && GOFLAGS=-mod=mod go build -o "$BIN_DIR/old-server-$n" ./cmd/server) || fail "cannot build $ref"
  old_schema_count="$(git ls-tree --name-only "$ref" migrations/ | grep -c '\.up\.sql$' || true)"
  echo "   $ref carries $old_schema_count migrations, the current tree $(ls migrations | grep -c '\.up\.sql$')" >&2

  # The old release writes the data, through its own API.
  start_server "$BIN_DIR/old-server-$n" "old-$n-a"
  out="$(call POST /auth/register "" "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")"
  [ "$(tail -1 <<<"$out")" = "201" ] || fail "old release: register answered $(tail -1 <<<"$out")"
  stop_server
  start_server "$BIN_DIR/old-server-$n" "old-$n-b" "ADMIN_EMAILS=$EMAIL"
  out="$(call POST /auth/login "" "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")"
  token="$(head -n -1 <<<"$out" | json "['token']")" || fail "old release: login"
  out="$(call POST /projects "$token" "{\"name\":\"$SLUG\",\"slug\":\"$SLUG\"}")"
  [ "$(tail -1 <<<"$out")" = "201" ] || fail "old release: create project answered $(tail -1 <<<"$out")"
  python3 - "$BASE" "$token" "$SLUG" <<'PY' || fail "old release: ingest"
import json, sys, urllib.request
base, token, slug = sys.argv[1:4]
raw = json.load(open("e2e/testdata/high-medium.sarif.json"))
req = urllib.request.Request(
    base + "/reports",
    data=json.dumps({"project": slug, "scanner": "sarif", "raw_data": raw}).encode(),
    headers={"Content-Type": "application/json", "Authorization": "Bearer " + token},
)
urllib.request.urlopen(req).read()
PY
  out="$(call GET "/projects/$SLUG/findings" "$token")"
  before="$(head -n -1 <<<"$out")"
  count_before="$(python3 -c 'import json,sys; d=json.load(sys.stdin); d=d if isinstance(d,list) else d.get("findings",[]); print(len(d))' <<<"$before")"
  [ "$count_before" -ge 2 ] || fail "old release: expected at least 2 findings, saw $count_before"
  fid="$(python3 -c 'import json,sys; d=json.load(sys.stdin); d=d if isinstance(d,list) else d.get("findings",[]); print(d[0]["id"])' <<<"$before")"
  out="$(call PATCH "/findings/$fid" "$token" '{"analysis_state":"false_positive","reason":"upgrade smoke"}')"
  [ "$(tail -1 <<<"$out")" = "200" ] || fail "old release: triage answered $(tail -1 <<<"$out")"
  out="$(call POST /auth/apikeys "$token" "{\"project\":\"$SLUG\",\"name\":\"upgrade\"}")"
  [ "$(tail -1 <<<"$out")" = "201" ] || fail "old release: create API key answered $(tail -1 <<<"$out")"
  raw_key="$(head -n -1 <<<"$out" | json "['raw_key']")"
  stop_server

  # The current build takes over the same database.
  start_server "$BIN_DIR/current-server" "current-$n-a" "ADMIN_EMAILS=$EMAIL"
  curl -fsS "$BASE/ready" >/dev/null || fail "the upgraded server is not ready"
  out="$(call POST /auth/login "" "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")"
  [ "$(tail -1 <<<"$out")" = "200" ] || fail "sign in after the upgrade answered $(tail -1 <<<"$out")"
  token="$(head -n -1 <<<"$out" | json "['token']")"
  out="$(call GET "/projects/$SLUG" "$token")"
  [ "$(tail -1 <<<"$out")" = "200" ] || fail "the project is gone after the upgrade"
  out="$(call GET "/projects/$SLUG/findings" "$token")"
  after="$(head -n -1 <<<"$out")"
  count_after="$(python3 -c 'import json,sys; d=json.load(sys.stdin); d=d if isinstance(d,list) else d.get("findings",[]); print(len(d))' <<<"$after")"
  [ "$count_after" = "$count_before" ] || fail "findings changed across the upgrade: $count_before before, $count_after after"
  out="$(call GET "/findings/$fid" "$token")"
  [ "$(tail -1 <<<"$out")" = "200" ] || fail "the triaged finding is gone after the upgrade"
  [ "$(head -n -1 <<<"$out" | json "['analysis_state']")" = "false_positive" ] || fail "the triage decision did not survive the upgrade"
  out="$(call GET "/projects/$SLUG/gate" "$raw_key")"
  [ "$(tail -1 <<<"$out")" = "200" ] || fail "the API key made before the upgrade stopped working (got $(tail -1 <<<"$out"))"
  out="$(call GET "/projects/$SLUG/reports" "$token")"
  [ "$(tail -1 <<<"$out")" = "200" ] || fail "reports are unreadable after the upgrade"
  stop_server

  # A second start finds nothing to migrate.
  start_server "$BIN_DIR/current-server" "current-$n-b" "ADMIN_EMAILS=$EMAIL"
  curl -fsS "$BASE/ready" >/dev/null || fail "not ready on the second start"
  stop_server
  echo "   upgrade from $ref: ok" >&2
done

echo "upgrade smoke: ok" >&2
