#!/usr/bin/env bash
# Compose smoke: follows deploy/README.md "Start" on a clean machine. Builds the image from source
# with the build override, starts the stack, runs first-run setup with the setup token, creates a
# project, ingests a scan, reads the gate verdict, restarts the server and checks it comes back.
#
# Requirements: Docker with the compose plugin, curl, python3.
#
# Optional env: COMPOSE_SMOKE_PORT (default 18083).
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${COMPOSE_SMOKE_PORT:-18083}"
PROJECT="specht-smoke"
WORK="$(mktemp -d)"
ENV_FILE="$WORK/.env.prod"
BASE="http://127.0.0.1:$PORT/api/v1"
EMAIL="smoke@example.test"
PASSWORD="compose-smoke-123"
SETUP_TOKEN="compose-smoke-setup-token"
COMPOSE=(docker compose -p "$PROJECT" -f deploy/docker-compose.yml -f deploy/docker-compose.build.yml --env-file "$ENV_FILE")

cleanup() {
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
  echo "compose smoke: FAILED: $*" >&2
  echo "--- server log ---" >&2
  "${COMPOSE[@]}" logs --no-color server >&2 2>/dev/null || true
  exit 1
}

# The production example with its placeholders filled in. The bundled database has no TLS, so the
# example's own POSTGRES_SSLMODE value is what an operator starts from.
sed \
  -e "s/CHANGE-ME-32-plus-random-chars/$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')smoke0000/" \
  -e "s/CHANGE-ME-64-random-chars-min-32-bytes/$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')smoke00000000000000/" \
  -e "s/^SERVER_PORT=.*/SERVER_PORT=$PORT/" \
  -e "s/^ADMIN_EMAILS=.*/ADMIN_EMAILS=$EMAIL/" \
  deploy/.env.prod.example >"$ENV_FILE"
{
  echo "SETUP_TOKEN=$SETUP_TOKEN"
  echo "RATE_LIMIT_AUTH_RPS=100000"
  echo "RATE_LIMIT_AUTH_BURST=100000"
} >>"$ENV_FILE"

wait_healthy() {
  for _ in $(seq 1 90); do
    if curl -fsS "$BASE/health" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  fail "the server never became healthy"
}

json() { python3 -c 'import json,sys; print(json.load(sys.stdin)'"$1"')'; }

echo "== compose up (build from source) ==" >&2
"${COMPOSE[@]}" up -d --build >/dev/null 2>&1 || fail "docker compose up"
wait_healthy
curl -fsS "$BASE/ready" >/dev/null || fail "the server is healthy but not ready"
curl -fsS "$BASE/version" >/dev/null || fail "version endpoint"

echo "== first-run setup ==" >&2
caps="$(curl -fsS "$BASE/capabilities")"
[ "$(printf '%s' "$caps" | json "['setup']['required']")" = "True" ] || fail "setup is not required on a fresh stack"
code="$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
  -d "{\"token\":\"wrong\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" "$BASE/setup")"
[ "$code" = "403" ] || fail "a wrong setup token answered $code, want 403"
session="$(curl -fsS -H 'Content-Type: application/json' \
  -d "{\"token\":\"$SETUP_TOKEN\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" "$BASE/setup")" || fail "setup"
token="$(printf '%s' "$session" | json "['token']")"
caps="$(curl -fsS "$BASE/capabilities")"
[ "$(printf '%s' "$caps" | json "['setup']['required']")" = "False" ] || fail "setup still required after it finished"

echo "== project, scan, verdict ==" >&2
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -d '{"name":"smoke","slug":"smoke"}' "$BASE/projects")"
[ "$code" = "201" ] || fail "create project answered $code"
python3 - "$BASE" "$token" <<'PY' || fail "ingest"
import json, sys, urllib.request
base, token = sys.argv[1:3]
raw = json.load(open("e2e/testdata/high.sarif.json"))
req = urllib.request.Request(
    base + "/reports",
    data=json.dumps({"project": "smoke", "scanner": "sarif", "raw_data": raw}).encode(),
    headers={"Content-Type": "application/json", "Authorization": "Bearer " + token},
)
urllib.request.urlopen(req).read()
PY
gate="$(curl -fsS -H "Authorization: Bearer $token" "$BASE/projects/smoke/gate")" || fail "gate"
[ "$(printf '%s' "$gate" | json "['threshold_breached']")" = "True" ] || fail "the high finding did not block the gate: $gate"

echo "== restart ==" >&2
"${COMPOSE[@]}" restart server >/dev/null 2>&1 || fail "restart"
wait_healthy
curl -fsS "$BASE/ready" >/dev/null || fail "not ready after a restart"
code="$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" "$BASE/auth/login")"
[ "$code" = "200" ] || fail "sign in after a restart answered $code"

echo "compose smoke: ok" >&2
