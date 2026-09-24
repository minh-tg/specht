#!/usr/bin/env bash
# Self-hosted dogfood: ingest scanner SARIF reports into a Specht instance
# so the product tracks its own vulnerabilities. Introduced-by-change,
# gates, and verified-fixed closure then run on real data every pipeline.
#
# The server must be running with DB_MIGRATE=true and ADMIN_EMAILS
# including SPECHT_ADMIN_EMAIL. Bootstrap promotes only accounts that
# exist, so register first, then (re)start the server:
#
#   1. start server (DB_MIGRATE=true)
#   2. POST /api/v1/auth/register {email, password}
#   3. restart server with ADMIN_EMAILS=<email>
#   4. run this script
#
# Required env: SPECHT_API_URL, SPECHT_ADMIN_EMAIL, SPECHT_ADMIN_PASSWORD,
#   SPECHT_PROJECT (slug; created when missing), SARIF_FILES (paths).
# Optional: GATE_MODE=advisory (default) or block (exit 1 on breach).
set -euo pipefail

: "${SPECHT_API_URL:?set SPECHT_API_URL}"
: "${SPECHT_ADMIN_EMAIL:?set SPECHT_ADMIN_EMAIL}"
: "${SPECHT_ADMIN_PASSWORD:?set SPECHT_ADMIN_PASSWORD}"
: "${SPECHT_PROJECT:?set SPECHT_PROJECT}"
: "${SARIF_FILES:?set SARIF_FILES to SARIF report paths}"
GATE_MODE="${GATE_MODE:-advisory}"

api() {
  curl -sS -w '\n%{http_code}' "$@"
}

split_body() {
  # usage: split_body <curl-output> ; sets BODY and CODE globals
  BODY=$(printf '%s' "$1" | sed '$d')
  CODE=$(printf '%s' "$1" | tail -1)
}

echo "== login $SPECHT_ADMIN_EMAIL ==" >&2
out=$(api -X POST "$SPECHT_API_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg e "$SPECHT_ADMIN_EMAIL" --arg p "$SPECHT_ADMIN_PASSWORD" '{email:$e,password:$p}')")
split_body "$out"
if [ "$CODE" != "200" ]; then
  echo "login failed (HTTP $CODE): $BODY" >&2
  exit 1
fi
TOKEN=$(printf '%s' "$BODY" | jq -r .token)
if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "login returned no token" >&2
  exit 1
fi

echo "== ensure project $SPECHT_PROJECT ==" >&2
out=$(api -X POST "$SPECHT_API_URL/api/v1/projects" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg s "$SPECHT_PROJECT" '{name:$s,slug:$s}')")
split_body "$out"
if [ "$CODE" != "201" ] && [ "$CODE" != "200" ]; then
  # Reruns reuse the slug: a duplicate answers 409; confirm the project
  # exists before failing.
  out=$(api "$SPECHT_API_URL/api/v1/projects/$SPECHT_PROJECT" \
    -H "Authorization: Bearer $TOKEN")
  split_body "$out"
  if [ "$CODE" != "200" ]; then
    echo "project create failed (HTTP $CODE): $BODY" >&2
    echo "hint: the login account needs global admin (ADMIN_EMAILS + restart after register)" >&2
    exit 1
  fi
  echo "project exists, reusing" >&2
fi

echo "== mint API key ==" >&2
out=$(api -X POST "$SPECHT_API_URL/api/v1/auth/apikeys" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg p "$SPECHT_PROJECT" --arg n "ci-dogfood-$(date +%s)" '{project:$p,name:$n}')")
split_body "$out"
if [ "$CODE" != "201" ]; then
  echo "apikey create failed (HTTP $CODE): $BODY" >&2
  exit 1
fi
KEY=$(printf '%s' "$BODY" | jq -r .raw_key)

# shellcheck disable=SC2086
for sarif in $SARIF_FILES; do
  echo "== ingest $sarif ==" >&2
  # Bodies travel via temp file, not argv: SARIF payloads exceed
  # command-substitution limits.
  body_file=$(mktemp)
  jq -n --arg p "$SPECHT_PROJECT" --slurpfile raw "$sarif" '{project:$p,scanner:"sarif",raw_data:$raw[0]}' > "$body_file"
  out=$(api -X POST "$SPECHT_API_URL/api/v1/reports" \
    -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
    --data @"$body_file")
  rm -f "$body_file"
  split_body "$out"
  if [ "$CODE" != "201" ] && [ "$CODE" != "200" ]; then
    echo "ingest failed for $sarif (HTTP $CODE): $BODY" >&2
    exit 1
  fi
  echo "$BODY"
done

echo "== gate status ==" >&2
out=$(api "$SPECHT_API_URL/api/v1/projects/$SPECHT_PROJECT/gate" \
  -H "Authorization: Bearer $KEY")
split_body "$out"
if [ "$CODE" != "200" ]; then
  echo "gate check failed (HTTP $CODE): $BODY" >&2
  exit 1
fi
echo "$BODY"
breached=$(printf '%s' "$BODY" | jq -r .threshold_breached)
if [ "$breached" = "true" ]; then
  echo "gate BREACHED on self-scan" >&2
  if [ "$GATE_MODE" = "block" ]; then
    exit 1
  fi
fi
