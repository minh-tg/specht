#!/usr/bin/env bash
# Run a disposable, reproducible SonarQube scan of Specht.
#
# Usage:
#   SONAR_ADMIN_PASSWORD=admin scripts/sonar-scan.sh
#
# The SonarQube and scanner image tags are intentionally pinned. Override them
# only when validating an upgrade.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SONAR_IMAGE="${SONAR_IMAGE:-docker.io/library/sonarqube:26.9.0.129388-community}"
SCANNER_IMAGE="${SCANNER_IMAGE:-docker.io/sonarsource/sonar-scanner-cli:12.2.0.4256_8.1.0}"
SONAR_PORT="${SONAR_PORT:-9001}"
PROJECT_KEY="${SONAR_PROJECT_KEY:-specht}"
SONAR_SCM_DISABLED="${SONAR_SCM_DISABLED:-true}"
SONAR_EXCLUSIONS="${SONAR_EXCLUSIONS:-node_modules/**,frontend/dist/**,frontend/node_modules/**,.git/**,.codeql-results/**,bin/**,cmd/server/dist/dist/**}"

: "${SONAR_ADMIN_PASSWORD:?set SONAR_ADMIN_PASSWORD, usually admin for a fresh local instance}"

for command in curl docker python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "missing required command: $command" >&2
    exit 1
  fi
done

container_name="specht-sonar-scan-$$"
sonar_url="http://127.0.0.1:${SONAR_PORT}"

cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "== pull pinned images ==" >&2
docker pull "$SONAR_IMAGE" >/dev/null
docker pull "$SCANNER_IMAGE" >/dev/null

echo "== start disposable SonarQube ==" >&2
docker run -d --rm \
  --name "$container_name" \
  -p "127.0.0.1:${SONAR_PORT}:9000" \
  "$SONAR_IMAGE" >/dev/null

echo "== wait for SonarQube ==" >&2
for attempt in $(seq 1 144); do
  status=$(curl -fsS -u "admin:${SONAR_ADMIN_PASSWORD}" \
    "${sonar_url}/api/system/status" 2>/dev/null \
    | python3 -c 'import json, sys; print(json.load(sys.stdin).get("status", ""))' \
    2>/dev/null \
    || true)
  if [ "$status" = "UP" ]; then
    break
  fi
  if [ "$attempt" = 144 ]; then
    echo "timed out waiting for SonarQube" >&2
    docker logs "$container_name" >&2
    exit 1
  fi
  sleep 5
done

echo "== create project token ==" >&2
scan_token=$(curl -fsS -u "admin:${SONAR_ADMIN_PASSWORD}" \
  -X POST --data-urlencode "name=${PROJECT_KEY}-local-scan-$(date +%s)" \
  "${sonar_url}/api/user_tokens/generate" \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["token"])')
curl -fsS -u "${scan_token}:" -X POST \
  --data-urlencode "name=${PROJECT_KEY}" \
  --data-urlencode "project=${PROJECT_KEY}" \
  "${sonar_url}/api/projects/create" >/dev/null

echo "== scan ==" >&2
docker run --rm --network=host \
  -v "${REPO_ROOT}:/usr/src" \
  -w /usr/src \
  -e SONAR_HOST_URL="$sonar_url" \
  -e SONAR_TOKEN="$scan_token" \
  "$SCANNER_IMAGE" \
  "-Dsonar.projectKey=${PROJECT_KEY}" \
  "-Dsonar.projectName=${PROJECT_KEY}" \
  -Dsonar.sources=. \
  -Dsonar.sourceEncoding=UTF-8 \
  "-Dsonar.scm.disabled=${SONAR_SCM_DISABLED}" \
  "-Dsonar.exclusions=${SONAR_EXCLUSIONS}" \
  -Dsonar.qualitygate.wait=true

echo "== findings summary ==" >&2
curl -fsS -u "${scan_token}:" \
  "${sonar_url}/api/issues/search?componentKeys=${PROJECT_KEY}&ps=500&facets=types,severities" \
  | python3 -c '
import json
import sys
from collections import Counter

issues = json.load(sys.stdin).get("issues", [])
print("issues:", len(issues))
print("types:", dict(Counter(issue.get("type") for issue in issues)))
print("severities:", dict(Counter(issue.get("severity") for issue in issues)))
'
curl -fsS -u "${scan_token}:" \
  "${sonar_url}/api/hotspots/search?projectKey=${PROJECT_KEY}&ps=500" \
  | python3 -c '
import json
import sys

print("hotspots:", json.load(sys.stdin).get("paging", {}).get("total", 0))
'
