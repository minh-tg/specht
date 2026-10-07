#!/usr/bin/env bash
# Run a disposable SonarQube scan with the scanner provided by the Nix dev shell.
# Each run is a fresh instance; new-code flags are an initial baseline, not a diff.
# The server image is pinned here; the scanner version is pinned by flake.lock.
#
# Usage:
#   SONAR_ADMIN_PASSWORD=admin make sonar
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
SONAR_IMAGE="${SONAR_IMAGE:-docker.io/library/sonarqube:26.9.0.129388-community}"
SONAR_PORT="${SONAR_PORT:-9001}"
PROJECT_KEY="${SONAR_PROJECT_KEY:-specht}"
# Disable JGit blame by default; it fails on this checkout's local object store.
SONAR_SCM_DISABLED="${SONAR_SCM_DISABLED:-true}"
SONAR_EXCLUSIONS="${SONAR_EXCLUSIONS:-node_modules/**,frontend/dist/**,frontend/node_modules/**,.git/**,.codeql-results/**,.direnv/**,.agents/**,.opencode/**,.claude/**,.superpowers/**,openspec/**,plannotator/**,local-docs/**,static_analysis/**,static_analysis_codeql_1/**,AGENTS.md,Handoff.md,CLAUDE.md,.env*,bin/**,cmd/server/dist/dist/**}"

: "${SONAR_ADMIN_PASSWORD:?set SONAR_ADMIN_PASSWORD, usually admin for a fresh local instance}"

for command in curl docker python3 go sonar-scanner; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "missing required command: $command" >&2
    exit 1
  fi
done

container_name="specht-sonar-scan-$$"
sonar_url="http://127.0.0.1:${SONAR_PORT}"
coverage_report="$(mktemp -t specht-sonar-coverage.XXXXXX)"
scanner_working_dir="$(mktemp -d -t specht-sonar-work.XXXXXX)"

cleanup() {
  rm -f "$coverage_report"
  rm -rf "$scanner_working_dir"
  docker rm -f "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "== Go tests and coverage ==" >&2
go test -coverpkg=./... -coverprofile="$coverage_report" -count=1 -short ./...

echo "== pull pinned SonarQube image ==" >&2
docker pull "$SONAR_IMAGE" >/dev/null

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
scan_status=0
SONAR_HOST_URL="$sonar_url" SONAR_TOKEN="$scan_token" \
SONAR_SCANNER_SKIP_JRE_PROVISIONING="true" sonar-scanner \
  "-Dsonar.projectKey=${PROJECT_KEY}" \
  "-Dsonar.projectName=${PROJECT_KEY}" \
  -Dsonar.sources=. \
  "-Dsonar.working.directory=${scanner_working_dir}" \
  -Dsonar.sourceEncoding=UTF-8 \
  "-Dsonar.scm.disabled=${SONAR_SCM_DISABLED}" \
  "-Dsonar.exclusions=${SONAR_EXCLUSIONS}" \
  "-Dsonar.go.coverage.reportPaths=${coverage_report}" \
  "-Dsonar.scanner.skipJreProvisioning=true" \
  -Dsonar.qualitygate.wait=true || scan_status=$?

echo "== findings summary ==" >&2
SONAR_HOST_URL="$sonar_url" SONAR_TOKEN="$scan_token" \
SONAR_PROJECT_KEY="$PROJECT_KEY" \
SONAR_REPORT_PATH="${SONAR_REPORT_PATH:-/tmp/specht-sonar-findings.json}" \
python3 - <<'PY'
import base64
import json
import os
from collections import Counter
from urllib.parse import urlencode
from urllib.request import Request, urlopen

host = os.environ["SONAR_HOST_URL"].rstrip("/")
token = os.environ["SONAR_TOKEN"]
project = os.environ["SONAR_PROJECT_KEY"]
report_path = os.environ["SONAR_REPORT_PATH"]
auth = "Basic " + base64.b64encode(f"{token}:".encode()).decode()


def api(path, params):
    url = f"{host}{path}?{urlencode(params)}"
    request = Request(url, headers={"Authorization": auth})
    with urlopen(request, timeout=60) as response:
        return json.load(response)


def all_issues(new_code=False):
    issues = []
    page = 1
    total = None
    while total is None or len(issues) < total:
        params = {"componentKeys": project, "resolved": "false", "ps": 500, "p": page}
        if new_code:
            params["sinceLeakPeriod"] = "true"
        result = api("/api/issues/search", params)
        batch = result.get("issues", [])
        issues.extend(batch)
        total = result.get("paging", {}).get("total", len(issues))
        if not batch:
            break
        page += 1
    return issues


current = all_issues()
new_code = all_issues(new_code=True)
new_keys = {issue.get("key") for issue in new_code}
current_keys = {issue.get("key") for issue in current}
new_keys &= current_keys
current_code = [issue for issue in current if issue.get("key") not in new_keys]

hotspots = []
page = 1
hotspot_total = None
while hotspot_total is None or len(hotspots) < hotspot_total:
    result = api("/api/hotspots/search", {"projectKey": project, "ps": 500, "p": page})
    batch = result.get("hotspots", [])
    hotspots.extend(batch)
    hotspot_total = result.get("paging", {}).get("total", len(hotspots))
    if not batch:
        break
    page += 1


def counts(rows, key):
    return dict(sorted(Counter(row.get(key, "unknown") for row in rows).items()))


print(f"current issues: {len(current)}")
print(f"new-code issues: {len(new_keys)}")
print(f"existing-code issues: {len(current_code)}")
print(f"issue types: {counts(current, 'type')}")
print(f"issue severities: {counts(current, 'severity')}")
print(f"security hotspots: {len(hotspots)}")
for issue in current:
    key = issue.get("key", "")
    category = "NEW" if key in new_keys else "CURRENT"
    component = issue.get("component", "").removeprefix(project + ":")
    line = issue.get("line") or "?"
    print(f"{category} {issue.get('severity', '?')} {issue.get('type', '?')} "
          f"{component}:{line} {issue.get('rule', '?')} — {issue.get('message', '')}")
for hotspot in hotspots:
    component = hotspot.get("component", "").removeprefix(project + ":")
    line = hotspot.get("line") or "?"
    print(f"HOTSPOT {hotspot.get('status', '?')} {component}:{line} "
          f"{hotspot.get('ruleKey', '?')} — {hotspot.get('message', '')}")

with open(report_path, "w", encoding="utf-8") as report:
    json.dump({
        "projectKey": project,
        "analysisNote": "Fresh disposable instance; new-code classification is not historical.",
        "currentIssues": current,
        "newCodeIssues": [issue for issue in current if issue.get("key") in new_keys],
        "existingCodeIssues": current_code,
        "hotspots": hotspots,
    }, report, indent=2)
print("Note: this disposable instance has no prior scan; new-code means first-analysis baseline.")
print(f"full report: {report_path}")
PY

exit "$scan_status"
