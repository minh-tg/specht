#!/usr/bin/env bash
# Local CodeQL scan (offline-friendly): builds CodeQL databases for Go and
# JavaScript, analyzes them with the security-extended suites, and writes
# SARIF reports. Optionally ingests the SARIF into a local Specht instance
# for tracking (Specht's SARIF adapter consumes it directly).
#
# License note: the CodeQL CLI bundle downloads free of charge, but its
# grant covers open-source analysis. Evaluate private-codebase use against
# the CodeQL license terms before adopting this routinely.
#
# Usage:
#   scripts/codeql-local.sh [--go-only] [--js-only] [--skip-ingest]
#
# Environment:
#   CODEQL_VERSION  bundle version to download if missing (default 2.27.0)
#   CODEQL_DIR      bundle install dir (default ~/.cache/specht-codeql)
#   OUT_DIR         SARIF + database output dir (default ./.codeql-results,
#                   git-ignored)
#   SPECHT_API_URL  e.g. http://localhost:8080 (enables ingest)
#   SPECHT_API_KEY  API key for ingest (enables ingest)
#   SPECHT_PROJECT  project slug for ingest (default: repo dir name)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CODEQL_VERSION="${CODEQL_VERSION:-2.27.0}"
CODEQL_DIR="${CODEQL_DIR:-$HOME/.cache/specht-codeql}"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/.codeql-results}"
GO_ONLY=false
JS_ONLY=false
SKIP_INGEST=false

for arg in "$@"; do
  case "$arg" in
    --go-only) GO_ONLY=true ;;
    --js-only) JS_ONLY=true ;;
    --skip-ingest) SKIP_INGEST=true ;;
    -h|--help)
      sed -n '2,20p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [ ! -x "$CODEQL_DIR/codeql/codeql" ]; then
  echo "downloading CodeQL bundle v$CODEQL_VERSION..." >&2
  mkdir -p "$CODEQL_DIR"
  curl -sL -o "$CODEQL_DIR/codeql-bundle.tar.gz" \
    "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz"
  tar -xzf "$CODEQL_DIR/codeql-bundle.tar.gz" -C "$CODEQL_DIR"
fi
CODEQL="$CODEQL_DIR/codeql/codeql"

PACK_BASE="$CODEQL_DIR/codeql/qlpacks"
GO_SUITE=$(ls -d "$PACK_BASE"/codeql/go-queries/*/codeql-suites/go-security-extended.qls | sort -V | tail -1)
JS_SUITE=$(ls -d "$PACK_BASE"/codeql/javascript-queries/*/codeql-suites/javascript-security-extended.qls | sort -V | tail -1)

mkdir -p "$OUT_DIR"
cd "$REPO_ROOT"

run_lang() {
  local lang="$1" db="$2" suite="$3"
  shift 3
  echo "== CodeQL $lang: database ==" >&2
  if [ "$lang" = "go" ]; then
    "$CODEQL" database create "$db" --language=go --source-root="$REPO_ROOT" --command="go build ./..." --overwrite
  else
    "$CODEQL" database create "$db" --language=javascript --source-root="$REPO_ROOT" --overwrite
  fi
  echo "== CodeQL $lang: analyze ==" >&2
  "$CODEQL" database analyze "$db" --format=sarif-latest --output="$OUT_DIR/codeql-$lang.sarif" "$suite"
}

if [ "$JS_ONLY" = false ]; then
  run_lang go "$OUT_DIR/specht-go-db" "$GO_SUITE"
fi
if [ "$GO_ONLY" = false ]; then
  run_lang js "$OUT_DIR/specht-js-db" "$JS_SUITE"
fi

echo "== findings ==" >&2
python3 - "$OUT_DIR" <<'EOF'
import glob
import json
import sys

total = 0
for path in sorted(glob.glob(sys.argv[1] + "/codeql-*.sarif")):
    with open(path) as f:
        sarif = json.load(f)
    results = sarif["runs"][0].get("results", [])
    total += len(results)
    print(f"{path}: {len(results)} result(s)")
    for r in results:
        loc = r["locations"][0]["physicalLocation"]
        region = loc["region"]
        print(f"  {r['ruleId']} {loc['artifactLocation']['uri']}:{region.get('startLine')}")
print(f"total: {total}")
EOF

# Optional ingest: SARIF straight into Specht for tracking, reopen, and
# verified-fixed lifecycle. Requires a running server, an API key, and a
# project slug; skipped silently otherwise.
if [ "$SKIP_INGEST" = false ] && [ -n "${SPECHT_API_URL:-}" ] && [ -n "${SPECHT_API_KEY:-}" ]; then
  project="${SPECHT_PROJECT:-$(basename "$REPO_ROOT")}"
  for sarif in "$OUT_DIR"/codeql-*.sarif; do
    echo "== ingest $sarif -> $project ==" >&2
    python3 - "$sarif" "$SPECHT_API_URL" "$SPECHT_API_KEY" "$project" <<'EOF'
import json
import sys
import urllib.request

sarif_path, api_url, api_key, project = sys.argv[1:5]
with open(sarif_path) as f:
    raw = json.load(f)
body = json.dumps({
    "project": project,
    "scanner": "sarif",
    "raw_data": raw,
}).encode()
req = urllib.request.Request(
    api_url.rstrip("/") + "/api/v1/reports",
    data=body,
    headers={"Content-Type": "application/json", "Authorization": "Bearer " + api_key},
)
with urllib.request.urlopen(req) as resp:
    print(resp.status, resp.read().decode()[:200])
EOF
  done
else
  echo "ingest skipped (set SPECHT_API_URL, SPECHT_API_KEY, SPECHT_PROJECT to enable)" >&2
fi
