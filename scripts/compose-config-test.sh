#!/usr/bin/env bash
# Check the resolved deployment configuration without starting containers.
set -euo pipefail
cd "$(dirname "$0")/.."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cat >"$work/env" <<'ENV'
POSTGRES_PASSWORD=compose-config-test-password
JWT_SECRET=compose-config-test-secret-at-least-32-bytes
FINGERPRINT_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
RAW_RETENTION_DAYS=0
INTEL_ENABLED=false
ENV

docker compose -f deploy/docker-compose.yml --env-file "$work/env" \
  config --format json >"$work/config.json"
python3 - "$work/config.json" <<'PY'
import json, sys

server = json.load(open(sys.argv[1]))['services']['server']
env = server['environment']
expected = {
    'FINGERPRINT_KEY': '0123456789abcdef' * 4,
    'RAW_RETENTION_DAYS': '0',
    'INTEL_ENABLED': 'false',
}
for name, value in expected.items():
    if str(env.get(name)) != value:
        raise SystemExit(f'{name} did not reach the server configuration')
print('compose environment settings: ok')
PY
