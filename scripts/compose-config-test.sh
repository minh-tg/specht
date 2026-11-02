#!/usr/bin/env bash
# Check the resolved deployment configuration without starting containers.
set -euo pipefail
cd "$(dirname "$0")/.."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cat >"$work/env" <<'ENV'
POSTGRES_PASSWORD=compose-config-test-password
SPECHT_APP_DB_PASSWORD=compose-config-test-app-password
JWT_SECRET=compose-config-test-secret-at-least-32-bytes
FINGERPRINT_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
RAW_RETENTION_DAYS=0
INTEL_ENABLED=false
ENV

docker compose -f deploy/docker-compose.yml --env-file "$work/env" \
  config --format json >"$work/config.json"
python3 - "$work/config.json" <<'PY'
import json, sys

services = json.load(open(sys.argv[1]))['services']
server = services['server']
env = server['environment']
if not env['DATABASE_URL'].startswith('postgres://specht_app:compose-config-test-app-password@db:5432/specht?'):
    raise SystemExit('the server must query as specht_app')
if not env['MIGRATE_DATABASE_URL'].startswith('postgres://specht:compose-config-test-password@db:5432/specht?'):
    raise SystemExit('migrations must run as the owner, specht')
db = services['db']
if db['environment'].get('SPECHT_APP_DB_PASSWORD') != 'compose-config-test-app-password':
    raise SystemExit('the database init script needs SPECHT_APP_DB_PASSWORD')
if not any(v.get('target') == '/docker-entrypoint-initdb.d' for v in db.get('volumes', [])):
    raise SystemExit('the database must mount deploy/postgres/initdb')
expected = {
    'FINGERPRINT_KEY': '0123456789abcdef' * 4,
    'RAW_RETENTION_DAYS': '0',
    'INTEL_ENABLED': 'false',
}
for name, value in expected.items():
    if str(env.get(name)) != value:
        raise SystemExit(f'{name} did not reach the server configuration')
if env['INGEST_MEMORY_BUDGET'] != '2GiB':
    raise SystemExit('update the memory-default check for the configured ingest budget')
if int(server['mem_limit']) < 3 * 1024**3:
    raise SystemExit('the container needs the 2 GiB ingest budget plus 1 GiB')
print('compose environment settings, database roles and memory defaults: ok')
PY
