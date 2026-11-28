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
import glob, json, re, sys

services = json.load(open(sys.argv[1]))['services']
server = services['server']
env = server['environment']

# Every variable the server reads must reach it: deploy/README.md tells
# operators to set them in deploy/.env.prod, and compose passes on only the
# ones the file names. The names are the quoted ones in the server's sources;
# the rest are built at runtime or read by the Go runtime.
read = {'CVE_DETAIL_NVD_RPS', 'CVE_DETAIL_VULNCHECK_RPS', 'CVE_DETAIL_OSV_RPS', 'GOMEMLIMIT'}
for pattern in ('internal/config/*.go', 'internal/tracker/*.go', 'internal/watcher/*.go', 'cmd/server/*.go'):
    for path in glob.glob(pattern):
        if not path.endswith('_test.go'):
            read.update(re.findall(r'"([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)"', open(path).read()))
missing = sorted(read - env.keys())
if missing:
    raise SystemExit('the server reads these variables but compose does not forward them: ' + ', '.join(missing))
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
soft = re.fullmatch(r'(\d+)(B|KiB|MiB|GiB)', env['GOMEMLIMIT'])
if not soft:
    raise SystemExit('GOMEMLIMIT must be a whole number with a unit such as MiB')
soft_bytes = int(soft[1]) * {'B': 1, 'KiB': 1024, 'MiB': 1024**2, 'GiB': 1024**3}[soft[2]]
if not 0.8 * int(server['mem_limit']) <= soft_bytes < int(server['mem_limit']):
    raise SystemExit('GOMEMLIMIT should be about 90% of the container memory limit')
print('compose environment settings, forwarded variables, database roles and memory defaults: ok')
PY
