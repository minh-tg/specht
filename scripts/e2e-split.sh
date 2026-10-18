#!/usr/bin/env bash
# Runs the e2e suite as two test processes at the same time: TestAuthzMatrix,
# which is about 40% of the suite's runtime on its own, and every other test.
# Each process starts its own Postgres container, temp directory and free
# ports (see e2e/harness_test.go), so they share nothing. The test binary is
# built once and started twice from the e2e directory, which the harness
# expects as its working directory.
set -euo pipefail

cd "$(dirname "$0")/.."
export TESTCONTAINERS_RYUK_DISABLED="${TESTCONTAINERS_RYUK_DISABLED:-true}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

go test -tags e2e -c -o "$work/e2e.test" ./e2e/

cd e2e
"$work/e2e.test" -test.count=1 -test.timeout=15m -test.run='^TestAuthzMatrix$' >"$work/matrix.log" 2>&1 &
matrix_pid=$!
"$work/e2e.test" -test.count=1 -test.timeout=15m -test.skip='^TestAuthzMatrix$' >"$work/rest.log" 2>&1 &
rest_pid=$!

status=0
wait "$matrix_pid" || status=1
wait "$rest_pid" || status=1

echo "::group::authz matrix"
cat "$work/matrix.log"
echo "::endgroup::"
echo "::group::all other e2e tests"
cat "$work/rest.log"
echo "::endgroup::"
exit "$status"
