#!/usr/bin/env bash
# Tests the verification policy of action/specht-gate.sh without the network.
#
# Covers the certificate identity the keyless branch builds for a release tag,
# and that a caller outside the self-test action cannot change the download
# origin, the verification key or the certificate identity. The self-test
# workflow runs this file and it is runnable locally with no arguments.
#
# Usage: action/specht-gate_test.sh
set -euo pipefail

script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/specht-gate.sh"
identity_prefix="https://github.com/minh-tg/specht/.github/workflows/release.yml"
failures=0

# The script must see a clean policy environment: no self-test flag and no
# overrides, whatever the caller's shell carries.
clean_env=(env -u SPECHT_SELFTEST -u SPECHT_RELEASE_BASE_URL -u SPECHT_COSIGN_PUBLIC_KEY -u SPECHT_CERTIFICATE_IDENTITY)

check() {
  local want="$1" got="$2" what="$3"
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: ${what}: want '${want}', got '${got}'" >&2
    failures=$((failures + 1))
  else
    echo "ok: ${what}"
  fi
}

expect_identity() {
  local tag="$1" want="$2" got
  got="$("${clean_env[@]}" bash "$script" identity "$tag")"
  check "$want" "$got" "certificate identity for ${tag}"
}

expect_refusal() {
  local what="$1"
  shift
  if "${clean_env[@]}" "$@" bash "$script" identity v1.2.3 >/dev/null 2>&1; then
    echo "FAIL: ${what} was accepted without the self-test flag" >&2
    failures=$((failures + 1))
  else
    echo "ok: ${what} is refused without the self-test flag"
  fi
}

expect_identity v1.2.3 "${identity_prefix}@refs/tags/v1.2.3"
expect_identity v1.2.3-rc.1 "${identity_prefix}@refs/tags/v1.2.3-rc.1"

expect_refusal "the cosign public key override" SPECHT_COSIGN_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----"
expect_refusal "the release base URL override" SPECHT_RELEASE_BASE_URL="http://127.0.0.1:8123"
expect_refusal "the certificate identity override" SPECHT_CERTIFICATE_IDENTITY="https://example.invalid/wf.yml@refs/heads/main"

# The self-test action is the only caller that may set the flag, and with it
# the identity override reaches the keyless branch.
override="https://example.invalid/wf.yml@refs/heads/main"
got="$(env -u SPECHT_RELEASE_BASE_URL -u SPECHT_COSIGN_PUBLIC_KEY SPECHT_SELFTEST=1 SPECHT_CERTIFICATE_IDENTITY="$override" bash "$script" identity v1.2.3)"
check "$override" "$got" "certificate identity override with the self-test flag"

if [[ "$failures" -ne 0 ]]; then
  echo "::error::${failures} check(s) failed" >&2
  exit 1
fi
echo "all specht-gate.sh policy checks passed"
