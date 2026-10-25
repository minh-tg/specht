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

# The adapter gets the gate scope as an explicit true or false, so an
# introduced-only: false input is not overridden by the detected base ref.
expect_introduced() {
  local event="$1" input="$2" want="$3" got
  got="$("${clean_env[@]}" SPECHT_EVENT_NAME="$event" SPECHT_INPUT_INTRODUCED_ONLY="$input" \
    bash -c 'source "$1"; introduced_only' _ "$script")"
  check "$want" "$got" "introduced-only for event '${event}' and input '${input}'"
}

expect_introduced pull_request "" true
expect_introduced pull_request_target "" true
expect_introduced push "" false
expect_introduced pull_request false false
expect_introduced push true true

if "${clean_env[@]}" SPECHT_INPUT_INTRODUCED_ONLY=yes bash -c 'source "$1"; introduced_only' _ "$script" >/dev/null 2>&1; then
  echo "FAIL: introduced-only 'yes' was accepted" >&2
  failures=$((failures + 1))
else
  echo "ok: introduced-only 'yes' is refused"
fi

# Failures of the script itself exit 2, never 1, which means blocked by
# findings. Each case runs one function in a sourced copy of the script.
expect_exit() {
  local want="$1" what="$2" body="$3"
  shift 3
  local got=0
  "${clean_env[@]}" "$@" bash -c "source \"\$1\"; ${body}" _ "$script" >/dev/null 2>&1 || got=$?
  check "$want" "$got" "exit code when ${what}"
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/rel"
# A stand-in cosign whose verdict the test controls.
printf '#!/usr/bin/env bash\nexit "${FAKE_COSIGN_EXIT:-0}"\n' >"$work/bin/cosign"
chmod +x "$work/bin/cosign"
printf 'adapter bytes\n' >"$work/rel/specht-adapter_1.2.3_linux_amd64.tar.gz"
verify="tmp='$work/rel'; asset=specht-adapter_1.2.3_linux_amd64.tar.gz; os=linux; tag=v1.2.3; verify_release"
sum="$(cd "$work/rel" && sha256sum specht-adapter_1.2.3_linux_amd64.tar.gz)"

expect_exit 2 "the release base URL override is refused" "main identity v1.2.3" SPECHT_RELEASE_BASE_URL="http://127.0.0.1:8123"
expect_exit 2 "the mode is unknown" "main bogus"
expect_exit 2 "the runner OS is unsupported" "resolve_release" SPECHT_INPUT_VERSION=v1.2.3 RUNNER_OS=Plan9 RUNNER_ARCH=X64
expect_exit 2 "the api-key is missing on a push" "resolve_skip" SPECHT_EVENT_NAME=push SPECHT_INPUT_API_KEY=
expect_exit 2 "introduced-only is not a boolean" "introduced_only" SPECHT_INPUT_INTRODUCED_ONLY=yes
expect_exit 2 "the download fails" "tag=v1.2.3; asset=a.tar.gz; download_release" SPECHT_SELFTEST=1 SPECHT_RELEASE_BASE_URL="http://127.0.0.1:1" RUNNER_TEMP="$work/dl"

printf '%s\n' "$sum" >"$work/rel/SHA256SUMS"
expect_exit 0 "the signature and checksum verify" "$verify" PATH="$work/bin:$PATH"
expect_exit 2 "the signature does not verify" "$verify" PATH="$work/bin:$PATH" FAKE_COSIGN_EXIT=1
printf '%s  other.tar.gz\n' "${sum%% *}" >"$work/rel/SHA256SUMS"
expect_exit 2 "SHA256SUMS has no entry for the asset" "$verify" PATH="$work/bin:$PATH"
printf '%064d  specht-adapter_1.2.3_linux_amd64.tar.gz\n' 0 >"$work/rel/SHA256SUMS"
expect_exit 2 "the archive checksum does not match" "$verify" PATH="$work/bin:$PATH"

if [[ "$failures" -ne 0 ]]; then
  echo "::error::${failures} check(s) failed" >&2
  exit 1
fi
echo "all specht-gate.sh policy checks passed"
