#!/usr/bin/env bash
# Specht security gate.
#
# Downloads the specht-adapter release for the runner platform, verifies the
# checksum manifest with cosign (keyless by default, pinned to the release
# workflow identity) and the archive against its SHA256SUMS line, then runs the
# adapter against the Specht API. Nothing is executed before verification
# succeeds, so a tampered or unsigned archive never runs.
#
# One implementation serves two callers: the public action at the repository
# root, which fixes the download origin and the keyless verification policy,
# and the test-only action in .github/action-selftest. Only the test action
# sets SPECHT_SELFTEST=1, and the script refuses the overrides below without
# it. The public action also clears these variables, so a job-level env cannot
# supply them either.
#
# Usage:
#   specht-gate.sh prepare            resolve the release and write outputs
#   specht-gate.sh run                download, verify and run the adapter
#   specht-gate.sh identity TAG       print the certificate identity for a tag
#
# Environment:
#   SPECHT_INPUT_*        action inputs, see action.yml
#   SPECHT_ACTION_REF     github.action_ref
#   SPECHT_EVENT_NAME     github.event_name
#   SPECHT_PR_HEAD_REPO   github.event.pull_request.head.repo.full_name
#   SPECHT_PR_BASE_REPO   github.event.pull_request.base.repo.full_name
#   SPECHT_EVENT_BASE_REF github.base_ref
#   RUNNER_OS, RUNNER_ARCH, RUNNER_TEMP, GITHUB_OUTPUT
#
# Test-only overrides, refused unless SPECHT_SELFTEST=1:
#   SPECHT_RELEASE_BASE_URL      release download origin
#   SPECHT_COSIGN_PUBLIC_KEY     PEM public key for cosign verify-blob
#   SPECHT_CERTIFICATE_IDENTITY  full certificate identity for keyless verify
set -euo pipefail

RELEASE_BASE_URL_DEFAULT="https://github.com/minh-tg/specht/releases/download"
IDENTITY_PREFIX_DEFAULT="https://github.com/minh-tg/specht/.github/workflows/release.yml"
OIDC_ISSUER_DEFAULT="https://token.actions.githubusercontent.com"

error() {
  echo "::error::$*" >&2
  exit 1
}

selftest=0
if [[ "${SPECHT_SELFTEST:-}" == "1" ]]; then
  selftest=1
fi

# A caller that is not the test action may not redirect the download origin or
# replace the verification key or identity, not even by naming the default.
if [[ "$selftest" != "1" ]]; then
  if [[ -n "${SPECHT_RELEASE_BASE_URL:-}" && "${SPECHT_RELEASE_BASE_URL}" != "$RELEASE_BASE_URL_DEFAULT" ]]; then
    error "the release-base-url override is test-only and is refused outside the self-test action"
  fi
  if [[ -n "${SPECHT_COSIGN_PUBLIC_KEY:-}" ]]; then
    error "the cosign-public-key override is test-only and is refused outside the self-test action"
  fi
  if [[ -n "${SPECHT_CERTIFICATE_IDENTITY:-}" ]]; then
    error "the certificate-identity override is test-only and is refused outside the self-test action"
  fi
fi

release_base_url="${SPECHT_RELEASE_BASE_URL:-$RELEASE_BASE_URL_DEFAULT}"
cosign_public_key="${SPECHT_COSIGN_PUBLIC_KEY:-}"

# The keyless identity is the release workflow at the tag being downloaded.
# Only the test action may replace it, and only for the self-test workflow.
certificate_identity() {
  local tag="$1"
  if [[ -n "${SPECHT_CERTIFICATE_IDENTITY:-}" ]]; then
    printf '%s\n' "$SPECHT_CERTIFICATE_IDENTITY"
  else
    printf '%s@refs/tags/%s\n' "$IDENTITY_PREFIX_DEFAULT" "$tag"
  fi
}

# Sets tag, file_version, os, arch and asset from the action inputs and the
# runner platform.
resolve_release() {
  local version="${SPECHT_INPUT_VERSION:-}"
  local action_ref="${SPECHT_ACTION_REF:-}"
  if [[ -z "$version" && "$action_ref" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    version="$action_ref"
  fi
  if [[ -z "$version" ]]; then
    error "no Specht release tag resolved. Pin the action to a release tag (uses: minh-tg/specht@v1.2.3) or set the version input to one, such as v1.2.3. There is no latest fallback."
  fi
  if [[ ! "$version" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    error "version '${version}' is not a release tag such as v1.2.3"
  fi
  tag="v${version#v}"
  file_version="${tag#v}"

  case "${RUNNER_OS:-}" in
    Linux) os=linux ;;
    macOS) os=darwin ;;
    Windows) os=windows ;;
    *)
      error "unsupported RUNNER_OS '${RUNNER_OS:-}'; Specht supports Linux, macOS and Windows runners"
      ;;
  esac
  case "${RUNNER_ARCH:-}" in
    X64) arch=amd64 ;;
    ARM64) arch=arm64 ;;
    *)
      error "unsupported RUNNER_ARCH '${RUNNER_ARCH:-}'; Specht supports X64 and ARM64 runners"
      ;;
  esac
  if [[ "$os" == windows && "$arch" != amd64 ]]; then
    error "Specht publishes no windows/${arch} adapter archive; only windows/amd64 is supported"
  fi

  ext=tar.gz
  if [[ "$os" == windows ]]; then
    ext=zip
  fi
  asset="specht-adapter_${file_version}_${os}_${arch}.${ext}"
}

# Sets skipped. A fork pull request without an api-key is the one event that
# may skip; anywhere else an empty api-key is an error.
resolve_skip() {
  skipped=false
  if [[ -z "${SPECHT_INPUT_API_KEY:-}" ]]; then
    if [[ "${SPECHT_EVENT_NAME:-}" == pull_request && -n "${SPECHT_PR_HEAD_REPO:-}" && "${SPECHT_PR_HEAD_REPO}" != "${SPECHT_PR_BASE_REPO:-}" ]]; then
      echo "::notice::Specht skipped: pull requests from forks do not receive the api-key secret."
      skipped=true
    else
      error "Specht needs the api-key input; set it from a repository secret, for example secrets.SPECHT_API_KEY. Only pull_request events from forks may leave it empty."
    fi
  fi
}

# Sets tmp and downloads the archive, the manifest, the manifest signature and,
# on the keyless path, the manifest certificate.
download_release() {
  local base="${release_base_url%/}"
  local proto
  case "$base" in
    https://*)
      proto="=https"
      ;;
    http://127.0.0.1 | http://127.0.0.1[:/]* | http://localhost | http://localhost[:/]*)
      proto="=https,http"
      ;;
    *)
      error "release-base-url must use https; plain http is allowed only for 127.0.0.1 or localhost"
      ;;
  esac

  tmp="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/specht-action"
  rm -rf "$tmp"
  mkdir -p "$tmp"

  local files=("$asset" SHA256SUMS SHA256SUMS.sig)
  if [[ -z "$cosign_public_key" ]]; then
    files+=(SHA256SUMS.pem)
  fi
  local f
  for f in "${files[@]}"; do
    echo "downloading ${base}/${tag}/${f}"
    curl --fail --location --retry 3 --retry-delay 2 --silent --show-error \
      --proto "$proto" --proto-redir "$proto" \
      --output "$tmp/$f" "${base}/${tag}/${f}"
  done
}

# Verifies the manifest signature and the archive checksum against SHA256SUMS.
verify_release() {
  local identity
  if [[ -n "$cosign_public_key" ]]; then
    local key="$tmp/cosign.pub"
    if [[ -f "$cosign_public_key" ]]; then
      key="$cosign_public_key"
    else
      printf '%s\n' "$cosign_public_key" >"$key"
    fi
    cosign verify-blob \
      --key "$key" \
      --signature "$tmp/SHA256SUMS.sig" \
      "$tmp/SHA256SUMS"
  else
    identity="$(certificate_identity "$tag")"
    cosign verify-blob \
      --certificate "$tmp/SHA256SUMS.pem" \
      --signature "$tmp/SHA256SUMS.sig" \
      --certificate-identity "$identity" \
      --certificate-oidc-issuer "$OIDC_ISSUER_DEFAULT" \
      "$tmp/SHA256SUMS"
  fi

  local line
  line="$(awk -v asset="$asset" '$2 == asset { print }' "$tmp/SHA256SUMS")"
  if [[ -z "$line" ]]; then
    error "SHA256SUMS has no entry for ${asset}"
  fi
  (
    cd "$tmp"
    if [[ "$os" == darwin ]]; then
      printf '%s\n' "$line" | shasum -a 256 -c -
    else
      printf '%s\n' "$line" | sha256sum -c -
    fi
  )
}

# Extracts the verified archive and runs the adapter. The adapter's exit code
# is the step's: 0 pass, 1 blocked (findings), 2 error.
run_adapter() {
  mkdir -p "$tmp/adapter"
  case "$os" in
    windows) unzip -q -o "$tmp/$asset" -d "$tmp/adapter" ;;
    *) tar -xzf "$tmp/$asset" -C "$tmp/adapter" ;;
  esac
  local bin="$tmp/adapter/specht-adapter"
  if [[ "$os" == windows ]]; then
    bin="${bin}.exe"
  fi
  chmod +x "$bin"

  local args=(-file "${SPECHT_INPUT_FILE:?SPECHT_INPUT_FILE is required}" -tool "${SPECHT_INPUT_TOOL:?SPECHT_INPUT_TOOL is required}")
  if [[ -n "${SPECHT_INPUT_PROJECT:-}" ]]; then
    args+=(-project "$SPECHT_INPUT_PROJECT")
  fi

  local introduced="${SPECHT_INPUT_INTRODUCED_ONLY:-}"
  if [[ -z "$introduced" ]]; then
    if [[ "${SPECHT_EVENT_NAME:-}" == pull_request* ]]; then
      introduced=true
    else
      introduced=false
    fi
  fi
  if [[ "$introduced" == "true" ]]; then
    args+=(-introduced-only)
  fi

  local base_ref="${SPECHT_INPUT_BASE_REF:-}"
  if [[ -z "$base_ref" ]]; then
    base_ref="${SPECHT_EVENT_BASE_REF:-}"
  fi
  if [[ -n "$base_ref" ]]; then
    args+=(-base-ref "$base_ref")
  fi

  # The adapter reads API_URL and API_KEY; the SPECHT_* names are kept for
  # older releases. The key is never echoed.
  export SPECHT_API_URL="${SPECHT_INPUT_API_URL:?SPECHT_INPUT_API_URL is required}"
  export SPECHT_API_KEY="${SPECHT_INPUT_API_KEY:-}"
  export API_URL="$SPECHT_API_URL"
  export API_KEY="$SPECHT_API_KEY"
  export GITHUB_TOKEN="${SPECHT_INPUT_GITHUB_TOKEN:-}"

  "$bin" "${args[@]}"
}

mode="${1:-run}"
case "$mode" in
  identity)
    certificate_identity "${2:?usage: specht-gate.sh identity TAG}"
    ;;
  prepare)
    resolve_release
    resolve_skip
    if [[ -z "${GITHUB_OUTPUT:-}" ]]; then
      error "GITHUB_OUTPUT is required for prepare"
    fi
    {
      echo "version=$file_version"
      echo "tag=$tag"
      echo "os=$os"
      echo "arch=$arch"
      echo "asset=$asset"
      echo "skipped=$skipped"
    } >>"$GITHUB_OUTPUT"
    ;;
  run)
    resolve_release
    resolve_skip
    if [[ "$skipped" == "true" ]]; then
      exit 0
    fi
    download_release
    verify_release
    run_adapter
    ;;
  *)
    error "unknown mode '${mode}'; expected prepare, run or identity"
    ;;
esac
