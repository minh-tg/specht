#!/usr/bin/env bash
# Signs a self-test release with throwaway cosign keys.
#
# Usage: sign-release.sh DIST KEYDIR
#
# Generates two unrelated key pairs. The first signs DIST/SHA256SUMS, so the
# action verifies it with --key when the self-test passes the matching public
# key. The second never signs anything and is handed to the action as the
# trusted key in the bad-signature case, which must fail verification.
# COSIGN_PASSWORD is empty because the keys are disposable and stay in the job.
set -euo pipefail

dist="${1:?usage: sign-release.sh DIST KEYDIR}"
keydir="${2:?usage: sign-release.sh DIST KEYDIR}"

command -v cosign >/dev/null 2>&1 || {
  echo "error: cosign is required to sign the self-test release" >&2
  exit 1
}

mkdir -p "$keydir/signing" "$keydir/other"
export COSIGN_PASSWORD=""
(cd "$keydir/signing" && cosign generate-key-pair >/dev/null)
(cd "$keydir/other" && cosign generate-key-pair >/dev/null)

cosign sign-blob --yes \
  --key "$keydir/signing/cosign.key" \
  --output-signature "$dist/SHA256SUMS.sig" \
  "$dist/SHA256SUMS"

echo "signed $dist/SHA256SUMS with a throwaway key"
