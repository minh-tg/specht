#!/usr/bin/env bash
# commit-msg hook: appends a "Signed-off-by" trailer for the configured git
# identity, so every commit carries the DCO sign-off CONTRIBUTING.md asks for
# without remembering `git commit -s`. Idempotent: a message that already has
# the trailer (from -s, an amend or a rebase) is left unchanged.
#
# Usage: scripts/dco-signoff.sh <commit-msg-file>
set -euo pipefail

msg_file="${1:?usage: dco-signoff.sh <commit-msg-file>}"

# "Name <email> 1700000000 +0000" -> "Name <email>"
ident="$(git var GIT_COMMITTER_IDENT)"
signoff="${ident%>*}>"

git interpret-trailers --in-place --if-exists addIfDifferent \
  --trailer "Signed-off-by: ${signoff}" "$msg_file"
