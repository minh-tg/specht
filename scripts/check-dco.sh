#!/usr/bin/env bash
# Verifies the Developer Certificate of Origin sign-off on every commit a pull
# request adds (base..head, merge commits excluded). A commit passes when its
# trailer block holds a well-formed "Signed-off-by: Name <email>" whose email
# matches the commit's author or committer, compared case-insensitively.
#
# A pull request opened by a known bot account (for example Dependabot) is exempt as a whole. The
# workflow passes the pull request author's login in PR_AUTHOR, which comes from GitHub's account
# data. The script never exempts a commit because of its author name or email, since the committer
# chooses both.
#
# Usage: PR_AUTHOR=<login> scripts/check-dco.sh <base-sha> <head-sha>
set -euo pipefail

base="${1:?usage: check-dco.sh <base-sha> <head-sha>}"
head="${2:?usage: check-dco.sh <base-sha> <head-sha>}"

exempt_authors=('dependabot[bot]')

signoff_re='^Signed-off-by: .+ <([^<> ]+@[^<> ]+)>$'

lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

has_valid_signoff() {
  local sha="$1" author committer line email
  author="$(lower "$(git show -s --format=%ae "$sha")")"
  committer="$(lower "$(git show -s --format=%ce "$sha")")"
  while IFS= read -r line; do
    if [[ $line =~ $signoff_re ]]; then
      email="$(lower "${BASH_REMATCH[1]}")"
      if [[ $email == "$author" || $email == "$committer" ]]; then
        return 0
      fi
    fi
  done < <(git show -s --format=%B "$sha" | git interpret-trailers --parse)
  return 1
}

# Resolve the range up front: a failure inside a process substitution would be
# ignored by `set -e` and let an unresolvable range pass as "nothing to check".
commits="$(git rev-list --no-merges --reverse "$base..$head")"

pr_author="${PR_AUTHOR:-}"
for exempt in "${exempt_authors[@]}"; do
  if [[ -n $pr_author && $pr_author == "$exempt" ]]; then
    printf 'Pull request opened by %s: sign-off not required.\n' "$exempt"
    exit 0
  fi
done

checked=0
failed=()
while IFS= read -r sha; do
  [[ -n $sha ]] || continue
  checked=$((checked + 1))
  if ! has_valid_signoff "$sha"; then
    failed+=("$(git show -s --format='%h %s' "$sha")")
  fi
done <<<"$commits"

if ((${#failed[@]} > 0)); then
  printf 'DCO sign-off missing or invalid on %d of %d commit(s):\n' "${#failed[@]}" "$checked"
  printf '  %s\n' "${failed[@]}"
  cat <<'EOF'

Each commit needs a "Signed-off-by: Name <email>" trailer whose email matches
the commit's author or committer.

  Sign every commit on the branch:  git rebase --signoff origin/main
                                    git push --force-with-lease
  Sign only the latest commit:      git commit --amend --signoff --no-edit

See CONTRIBUTING.md#developer-certificate-of-origin
EOF
  exit 1
fi

printf 'DCO sign-off present on all %d checked commit(s).\n' "$checked"
