#!/usr/bin/env bash
# Exercises scripts/check-dco.sh and scripts/dco-signoff.sh against a
# throwaway repository. Run from anywhere: scripts/dco_test.sh
set -euo pipefail

scripts="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Ignore the caller's git configuration (global hooks, signing, templates).
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME="Ada Dev" GIT_AUTHOR_EMAIL="ada@example.com"
export GIT_COMMITTER_NAME="Ada Dev" GIT_COMMITTER_EMAIL="ada@example.com"

cd "$work"
git init -q -b main .
git commit -q --allow-empty -m "chore: base"
base="$(git rev-parse HEAD)"

failures=0

report() {
  if [[ $2 == "$3" ]]; then
    printf 'ok   - %s\n' "$1"
  else
    printf 'FAIL - %s (wanted %s, got %s)\n' "$1" "$3" "$2"
    failures=$((failures + 1))
  fi
}

# expect_check <name> <pass|fail> <base> <head>
expect_check() {
  local got=pass
  "$scripts/check-dco.sh" "$3" "$4" >/dev/null 2>&1 || got=fail
  report "$1" "$got" "$2"
}

reset() {
  git switch -q main
  git reset -q --hard "$base"
}

signed="$(printf 'feat: a\n\nSigned-off-by: Ada Dev <ada@example.com>')"

reset
git commit -q --allow-empty -m "$signed"
expect_check "valid sign-off passes" pass "$base" HEAD

reset
git commit -q --allow-empty -m "feat: a"
expect_check "missing sign-off fails" fail "$base" HEAD

reset
git commit -q --allow-empty -m "$(printf 'feat: a\n\nSigned-off-by: Eve <eve@example.com>')"
expect_check "sign-off from another email fails" fail "$base" HEAD

reset
GIT_AUTHOR_EMAIL=bob@example.com git commit -q --allow-empty -m "$signed"
expect_check "sign-off matching only the committer passes" pass "$base" HEAD

reset
git commit -q --allow-empty -m "$(printf 'feat: a\n\nSigned-off-by: ADA Dev <ADA@Example.COM>')"
expect_check "email comparison ignores case" pass "$base" HEAD

reset
git commit -q --allow-empty -m "$(printf 'feat: a\n\nSigned-off-by: Ada')"
expect_check "malformed trailer fails" fail "$base" HEAD

reset
git commit -q --allow-empty -m "$(printf 'feat: a\n\nSigned-off-by: Ada Dev <ada@example.com>\n\nA closing paragraph.')"
expect_check "sign-off outside the trailer block fails" fail "$base" HEAD

reset
GIT_AUTHOR_EMAIL='49699333+dependabot[bot]@users.noreply.github.com' git commit -q --allow-empty -m "build(deps): bump x"
expect_check "bot commits are exempt" pass "$base" HEAD

reset
git commit -q --allow-empty -m "$signed"
git commit -q --allow-empty -m "feat: b"
expect_check "one unsigned commit among several fails" fail "$base" HEAD

reset
git commit -q --allow-empty -m "$signed"
git commit -q --allow-empty -m "$(printf 'feat: b\n\nSigned-off-by: Ada Dev <ada@example.com>')"
expect_check "several signed commits pass" pass "$base" HEAD

reset
git switch -q -c side
git commit -q --allow-empty -m "$signed"
git switch -q main
git commit -q --allow-empty -m "chore: unrelated commit already on the base branch"
main_tip="$(git rev-parse HEAD)"
git switch -q side
git merge -q --no-ff -m "Merge main into side" main
expect_check "merge commits are skipped" pass "$main_tip" HEAD
git switch -q main
git branch -q -D side

reset
expect_check "empty range passes" pass "$base" HEAD
expect_check "unresolvable range fails closed" fail 0000000000000000000000000000000000000000 HEAD

# dco-signoff.sh
msg="$work/COMMIT_EDITMSG"
sign() { "$scripts/dco-signoff.sh" "$msg"; }
trailer='Signed-off-by: Ada Dev <ada@example.com>'

printf 'feat: a\n' >"$msg"
sign
report "hook appends the committer sign-off" "$(cat "$msg")" "$(printf 'feat: a\n\n%s' "$trailer")"

sign
report "hook is idempotent" "$(cat "$msg")" "$(printf 'feat: a\n\n%s' "$trailer")"

printf 'feat: a\n\n%s\n' "$trailer" >"$msg"
sign
report "hook leaves a message already signed with -s unchanged" "$(cat "$msg")" "$(printf 'feat: a\n\n%s' "$trailer")"

printf 'feat: a\n\n# Please enter the commit message\n' >"$msg"
sign
report "hook keeps editor comments below the trailer" "$(cat "$msg")" \
  "$(printf 'feat: a\n\n%s\n\n# Please enter the commit message' "$trailer")"

printf 'feat: a\n\nCo-authored-by: Bob <bob@example.com>\n' >"$msg"
sign
report "hook adds to an existing trailer block" "$(cat "$msg")" \
  "$(printf 'feat: a\n\nCo-authored-by: Bob <bob@example.com>\n%s' "$trailer")"

reset
printf 'feat: a\n' >"$msg"
sign
git commit -q --allow-empty -F "$msg"
expect_check "a commit signed by the hook passes the check" pass "$base" HEAD

if ((failures > 0)); then
  printf '%d check(s) failed\n' "$failures"
  exit 1
fi
echo "all DCO script checks passed"
