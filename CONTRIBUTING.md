# Contributing to Specht

Thanks for considering a contribution. This project is licensed under the
[GNU Affero General Public License v3.0](LICENSE).

## Developer Certificate of Origin

Contributions follow the [Developer Certificate of Origin, version
1.1](https://developercertificate.org/). By signing off a commit, you certify
that you have the right to submit the work and that it may be distributed
under this project's AGPL-3.0 license.

Sign off each commit with:

```bash
git commit -s -m "type(scope): description"
```

The commit must contain a trailer like this:

```text
Signed-off-by: Your Name <you@example.com>
```

All commits in a pull request must be signed off. Do not sign off a
contribution you did not author or do not have permission to submit.

The `dco` check on every pull request fails when a commit has no
`Signed-off-by` trailer whose email matches the commit's author or committer.
Commits by bot accounts such as Dependabot are exempt. To sign off a branch
that is missing it:

```bash
git rebase --signoff origin/main
git push --force-with-lease
```

Installing the hooks with `prek install` also signs off for you: the
`dco-signoff` hook adds the trailer from your git identity when you commit, so
`-s` becomes optional. The sign-off still certifies the statement above, so
review what you commit.

Maintainers: squash merges keep each commit's sign-off because the repository
builds the squash message from the commit messages. Leave that setting as is.

## Development

- Commits are checked by pre-commit hooks (installed via `prek install`):
  gofumpt, staticcheck, `go vet`, `go mod tidy`, dprint/oxlint (frontend),
  hadolint, gitleaks, conventional-commit message validation, and an automatic
  DCO sign-off.
- Run the test suite with `go test ./... -count=1 -short` (unit) or
  `go test -tags integration ./internal/repo/ -count=1` (needs Docker for
  testcontainers).
- Keep pull requests focused and reasonably sized.

### Reproducible CI inputs

The Nix development environment uses the committed `flake.lock` for its
`nixos-unstable` input. Refresh it deliberately with `nix flake lock` during
quarterly dependency maintenance (or sooner for a security fix), then review
the resulting input changes; do not update the lock opportunistically in
unrelated pull requests.
