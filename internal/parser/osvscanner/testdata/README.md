# OSV-Scanner fixtures

`two-lockfiles.json` is an OSV-Scanner report of two npm lockfiles with
lodash 4.17.20 in one and 4.17.15 in the other, both affected by
GHSA-29mw-wpgm-hmr9. The first result is real OSV-Scanner output; the second
is a copy of it with the lockfile path and the installed version changed.

- Command: `osv-scanner scan source --format json -L package-lock.json`
- Changes: the first lockfile path is replaced by `/repo/app/package-lock.json`.
