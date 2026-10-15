# Gitleaks fixtures

`gitleaks-two-secrets.json` is a real Gitleaks 8.30.1 report of a `.env` file
with two different keys of one rule (`generic-api-key`) on lines 2 and 3.

- Command: `gitleaks detect --source . --report-format json --report-path report.json`
- Changes: the two secret values (and the matches that contain them) are replaced
  by distinct placeholders, so the file holds nothing a secret scanner would
  flag, and the author, date and commit are replaced.

`gitleaks.json` is an earlier capture used by the other tests.
