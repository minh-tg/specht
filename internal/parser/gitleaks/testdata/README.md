# Gitleaks fixtures

`gitleaks-two-secrets.json` is a real Gitleaks 8.30.1 report of a `.env` file
with two different keys of one rule (`generic-api-key`) on lines 2 and 3.

- Command: `gitleaks detect --source . --report-format json --report-path report.json`
- Changes: the two secret values (and the matches that contain them) are replaced
  by distinct placeholders, so the file holds nothing a secret scanner would
  flag, and the author, date and commit are replaced.

`gitleaks.json` is an earlier capture used by the other tests.

`gitleaks-two-secrets.sarif`, `gitleaks-history.sarif` and `gitleaks-redacted.sarif`
are real Gitleaks 8.30.1 SARIF reports of a `.env` file with two GitHub tokens.

- Commands: `gitleaks detect --source . --no-git --report-format sarif` (two secrets),
  `gitleaks detect --source . --report-format sarif` over three commits (history, where
  one token is in two commits at different lines) and `--no-git --redact` (redacted).
- Changes: the tokens are replaced by placeholders, the rule list is cut to the one rule
  that fired, and the commit ids, author, email and dates are replaced.

`gitleaks-dir-mode.json` and `gitleaks-dir-mode.sarif` are real Gitleaks 8.30.1 reports
of a directory scan that holds `config/app.env` with one Slack bot token.

- Command: `gitleaks dir --report-format json --report-path report.json /abs/path/to/repo`
  (and `--report-format sarif`). Both formats write the absolute path in `File` and in the
  SARIF `uri`; `gitleaks dir .` writes `config/app.env`.
- Changes: the temporary directory in the path is replaced by `/src/`, the token is
  replaced by a placeholder, and the SARIF rule list is cut to the one rule that fired.
