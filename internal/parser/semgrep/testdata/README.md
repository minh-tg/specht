# Semgrep fixtures

`semgrep-native.json` and `semgrep-native-sarif.json` are the same scan of one
small project in both output formats. They hold three findings: a formatted SQL
query and a shell=True call in `app.py`, and a Dockerfile that ends as root.

- Tool: Semgrep 1.172.0 (OSS engine), rules from `--config auto`.
- Native: `semgrep scan --config auto --json`
- SARIF: `semgrep scan --config auto --sarif`
- Changes: three results kept in each, profiling and skipped-rule blocks
  dropped, unused rules removed from the SARIF.

`semgrep-sarif.json` is an older SARIF capture used by the other tests.
