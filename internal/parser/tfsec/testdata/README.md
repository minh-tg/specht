# tfsec fixtures

`tfsec-two-modules.json` is a real tfsec 1.28.14 report of two directories,
`a/` and `b/`, whose `main.tf` each declare `aws_s3_bucket.this`: nine failed
checks per directory.

- Command: `tfsec . --format json --out tfsec.json`
- Changes: the scan directory in each absolute `filename` is replaced by
  `/src/infra`.

`tfsec.json` is a hand-written report used by the other tests.
