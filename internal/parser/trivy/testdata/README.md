# Trivy fixtures

`two-resources-misconfig.json` is a real Trivy 0.76.0 report of a `main.tf`
with two S3 buckets (`aws_s3_bucket.a`, `aws_s3_bucket.b`) and two security
group rules: 19 failed checks, each on its own resource.

- Command: `trivy config --format json -o report.json .`

`two-secrets.json` is a real Trivy 0.76.0 report of a `cred.env` with two
GitHub tokens of one rule on lines 1 and 2. Trivy masks the token in `Match`
and `Code`, so the file holds no credential.

- Command: `trivy fs --scanners secret --format json -o report.json .`
