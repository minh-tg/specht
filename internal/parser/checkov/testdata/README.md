# Checkov fixtures

`checkov-multi.json` is the output of one Checkov run over a directory that
holds Terraform, Kubernetes and a Dockerfile, so Checkov writes a JSON array
with one report per framework.

- Tool: Checkov 3.3.29 (container image `bridgecrew/checkov`)
- Command: `checkov -d . --framework terraform kubernetes dockerfile -o json --soft-fail`
- Changes: two failed checks kept per framework, code blocks shortened, the
  container path replaced by the repository-relative one.

The other files are single-framework reports (an object, not an array).
