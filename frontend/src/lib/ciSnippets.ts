export interface CiSnippetOptions {
  /** Specht base URL the pipeline talks to, e.g. window.location.origin. */
  apiUrl: string;
  /** Target project slug. */
  project: string;
}

/**
 * GitHub Actions workflow for the Specht gate: scan with Trivy, wrap the raw
 * JSON in an ingest envelope, then ingest and evaluate the gate with the
 * adapter (see examples/ci/github-actions.yml). The API key is only ever read
 * from the SPECHT_API_KEY secret, never inlined into the workflow.
 */
export function githubActionsSnippet({ apiUrl, project }: CiSnippetOptions): string {
  return `# Specht gate for GitHub Actions.
#
# Store the API key you created above as the SPECHT_API_KEY repository secret
# (Settings > Secrets and variables > Actions). Never commit it.
#
# Exit codes: 0 gate passed, 1 severity threshold breached, 2 runtime error.

name: specht-gate

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  specht:
    runs-on: ubuntu-latest
    env:
      SPECHT_API_URL: ${apiUrl}
      SPECHT_PROJECT: ${project}
      SPECHT_ENVIRONMENT: ci
    steps:
      - uses: actions/checkout@v4

      - name: Scan with Trivy
        uses: aquasecurity/trivy-action@v0.24.0
        with:
          scan-type: fs
          format: json
          output: trivy-results.json
          exit-code: "0"

      - name: Ingest and gate with Specht
        env:
          API_URL: \${{ env.SPECHT_API_URL }}
          API_KEY: \${{ secrets.SPECHT_API_KEY }}
          PROJECT: \${{ env.SPECHT_PROJECT }}
          BRANCH: \${{ github.head_ref || github.ref_name }}
          COMMIT_SHA: \${{ github.sha }}
          REPOSITORY: \${{ github.repository }}
        run: |
          go run ./cmd/adapter \\
            -project "$PROJECT" \\
            -tool trivy < <(jq -n \\
              --arg project "$PROJECT" \\
              --arg branch "$BRANCH" \\
              --arg commit "$COMMIT_SHA" \\
              --arg env "$SPECHT_ENVIRONMENT" \\
              --arg owner "github://$REPOSITORY" \\
              --slurpfile raw trivy-results.json \\
              '{project: $project, scanner: "trivy",
                branch: $branch, commit_sha: $commit,
                environment: $env, owner: $owner,
                raw_data: $raw[0]}')
`;
}

/**
 * GitLab CI pipeline for the Specht gate: same scan, adapter and gate steps as
 * the GitHub Actions template (see examples/ci/gitlab-ci.yml). The API key is
 * read from the masked SPECHT_API_KEY CI/CD variable, never inlined.
 */
export function gitlabCiSnippet({ apiUrl, project }: CiSnippetOptions): string {
  return `# Specht gate for GitLab CI.
#
# Store the API key you created above as the masked SPECHT_API_KEY CI/CD
# variable (Settings > CI/CD > Variables). Never commit it.
#
# Exit codes: 0 gate passed, 1 severity threshold breached, 2 runtime error.

stages: [scan, gate]

variables:
  SPECHT_API_URL: ${apiUrl}
  SPECHT_PROJECT: ${project}
  SPECHT_ENVIRONMENT: ci

trivy-scan:
  stage: scan
  image:
    name: aquasec/trivy:0.59.0
    entrypoint: [""]
  script:
    - trivy fs --format json --output trivy-results.json --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL .
  artifacts:
    paths: [trivy-results.json]

specht-gate:
  stage: gate
  image: golang:1.26-bookworm
  needs: [trivy-scan]
  variables:
    API_URL: $SPECHT_API_URL
    API_KEY: $SPECHT_API_KEY
    PROJECT: $SPECHT_PROJECT
  script:
    - |
      jq -n \\
        --arg project "$PROJECT" \\
        --arg branch "$CI_COMMIT_REF_NAME" \\
        --arg commit "$CI_COMMIT_SHA" \\
        --arg env "$SPECHT_ENVIRONMENT" \\
        --arg owner "gitlab://$CI_PROJECT_PATH" \\
        --slurpfile raw trivy-results.json \\
        '{project: $project, scanner: "trivy",
          branch: $branch, commit_sha: $commit,
          environment: $env, owner: $owner,
          raw_data: $raw[0]}' \\
      | go run ./cmd/adapter -project "$PROJECT" -tool trivy
`;
}
