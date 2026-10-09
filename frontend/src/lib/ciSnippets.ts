export interface CiSnippetOptions {
  /** Specht base URL the pipeline talks to, e.g. window.location.origin. */
  apiUrl: string;
  /** Target project slug. */
  project: string;
  /** Release tag of the Specht server the user is looking at, e.g. "v1.2.3".
   * Use VERSION_PLACEHOLDER when the server version is not a release. */
  version: string;
}

/**
 * The release tag written into the snippets when the server version is not a
 * release. The setup page tells the reader to replace it.
 */
export const VERSION_PLACEHOLDER = "vX.Y.Z";

/**
 * One Trivy version for both pipelines: the `version:` input of the pinned
 * trivy-action and the tag of the aquasec/trivy image in the GitLab pipeline.
 * They have to match so both providers scan with the same engine. The value
 * tracks the trivy-action revision pinned below.
 */
const TRIVY_VERSION = "0.70.0";

/** A release version: X.Y.Z, with or without the leading v, optional prerelease. */
const RELEASE_PATTERN = /^v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?)$/;

/**
 * The release tag the CI adapters should run, or undefined when the server did
 * not report a release version. Development, commit-pinned, unknown and
 * still-loading builds fall back to the caller; "main" and "latest" are never
 * pinned because a branch can change under a pipeline that already ran.
 */
export function releaseTagFor(version?: { version: string; commit: string; }): string | undefined {
  const raw = (version?.version ?? "").trim();
  const match = RELEASE_PATTERN.exec(raw);
  return match ? `v${match[1]}` : undefined;
}

/**
 * A YAML double-quoted scalar. JSON string syntax is valid YAML, so a value
 * with a newline, colon, quote or `#` stays inside its own line instead of
 * adding keys or jobs to the generated pipeline.
 */
function yamlString(value: string): string {
  return JSON.stringify(value);
}

/**
 * GitHub Actions workflow for the Specht gate: scan with Trivy, then run the
 * Specht action for the pinned release, which ingests the report and evaluates
 * the deployment gate. The action downloads a verified adapter binary, so the
 * runner needs no Go toolchain (see examples/ci/github-actions.yml). The API
 * key is only ever read from the SPECHT_API_KEY secret, never inlined.
 */
export function githubActionsSnippet({ apiUrl, project, version }: CiSnippetOptions): string {
  return `# Specht gate for GitHub Actions.
#
# Scans the checkout with Trivy, then runs the Specht adapter for the pinned
# release to ingest the report and evaluate the deployment gate. The adapter
# and the server must be the same release, so the action is pinned to a tag.
#
# Store the API key you created above as the SPECHT_API_KEY repository secret
# (Settings > Secrets and variables > Actions). Never commit it.
#
# Pull requests from forks skip the gate: they do not receive repository
# secrets, and no secret ever reaches untrusted code.
#
# Exit codes: 0 gate passed, 1 severity threshold breached, 2 runtime error.

name: specht-gate

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  # Optional: uncomment to publish the gate result as a GitHub check run.
  # checks: write

jobs:
  specht:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4

      - name: Scan with Trivy
        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0
        with:
          scan-type: fs
          format: json
          output: trivy-results.json
          exit-code: "0"
          severity: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL
          version: v${TRIVY_VERSION}

      - name: Gate with Specht
        uses: minh-tg/specht@${version}
        with:
          api-url: ${yamlString(apiUrl)}
          api-key: \${{ secrets.SPECHT_API_KEY }}
          project: ${yamlString(project)}
          file: trivy-results.json
          tool: trivy
`;
}

/**
 * GitLab CI pipeline for the Specht gate: the same scan and the same Trivy
 * version as the GitHub Actions template, then the adapter image of the pinned
 * release reads the artifact and evaluates the gate (see
 * examples/ci/gitlab-ci.yml). The image is cleared with `entrypoint: [""]` so
 * the runner can run it in a shell; it needs no jq and no Go. The API key is
 * read from the masked SPECHT_API_KEY CI/CD variable, never inlined.
 */
export function gitlabCiSnippet({ apiUrl, project, version }: CiSnippetOptions): string {
  return `# Specht gate for GitLab CI.
#
# Scans the checkout with Trivy, then runs the Specht adapter image for the
# pinned release on the scanner output. The adapter and the server must be the
# same release, so the image is pinned to a tag.
#
# Store the API key you created above as the masked SPECHT_API_KEY CI/CD
# variable (Settings > CI/CD > Variables). Never commit it.
#
# The adapter reads the commit, branch and project from the GitLab CI
# variables. Merge requests gate on what they introduce: on a merge request
# pipeline the gate script adds -introduced-only, and the adapter takes the
# target branch from CI_MERGE_REQUEST_TARGET_BRANCH_NAME. The default branch
# has no merge request, so it gates on the whole project.
#
# Optional: set SPECHT_ENVIRONMENT to name the deployed environment (defaults to ci).
#
# Exit codes: 0 gate passed, 1 severity threshold breached, 2 runtime error.

stages: [scan, gate]

# One pipeline per change: a merge request event or a push to the default
# branch, never both jobs from the branch and the merge request at once.
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

variables:
  SPECHT_API_URL: ${yamlString(apiUrl)}
  SPECHT_PROJECT: ${yamlString(project)}

trivy-scan:
  stage: scan
  image:
    name: aquasec/trivy:${TRIVY_VERSION}
    entrypoint: [""]
  script:
    - trivy fs --format json --output trivy-results.json --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL .
  artifacts:
    paths: [trivy-results.json]

specht-gate:
  stage: gate
  image:
    name: ghcr.io/minh-tg/specht-adapter:${version}
    entrypoint: [""]
  needs: [trivy-scan]
  script:
    - |
      set -- -file trivy-results.json -tool trivy -project "$SPECHT_PROJECT"
      if [ -n "$CI_MERGE_REQUEST_IID" ]; then
        set -- "$@" -introduced-only
      fi
      specht-adapter "$@"
`;
}
