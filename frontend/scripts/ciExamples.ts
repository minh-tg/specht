import {
  githubActionsSnippet,
  gitlabCiSnippet,
  VERSION_PLACEHOLDER,
} from "../src/lib/ciSnippets.ts";

/**
 * Placeholder values for the checked-in example pipelines. The setup page
 * fills in the real API URL, project slug and server version.
 */
export const EXAMPLE_API_URL = "https://specht.example.com";
export const EXAMPLE_PROJECT = "my-app";

/**
 * Header shared by the generated example files, so a reader who opens
 * examples/ci/ knows the snippet source and how to refresh the file.
 */
export const GENERATED_HEADER = `# This file is generated. Do not edit it by hand.
#
# Source: frontend/src/lib/ciSnippets.ts, the same code that renders the
# snippet on the project setup page.
#
# Regenerate: pnpm --dir frontend ci:examples
`;

const EXAMPLE_OPTIONS = {
  apiUrl: EXAMPLE_API_URL,
  project: EXAMPLE_PROJECT,
  version: VERSION_PLACEHOLDER,
};

/** The GitHub Actions example exactly as the generator writes it. */
export function githubActionsExample(): string {
  return `${GENERATED_HEADER}\n${githubActionsSnippet(EXAMPLE_OPTIONS)}`;
}

/** The GitLab CI example exactly as the generator writes it. */
export function gitlabCiExample(): string {
  return `${GENERATED_HEADER}\n${gitlabCiSnippet(EXAMPLE_OPTIONS)}`;
}

/** The generated example files, by path relative to the repository root. */
export const CI_EXAMPLES: ReadonlyArray<{ path: string; content: string; }> = [
  { path: "examples/ci/github-actions.yml", content: githubActionsExample() },
  { path: "examples/ci/gitlab-ci.yml", content: gitlabCiExample() },
];
