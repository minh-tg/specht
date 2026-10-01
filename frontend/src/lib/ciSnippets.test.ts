import { describe, expect, it } from "vitest";
import { githubActionsSnippet, gitlabCiSnippet } from "./ciSnippets";

const API_URL = "https://specht.example.com";
const PROJECT = "acme-api";
/** Stand-in for the one-time secret: it must never reach a snippet. */
const RAW_KEY = "sk-live-0123456789abcdef";

const snippets = [
  ["githubActionsSnippet", githubActionsSnippet],
  ["gitlabCiSnippet", gitlabCiSnippet],
] as const;

describe("ciSnippets", () => {
  it.each(snippets)("%s embeds the API URL and the project slug", (_name, build) => {
    const snippet = build({ apiUrl: API_URL, project: PROJECT });
    expect(snippet).toContain(API_URL);
    expect(snippet).toContain(PROJECT);
  });

  it.each(snippets)("%s never embeds a key value", (_name, build) => {
    const snippet = build({ apiUrl: API_URL, project: PROJECT });
    expect(snippet).not.toContain("raw_key");
    expect(snippet).not.toContain(RAW_KEY);
  });

  it.each(snippets)("%s keeps the documented environment variable names", (_name, build) => {
    const snippet = build({ apiUrl: API_URL, project: PROJECT });
    expect(snippet).toContain("SPECHT_API_URL");
    expect(snippet).toContain("SPECHT_API_KEY");
    expect(snippet).toContain("SPECHT_PROJECT");
  });

  it("references the key as a secret in the GitHub Actions workflow", () => {
    const snippet = githubActionsSnippet({ apiUrl: API_URL, project: PROJECT });
    expect(snippet).toContain("${{ secrets.SPECHT_API_KEY }}");
    expect(snippet).not.toContain("API_KEY: sk-");
  });

  it("references the key as a variable in the GitLab CI pipeline", () => {
    const snippet = gitlabCiSnippet({ apiUrl: API_URL, project: PROJECT });
    expect(snippet).toContain("$SPECHT_API_KEY");
  });

  it("keeps the scan, adapter and gate steps of the shipped examples", () => {
    const github = githubActionsSnippet({ apiUrl: API_URL, project: PROJECT });
    expect(github).toContain("aquasecurity/trivy-action");
    expect(github).toContain("./cmd/adapter");

    const gitlab = gitlabCiSnippet({ apiUrl: API_URL, project: PROJECT });
    expect(gitlab).toContain("aquasec/trivy");
    expect(gitlab).toContain("./cmd/adapter");
    expect(gitlab).toContain("specht-gate");
  });
});
