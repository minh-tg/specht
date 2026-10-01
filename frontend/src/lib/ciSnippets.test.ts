import { describe, expect, it } from "vitest";
import { adapterRefFor, githubActionsSnippet, gitlabCiSnippet } from "./ciSnippets";

const API_URL = "https://specht.example.com";
const PROJECT = "acme-api";
const ADAPTER_REF = "4f93c32a1b2c3d4e5f60718293a4b5c6d7e8f901";
/** Stand-in for the one-time secret: it must never reach a snippet. */
const RAW_KEY = "sk-live-0123456789abcdef";

const snippets = [
  ["githubActionsSnippet", githubActionsSnippet],
  ["gitlabCiSnippet", gitlabCiSnippet],
] as const;

describe("ciSnippets", () => {
  it.each(snippets)(
    "%s embeds the API URL, the project slug and the adapter ref",
    (_name, build) => {
      const snippet = build({ apiUrl: API_URL, project: PROJECT, adapterRef: ADAPTER_REF });
      expect(snippet).toContain(API_URL);
      expect(snippet).toContain(PROJECT);
      expect(snippet).toContain(`cmd/adapter@${ADAPTER_REF}`);
      expect(snippet).not.toContain("./cmd/adapter");
    },
  );

  it.each(snippets)("%s never embeds a key value", (_name, build) => {
    const snippet = build({ apiUrl: API_URL, project: PROJECT, adapterRef: ADAPTER_REF });
    expect(snippet).not.toContain("raw_key");
    expect(snippet).not.toContain(RAW_KEY);
  });

  it.each(snippets)("%s keeps the documented environment variable names", (_name, build) => {
    const snippet = build({ apiUrl: API_URL, project: PROJECT, adapterRef: ADAPTER_REF });
    expect(snippet).toContain("SPECHT_API_URL");
    expect(snippet).toContain("SPECHT_API_KEY");
    expect(snippet).toContain("SPECHT_PROJECT");
  });

  it.each(snippets)("%s explains that the adapter runs from source", (_name, build) => {
    const snippet = build({ apiUrl: API_URL, project: PROJECT, adapterRef: ADAPTER_REF });
    expect(snippet).toContain(
      "# The adapter runs from source at the same build as your Specht server (standalone binaries are not published yet; requires Go).",
    );
  });

  it("references the key as a secret in the GitHub Actions workflow", () => {
    const snippet = githubActionsSnippet({
      apiUrl: API_URL,
      project: PROJECT,
      adapterRef: ADAPTER_REF,
    });
    expect(snippet).toContain("${{ secrets.SPECHT_API_KEY }}");
    expect(snippet).not.toContain("API_KEY: sk-");
  });

  it("pins the GitHub Actions steps by commit hash", () => {
    const snippet = githubActionsSnippet({
      apiUrl: API_URL,
      project: PROJECT,
      adapterRef: ADAPTER_REF,
    });
    expect(snippet).toContain(
      "actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4",
    );
    expect(snippet).toContain(
      "aquasecurity/trivy-action@6e7b7d1fd3e4fef0c5fa8cce1229c54b2c9bd0d8 # v0.24.0",
    );
    expect(snippet).toContain("severity: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL");
  });

  it("references the key as a variable in the GitLab CI pipeline", () => {
    const snippet = gitlabCiSnippet({ apiUrl: API_URL, project: PROJECT, adapterRef: ADAPTER_REF });
    expect(snippet).toContain("$SPECHT_API_KEY");
  });

  it("keeps the scan, adapter and gate steps of the shipped examples", () => {
    const github = githubActionsSnippet({
      apiUrl: API_URL,
      project: PROJECT,
      adapterRef: ADAPTER_REF,
    });
    expect(github).toContain("aquasecurity/trivy-action");
    expect(github).toContain("github.com/minh-tg/specht/cmd/adapter@");

    const gitlab = gitlabCiSnippet({ apiUrl: API_URL, project: PROJECT, adapterRef: ADAPTER_REF });
    expect(gitlab).toContain("aquasec/trivy");
    expect(gitlab).toContain("github.com/minh-tg/specht/cmd/adapter@");
    expect(gitlab).toContain("specht-gate");
  });
});

describe("adapterRefFor", () => {
  it("returns the server commit when it is a hex hash", () => {
    expect(adapterRefFor({ version: "1.2.3", commit: "4f93c32" })).toBe("4f93c32");
    expect(adapterRefFor({ version: "dev", commit: "a1b2c3d" })).toBe("a1b2c3d");
    expect(adapterRefFor({ version: "dev", commit: "a".repeat(40) })).toBe("a".repeat(40));
  });

  it("falls back to main when the commit is unusable", () => {
    expect(adapterRefFor()).toBe("main");
    expect(adapterRefFor({ version: "1.2.3", commit: "" })).toBe("main");
    expect(adapterRefFor({ version: "1.2.3", commit: "unknown" })).toBe("main");
    expect(adapterRefFor({ version: "1.2.3", commit: "main" })).toBe("main");
  });

  it("rejects hashes that are too short or too long", () => {
    expect(adapterRefFor({ version: "1.2.3", commit: "abc123" })).toBe("main");
    expect(adapterRefFor({ version: "1.2.3", commit: "f".repeat(41) })).toBe("main");
  });

  it("rejects anything that is not made of hex digits", () => {
    expect(adapterRefFor({ version: "1.2.3", commit: "4f93c32z" })).toBe("main");
    expect(adapterRefFor({ version: "1.2.3", commit: "3.14.15" })).toBe("main");
    expect(adapterRefFor({ version: "1.2.3", commit: "release-1" })).toBe("main");
  });
});
