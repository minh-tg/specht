import { describe, expect, it } from "vitest";
import {
  githubActionsSnippet,
  gitlabCiSnippet,
  releaseTagFor,
  VERSION_PLACEHOLDER,
} from "./ciSnippets";

const API_URL = "https://specht.example.com";
const PROJECT = "acme-api";
const VERSION = "v1.2.3";
const OPTIONS = { apiUrl: API_URL, project: PROJECT, version: VERSION };
/** Stand-in for the one-time secret: it must never reach a snippet. */
const RAW_KEY = "sk-live-0123456789abcdef";

const snippets = [
  ["githubActionsSnippet", githubActionsSnippet],
  ["gitlabCiSnippet", gitlabCiSnippet],
] as const;

describe("ciSnippets", () => {
  it.each(snippets)(
    "%s embeds the API URL, the project slug and the pinned release tag",
    (_name, build) => {
      const snippet = build(OPTIONS);
      expect(snippet).toContain(API_URL);
      expect(snippet).toContain(PROJECT);
      expect(snippet).toContain(VERSION);
    },
  );

  it.each(snippets)("%s needs no Go toolchain and no jq", (_name, build) => {
    const snippet = build(OPTIONS);
    expect(snippet).not.toContain("go run");
    expect(snippet).not.toContain("./cmd/adapter");
    expect(snippet).not.toContain("jq");
    expect(snippet).not.toContain("cmd/adapter@");
  });

  it.each(snippets)("%s never embeds a key value", (_name, build) => {
    const snippet = build(OPTIONS);
    expect(snippet).not.toContain("raw_key");
    expect(snippet).not.toContain(RAW_KEY);
  });

  it("scans with the same Trivy version in both pipelines", () => {
    const github = githubActionsSnippet(OPTIONS);
    const gitlab = gitlabCiSnippet(OPTIONS);
    const match = /version: v(\d+\.\d+\.\d+)/.exec(github);
    expect(match).not.toBeNull();
    const version = match?.[1] ?? "";
    expect(version).not.toBe("");
    expect(gitlab).toContain(`aquasec/trivy:${version}`);
  });

  it("pins the GitHub Actions steps by commit hash", () => {
    const snippet = githubActionsSnippet(OPTIONS);
    expect(snippet).toContain("actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4");
    expect(snippet).toContain(
      "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0",
    );
    expect(snippet).toContain("scan-type: fs");
    expect(snippet).toContain("format: json");
    expect(snippet).toContain("output: trivy-results.json");
    expect(snippet).toContain("exit-code: \"0\"");
    expect(snippet).toContain("severity: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL");
    expect(snippet).toContain("version: v");
  });

  it("runs the Specht action at the pinned release tag", () => {
    const snippet = githubActionsSnippet(OPTIONS);
    expect(snippet).toContain(`uses: minh-tg/specht@${VERSION}`);
    expect(snippet).toContain("file: trivy-results.json");
    expect(snippet).toContain("tool: trivy");
  });

  it("grants only contents: read and marks checks: write as optional", () => {
    const snippet = githubActionsSnippet(OPTIONS);
    expect(snippet).toContain("contents: read");
    expect(snippet).toContain("Optional");
    expect(snippet).toContain("# checks: write");
    expect(snippet).not.toMatch(/^\s+checks: write$/m);
  });

  it("explains that fork pull requests skip the gate", () => {
    expect(githubActionsSnippet(OPTIONS)).toContain("forks skip the gate");
  });

  it("references the key as a secret in the GitHub Actions workflow", () => {
    const snippet = githubActionsSnippet(OPTIONS);
    expect(snippet).toContain("${{ secrets.SPECHT_API_KEY }}");
    expect(snippet).not.toContain("API_KEY: sk-");
  });

  it("runs the adapter image at the pinned release tag in GitLab", () => {
    const snippet = gitlabCiSnippet(OPTIONS);
    expect(snippet).toContain(`ghcr.io/minh-tg/specht-adapter:${VERSION}`);
    expect(snippet).toContain("specht-adapter -file trivy-results.json -tool trivy");
    expect(snippet).toContain("-project \"$SPECHT_PROJECT\"");
  });

  it("clears the image entrypoint so the GitLab runner can use a shell", () => {
    const snippet = gitlabCiSnippet(OPTIONS);
    expect(snippet).toContain("entrypoint: [\"\"]");
  });

  it("keeps the variables the GitLab adapter reads", () => {
    const snippet = gitlabCiSnippet(OPTIONS);
    expect(snippet).toContain("SPECHT_API_URL");
    expect(snippet).toContain("SPECHT_PROJECT");
    expect(snippet).toContain("masked SPECHT_API_KEY");
  });

  it("produces the scan artifact the gate job consumes", () => {
    const snippet = gitlabCiSnippet(OPTIONS);
    expect(snippet).toContain("stage: scan");
    expect(snippet).toContain("stage: gate");
    expect(snippet).toContain("paths: [trivy-results.json]");
    expect(snippet).toContain("needs: [trivy-scan]");
  });
});

describe("releaseTagFor", () => {
  it("pins a plain release version with a leading v", () => {
    expect(releaseTagFor({ version: "1.2.3", commit: "4f93c32" })).toBe("v1.2.3");
    expect(releaseTagFor({ version: "v1.2.3", commit: "4f93c32" })).toBe("v1.2.3");
    expect(releaseTagFor({ version: "10.20.30", commit: "" })).toBe("v10.20.30");
  });

  it("keeps the prerelease suffix", () => {
    expect(releaseTagFor({ version: "1.2.3-rc.1", commit: "" })).toBe("v1.2.3-rc.1");
    expect(releaseTagFor({ version: "v1.2.3-beta.2", commit: "" })).toBe("v1.2.3-beta.2");
  });

  it("ignores whitespace around the version", () => {
    expect(releaseTagFor({ version: " v1.2.3 ", commit: "" })).toBe("v1.2.3");
  });

  it("falls back when the build is not a release", () => {
    expect(releaseTagFor()).toBeUndefined();
    expect(releaseTagFor({ version: "dev", commit: "4f93c32" })).toBeUndefined();
    expect(releaseTagFor({ version: "unknown", commit: "" })).toBeUndefined();
    expect(releaseTagFor({ version: "", commit: "" })).toBeUndefined();
  });

  it("never pins a commit-like or moving ref", () => {
    expect(releaseTagFor({ version: "4f93c32a1b2c3d4e5f60718293a4b5c6d7e8f901", commit: "" }))
      .toBeUndefined();
    expect(releaseTagFor({ version: "main", commit: "4f93c32" })).toBeUndefined();
    expect(releaseTagFor({ version: "latest", commit: "" })).toBeUndefined();
    expect(releaseTagFor({ version: "1.2", commit: "" })).toBeUndefined();
    expect(releaseTagFor({ version: "1.2.3.4", commit: "" })).toBeUndefined();
  });

  it("offers a placeholder for the setup page to fall back to", () => {
    expect(VERSION_PLACEHOLDER).toBe("vX.Y.Z");
  });
});
