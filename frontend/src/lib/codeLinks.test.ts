import { describe, expect, it } from "vitest";

import { codeSource, fileUrl, pullRequestUrl } from "@/lib/codeLinks";

const SHA = "9fceb02d0ae598e95dc970b74767f19372d61af8";

describe("codeSource", () => {
  it("recognizes GitHub and GitLab by their public hosts", () => {
    expect(codeSource({ repository_url: "https://github.com/acme/shop", commit_sha: SHA })).toEqual(
      {
        repoUrl: "https://github.com/acme/shop",
        host: "github",
        commit: SHA,
      },
    );
    expect(codeSource({ repository_url: "https://gitlab.com/acme/shop/" })?.host).toBe("gitlab");
  });

  it("recognizes a self-hosted instance by its run address", () => {
    expect(
      codeSource({
        repository_url: "https://git.corp.example/acme/shop",
        ci_run_url: "https://git.corp.example/acme/shop/actions/runs/4",
      })?.host,
    ).toBe("github");
    expect(
      codeSource({
        repository_url: "https://code.corp.example/acme/shop",
        ci_run_url: "https://code.corp.example/acme/shop/-/jobs/77",
      })?.host,
    ).toBe("gitlab");
  });

  it("gives no source for an unknown host, a missing URL or a non-http scheme", () => {
    expect(codeSource({ repository_url: "https://bitbucket.org/acme/shop" })).toBeNull();
    expect(codeSource({})).toBeNull();
    expect(codeSource({ repository_url: "javascript:alert(1)" })).toBeNull();
  });

  it("keeps the commit only when it is a hex SHA", () => {
    expect(codeSource({ repository_url: "https://github.com/a/b", commit_sha: "v1.2.3" })?.commit)
      .toBeUndefined();
  });
});

describe("pullRequestUrl", () => {
  const gh = codeSource({ repository_url: "https://github.com/acme/shop" })!;
  const gl = codeSource({ repository_url: "https://gitlab.com/acme/shop" })!;

  it("links the host's pull or merge request page", () => {
    expect(pullRequestUrl(gh, 123)).toBe("https://github.com/acme/shop/pull/123");
    expect(pullRequestUrl(gl, 15)).toBe("https://gitlab.com/acme/shop/-/merge_requests/15");
  });

  it("gives nothing without a number", () => {
    expect(pullRequestUrl(gh, undefined)).toBeNull();
    expect(pullRequestUrl(gh, 0)).toBeNull();
  });
});

describe("fileUrl", () => {
  const gh = codeSource({ repository_url: "https://github.com/acme/shop", commit_sha: SHA })!;
  const gl = codeSource({ repository_url: "https://gitlab.com/acme/shop", commit_sha: SHA })!;

  it("links the file at the commit and line", () => {
    expect(fileUrl(gh, "src/app.ts", 12)).toBe(
      `https://github.com/acme/shop/blob/${SHA}/src/app.ts#L12`,
    );
    expect(fileUrl(gl, "./src/app.ts")).toBe(
      `https://gitlab.com/acme/shop/-/blob/${SHA}/src/app.ts`,
    );
  });

  it("encodes each path segment", () => {
    expect(fileUrl(gh, "docs/a b#c.md")).toBe(
      `https://github.com/acme/shop/blob/${SHA}/docs/a%20b%23c.md`,
    );
  });

  it("links nothing outside the repository or without a commit", () => {
    expect(fileUrl(gh, "/etc/passwd")).toBeNull();
    expect(fileUrl(gh, "../secrets.txt")).toBeNull();
    expect(fileUrl(gh, "https://example.com/x")).toBeNull();
    expect(fileUrl(gh, "C:\\repo\\a.go")).toBeNull();
    expect(fileUrl(gh, undefined)).toBeNull();
    expect(fileUrl({ ...gh, commit: undefined }, "src/app.ts")).toBeNull();
  });
});
