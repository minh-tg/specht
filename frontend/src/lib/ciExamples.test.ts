import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  CI_EXAMPLES,
  EXAMPLE_PROJECT,
  GENERATED_HEADER,
  githubActionsExample,
  gitlabCiExample,
} from "../../scripts/ciExamples.ts";

/** Resolve a path relative to the repository root; vitest runs from frontend/. */
function repoFile(path: string): string {
  return resolve(process.cwd(), "..", path);
}

describe("ciExamples", () => {
  it.each(CI_EXAMPLES)("keeps $path identical to the generator output", ({ path, content }) => {
    expect(readFileSync(repoFile(path), "utf8")).toBe(content);
  });

  it("tells the reader the file is generated and how to regenerate it", () => {
    expect(GENERATED_HEADER).toContain("generated");
    expect(GENERATED_HEADER).toContain("pnpm --dir frontend ci:examples");
    for (const { content } of CI_EXAMPLES) {
      expect(content.startsWith(GENERATED_HEADER)).toBe(true);
    }
  });

  it("fills the examples with the documented placeholders", () => {
    for (const { content } of CI_EXAMPLES) {
      expect(content).toContain(EXAMPLE_PROJECT);
      expect(content).toContain("vX.Y.Z");
      expect(content).not.toContain("go run");
      expect(content).not.toContain("jq");
    }
  });

  it("renders different content for the two providers", () => {
    expect(githubActionsExample()).toContain("minh-tg/specht@vX.Y.Z");
    expect(gitlabCiExample()).toContain("ghcr.io/minh-tg/specht-adapter:vX.Y.Z");
  });
});
