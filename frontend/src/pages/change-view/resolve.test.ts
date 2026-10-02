import type { Report } from "@/types/api";
import { describe, expect, it } from "vitest";
import {
  existingBlockers,
  fixLine,
  floorSourceLabel,
  locationLine,
  resolveReport,
  shortCommit,
} from "./resolve";

const FULL_SHA = "abcdef1234567890abcdef1234567890abcdef12";

function report(overrides: Partial<Report> & { id: string; commit_sha: string; }): Report {
  return {
    project_id: "p1",
    tool_name: "trivy",
    tool_version: null,
    scan_type: "filesystem",
    scan_target: null,
    status: "completed",
    total_findings: 1,
    branch: "main",
    created_at: "2025-01-01T00:00:00Z",
    completed_at: null,
    ...overrides,
  };
}

describe("resolveReport", () => {
  it("resolves an exact full SHA", () => {
    const target = report({ id: "r1", commit_sha: FULL_SHA });
    const other = report({ id: "r2", commit_sha: "9999999999999999999999999999999999999999" });

    expect(resolveReport([other, target], FULL_SHA)?.id).toBe("r1");
  });

  it("resolves a prefix of at least seven characters", () => {
    const target = report({ id: "r1", commit_sha: FULL_SHA });

    expect(resolveReport([target], "abcdef1")?.id).toBe("r1");
  });

  it("matches the commit case-insensitively", () => {
    const target = report({ id: "r1", commit_sha: FULL_SHA.toUpperCase() });

    expect(resolveReport([target], "ABCDEF1")?.id).toBe("r1");
  });

  it("picks the newest matching report by created_at", () => {
    const older = report({
      id: "old",
      commit_sha: FULL_SHA,
      created_at: "2025-01-01T00:00:00Z",
    });
    const newer = report({
      id: "new",
      commit_sha: FULL_SHA,
      created_at: "2025-02-01T00:00:00Z",
    });

    expect(resolveReport([older, newer], "abcdef1")?.id).toBe("new");
    // Order in the response must not decide the winner.
    expect(resolveReport([newer, older], "abcdef1")?.id).toBe("new");
  });

  it("lets an explicit report id override the commit match", () => {
    const byCommit = report({
      id: "by-commit",
      commit_sha: FULL_SHA,
      created_at: "2025-02-01T00:00:00Z",
    });
    const override = report({
      id: "override",
      commit_sha: "0000000000",
      created_at: "2025-01-01T00:00:00Z",
    });

    expect(resolveReport([byCommit, override], "abcdef1", "override")?.id).toBe("override");
  });

  it("returns null for an override that is not in the list", () => {
    const byCommit = report({ id: "by-commit", commit_sha: FULL_SHA });

    expect(resolveReport([byCommit], "abcdef1", "missing")).toBeNull();
  });

  it("returns null when nothing matches the commit", () => {
    const other = report({ id: "r2", commit_sha: "9999999999999999999999999999999999999999" });

    expect(resolveReport([other], "abcdef1")).toBeNull();
    expect(resolveReport([], "abcdef1")).toBeNull();
    expect(resolveReport(undefined, "abcdef1")).toBeNull();
  });

  it("does not match reports whose commit is unknown", () => {
    const unattributed = { ...report({ id: "r1", commit_sha: "" }), commit_sha: null };

    expect(resolveReport([unattributed], "abcdef1")).toBeNull();
  });
});

describe("shortCommit", () => {
  it("keeps the first seven characters", () => {
    expect(shortCommit(FULL_SHA)).toBe("abcdef1");
  });
});

describe("locationLine", () => {
  it("prefers file and start line", () => {
    expect(locationLine({ file: "src/a.ts", start_line: 12, resource: "res", summary: "sum" }))
      .toBe("src/a.ts:12");
  });

  it("omits the line when the file has none", () => {
    expect(locationLine({ file: "src/a.ts" })).toBe("src/a.ts");
  });

  it("falls back to resource then summary", () => {
    expect(locationLine({ resource: "pkg:lodash" })).toBe("pkg:lodash");
    expect(locationLine({ summary: "an image layer" })).toBe("an image layer");
  });

  it("returns null when the location is empty", () => {
    expect(locationLine({})).toBeNull();
    expect(locationLine(undefined)).toBeNull();
  });
});

describe("fixLine", () => {
  it("uses the first line of the remediation summary", () => {
    expect(fixLine({ remediation: { summary: "Upgrade lodash\nor pin it" } })).toBe(
      "Upgrade lodash",
    );
  });

  it("falls back to the suggestion action and target", () => {
    expect(
      fixLine({ suggestion: { action: "Upgrade", target: "lodash@4.17.21", confidence: "high" } }),
    )
      .toBe("Upgrade lodash@4.17.21");
    expect(fixLine({ suggestion: { action: "Rotate the key", confidence: "high" } }))
      .toBe("Rotate the key");
  });

  it("says so when there is no fix", () => {
    expect(fixLine({})).toBe("No fix suggested");
  });
});

describe("floorSourceLabel", () => {
  it("names the policy layer", () => {
    expect(floorSourceLabel("template")).toBe("team template");
    expect(floorSourceLabel("override")).toBe("project override");
    expect(floorSourceLabel("default")).toBe("platform default");
  });
});

describe("existingBlockers", () => {
  it("keeps project blockers the change did not introduce", () => {
    expect(existingBlockers(["a", "b", "c"], ["b"])).toEqual(["a", "c"]);
  });

  it("excludes every id introduced by the change", () => {
    expect(existingBlockers(["a", "b"], ["a", "b"])).toEqual([]);
  });

  it("tolerates a missing gate", () => {
    expect(existingBlockers(undefined, ["a"])).toEqual([]);
  });
});
