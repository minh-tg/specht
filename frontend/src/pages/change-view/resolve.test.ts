import type { Report } from "@/types/api";
import { describe, expect, it } from "vitest";
import {
  commitScans,
  existingBlockers,
  fixAction,
  floorSourceLabel,
  isRealFix,
  locationLine,
  shortCommit,
} from "./resolve";

const FULL_SHA = "abcdef1234567890abcdef1234567890abcdef12";

function report(overrides: Partial<Report> & { id: string; }): Report {
  return {
    project_id: "p1",
    commit_sha: FULL_SHA,
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

describe("commitScans", () => {
  const OTHER_SHA = "abcdef1999999999999999999999999999999999";

  it("resolves an exact full SHA and a prefix of it", () => {
    const target = report({ id: "r1", commit_sha: FULL_SHA });
    const other = report({ id: "r2", commit_sha: "9999999999999999999999999999999999999999" });

    expect(commitScans([other, target], FULL_SHA)?.reports.map((r) => r.id)).toEqual(["r1"]);
    expect(commitScans([target], "abcdef1")?.sha).toBe(FULL_SHA);
  });

  it("matches the commit case-insensitively and gives the SHA in lower case", () => {
    const target = report({ id: "r1", commit_sha: FULL_SHA.toUpperCase() });

    expect(commitScans([target], "ABCDEF1")?.sha).toBe(FULL_SHA);
  });

  it("counts every scanner of the commit and keeps the newest report of each", () => {
    const trivyOld = report({ id: "t1", tool_name: "trivy", created_at: "2025-01-01T00:00:00Z" });
    const trivyNew = report({ id: "t2", tool_name: "trivy", created_at: "2025-01-03T00:00:00Z" });
    const semgrep = report({ id: "s1", tool_name: "semgrep", created_at: "2025-01-02T00:00:00Z" });
    const gosec = report({
      id: "g1",
      tool_name: "sarif",
      producer: "Gosec",
      created_at: "2025-01-02T00:00:00Z",
    });

    const scans = commitScans([trivyOld, semgrep, trivyNew, gosec], "abcdef1");
    expect(scans?.reports.map((r) => r.id)).toEqual(["t2", "s1", "g1", "t1"]);
    expect(scans?.latest.map((r) => r.id)).toEqual(["g1", "s1", "t2"]);
    expect(scans?.focus.id).toBe("t2");
    expect(scans?.judged).toBe(true);
  });

  it("names scanners still running or failed by their newest report only", () => {
    const scans = commitScans([
      report({
        id: "t1",
        tool_name: "trivy",
        status: "failed",
        created_at: "2025-01-01T00:00:00Z",
      }),
      report({
        id: "t2",
        tool_name: "trivy",
        status: "completed",
        created_at: "2025-01-02T00:00:00Z",
      }),
      report({ id: "s1", tool_name: "semgrep", status: "processing" }),
      report({ id: "g1", tool_name: "gitleaks", status: "failed" }),
    ], "abcdef1");

    expect(scans?.running).toEqual(["semgrep"]);
    expect(scans?.failed).toEqual(["gitleaks"]);
    expect(scans?.judged).toBe(true);
  });

  it("has no verdict until one report of the commit completed", () => {
    const scans = commitScans([
      report({ id: "s1", tool_name: "semgrep", status: "processing" }),
      report({ id: "g1", tool_name: "gitleaks", status: "failed" }),
    ], "abcdef1");

    expect(scans?.judged).toBe(false);
  });

  it("takes the header's report from the link, never the verdict", () => {
    const newest = report({ id: "new", created_at: "2025-02-01T00:00:00Z" });
    const linked = report({
      id: "linked",
      tool_name: "semgrep",
      created_at: "2025-01-01T00:00:00Z",
    });

    const scans = commitScans([newest, linked], "abcdef1", "linked");
    expect(scans?.focus.id).toBe("linked");
    expect(scans?.reports).toHaveLength(2);
  });

  it("falls back to the newest report when the link names one that is gone", () => {
    const only = report({ id: "only" });

    expect(commitScans([only], "abcdef1", "deleted")?.focus.id).toBe("only");
  });

  it("lets the linked report pick the SHA when a short prefix matches two commits", () => {
    const newer = report({ id: "a", commit_sha: OTHER_SHA, created_at: "2025-02-01T00:00:00Z" });
    const linked = report({ id: "b", commit_sha: FULL_SHA, created_at: "2025-01-01T00:00:00Z" });

    expect(commitScans([newer, linked], "abcdef1")?.sha).toBe(OTHER_SHA);
    const scans = commitScans([newer, linked], "abcdef1", "b");
    expect(scans?.sha).toBe(FULL_SHA);
    expect(scans?.reports.map((r) => r.id)).toEqual(["b"]);
  });

  it("returns null when nothing matches the commit", () => {
    const other = report({ id: "r2", commit_sha: "9999999999999999999999999999999999999999" });
    const unattributed = { ...report({ id: "r1", commit_sha: "" }), commit_sha: null };

    expect(commitScans([other, unattributed], "abcdef1")).toBeNull();
    expect(commitScans([], "abcdef1")).toBeNull();
    expect(commitScans(undefined, "abcdef1")).toBeNull();
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

describe("fixAction", () => {
  it("uses the first line of the remediation summary", () => {
    expect(fixAction({ remediation: { summary: "Upgrade lodash\nor pin it" } })).toBe(
      "Upgrade lodash",
    );
  });

  it("falls back to the suggestion action and target", () => {
    expect(
      fixAction({
        suggestion: { action: "Upgrade", target: "lodash@4.17.21", confidence: "high" },
      }),
    )
      .toBe("Upgrade lodash@4.17.21");
    expect(fixAction({ suggestion: { action: "Rotate the key", confidence: "high" } }))
      .toBe("Rotate the key");
  });

  it("does not offer the server's fallback label as the thing to do", () => {
    const fallback = { summary: "No fix description reported", fallback: true };
    expect(fixAction({ remediation: fallback })).toBeNull();
    // A real suggestion still wins over a fallback label.
    expect(
      fixAction({
        remediation: fallback,
        suggestion: { action: "Upgrade", target: "lodash@4.17.21", confidence: "high" },
      }),
    ).toBe("Upgrade lodash@4.17.21");
  });

  it("treats the server's generic review suggestion as no fix", () => {
    expect(
      fixAction({
        suggestion: {
          action: "review",
          target: "src/db.ts",
          detail: "No fix description reported",
          confidence: "low",
          fallback: true,
        },
      }),
    ).toBeNull();
    // A scanner summary still wins over a fallback suggestion.
    expect(
      fixAction({
        remediation: { summary: "Use a parameterized query" },
        suggestion: { action: "review", target: "src/db.ts", confidence: "low", fallback: true },
      }),
    ).toBe("Use a parameterized query");
  });

  it("is null when there is no fix, so nothing is invented", () => {
    expect(fixAction({})).toBeNull();
    expect(fixAction({ remediation: { summary: "   " } })).toBeNull();
  });
});

describe("isRealFix", () => {
  it("accepts a source-backed suggestion", () => {
    expect(isRealFix({ action: "upgrade", target: "lodash", confidence: "high", fallback: false }))
      .toBe(true);
    expect(
      isRealFix({ action: "fix-code", target: "src/db.ts", confidence: "medium", fallback: false }),
    ).toBe(
      true,
    );
    expect(isRealFix({ action: "rotate", confidence: "high", fallback: false })).toBe(true);
  });

  it("rejects the generic review fallback and a missing suggestion", () => {
    expect(isRealFix({ action: "review", target: "src/db.ts", confidence: "low", fallback: true }))
      .toBe(false);
    expect(isRealFix(undefined)).toBe(false);
  });

  it("trusts the server's fallback flag over the action name", () => {
    expect(
      isRealFix({ action: "review", target: "src/db.ts", confidence: "medium", fallback: false }),
    )
      .toBe(true);
    expect(isRealFix({ action: "upgrade", target: "lodash", confidence: "low", fallback: true }))
      .toBe(false);
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
