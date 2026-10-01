import type { GateStatus, ProjectStats, Report } from "@/types/api";
import { describe, expect, it } from "vitest";
import {
  blockerCount,
  isDegraded,
  isReportInProgress,
  projectVerdict,
  triageBuckets,
} from "./verdict";

function gate(overrides: Partial<GateStatus> = {}): GateStatus {
  return { threshold_breached: false, blocking_count: 0, ...overrides };
}

function report(status: string): Report {
  return {
    id: "r1",
    project_id: "p1",
    tool_name: "trivy",
    tool_version: null,
    scan_type: "image",
    scan_target: null,
    status,
    total_findings: null,
    branch: null,
    commit_sha: null,
    created_at: "2026-10-01T00:00:00Z",
    completed_at: null,
  };
}

function stats(overrides: Partial<ProjectStats> = {}): ProjectStats {
  return {
    total_findings: 0,
    blocking_count: 0,
    waiver_count: 0,
    report_count: 1,
    by_severity: [],
    ...overrides,
  };
}

describe("projectVerdict", () => {
  it("is unknown while the gate or the stats are missing", () => {
    expect(projectVerdict({})).toBe("unknown");
    expect(projectVerdict({ gate: gate() })).toBe("unknown");
    expect(projectVerdict({ stats: stats() })).toBe("unknown");
  });

  it("is no_scans when the project has no reports", () => {
    expect(projectVerdict({ gate: gate(), stats: stats({ report_count: 0 }) })).toBe("no_scans");
  });

  it("is blocked when the gate threshold was breached", () => {
    const input = { gate: gate({ threshold_breached: true }), stats: stats() };
    expect(projectVerdict(input)).toBe("blocked");
  });

  it("is passing when reports exist and the gate holds", () => {
    expect(projectVerdict({ gate: gate(), stats: stats() })).toBe("passing");
  });

  it("prefers no_scans over blocked when there are no reports", () => {
    // A stale gate breach must not label an unscanned project as blocked.
    const input = { gate: gate({ threshold_breached: true }), stats: stats({ report_count: 0 }) };
    expect(projectVerdict(input)).toBe("no_scans");
  });
});

describe("blockerCount", () => {
  it("is zero without a gate", () => {
    expect(blockerCount(undefined)).toBe(0);
  });

  it("is zero when no findings are listed", () => {
    expect(blockerCount(gate())).toBe(0);
    expect(blockerCount(gate({ blocked_by: [] }))).toBe(0);
  });

  it("counts the blocked_by ids", () => {
    expect(blockerCount(gate({ blocked_by: ["f1", "f2"] }))).toBe(2);
  });

  it("never trusts the blocking_count summary", () => {
    // The summary can desynchronise from the real blocking set.
    expect(blockerCount(gate({ blocking_count: 7, blocked_by: [] }))).toBe(0);
    expect(blockerCount(gate({ blocking_count: 7, blocked_by: ["f1"] }))).toBe(1);
  });
});

describe("isDegraded", () => {
  it("is false without stats or a latest report", () => {
    expect(isDegraded(undefined)).toBe(false);
    expect(isDegraded(stats())).toBe(false);
  });

  it("is false for a completed report", () => {
    expect(isDegraded(stats({ latest_report: report("completed") }))).toBe(false);
  });

  it("is true while the latest report is processing or failed", () => {
    // `processing` is what the server stores; `pending` is what openapi.yaml calls it.
    expect(isDegraded(stats({ latest_report: report("processing") }))).toBe(true);
    expect(isDegraded(stats({ latest_report: report("pending") }))).toBe(true);
    expect(isDegraded(stats({ latest_report: report("failed") }))).toBe(true);
  });

  it("is false for a status outside the vocabulary", () => {
    expect(isDegraded(stats({ latest_report: report("archived") }))).toBe(false);
  });
});

describe("isReportInProgress", () => {
  it("accepts the stored value and the documented alias only", () => {
    expect(isReportInProgress("processing")).toBe(true);
    expect(isReportInProgress("pending")).toBe(true);
    expect(isReportInProgress("completed")).toBe(false);
    expect(isReportInProgress("failed")).toBe(false);
    expect(isReportInProgress(undefined)).toBe(false);
  });
});

describe("triageBuckets", () => {
  it("is null when the server sent no breakdown", () => {
    expect(triageBuckets(undefined)).toBeNull();
  });

  it("returns zeros for an empty breakdown", () => {
    expect(triageBuckets([])).toEqual({ needsTriage: 0, exploitable: 0, dismissed: 0 });
  });

  it("sums every analysis state into its bucket", () => {
    const result = triageBuckets([
      { state: "unanalyzed", count: 4 },
      { state: "in_triage", count: 1 },
      { state: "exploitable", count: 3 },
      { state: "false_positive", count: 2 },
      { state: "not_affected", count: 5 },
      { state: "accepted_risk", count: 6 },
      { state: "wont_fix", count: 7 },
    ]);

    expect(result).toEqual({ needsTriage: 5, exploitable: 3, dismissed: 20 });
  });

  it("ignores out-of-vocabulary states", () => {
    const result = triageBuckets([
      { state: "pending_review", count: 99 },
      { state: "", count: 99 },
      { state: "exploitable", count: 1 },
    ]);

    expect(result).toEqual({ needsTriage: 0, exploitable: 1, dismissed: 0 });
  });
});
