import type { Aging, OverdueFinding, ProjectStats } from "@/types/api";
import { describe, expect, it } from "vitest";
import { ageBars, daysOverdue, severityBars, stateBars, weeklyCounts } from "./model";

function stats(extra: Partial<ProjectStats>): ProjectStats {
  return {
    total_findings: 0,
    blocking_count: 0,
    waiver_count: 0,
    report_count: 0,
    by_severity: [],
    ...extra,
  };
}

describe("severityBars", () => {
  it("always shows the four named levels, most severe first, even at zero", () => {
    const rows = severityBars(stats({}));
    expect(rows.map((r) => [r.label, r.count])).toEqual([
      ["Critical", 0],
      ["High", 0],
      ["Medium", 0],
      ["Low", 0],
    ]);
  });

  it("carries the blocking share of each severity", () => {
    const rows = severityBars(stats({
      by_severity: [
        { severity: "high", count: 5, blocking_count: 1 },
        { severity: "CRITICAL", count: 2, blocking_count: 2 },
      ],
    }));
    expect(rows[0]).toMatchObject({ key: "critical", count: 2, blocking: 2 });
    expect(rows[1]).toMatchObject({ key: "high", count: 5, blocking: 1 });
  });

  it("adds an unrated row only when something has no rating", () => {
    const rows = severityBars(stats({
      by_severity: [{ severity: "unknown", count: 3, blocking_count: 0 }, {
        severity: "none",
        count: 1,
        blocking_count: 0,
      }],
    }));
    expect(rows.at(-1)).toMatchObject({ key: "unrated", count: 4, tone: "neutral" });
    expect(severityBars(stats({ by_severity: [{ severity: "low", count: 1, blocking_count: 0 }] })))
      .toHaveLength(4);
  });
});

describe("stateBars", () => {
  it("lists only the states someone holds, in the order the work moves", () => {
    const rows = stateBars(stats({
      by_analysis_state: [
        { state: "accepted_risk", count: 1 },
        { state: "unanalyzed", count: 8 },
        { state: "in_triage", count: 0 },
        { state: "exploitable", count: 2 },
      ],
    }));
    expect(rows.map((r) => [r.label, r.count])).toEqual([
      ["Not triaged", 8],
      ["Exploitable", 2],
      ["Accepted risk", 1],
    ]);
  });

  it("is empty when the server sends no breakdown", () => {
    expect(stateBars(stats({}))).toEqual([]);
  });
});

const aging: Aging = {
  buckets: [{ bucket: "stale", count: 5, overdue: 2 }, { bucket: "new", count: 3, overdue: 0 }],
  overdue_total: 2,
  overdue: [],
  reopened: 0,
  new_per_week: [{ week: "2026-09-28", count: 1 }, { week: "2026-10-05", count: 4 }],
  truncated: false,
};

describe("ageBars and weeklyCounts", () => {
  it("shows all four buckets, youngest first, with zero for a missing one", () => {
    expect(ageBars(aging).map((r) => [r.label, r.count])).toEqual([
      ["Under 7 days", 3],
      ["7 to 29 days", 0],
      ["30 to 89 days", 5],
      ["90 days or more", 0],
    ]);
  });

  it("keeps the weekly counts in order", () => {
    expect(weeklyCounts(aging)).toEqual([1, 4]);
  });
});

describe("daysOverdue", () => {
  const finding = (due_date: string): OverdueFinding => ({
    id: "f",
    title: "t",
    severity: "high",
    age_days: 40,
    sla_days: 30,
    due_date,
    reopened: false,
  });
  const now = new Date("2026-10-12T12:00:00Z");

  it("counts whole days since the fix date", () => {
    expect(daysOverdue(finding("2026-09-09T00:00:00Z"), now)).toBe(33);
  });

  it("is zero for a date in the future or one that cannot be read", () => {
    expect(daysOverdue(finding("2026-10-20T00:00:00Z"), now)).toBe(0);
    expect(daysOverdue(finding("later"), now)).toBe(0);
  });
});
