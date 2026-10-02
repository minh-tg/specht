import { formatDate } from "@/lib/format";
import type { Finding } from "@/types/api";
import { describe, expect, it } from "vitest";
import { compactMeta, PAGE_SIZE, SORT_OPTIONS, sortFindings } from "./sort";

const BASE: Finding = {
  id: "f1",
  project_id: "p1",
  finding_kind: "sca",
  fingerprint: "fp",
  current_title: "Test",
  current_severity: "high",
  current_score: null,
  state: "open",
  triage_status: "untriaged",
  analysis_state: "unanalyzed",
  gate_effect: "block",
  first_seen_at: "2025-01-01T00:00:00Z",
  last_seen_at: "2025-01-01T00:00:00Z",
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-01T00:00:00Z",
};

function finding(overrides: Partial<Record<keyof Finding, unknown>> = {}): Finding {
  return { ...BASE, ...overrides } as Finding;
}

describe("sortFindings", () => {
  it("orders by the shared severity rank rather than alphabetically", () => {
    const rows = [
      finding({ id: "a", current_title: "Low", current_severity: "low" }),
      finding({ id: "b", current_title: "Critical", current_severity: "critical" }),
      finding({ id: "c", current_title: "Unrated", current_severity: "unknown" }),
      finding({ id: "d", current_title: "Bogus", current_severity: "bogus" }),
    ];

    expect(sortFindings(rows, "severity", "asc").map((f) => f.current_title)).toEqual([
      "Bogus",
      "Unrated",
      "Low",
      "Critical",
    ]);
    expect(sortFindings(rows, "severity", "desc").map((f) => f.current_title)).toEqual([
      "Critical",
      "Low",
      "Unrated",
      "Bogus",
    ]);
  });

  it("treats the none severity alias as the same rank as unknown, stably", () => {
    const rows = [
      finding({ id: "a", current_title: "Alias", current_severity: "none" }),
      finding({ id: "b", current_title: "Canonical", current_severity: "unknown" }),
    ];

    // Both rank 0, so the original order survives in either direction.
    expect(sortFindings(rows, "severity", "desc").map((f) => f.current_title)).toEqual([
      "Alias",
      "Canonical",
    ]);
    expect(sortFindings(rows, "severity", "asc").map((f) => f.current_title)).toEqual([
      "Alias",
      "Canonical",
    ]);
  });

  it("keeps equal keys in their original order", () => {
    const rows = [
      finding({ id: "a", current_title: "Zebra", current_severity: "critical" }),
      finding({ id: "b", current_title: "Alpha", current_severity: "critical" }),
    ];

    expect(sortFindings(rows, "severity", "desc").map((f) => f.current_title)).toEqual([
      "Zebra",
      "Alpha",
    ]);
  });

  it("sorts titles in both directions", () => {
    const rows = [
      finding({ id: "a", current_title: "Zebra" }),
      finding({ id: "b", current_title: "Alpha" }),
      finding({ id: "c", current_title: "Mystery" }),
    ];

    expect(sortFindings(rows, "title", "asc").map((f) => f.current_title)).toEqual([
      "Alpha",
      "Mystery",
      "Zebra",
    ]);
    expect(sortFindings(rows, "title", "desc").map((f) => f.current_title)).toEqual([
      "Zebra",
      "Mystery",
      "Alpha",
    ]);
  });

  it("sorts by last seen and falls back to it for an unknown column", () => {
    const rows = [
      finding({ id: "a", current_title: "Old", last_seen_at: "2025-01-01T00:00:00Z" }),
      finding({ id: "b", current_title: "New", last_seen_at: "2025-03-01T00:00:00Z" }),
    ];

    expect(sortFindings(rows, "last_seen", "asc").map((f) => f.current_title)).toEqual([
      "Old",
      "New",
    ]);
    expect(sortFindings(rows, "last_seen", "desc").map((f) => f.current_title)).toEqual([
      "New",
      "Old",
    ]);
    expect(sortFindings(rows, "whatever", "desc").map((f) => f.current_title)).toEqual([
      "New",
      "Old",
    ]);
  });

  it("does not mutate the array it is given", () => {
    const rows = [
      finding({ id: "a", current_title: "Low", current_severity: "low" }),
      finding({ id: "b", current_title: "Critical", current_severity: "critical" }),
    ];
    const original = [...rows];

    sortFindings(rows, "severity", "desc");

    expect(rows).toEqual(original);
  });
});

describe("SORT_OPTIONS", () => {
  it("offers a unique value for every sortable column and direction", () => {
    const values = SORT_OPTIONS.map((option) => option.value);
    expect(new Set(values).size).toBe(values.length);
    expect(values).toEqual([
      "severity:desc",
      "severity:asc",
      "title:asc",
      "title:desc",
      "last_seen:desc",
      "last_seen:asc",
    ]);
  });
});

describe("compactMeta", () => {
  it("joins the narrow-screen columns into one readable line", () => {
    const row = finding({ finding_kind: "sca", state: "open", analysis_state: "accepted_risk" });

    expect(compactMeta(row)).toBe(
      `SCA · Open · Accepted risk · Last seen ${formatDate("2025-01-01T00:00:00Z")}`,
    );
  });

  it("omits columns that have no value", () => {
    const row = finding({ finding_kind: "sast", state: "", analysis_state: null });

    expect(compactMeta(row)).toBe(`SAST · Last seen ${formatDate("2025-01-01T00:00:00Z")}`);
  });

  it("renders a controlled label instead of echoing unrecognised wire values", () => {
    const row = finding({ finding_kind: "<img src=x>", state: "bogus", analysis_state: "bogus" });

    expect(compactMeta(row)).toBe(
      `Unknown · Unknown · Unknown · Last seen ${formatDate("2025-01-01T00:00:00Z")}`,
    );
  });
});

describe("PAGE_SIZE", () => {
  it("is the page size the dashboard requests", () => {
    expect(PAGE_SIZE).toBe(20);
  });
});
