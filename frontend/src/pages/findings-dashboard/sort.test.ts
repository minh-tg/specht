import { formatDate } from "@/lib/format";
import type { Finding } from "@/types/api";
import { describe, expect, it } from "vitest";
import { compactMeta, PAGE_SIZE, SORT_OPTIONS } from "./sort";

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

describe("SORT_OPTIONS", () => {
  it("offers a unique value for every sortable column and direction", () => {
    const values = SORT_OPTIONS.map((option) => option.value);
    expect(new Set(values).size).toBe(values.length);
    expect(values).toEqual([
      "severity:desc",
      "severity:asc",
      "first_seen:asc",
      "first_seen:desc",
      "last_seen:desc",
      "last_seen:asc",
      "title:asc",
      "title:desc",
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
