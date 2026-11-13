import {
  carryPrevious,
  explainCleared,
  judgeCleared,
  readPrevious,
} from "@/pages/change-view/cleared";
import type { Finding, GateStatus } from "@/types/api";
import { describe, expect, it } from "vitest";

const NOW = new Date("2026-01-01T00:00:00Z");

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    state: "open",
    analysis_state: "unanalyzed",
    gate_effect: "block",
    ...overrides,
  } as Finding;
}

function gate(overrides: Partial<GateStatus> = {}): GateStatus {
  return { threshold_breached: false, blocking_count: 0, ...overrides };
}

describe("readPrevious", () => {
  const OLD = "1111111111111111111111111111111111111111";
  const NOW = "2222222222222222222222222222222222222222";
  const valid = carryPrevious({ slug: "acme", commit: OLD, ids: ["f1"] });

  it("reads what a blocked page carried", () => {
    expect(readPrevious(valid, "acme", NOW)).toEqual({ slug: "acme", commit: OLD, ids: ["f1"] });
  });

  it.each([
    ["no state", undefined],
    ["a string", "x"],
    ["another project", carryPrevious({ slug: "other", commit: OLD, ids: ["f1"] })],
    ["no ids", carryPrevious({ slug: "acme", commit: OLD, ids: [] })],
    ["null ids", { previousBlockers: { slug: "acme", commit: OLD, ids: null } }],
    ["a non-string id", { previousBlockers: { slug: "acme", commit: OLD, ids: [1] } }],
    ["no commit", { previousBlockers: { slug: "acme", ids: ["f1"] } }],
    ["a report id from before", {
      previousBlockers: { slug: "acme", reportId: "r1", ids: ["f1"] },
    }],
    ["a commit that is not hex", {
      previousBlockers: { slug: "acme", commit: "../x", ids: ["f1"] },
    }],
  ])("rejects %s", (_, state) => {
    expect(readPrevious(state, "acme", NOW)).toBeNull();
  });

  it("rejects state naming the commit on screen", () => {
    expect(readPrevious(valid, "acme", OLD)).toBeNull();
  });
});

describe("judgeCleared", () => {
  const previous = { slug: "acme", commit: "1111111", ids: ["a", "b"] };

  it("waits, and gives up, without a gate", () => {
    expect(judgeCleared(previous, undefined, "pending")).toEqual({ kind: "checking" });
    expect(judgeCleared(previous, undefined, "error")).toEqual({ kind: "unchecked" });
  });

  it("reports only the earlier blockers the gate still lists", () => {
    expect(judgeCleared(previous, gate({ blocked_by: ["b", "new"] }), "success")).toEqual({
      kind: "open",
      ids: ["b"],
    });
  });

  it("reads a null blocked_by as nothing blocking", () => {
    expect(
      judgeCleared(previous, { ...gate(), blocked_by: null } as unknown as GateStatus, "success"),
    ).toEqual({ kind: "unblocked" });
  });
});

describe("explainCleared", () => {
  const context = { earlierGate: undefined, gate: undefined, waivers: [], now: NOW };

  it("puts a fixed finding first, even when a waiver also names it", () => {
    expect(
      explainCleared(finding({ state: "fixed" }), {
        ...context,
        earlierGate: gate({ waived_finding_ids: ["f1"] }),
      }),
    ).toEqual({ kind: "fixed" });
  });

  it("takes waived ids from either gate", () => {
    expect(
      explainCleared(finding(), { ...context, gate: gate({ waived_finding_ids: ["f1"] }) }),
    ).toEqual({ kind: "waived", waiver: undefined });
  });

  it("does not name a waiver that was switched off or has expired", () => {
    const base = {
      status: "approved",
      targets: [{ id: "t", finding_id: "f1" }],
    };
    const waivers = [
      { ...base, id: "w1", enabled: false },
      { ...base, id: "w2", enabled: true, expires_at: "2025-01-01T00:00:00Z" },
    ] as never;
    const cause = explainCleared(finding(), {
      ...context,
      waivers,
      earlierGate: gate({ waived_finding_ids: ["f1"] }),
    });
    expect(cause).toEqual({ kind: "waived", waiver: undefined });
  });

  it("explains each state the gate ignores", () => {
    for (const state of ["false_positive", "not_affected", "accepted_risk", "wont_fix"] as const) {
      expect(explainCleared(finding({ analysis_state: state, gate_effect: "ignore" }), context))
        .toMatchObject({ kind: "triaged", state });
    }
  });

  it("does not call a blocking in-triage finding dismissed", () => {
    expect(explainCleared(finding({ analysis_state: "in_triage" }), context)).toEqual({
      kind: "uncounted",
    });
  });
});
