import type { Waiver } from "@/types/api";
import { describe, expect, it } from "vitest";
import { waiverCandidates, waiverChip, waiverView, waiverViewsByFinding } from "./waiverState";

const NOW = new Date("2026-11-01T12:00:00Z");
const PAST = "2026-10-20T00:00:00Z";
const FUTURE = "2026-12-01T00:00:00Z";

function waiver(extra: Partial<Waiver> = {}): Waiver {
  return {
    id: "w1",
    project_id: "p1",
    name: "Waiver request: x",
    description: "",
    enabled: true,
    status: "pending",
    scope_all: false,
    reason: "not reachable",
    decision_note: "",
    expires_at: FUTURE,
    targets: [{ id: "t1", finding_id: "f1" }],
    created_at: "2026-10-01T00:00:00Z",
    updated_at: "2026-10-01T00:00:00Z",
    ...extra,
  };
}

describe("waiverView", () => {
  it("reads every status the server has", () => {
    expect(waiverView(waiver({ status: "pending" }), NOW).kind).toBe("pending");
    expect(waiverView(waiver({ status: "withdrawn" }), NOW).kind).toBe("withdrawn");
    expect(waiverView(waiver({ status: "rejected", decision_note: "no" }), NOW).kind)
      .toBe("rejected");
    expect(waiverView(waiver({ status: "approved" }), NOW).kind).toBe("in_force");
  });

  it("calls a request the server rejected for lateness expired, by decision_reason and not by note", () => {
    const expired = waiver({
      status: "rejected",
      decision_reason: "expired",
      decision_note: "something else entirely",
    });
    expect(waiverView(expired, NOW).kind).toBe("request_expired");
    const typed = waiver({
      status: "rejected",
      decision_reason: null,
      decision_note: "expired before a decision",
    });
    expect(waiverView(typed, NOW).kind).toBe("rejected");
    expect(waiverView(waiver({ status: "rejected" }), NOW).kind).toBe("rejected");
  });

  it("tells an approved waiver that ran out from one a manager switched off", () => {
    const ranOut = waiver({ status: "approved", enabled: false, expires_at: PAST });
    expect(waiverView(ranOut, NOW).kind).toBe("expired");
    const notYetSwept = waiver({ status: "approved", enabled: true, expires_at: PAST });
    expect(waiverView(notYetSwept, NOW).kind).toBe("expired");
    const revoked = waiver({ status: "approved", enabled: false, expires_at: FUTURE });
    expect(waiverView(revoked, NOW).kind).toBe("revoked");
    const revokedNoEnd = waiver({ status: "approved", enabled: false, expires_at: null });
    expect(waiverView(revokedNoEnd, NOW).kind).toBe("revoked");
  });

  it("has a chip for every kind", () => {
    for (
      const kind of [
        "pending",
        "in_force",
        "rejected",
        "request_expired",
        "withdrawn",
        "revoked",
        "expired",
      ] as const
    ) {
      expect(waiverChip(kind)).not.toBe("");
    }
  });
});

describe("waiverViewsByFinding", () => {
  it("maps each finding a waiver names", () => {
    const views = waiverViewsByFinding([
      waiver({
        targets: [{ id: "t1", finding_id: "f1" }, { id: "t2", finding_id: "f2" }],
      }),
    ], NOW);
    expect(views.get("f1")?.kind).toBe("pending");
    expect(views.get("f2")?.kind).toBe("pending");
    expect(views.has("f3")).toBe(false);
  });

  it("lets a waiting request win over a newer closed one", () => {
    const views = waiverViewsByFinding([
      waiver({ id: "old", status: "pending", updated_at: "2026-10-02T00:00:00Z" }),
      waiver({ id: "new", status: "rejected", updated_at: "2026-10-30T00:00:00Z" }),
    ], NOW);
    expect(views.get("f1")?.waiver.id).toBe("old");
  });

  it("otherwise takes the waiver touched last", () => {
    const views = waiverViewsByFinding([
      waiver({ id: "a", status: "rejected", updated_at: "2026-10-02T00:00:00Z" }),
      waiver({ id: "b", status: "withdrawn", updated_at: "2026-10-30T00:00:00Z" }),
    ], NOW);
    expect(views.get("f1")?.waiver.id).toBe("b");
  });

  it("reads a null list and a null target list as empty", () => {
    expect(waiverViewsByFinding(null, NOW).size).toBe(0);
    expect(waiverViewsByFinding(undefined, NOW).size).toBe(0);
    const nullTargets = waiver({ targets: null as unknown as Waiver["targets"] });
    expect(waiverViewsByFinding([nullTargets], NOW).size).toBe(0);
  });
});

describe("waiverCandidates", () => {
  function views(...entries: Array<[string, Partial<Waiver>]>) {
    return waiverViewsByFinding(
      entries.map(([id, extra], index) =>
        waiver({
          id: `w${index}`,
          targets: [{ id: `t${index}`, finding_id: id }],
          ...extra,
        })
      ),
      NOW,
    );
  }

  it("leaves out findings with a request waiting or a waiver in force", () => {
    const result = waiverCandidates(
      ["a", "b", "c", "d"],
      views(["a", { status: "pending" }], ["b", { status: "approved" }]),
    );

    expect(result).toEqual({ eligible: ["c", "d"], waiting: 1, inForce: 1 });
  });

  it("lets a finding be asked for again after a rejection, withdrawal, expiry or revocation", () => {
    const result = waiverCandidates(
      ["a", "b", "c", "d", "e"],
      views(
        ["a", { status: "rejected" }],
        ["b", { status: "withdrawn" }],
        ["c", { status: "approved", expires_at: PAST }],
        ["d", { status: "approved", enabled: false }],
      ),
    );

    expect(result).toEqual({ eligible: ["a", "b", "c", "d", "e"], waiting: 0, inForce: 0 });
  });

  it("reads an empty or missing waiver list as nothing covered", () => {
    expect(waiverCandidates(["a"], waiverViewsByFinding(null, NOW)).eligible).toEqual(["a"]);
    expect(waiverCandidates([], new Map())).toEqual({ eligible: [], waiting: 0, inForce: 0 });
  });
});
