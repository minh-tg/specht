import type { GateStatus } from "@/types/api";
import { describe, expect, it } from "vitest";
import { blocksGate, blocksGateLabel, blocksGateSentence, onlyOnBranchesLabel } from "./gate";

/** A gate that blocks nothing and imposes no floor. */
function gate(overrides: Partial<GateStatus> = {}): GateStatus {
  return {
    threshold_breached: false,
    blocking_count: 0,
    blocked_by: [],
    ...overrides,
  };
}

/** A finding that is not ignored and whose severity may or may not clear a floor. */
function finding(
  overrides: Partial<{ id: string; current_severity: string; gate_effect: string; }> = {},
) {
  return {
    id: "f1",
    current_severity: "high",
    gate_effect: "block",
    ...overrides,
  };
}

describe("blocksGate", () => {
  describe("a CVE watcher finding", () => {
    const watcher = (analysis_state = "unanalyzed") => ({
      ...finding(),
      finding_kind: "cve_watcher",
      analysis_state,
    });
    const policy = (watcher_gate: string) =>
      gate({ blocked_by: [], policy: { severity_floor: "high", watcher_gate } as never });

    it("says it waits for triage under require_triage", () => {
      expect(blocksGate(watcher(), policy("require_triage")))
        .toEqual({ blocks: false, reason: "needs_triage" });
    });
    it("gives no such reason once someone has triaged it", () => {
      expect(blocksGate(watcher("in_triage"), policy("require_triage")))
        .toEqual({ blocks: false });
    });
    it("says the policy keeps it out when the watcher gate is off", () => {
      expect(blocksGate(watcher("exploitable"), policy("off")))
        .toEqual({ blocks: false, reason: "watcher_off" });
    });
    it("trusts the gate when the gate says it blocks", () => {
      expect(blocksGate(watcher(), gate({ blocked_by: ["f1"] }))).toEqual({ blocks: true });
    });
    it("leaves a scanner's finding alone", () => {
      expect(
        blocksGate(
          { ...finding(), finding_kind: "sca", analysis_state: "unanalyzed" },
          policy("require_triage"),
        ),
      ).toEqual({ blocks: false });
    });
  });

  it("returns null while the gate status is unknown", () => {
    expect(blocksGate(finding(), undefined)).toBeNull();
  });

  it("blocks exactly when the finding id is in gate.blocked_by", () => {
    expect(blocksGate(finding({ id: "f1" }), gate({ blocked_by: ["f1", "f2"] }))).toEqual({
      blocks: true,
    });
    expect(blocksGate(finding({ id: "f3" }), gate({ blocked_by: ["f1", "f2"] }))).toEqual({
      blocks: false,
    });
  });

  it("never decides from gate_effect alone when the gate excludes the finding", () => {
    expect(blocksGate(finding({ gate_effect: "block" }), gate({ blocked_by: [] }))).toEqual({
      blocks: false,
    });
  });

  it("reports waived when an active waiver silences the finding", () => {
    expect(blocksGate(finding({ id: "f1" }), gate({ waived_finding_ids: ["f1"] }))).toEqual({
      blocks: false,
      reason: "waived",
    });
  });

  it("ignores a waiver that names a different finding and one whose list is absent", () => {
    expect(blocksGate(finding({ id: "f1" }), gate({ waived_finding_ids: ["f2"] }))).toEqual({
      blocks: false,
    });
    expect(blocksGate(finding({ id: "f1" }), gate())).toEqual({ blocks: false });
  });

  it("counts a finding in both blocked_by and waived_finding_ids as blocking", () => {
    expect(
      blocksGate(finding({ id: "f1" }), gate({ blocked_by: ["f1"], waived_finding_ids: ["f1"] })),
    ).toEqual({ blocks: true });
  });

  it("prefers waived over ignored and below the floor", () => {
    const result = blocksGate(
      finding({ gate_effect: "ignore", current_severity: "low" }),
      gate({ waived_finding_ids: ["f1"], policy: policy({ severity_floor: "critical" }) }),
    );
    expect(result).toEqual({ blocks: false, reason: "waived" });
  });

  it("blocks a finding whose gate_effect is ignore when the gate still lists it", () => {
    expect(blocksGate(finding({ id: "f1", gate_effect: "ignore" }), gate({ blocked_by: ["f1"] })))
      .toEqual({ blocks: true });
  });

  it("reports ignored when triage ignored the gate effect", () => {
    expect(blocksGate(finding({ gate_effect: "ignore" }), gate())).toEqual({
      blocks: false,
      reason: "ignored",
    });
  });

  it("prefers ignored over below the floor", () => {
    const result = blocksGate(
      finding({ gate_effect: "ignore", current_severity: "low" }),
      gate({ policy: policy({ severity_floor: "critical" }) }),
    );
    expect(result).toEqual({ blocks: false, reason: "ignored" });
  });

  it("reports below the floor when the finding ranks under the policy floor", () => {
    expect(
      blocksGate(
        finding({ current_severity: "low" }),
        gate({ policy: policy({ severity_floor: "high" }) }),
      ),
    ).toEqual({ blocks: false, reason: "below_floor" });
  });

  it("does not report below the floor when the finding meets or exceeds it", () => {
    expect(
      blocksGate(
        finding({ current_severity: "high" }),
        gate({ policy: policy({ severity_floor: "high" }) }),
      ),
    ).toEqual({ blocks: false });
    expect(
      blocksGate(
        finding({ current_severity: "critical" }),
        gate({ policy: policy({ severity_floor: "medium" }) }),
      ),
    ).toEqual({ blocks: false });
  });

  it("ranks an unrated finding below every real floor", () => {
    for (const current_severity of ["unknown", "none"]) {
      expect(
        blocksGate(
          finding({ current_severity }),
          gate({ policy: policy({ severity_floor: "low" }) }),
        ),
      ).toEqual({ blocks: false, reason: "below_floor" });
    }
  });

  it("has no reason when the policy carries no floor", () => {
    expect(blocksGate(finding({ current_severity: "unknown" }), gate())).toEqual({ blocks: false });
  });
});

describe("blocksGateLabel", () => {
  it("labels each verdict", () => {
    expect(blocksGateLabel(null)).toBe("None");
    expect(blocksGateLabel({ blocks: true })).toBe("Yes");
    expect(blocksGateLabel({ blocks: false })).toBe("No");
    expect(blocksGateLabel({ blocks: false, reason: "ignored" })).toBe("No (ignored by triage)");
    expect(blocksGateLabel({ blocks: false, reason: "below_floor" })).toBe("No (below the floor)");
    expect(blocksGateLabel({ blocks: false, reason: "waived" })).toBe("Waived");
  });
});

describe("blocksGateSentence", () => {
  it("returns null while the gate status is unknown", () => {
    expect(blocksGateSentence(null)).toBeNull();
  });

  it("uses the findings list column's phrasing", () => {
    expect(blocksGateSentence({ blocks: true })).toBe("Blocks gate");
    expect(blocksGateSentence({ blocks: false })).toBe("Does not block gate");
    expect(blocksGateSentence({ blocks: false, reason: "ignored" }))
      .toBe("Does not block gate (ignored by triage)");
    expect(blocksGateSentence({ blocks: false, reason: "below_floor" }))
      .toBe("Does not block gate (below the floor)");
    expect(blocksGateSentence({ blocks: false, reason: "waived" }))
      .toBe("Waived: does not block gate");
  });
});

function policy(overrides: Partial<NonNullable<GateStatus["policy"]>> = {}) {
  return {
    template_name: null,
    template_version: 1,
    severity_floor: "low",
    severity_source: "default" as const,
    watcher_gate: "off",
    watcher_source: "default" as const,
    ...overrides,
  };
}

describe("a finding seen only on change branches", () => {
  const finding = {
    id: "f1",
    current_severity: "high",
    gate_effect: "block",
    only_on_branches: ["feat/x"],
  };
  const status = gate({ policy: { severity_floor: "high" } as GateStatus["policy"] });

  it("does not block the project's verdict, and says why", () => {
    expect(blocksGate(finding, status)).toEqual({ blocks: false, reason: "change_branch" });
  });

  it("still blocks when the gate itself lists it", () => {
    const onBranch = { ...status, blocked_by: ["f1"] };
    expect(blocksGate(finding, onBranch)).toEqual({ blocks: true });
  });

  it("treats a missing list as counting toward the verdict", () => {
    expect(blocksGate({ ...finding, only_on_branches: undefined }, status)).toEqual({
      blocks: false,
    });
  });

  it("names the first branch and how many more", () => {
    expect(onlyOnBranchesLabel(["feat/x"])).toBe("Only on feat/x");
    expect(onlyOnBranchesLabel(["feat/x", "feat/y", "feat/z"])).toBe("Only on feat/x +2 more");
  });
});
