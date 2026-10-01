import type { GateStatus } from "@/types/api";
import { describe, expect, it } from "vitest";
import { blocksGate, blocksGateLabel } from "./gate";

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

  it("ranks an unknown severity below every floor", () => {
    expect(
      blocksGate(
        finding({ current_severity: "unknown" }),
        gate({ policy: policy({ severity_floor: "none" }) }),
      ),
    ).toEqual({ blocks: false, reason: "below_floor" });
  });

  it("has no reason when the policy carries no floor", () => {
    expect(blocksGate(finding({ current_severity: "none" }), gate())).toEqual({ blocks: false });
  });
});

describe("blocksGateLabel", () => {
  it("labels each verdict", () => {
    expect(blocksGateLabel(null)).toBe("–");
    expect(blocksGateLabel({ blocks: true })).toBe("Yes");
    expect(blocksGateLabel({ blocks: false })).toBe("No");
    expect(blocksGateLabel({ blocks: false, reason: "ignored" })).toBe("No (ignored by triage)");
    expect(blocksGateLabel({ blocks: false, reason: "below_floor" })).toBe("No (below the floor)");
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
