import type { GateStatus } from "@/types/api";
import { describe, expect, it } from "vitest";
import { findingWorkflowState } from "./findingState";

const open = { id: "f1", state: "open", analysis_state: "unanalyzed" } as const;
const gate = (waived: string[] = []): GateStatus => ({
  threshold_breached: true,
  blocking_count: 1,
  waived_finding_ids: waived,
});

describe("findingWorkflowState", () => {
  it("says Open for a finding nobody has dealt with", () => {
    expect(findingWorkflowState(open, gate())).toEqual({ label: "Open", open: true });
    expect(findingWorkflowState(open, undefined)).toEqual({ label: "Open", open: true });
  });

  it("names the triage decision once there is one", () => {
    expect(findingWorkflowState({ ...open, analysis_state: "accepted_risk" }, gate())).toEqual({
      label: "Accepted risk",
      open: false,
    });
    expect(findingWorkflowState({ ...open, analysis_state: "false_positive" }, gate()).label)
      .toBe("False positive");
  });

  it("keeps a finding in triage as open work", () => {
    expect(findingWorkflowState({ ...open, analysis_state: "in_triage" }, gate())).toEqual({
      label: "In triage",
      open: true,
    });
  });

  it("says Waived when the gate says an approved waiver covers it", () => {
    expect(findingWorkflowState(open, gate(["f1"]))).toEqual({ label: "Waived", open: false });
    expect(findingWorkflowState(open, gate(["other"]))).toEqual({ label: "Open", open: true });
  });

  it("lets a scan's verdict win: fixed and archived are not open work", () => {
    expect(findingWorkflowState({ ...open, state: "fixed" }, gate(["f1"])).label).toBe("Fixed");
    expect(findingWorkflowState({ ...open, state: "archived" }, gate()).label).toBe("Archived");
  });

  it("does not echo an unknown triage value", () => {
    expect(findingWorkflowState({ ...open, analysis_state: "bogus" as never }, gate()).label)
      .toBe("Unknown");
  });
});
