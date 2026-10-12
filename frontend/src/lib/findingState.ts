import { analysisStateLabel } from "@/lib/enums";
import type { Finding, GateStatus } from "@/types/api";

export interface FindingWorkflowState {
  /** The word the list shows. */
  readonly label: string;
  /** Open work gets a filled mark; everything someone has dealt with, or that scans closed, a hollow one. */
  readonly open: boolean;
}

/**
 * Where a finding stands in the work, in one word: Fixed or Archived when a scan or a deleted report
 * ended it, Waived when an approved waiver lets it through the gate, the triage decision when someone
 * made one, otherwise Open. The waiver list is the gate's own answer, so it is read from the gate.
 */
export function findingWorkflowState(
  finding: Pick<Finding, "id" | "state" | "analysis_state">,
  gate: GateStatus | undefined,
): FindingWorkflowState {
  if (finding.state === "archived") return { label: "Archived", open: false };
  if (finding.state === "fixed") return { label: "Fixed", open: false };
  if (gate?.waived_finding_ids?.includes(finding.id)) return { label: "Waived", open: false };
  if (finding.analysis_state === "in_triage") return { label: "In triage", open: true };
  if (finding.analysis_state && finding.analysis_state !== "unanalyzed") {
    return { label: analysisStateLabel(finding.analysis_state) ?? "Triaged", open: false };
  }
  return { label: "Open", open: true };
}
