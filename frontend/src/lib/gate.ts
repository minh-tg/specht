import { severityRank } from "@/lib/enums";
import { EMPTY_VALUE } from "@/lib/format";
import type { GateStatus } from "@/types/api";

/**
 * Whether a finding blocks the project's gate, and why it does not when it
 * does not.
 *
 * The gate is the backend's own decision: `gate.blocked_by` is the authority,
 * never the finding's `gate_effect` (which only records whether the effect was
 * ignored by triage). Deriving "blocks" from `gate_effect` alone would claim a
 * finding is blocking even after the gate service excluded it. The waiver list
 * (`gate.waived_finding_ids`) is equally the backend's decision, so it is
 * honoured before the finding-level ignore and floor rules.
 */
export interface BlocksGateResult {
  blocks: boolean;
  reason?: "ignored" | "below_floor" | "waived" | "needs_triage" | "watcher_off" | "change_branch";
}

/**
 * Resolves a finding's gate verdict. Returns null while the gate status is
 * unknown (still loading or unavailable) so callers can render an empty state
 * instead of an invented "No".
 */
export function blocksGate(
  finding: {
    id: string;
    current_severity: string;
    gate_effect: string;
    finding_kind?: string;
    analysis_state?: string;
    only_on_branches?: readonly string[];
  },
  gate: GateStatus | undefined,
): BlocksGateResult | null {
  if (!gate) return null;

  if (gate.blocked_by?.includes(finding.id)) {
    return { blocks: true };
  }

  if (gate.waived_finding_ids?.includes(finding.id)) {
    return { blocks: false, reason: "waived" };
  }

  if (finding.gate_effect === "ignore") {
    return { blocks: false, reason: "ignored" };
  }

  // Seen only on change branches: the project's verdict answers for its default branch.
  if ((finding.only_on_branches?.length ?? 0) > 0) {
    return { blocks: false, reason: "change_branch" };
  }

  const floor = gate.policy?.severity_floor;
  if (floor && severityRank(finding.current_severity) < severityRank(floor)) {
    return { blocks: false, reason: "below_floor" };
  }

  // The project's watcher policy keeps these out of the gate. Which ones is the rule in
  // internal/gate: off admits none, require_triage admits all but the untouched.
  if (finding.finding_kind === "cve_watcher") {
    const mode = gate.policy?.watcher_gate;
    if (mode === "off") return { blocks: false, reason: "watcher_off" };
    if (mode === "require_triage" && finding.analysis_state === "unanalyzed") {
      return { blocks: false, reason: "needs_triage" };
    }
  }

  return { blocks: false };
}

/** Names where a finding left out of the verdict was seen: "Only on feat/x", "+1 more". */
export function onlyOnBranchesLabel(branches: readonly string[]): string {
  const [first, ...rest] = branches;
  return rest.length > 0 ? `Only on ${first} +${rest.length} more` : `Only on ${first}`;
}

/** Human answer for a blocksGate result; EMPTY_VALUE while the gate is unknown. */
export function blocksGateLabel(result: BlocksGateResult | null): string {
  if (!result) return EMPTY_VALUE;
  if (result.blocks) return "Yes";
  if (result.reason === "ignored") return "No (ignored by triage)";
  if (result.reason === "below_floor") return "No (below the floor)";
  if (result.reason === "change_branch") return "No (only on an unmerged branch)";
  if (result.reason === "waived") return "Waived";
  if (result.reason === "needs_triage") return "Not until triaged";
  if (result.reason === "watcher_off") return "No (watcher findings are off)";
  return "No";
}

/**
 * Sentence form of a blocksGate verdict for prose, so the detail page and the
 * findings list column answer the same question with the same words. Returns
 * null while the gate is unknown so callers can omit the clause entirely.
 */
export function blocksGateSentence(result: BlocksGateResult | null): string | null {
  if (!result) return null;
  if (result.blocks) return "Blocks gate";
  if (result.reason === "ignored") return "Does not block gate (ignored by triage)";
  if (result.reason === "below_floor") return "Does not block gate (below the floor)";
  if (result.reason === "change_branch") return "Does not block gate (only on an unmerged branch)";
  if (result.reason === "waived") return "Waived: does not block gate";
  if (result.reason === "needs_triage") return "Does not block gate until someone triages it";
  if (result.reason === "watcher_off") return "Does not block gate (watcher findings are off)";
  return "Does not block gate";
}
