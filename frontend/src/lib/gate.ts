import { severityRank } from "@/lib/enums";
import type { GateStatus } from "@/types/api";

/**
 * Whether a finding blocks the project's gate, and why it does not when it
 * does not.
 *
 * The gate is the backend's own decision: `gate.blocked_by` is the authority,
 * never the finding's `gate_effect` (which only records whether the effect was
 * ignored by triage). Deriving "blocks" from `gate_effect` alone would claim a
 * finding is blocking even after the gate service excluded it.
 */
export interface BlocksGateResult {
  blocks: boolean;
  reason?: "ignored" | "below_floor";
}

/**
 * Resolves a finding's gate verdict. Returns null while the gate status is
 * unknown (still loading or unavailable) so callers can render an empty state
 * instead of an invented "No".
 */
export function blocksGate(
  finding: { id: string; current_severity: string; gate_effect: string; },
  gate: GateStatus | undefined,
): BlocksGateResult | null {
  if (!gate) return null;

  if (gate.blocked_by?.includes(finding.id)) {
    return { blocks: true };
  }

  if (finding.gate_effect === "ignore") {
    return { blocks: false, reason: "ignored" };
  }

  const floor = gate.policy?.severity_floor;
  if (floor && severityRank(finding.current_severity) < severityRank(floor)) {
    return { blocks: false, reason: "below_floor" };
  }

  return { blocks: false };
}

/** Human answer for a blocksGate result; an em-dash while the gate is unknown. */
export function blocksGateLabel(result: BlocksGateResult | null): string {
  if (!result) return "–";
  if (result.blocks) return "Yes";
  if (result.reason === "ignored") return "No (ignored by triage)";
  if (result.reason === "below_floor") return "No (below the floor)";
  return "No";
}
