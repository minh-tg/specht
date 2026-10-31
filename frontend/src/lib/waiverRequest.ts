import type { BlocksGateResult } from "@/lib/gate";

/** Shown when the server says the caller may not request a waiver (an API key, or not a member). */
export const NOT_A_MEMBER_REASON = "You are not a member of this project.";

/** What the "Request waiver" control does on a finding page, and why when it cannot be used. */
export type WaiverAction =
  | { readonly kind: "available"; }
  | { readonly kind: "pending"; }
  | { readonly kind: "disabled"; readonly reason: string; };

/**
 * Decides the waiver control on the finding page from data the page already holds. The control is
 * never dropped: when it cannot be used it says why. The server checks the role again on send.
 */
export function waiverAction({ permissions, loading, pending, blocking, gateRechecking }: {
  /** `permissions.request_waiver` from the project read, once that read has finished. */
  readonly permissions: boolean | undefined;
  readonly loading: boolean;
  /** A request for this finding is waiting for a decision. */
  readonly pending: boolean;
  /** The finding's gate verdict, or null while the gate is unknown. */
  readonly blocking: BlocksGateResult | null;
  /** A triage the person just made has not reached the gate yet. */
  readonly gateRechecking: boolean;
}): WaiverAction {
  if (loading) return { kind: "disabled", reason: "Checking what you may do on this project." };
  if (permissions !== true) return { kind: "disabled", reason: NOT_A_MEMBER_REASON };
  if (pending) return { kind: "pending" };
  if (gateRechecking) {
    return { kind: "disabled", reason: "The gate is rechecking after your triage." };
  }
  if (!blocking) {
    return { kind: "disabled", reason: "Checking whether this finding blocks the gate." };
  }
  if (blocking.blocks) return { kind: "available" };
  if (blocking.reason === "waived") {
    return { kind: "disabled", reason: "This finding is already waived." };
  }
  if (blocking.reason === "ignored") {
    return { kind: "disabled", reason: "Triage tells the gate to ignore this finding." };
  }
  if (blocking.reason === "below_floor") {
    return {
      kind: "disabled",
      reason: "This finding is below the severity floor, so it does not block the gate.",
    };
  }
  return { kind: "disabled", reason: "This finding does not block the gate." };
}
