import type { Waiver } from "@/types/api";

/**
 * Where a waiver for one finding stands, in the words the change view needs. The server has four
 * review states (pending, approved, rejected, withdrawn). Two more are read from the other fields:
 * an approved waiver that stopped counting is either revoked (switched off before its end date) or
 * expired, and a rejected request is "expired" when the server decided it itself.
 */
export type WaiverViewKind =
  | "pending"
  | "in_force"
  | "rejected"
  | "request_expired"
  | "withdrawn"
  | "revoked"
  | "expired";

export interface WaiverView {
  readonly kind: WaiverViewKind;
  readonly waiver: Waiver;
}

function time(iso: string | null | undefined): number {
  const at = iso ? Date.parse(iso) : Number.NaN;
  return Number.isFinite(at) ? at : 0;
}

function hasExpired(waiver: Waiver, now: Date): boolean {
  return !!waiver.expires_at && time(waiver.expires_at) <= now.getTime();
}

/**
 * Classifies one waiver. Expiry is tested before the switch: the sweeper switches an expired
 * waiver off and leaves it approved, which looks like a revoked one but is not.
 */
export function waiverView(waiver: Waiver, now: Date): WaiverView {
  switch (waiver.status) {
    case "pending":
      return { kind: "pending", waiver };
    case "withdrawn":
      return { kind: "withdrawn", waiver };
    case "rejected":
      return {
        kind: waiver.decision_reason === "expired" ? "request_expired" : "rejected",
        waiver,
      };
    case "approved":
      if (hasExpired(waiver, now)) return { kind: "expired", waiver };
      return { kind: waiver.enabled ? "in_force" : "revoked", waiver };
  }
}

/**
 * The waiver that speaks for each finding. A request that is waiting wins, because it is the one
 * someone can still act on; otherwise the waiver touched last. Lists from the API may be null and a
 * waiver's target list may be null, so both read as empty.
 */
export function waiverViewsByFinding(
  waivers: readonly Waiver[] | null | undefined,
  now: Date,
): ReadonlyMap<string, WaiverView> {
  const byFinding = new Map<string, WaiverView>();
  for (const waiver of waivers ?? []) {
    const view = waiverView(waiver, now);
    const touched = time(waiver.updated_at || waiver.created_at);
    for (const target of waiver.targets ?? []) {
      const current = byFinding.get(target.finding_id);
      if (!current || outranks(view, touched, current)) byFinding.set(target.finding_id, view);
    }
  }
  return byFinding;
}

function outranks(view: WaiverView, touched: number, current: WaiverView): boolean {
  if (current.kind === "pending") return false;
  if (view.kind === "pending") return true;
  return touched > time(current.waiver.updated_at || current.waiver.created_at);
}

/** The id of a finding's waiver block, so focus can be sent back to it after a dialog closes. */
export function waiverPathId(findingId: string): string {
  return `waiver-path-${findingId}`;
}

/** The short tag on a collapsed entry. */
export function waiverChip(kind: WaiverViewKind): string {
  switch (kind) {
    case "pending":
      return "Waiver requested";
    case "in_force":
      return "Waived";
    case "rejected":
      return "Waiver rejected";
    case "request_expired":
      return "Request expired";
    case "revoked":
      return "Waiver revoked";
    case "expired":
      return "Waiver expired";
    case "withdrawn":
      return "Request withdrawn";
  }
}
