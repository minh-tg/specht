import type { Waiver } from "@/types/api";

/** The three lists the page offers. */
export type WaiverBucket = "pending" | "in_force" | "closed";

export const BUCKETS: readonly WaiverBucket[] = ["pending", "in_force", "closed"];

export const BUCKET_LABEL: Record<WaiverBucket, string> = {
  pending: "Waiting",
  in_force: "In force",
  closed: "Closed",
};

/** Why a waiver in the closed list is closed. */
export type ClosedReason = "Rejected" | "Withdrawn" | "Revoked" | "Expired";

function hasExpired(waiver: Waiver, now: Date): boolean {
  if (!waiver.expires_at) return false;
  const at = Date.parse(waiver.expires_at);
  return Number.isFinite(at) && at <= now.getTime();
}

/**
 * Where a waiver belongs. Only an approved, switched-on waiver that has not run out counts in the
 * gate, so only that one is "in force". An approved waiver that was switched off or ran out has
 * stopped counting and sits with the closed ones.
 */
export function waiverBucket(waiver: Waiver, now: Date): WaiverBucket {
  if (waiver.status === "pending") return "pending";
  if (waiver.status === "approved" && waiver.enabled && !hasExpired(waiver, now)) {
    return "in_force";
  }
  return "closed";
}

export function closedReason(waiver: Waiver, now: Date): ClosedReason {
  if (waiver.status === "rejected") return "Rejected";
  if (waiver.status === "withdrawn") return "Withdrawn";
  if (waiver.status === "approved" && !waiver.enabled) return "Revoked";
  if (hasExpired(waiver, now)) return "Expired";
  return "Revoked";
}

/** A request is named "Waiver request: <title>"; the list already says what it is, so drop the prefix. */
export function waiverTitle(waiver: Waiver): string {
  const name = waiver.name.replace(/^Waiver request:\s*/, "").trim();
  return name || "Waiver";
}

export function countByBucket(waivers: readonly Waiver[], now: Date): Record<WaiverBucket, number> {
  const counts: Record<WaiverBucket, number> = { pending: 0, in_force: 0, closed: 0 };
  for (const waiver of waivers) counts[waiverBucket(waiver, now)] += 1;
  return counts;
}

const EVENT_LABEL = new Map<string, string>([
  ["created", "Created"],
  ["updated", "Edited"],
  ["enabled", "Switched on"],
  ["disabled", "Switched off"],
  ["auto_disabled", "Switched off automatically"],
  ["requested", "Requested"],
  ["approved", "Approved"],
  ["rejected", "Rejected"],
  ["auto_rejected", "Rejected automatically"],
  ["withdrawn", "Withdrawn"],
]);

/** Plain words for a waiver audit event. A type this screen does not know shows its raw value. */
export function waiverEventLabel(eventType: string): string {
  return EVENT_LABEL.get(eventType) ?? eventType;
}
