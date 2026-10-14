import type { WaiverUpdate } from "@/api/waiverActions";
import type { Waiver } from "@/types/api";
import { toExpiryTimestamp } from "../finding-detail/format";

/** The local calendar day an expiry falls on, in the form a date input takes. */
export function expiryDateValue(iso: string | null | undefined): string {
  if (!iso) return "";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

export interface WaiverDraft {
  readonly name: string;
  readonly description: string;
  readonly expiry: string;
  readonly noExpiry: boolean;
}

/**
 * The fields that differ from the stored waiver. An unchanged expiry is left out, so the server
 * keeps it; "No expiry" on a waiver that had one sends the empty string that clears it.
 */
export function changedFields(waiver: Waiver, draft: WaiverDraft): WaiverUpdate {
  const update: WaiverUpdate = {};
  const name = draft.name.trim();
  if (name !== waiver.name) update.name = name;
  if (draft.description !== waiver.description) update.description = draft.description;
  if (draft.noExpiry) {
    if (waiver.expires_at) update.expires_at = "";
  } else if (draft.expiry !== expiryDateValue(waiver.expires_at)) {
    const iso = toExpiryTimestamp(draft.expiry);
    if (iso) update.expires_at = iso;
  }
  return update;
}
