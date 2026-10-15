import { APIError } from "./client";

/** Where a revoke or restore was started: its own button, or the Undo on the revoke's toast. */
export type WaiverSwitchOrigin = "button" | "undo";

const EXPIRED = "The waiver has expired. Extend its expiry first.";

/**
 * Turns the server's refusal of a revoke or restore into a sentence for the person who pressed the
 * button. Any other error comes back unchanged. The refusals are `waiver_changed` (someone else
 * wrote the waiver since this screen loaded it), `waiver_expired` and `waiver_not_approved`.
 */
export function waiverSwitchError(error: unknown, origin: WaiverSwitchOrigin): unknown {
  if (!(error instanceof APIError) || error.status !== 409) return error;
  switch (error.code) {
    case "waiver_changed":
    case "waiver_not_approved":
      return new Error(
        origin === "undo"
          ? "The waiver changed in the meantime, so Undo did nothing."
          : "The waiver changed since this list loaded, so nothing was done. The list is up to date now.",
      );
    case "waiver_expired":
      return new Error(EXPIRED);
    default:
      return error;
  }
}
