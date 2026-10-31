import { APIError } from "@/api/client";
import type { BlocksGateResult } from "@/lib/gate";

/*
 * The limits the server enforces on a waiver request (internal/usecase/waiver_requests.go). The
 * dialog shows them before the person hits send; the server still checks them again.
 */
/** Longest reason, counted in characters after trimming. */
export const WAIVER_REASON_MAX = 1000;
/** Furthest ahead a request may expire, in days. */
export const WAIVER_EXPIRY_MAX_DAYS = 90;
/** Most findings one request may name. */
export const WAIVER_TARGETS_MAX = 50;

/** Characters the way the server counts them: whole code points of the trimmed text. */
export function reasonLength(reason: string): number {
  return Array.from(reason.trim()).length;
}

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

/** What went wrong with a send or a withdraw, in words a person can act on. */
export interface WaiverFailure {
  readonly title: string;
  readonly detail: string;
  /** The `X-Request-Id` of the failed response, when the server sent one. */
  readonly requestId?: string;
}

function failure(title: string, detail: string, error: unknown): WaiverFailure {
  return error instanceof APIError && error.requestId
    ? { title, detail, requestId: error.requestId }
    : { title, detail };
}

/** A server message as a sentence: first letter up, a full stop at the end. */
function sentence(message: string): string {
  const text = message.trim();
  if (!text) return "The server refused the request.";
  const upper = text.charAt(0).toUpperCase() + text.slice(1);
  return /[.!?]$/.test(upper) ? upper : `${upper}.`;
}

/**
 * The copy for a failed waiver request. The server's own message is shown for a refusal it
 * explains (a 400 names the field), and a conflict gets its own words. The person's text is kept
 * in every case, and the copy says so.
 */
export function waiverRequestFailure(error: unknown): WaiverFailure {
  const title = "Could not send the request.";
  if (!(error instanceof APIError)) {
    return failure(
      title,
      "The server could not be reached. Check your connection. Your text is kept.",
      error,
    );
  }
  if (error.code === "waiver_request_exists") {
    return failure(
      title,
      "A request for one of these findings is already waiting for a manager. Your text is kept: remove that finding, or close this and use the existing request.",
      error,
    );
  }
  if (error.status === 403) {
    return failure(title, "Only project members can ask for a waiver. Your text is kept.", error);
  }
  if (error.status === 429) {
    const wait = error.retryAfter ? ` Wait ${error.retryAfter} seconds.` : "";
    return failure(title, `Too many requests.${wait} Your text is kept.`, error);
  }
  if (error.status >= 500) {
    return failure(title, "The server had a problem. Your text is kept. Try again.", error);
  }
  return failure(title, `${sentence(error.message)} Your text is kept.`, error);
}

/** The copy for a failed withdraw. */
export function waiverWithdrawFailure(error: unknown): WaiverFailure {
  const title = "Could not withdraw the request.";
  if (!(error instanceof APIError)) {
    return failure(title, "The server could not be reached. Check your connection.", error);
  }
  if (error.code === "waiver_not_pending") {
    return failure(
      title,
      "Someone already decided this request. The page now shows what happened.",
      error,
    );
  }
  if (error.status === 403) {
    return failure(title, "Only the person who asked can withdraw a request.", error);
  }
  if (error.status === 404) {
    return failure(title, "This request no longer exists.", error);
  }
  if (error.status >= 500) {
    return failure(title, "The server had a problem. Try again.", error);
  }
  return failure(title, sentence(error.message), error);
}
