import { type AnalysisState, analysisStateLabel } from "@/lib/enums";
import { apiFetch } from "./client";
import type { UndoPlan } from "./undo";

/**
 * The triage states the API accepts without a reason or an expiry. The finding read does not return
 * the reason or expiry a finding was triaged with, so these are the only states a triage can be put
 * back to; a test keeps the list equal to the triage form's own requirements.
 */
export const REASONLESS_STATES: readonly AnalysisState[] = [
  "unanalyzed",
  "in_triage",
  "exploitable",
];

/**
 * The inverse of a single-finding triage: a second, honest PATCH with the previous state, so the
 * finding's history shows both events. There is none when the previous state needs a reason that
 * cannot be recovered. It checks the finding still holds the state this triage set before it
 * writes, so it never overrides a later decision by someone else.
 */
export function triageUndoPlan(
  { findingId, from, to, refresh }: {
    findingId: string;
    /** The state before the triage, as the finding page had it. */
    from: AnalysisState | undefined;
    /** The state the triage set. */
    to: AnalysisState;
    refresh: () => void;
  },
): UndoPlan | undefined {
  if (!from || from === to || !REASONLESS_STATES.includes(from)) return undefined;
  const path = `/api/v1/findings/${encodeURIComponent(findingId)}`;
  return {
    done: `Triage restored to ${analysisStateLabel(from) ?? from}`,
    refresh,
    run: async () => {
      const current = await apiFetch<{ analysis_state: AnalysisState; }>(path);
      if (current.analysis_state !== to) {
        throw new Error("This finding was triaged again in the meantime, so Undo did nothing.");
      }
      await apiFetch(path, {
        method: "PATCH",
        body: JSON.stringify({ analysis_state: from, reason: "", analysis_expires_at: null }),
      });
    },
  };
}
