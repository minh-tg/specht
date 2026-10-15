import { type AnalysisState, analysisStateLabel } from "@/lib/enums";
import type { ProjectMember, ProjectRole, Waiver } from "@/types/api";
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

/**
 * The inverse of revoking a waiver. Revoke is a blind toggle, so the plan reads the waiver first
 * and flips it back only while it is still approved and switched off; otherwise someone decided
 * something else meanwhile and flipping again would undo their decision, not this one. There is
 * none unless the revoke left the waiver approved and off.
 */
export function revokeUndoPlan(
  { slug, waiver, refresh }: { slug: string; waiver: Waiver; refresh: () => void; },
): UndoPlan | undefined {
  if (waiver.status !== "approved" || waiver.enabled) return undefined;
  const path = `/api/v1/projects/${encodeURIComponent(slug)}/waivers/${
    encodeURIComponent(waiver.id)
  }`;
  return {
    done: "Waiver back in force",
    refresh,
    run: async () => {
      const current = await apiFetch<Waiver>(path);
      if (current.status !== "approved" || current.enabled) {
        throw new Error("The waiver changed in the meantime, so Undo did nothing.");
      }
      await apiFetch<Waiver>(`${path}/toggle`, { method: "POST" });
    },
  };
}

/**
 * The inverse of removing a project member: grant the same role again. The grant is an upsert, so
 * the plan reads the roster first and refuses when the person is a member again, rather than
 * overwriting a role someone just gave them. The roster shows a new "Added" date afterwards.
 */
export function restoreMemberPlan(
  { slug, userId, role, refresh }: {
    slug: string;
    userId: string;
    role: ProjectRole;
    refresh: () => void;
  },
): UndoPlan {
  const path = `/api/v1/projects/${encodeURIComponent(slug)}/members`;
  return {
    done: "Member restored",
    refresh,
    run: async () => {
      const roster = await apiFetch<ProjectMember[]>(path);
      if (roster.some((member) => member.user_id === userId)) {
        throw new Error("They are a member again, so Undo did nothing.");
      }
      await apiFetch<void>(path, {
        method: "POST",
        body: JSON.stringify({ user_id: userId, role }),
      });
    },
  };
}
