import { type AnalysisState, analysisStateLabel } from "@/lib/enums";
import type { ProjectMember, ProjectRole, Waiver } from "@/types/api";
import { apiFetch } from "./client";
import type { UndoPlan } from "./undo";
import { waiverSwitchError } from "./waiverSwitch";

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
 * The inverse of revoking a waiver: a restore that carries the `updated_at` the revoke returned. The
 * server applies it only while the waiver is still as the revoke left it, so a later restore or
 * revoke by someone else is not overridden, and an expired waiver is not brought back. There is
 * none unless the revoke left the waiver approved and off.
 */
export function revokeUndoPlan(
  { slug, waiver, refresh }: { slug: string; waiver: Waiver; refresh: () => void; },
): UndoPlan | undefined {
  if (waiver.status !== "approved" || waiver.enabled) return undefined;
  const path = `/api/v1/projects/${encodeURIComponent(slug)}/waivers/${
    encodeURIComponent(waiver.id)
  }/restore`;
  return {
    done: "Waiver back in force",
    refresh,
    run: async () => {
      try {
        await apiFetch<Waiver>(path, {
          method: "POST",
          body: JSON.stringify({ expected_updated_at: waiver.updated_at }),
        });
      } catch (error) {
        throw waiverSwitchError(error, "undo");
      }
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
