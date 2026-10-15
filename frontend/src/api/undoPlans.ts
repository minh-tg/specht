import { type AnalysisState, analysisStateLabel } from "@/lib/enums";
import type { ProjectMember, ProjectRole, Waiver } from "@/types/api";
import { apiFetch } from "./client";
import type { UndoPlan } from "./undo";
import { waiverSwitchError } from "./waiverSwitch";

/**
 * The inverse of a single-finding triage. The server restores the exact analysis the finding had
 * before the change (state, reason, expiry and the manual and review flags) from the snapshot that
 * change recorded, and logs the undo as a new event, so the history shows both. It refuses while
 * the change is not the finding's latest one, so Undo never overrides a later decision; the
 * server's message says why and is shown as it is. There is no plan without the event id the
 * triage response carries.
 */
export function triageUndoPlan(
  { findingId, eventId, from, to, refresh }: {
    findingId: string;
    /** The event the triage wrote, from its response. */
    eventId: string | undefined;
    /** The state before the triage, as the finding page had it. Only names the confirmation. */
    from?: AnalysisState;
    /** The state the triage set. Only names the confirmation. */
    to?: AnalysisState;
    refresh: () => void;
  },
): UndoPlan | undefined {
  if (!eventId) return undefined;
  const restored = from && from !== to ? analysisStateLabel(from) ?? from : undefined;
  return {
    done: restored ? `Triage restored to ${restored}` : "Triage change undone",
    refresh,
    run: async () => {
      await apiFetch(`/api/v1/findings/${encodeURIComponent(findingId)}/analysis/undo`, {
        method: "POST",
        body: JSON.stringify({ event_id: eventId }),
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
