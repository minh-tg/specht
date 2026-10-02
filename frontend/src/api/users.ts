import type { FindingEvent, UserProfile } from "@/types/api";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./client";
import { useMe } from "./hooks";

/**
 * Admin-only directory of user profiles, used to turn the user ids on finding
 * events into names. The endpoint answers 403 for everyone else, so the query
 * stays disabled for non-admins and callers fall back to generic labels.
 * `retry: false` keeps a forbidden or failed lookup from stalling the history.
 */
export function useUserDirectory() {
  const me = useMe();
  return useQuery({
    queryKey: ["users", "directory"],
    queryFn: () => apiFetch<UserProfile[]>("/api/v1/users?limit=500"),
    enabled: me.data?.role === "admin",
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
}

/** The actor context a viewer has for resolving an event's user id. */
export interface ActorContext {
  readonly me?: UserProfile | null;
  readonly directory?: readonly UserProfile[] | null;
}

/**
 * Describes who performed a finding event without ever leaking the raw user
 * id. System events (empty user id) and the viewer's own events are always
 * nameable; another person resolves only when the admin directory loaded.
 */
export function actorLabel(
  event: Pick<FindingEvent, "user_id">,
  { me, directory }: ActorContext,
): string {
  if (!event.user_id) return "System";
  if (me && event.user_id === me.id) return "You";
  const actor = directory?.find((user) => user.id === event.user_id);
  if (actor) return actor.display_name || actor.email;
  return "A team member";
}
