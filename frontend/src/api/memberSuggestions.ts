import { isSystemAccount } from "@/lib/accounts";
import type { UserProfile } from "@/types/api";
import type { components } from "@/types/api.gen";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { apiFetch } from "./client";
import { useCapabilities } from "./hooks";

/** A person offered when adding someone by email. */
export type PersonSuggestion = components["schemas"]["MemberSuggestion"];

/** Shorter text returns no suggestions, here and on the server. */
export const MIN_SUGGESTION_QUERY = 3;
/** The most people offered for one query, here and on the server. */
export const MAX_SUGGESTIONS = 8;
const DEBOUNCE_MS = 200;
const NO_SUGGESTIONS: readonly PersonSuggestion[] = [];

/** Length in characters, not UTF-16 units, to match the server's count. */
function queryLength(query: string): number {
  return [...query].length;
}

function useDebounced<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);
  return debounced;
}

/**
 * Server-side suggestions for a project's "Add Direct Member" dialog. Typing is debounced and a
 * superseded request is cancelled through the query signal. Nothing is requested while sign-up is
 * open: the server answers `[]` then, because anyone could have registered under a colleague's
 * address.
 *
 * The previous answer stays in `data` while the next one loads, but it describes older text, so
 * `suggestions` is empty and `searching` is true from the keystroke until the answer for the
 * current text arrives (the debounce wait, then the round trip).
 */
export function useMemberSuggestions(slug: string, query: string, enabled = true) {
  const typed = query.trim();
  const trimmed = useDebounced(typed, DEBOUNCE_MS);
  const registrationOpen = useCapabilities().data?.registration?.enabled !== false;
  const active = enabled && !!slug && !registrationOpen
    && queryLength(typed) >= MIN_SUGGESTION_QUERY && queryLength(trimmed) >= MIN_SUGGESTION_QUERY;
  const result = useQuery({
    queryKey: ["projects", slug, "member-suggestions", trimmed] as const,
    queryFn: ({ signal }) =>
      apiFetch<PersonSuggestion[]>(
        `/api/v1/projects/${encodeURIComponent(slug)}/member-suggestions?q=${
          encodeURIComponent(trimmed)
        }`,
        { signal },
      ),
    enabled: active,
    staleTime: 30 * 1000,
    placeholderData: keepPreviousData,
    retry: false,
  });
  const stale = typed !== trimmed || result.isPlaceholderData;
  return {
    ...result,
    active,
    suggestions: stale ? NO_SUGGESTIONS : (result.data ?? NO_SUGGESTIONS),
    searching: active && (stale || (result.isFetching && !result.data)),
  };
}

/**
 * The server's suggestion rules applied to a directory already in memory, for the team roster
 * dialog (only instance admins add people there, and they have the directory loaded). A person
 * matches when their email starts with the query, or the query starts at the beginning of a word of
 * their display name ("ada lov" finds "Ada Lovelace").
 */
export function suggestFromDirectory(
  directory: readonly UserProfile[] | undefined,
  query: string,
  excludeIds: ReadonlySet<string>,
): PersonSuggestion[] {
  const needle = query.trim().toLowerCase();
  if (!directory || queryLength(needle) < MIN_SUGGESTION_QUERY) return [];
  const matches = directory.filter((user) => {
    if (user.disabled || user.disabled_at || isSystemAccount(user) || excludeIds.has(user.id)) {
      return false;
    }
    if (user.email.toLowerCase().startsWith(needle)) return true;
    // The server's rule: the needle starts at a word boundary, and may run on into later words.
    return (" " + (user.display_name ?? "").toLowerCase()).includes(" " + needle);
  });
  return matches
    .toSorted((a, b) => (a.email < b.email ? -1 : a.email > b.email ? 1 : 0))
    .slice(0, MAX_SUGGESTIONS)
    .map((user) => ({
      user_id: user.id,
      email: user.email,
      display_name: user.display_name ?? "",
    }));
}
