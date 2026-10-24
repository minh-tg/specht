import type {
  AdminStatus,
  RetentionPreview,
  RetentionResult,
  UserProfile,
  WatcherHealth,
} from "@/types/api";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "./client";

export const adminKeys = {
  all: ["admin"] as const,
  status: () => ["admin", "status"] as const,
  users: (email: string, limit: number) => ["admin", "users", email, limit] as const,
  retention: (days: number) => ["admin", "retention", days] as const,
  watcher: () => ["admin", "watcher"] as const,
};

/** Counts for the whole server. Global admins only. */
export function useAdminStatus(enabled = true) {
  return useQuery({
    queryKey: adminKeys.status(),
    queryFn: () => apiFetch<AdminStatus>("/api/v1/admin/status"),
    enabled,
  });
}

/** Accounts ordered by email, filtered by a substring of it, `limit` at a time. */
export function useUsers(email: string, limit: number) {
  return useQuery({
    queryKey: adminKeys.users(email, limit),
    queryFn: () =>
      apiFetch<UserProfile[]>(
        `/api/v1/users?limit=${limit}${email ? `&email=${encodeURIComponent(email)}` : ""}`,
      ),
    placeholderData: keepPreviousData,
  });
}

/** An account change shows in the list and in the directory other pages resolve names from. */
function useUsersChanged() {
  const queryClient = useQueryClient();
  return () => {
    void queryClient.invalidateQueries({ queryKey: ["admin", "users"] });
    void queryClient.invalidateQueries({ queryKey: adminKeys.status() });
    void queryClient.invalidateQueries({ queryKey: ["users", "directory"] });
  };
}

export function useChangeUserRole() {
  const changed = useUsersChanged();
  return useMutation({
    meta: { success: () => "Role changed" },
    mutationFn: ({ id, role }: { id: string; role: "admin" | "member"; }) =>
      apiFetch<UserProfile>(`/api/v1/users/${encodeURIComponent(id)}/role`, {
        method: "PUT",
        body: JSON.stringify({ role }),
      }),
    onSuccess: changed,
  });
}

/** Ends an account's access, or lets it sign in again. History and memberships stay either way. */
export function useSetUserActive() {
  const changed = useUsersChanged();
  return useMutation({
    meta: {
      success: (_data: unknown, vars: { id: string; active: boolean; }) =>
        vars.active ? "Account reactivated" : "Account deactivated",
      sound: (_data: unknown, vars: { id: string; active: boolean; }) =>
        vars.active ? undefined : "none",
    },
    mutationFn: ({ id, active }: { id: string; active: boolean; }) =>
      apiFetch<UserProfile>(
        `/api/v1/users/${encodeURIComponent(id)}/${active ? "reactivate" : "deactivate"}`,
        { method: "POST" },
      ),
    onSuccess: changed,
  });
}

/** How many settled reports fall outside a window of this many days. Deletes nothing. */
export function useRetentionPreview(days: number) {
  return useQuery({
    queryKey: adminKeys.retention(days),
    queryFn: () => apiFetch<RetentionPreview>(`/api/v1/admin/retention/preview?days=${days}`),
    placeholderData: keepPreviousData,
  });
}

function purgeRetentionMessage(data: RetentionResult): string {
  const removed = `Removed ${data.deleted_reports} ${
    data.deleted_reports === 1 ? "report" : "reports"
  }`;
  return data.remaining
    ? `${removed}. ${data.remaining} still past the cutoff; run it again to continue.`
    : removed;
}

export function usePurgeRetention() {
  const queryClient = useQueryClient();
  return useMutation({
    meta: {
      success: purgeRetentionMessage,
      sound: "none",
    },
    mutationFn: (days: number) =>
      apiFetch<RetentionResult>("/api/v1/admin/retention/purge", {
        method: "POST",
        body: JSON.stringify({ older_than_days: days }),
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["admin", "retention"] });
      void queryClient.invalidateQueries({ queryKey: adminKeys.status() });
    },
  });
}

/** The watcher's health across the server: when it last ran, whether it fails, and the last error. */
export function useWatcherHealth() {
  return useQuery({
    queryKey: adminKeys.watcher(),
    queryFn: () => apiFetch<WatcherHealth>("/api/v1/watcher/status"),
  });
}
