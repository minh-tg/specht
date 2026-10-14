import { apiFetch } from "@/api/client";
import { queryKeys } from "@/api/hooks";
import type { ApiKey } from "@/types/api";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

/** The keys of one project, as the server returns them. */
export function useApiKeys(project: string) {
  return useQuery({
    queryKey: queryKeys.apiKeys(project),
    queryFn: () =>
      apiFetch<ApiKey[]>(`/api/v1/auth/apikeys?project=${encodeURIComponent(project)}`),
    enabled: !!project,
  });
}

/** Revokes one key of a project; the list refetches once the server accepts it. */
export function useRevokeApiKey(project: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch(
        `/api/v1/auth/apikeys/${encodeURIComponent(id)}?project=${encodeURIComponent(project)}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.apiKeys(project) });
    },
  });
}

export const EXPIRY_OPTIONS = [
  { value: "none", label: "No expiry" },
  { value: "30d", label: "30 days" },
  { value: "90d", label: "90 days" },
  { value: "1y", label: "1 year" },
] as const;

export type ExpiryOption = (typeof EXPIRY_OPTIONS)[number]["value"];

const DAY_MS = 24 * 60 * 60 * 1000;

/** The RFC 3339 instant a new key expires at, or undefined for a key that never expires. */
export function expiresAtFor(option: ExpiryOption, now: Date): string | undefined {
  switch (option) {
    case "30d":
      return new Date(now.getTime() + 30 * DAY_MS).toISOString();
    case "90d":
      return new Date(now.getTime() + 90 * DAY_MS).toISOString();
    case "1y": {
      const later = new Date(now.getTime());
      later.setFullYear(later.getFullYear() + 1);
      return later.toISOString();
    }
    case "none":
      return undefined;
  }
}

/** The text for a key's end; a key whose end has passed reads as expired. */
export function keyEndLabel(
  expiresAt: string | null | undefined,
  now: Date,
): { label: string; expired: boolean; } {
  if (!expiresAt) return { label: "Never", expired: false };
  const date = new Date(expiresAt);
  const text = date.toLocaleDateString();
  if (date.getTime() <= now.getTime()) return { label: `Expired ${text}`, expired: true };
  return { label: text, expired: false };
}
