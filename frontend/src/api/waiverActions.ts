import { apiFetch } from "@/api/client";
import { queryKeys } from "@/api/hooks";
import type { Waiver } from "@/types/api";
import { useMutation, useQueryClient } from "@tanstack/react-query";

/** The fields an edit may send. An omitted field keeps the stored value. */
export interface WaiverUpdate {
  name?: string;
  description?: string;
  /** RFC 3339 to set the expiry, or "" to clear it. Omitted keeps the stored expiry. */
  expires_at?: string;
}

/**
 * Saves changes to a waiver's name, description or expiry. The gate changes when the expiry does,
 * so the verdict and the project numbers are refreshed too.
 */
export function useUpdateWaiver(slug: string) {
  const queryClient = useQueryClient();
  return useMutation({
    meta: { success: "Waiver saved" },
    mutationFn: ({ id, update }: { id: string; update: WaiverUpdate; }) =>
      apiFetch<Waiver>(
        `/api/v1/projects/${encodeURIComponent(slug)}/waivers/${encodeURIComponent(id)}`,
        { method: "PUT", body: JSON.stringify(update) },
      ),
    onSuccess: (_data, { id, update }) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.waivers(slug) });
      void queryClient.invalidateQueries({ queryKey: queryKeys.waiverEvents(slug, id) });
      if (update.expires_at !== undefined) {
        void queryClient.invalidateQueries({ queryKey: queryKeys.gate(slug) });
        void queryClient.invalidateQueries({ queryKey: queryKeys.projectStats(slug) });
      }
    },
  });
}
