import type { FindingEvidence } from "@/types/api";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "./client";

/** Query key for one finding's evidence list. */
export function evidenceQueryKey(findingId: string) {
  return ["finding-evidence", findingId] as const;
}

export function useEvidence(findingId: string) {
  return useQuery({
    queryKey: evidenceQueryKey(findingId),
    queryFn: () =>
      apiFetch<FindingEvidence[]>(`/api/v1/findings/${encodeURIComponent(findingId)}/evidence`),
    enabled: !!findingId,
  });
}

export function useAddEvidence() {
  const queryClient = useQueryClient();
  return useMutation({
    meta: { success: "Evidence added" },
    mutationFn: ({ findingId, type, url, description }: {
      findingId: string;
      type: string;
      url: string;
      description: string;
    }) =>
      apiFetch<FindingEvidence>(
        `/api/v1/findings/${encodeURIComponent(findingId)}/evidence`,
        {
          method: "POST",
          body: JSON.stringify({ type, url, description }),
        },
      ),
    onSuccess: (_data, vars) => {
      void queryClient.invalidateQueries({ queryKey: evidenceQueryKey(vars.findingId) });
    },
  });
}

export function useDeleteEvidence() {
  const queryClient = useQueryClient();
  return useMutation({
    meta: { success: "Evidence deleted" },
    mutationFn: ({ findingId, evidenceId }: { findingId: string; evidenceId: string; }) =>
      apiFetch<void>(
        `/api/v1/findings/${encodeURIComponent(findingId)}/evidence/${
          encodeURIComponent(evidenceId)
        }`,
        { method: "DELETE" },
      ),
    onSuccess: (_data, vars) => {
      void queryClient.invalidateQueries({ queryKey: evidenceQueryKey(vars.findingId) });
    },
  });
}
