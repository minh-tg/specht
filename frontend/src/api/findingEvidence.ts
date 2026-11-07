import type { FindingEvidence, Signoff, SignoffStatus } from "@/types/api";
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
    meta: { success: "Evidence deleted", sound: "none" },
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

/** Query key for one finding's reviewer sign-off. */
export function signoffQueryKey(findingId: string) {
  return ["finding-signoff", findingId] as const;
}

/**
 * The finding's reviewer sign-off, or null when nobody has signed off yet, which the
 * server answers with 204.
 */
export function useSignoff(findingId: string) {
  return useQuery({
    queryKey: signoffQueryKey(findingId),
    queryFn: async (): Promise<Signoff | null> => {
      const signoff = await apiFetch<Signoff | undefined>(
        `/api/v1/findings/${encodeURIComponent(findingId)}/signoff`,
      );
      return signoff ?? null;
    },
    enabled: !!findingId,
  });
}

export function useSaveSignoff() {
  const queryClient = useQueryClient();
  return useMutation({
    meta: { success: "Sign-off saved" },
    mutationFn: ({ findingId, status, comment }: {
      findingId: string;
      status: SignoffStatus;
      comment: string;
    }) =>
      apiFetch<Signoff>(`/api/v1/findings/${encodeURIComponent(findingId)}/signoff`, {
        method: "POST",
        body: JSON.stringify({ status, comment }),
      }),
    onSuccess: (_data, vars) => {
      void queryClient.invalidateQueries({ queryKey: signoffQueryKey(vars.findingId) });
    },
  });
}
