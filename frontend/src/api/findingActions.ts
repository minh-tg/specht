import type { VerifyResponse } from "@/types/api";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "./client";
import { queryKeys } from "./hooks";

/**
 * Asks the server whether a finding is still present in the latest scan of its scope.
 * A verified fix moves the finding to `fixed`, so its page data is refetched.
 */
export function useVerifyFinding(findingId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiFetch<VerifyResponse>(`/api/v1/findings/${encodeURIComponent(findingId)}/verify`, {
        method: "POST",
      }),
    onSuccess: (data) => {
      if (data.outcome !== "verified_fixed") return;
      void queryClient.invalidateQueries({ queryKey: queryKeys.finding(findingId) });
      void queryClient.invalidateQueries({ queryKey: queryKeys.findingEvents(findingId) });
      void queryClient.invalidateQueries({ queryKey: queryKeys.findings() });
      void queryClient.invalidateQueries({ queryKey: queryKeys.gate() });
      void queryClient.invalidateQueries({ queryKey: queryKeys.projectStats() });
    },
  });
}
