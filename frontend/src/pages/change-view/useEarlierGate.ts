import { apiFetch } from "@/api/client";
import { queryKeys } from "@/api/hooks";
import type { GateStatus } from "@/types/api";
import { useQuery } from "@tanstack/react-query";

/**
 * The gate of the scan that blocked, evaluated against today's findings. It lists the earlier
 * scan's findings that still block and the ones a waiver now silences. Its own cache key keeps it
 * apart from the blocked page's copy of the same gate, which was taken before the fix and would
 * read as still blocking.
 */
export function useEarlierGate(
  slug: string,
  reportId: string | undefined,
  severity?: string,
) {
  const query = new URLSearchParams({ introduced_only: "true", report_id: reportId ?? "" });
  if (severity) query.set("severity", severity);
  return useQuery({
    queryKey: [...queryKeys.changeGate(slug, reportId), "earlier", severity ?? ""],
    queryFn: () =>
      apiFetch<GateStatus>(`/api/v1/projects/${encodeURIComponent(slug)}/gate?${query}`),
    enabled: !!slug && !!reportId,
  });
}
