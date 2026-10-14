import type { GateStatus, ProjectStats } from "@/types/api";
import { queryOptions } from "@tanstack/react-query";
import { apiFetch } from "./client";
import { queryKeys } from "./hooks";

/** The gate status of a project, one query per row of the project list. */
export function projectGateQuery(slug: string) {
  return queryOptions({
    queryKey: queryKeys.gate(slug),
    queryFn: () => apiFetch<GateStatus>(`/api/v1/projects/${slug}/gate`),
  });
}

/** The finding and scan counts of a project, one query per row of the project list. */
export function projectStatsQuery(slug: string) {
  return queryOptions({
    queryKey: queryKeys.projectStats(slug),
    queryFn: () => apiFetch<ProjectStats>(`/api/v1/projects/${slug}/stats`),
  });
}
