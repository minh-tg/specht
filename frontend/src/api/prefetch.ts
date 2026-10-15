import { findingQueryOptions, findingsQueryOptions, projectQueryOptions } from "@/api/hooks";
import { findingsRequest } from "@/pages/findings-dashboard/findingsRequest";
import type { QueryClient } from "@tanstack/react-query";

/** The one request a finding page needs before it can show anything. The rest load on the page. */
export function prefetchFinding(queryClient: QueryClient, findingId: string): Promise<unknown> {
  return queryClient.prefetchQuery(findingQueryOptions(findingId));
}

/** What a project opens with: the project itself and the default first page of its findings. */
export function prefetchProject(queryClient: QueryClient, slug: string): Promise<unknown> {
  return Promise.all([
    queryClient.prefetchQuery(projectQueryOptions(slug)),
    queryClient.prefetchQuery(findingsQueryOptions(slug, findingsRequest())),
  ]);
}
