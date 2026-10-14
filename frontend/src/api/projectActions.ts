import type { Project } from "@/types/api";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "./client";
import { queryKeys } from "./hooks";

/** The fields a project admin may change. The slug never changes, so it is not here. */
export interface ProjectChange {
  name?: string;
  description?: string;
}

/**
 * Renames or re-describes a project. Only the fields passed are sent; the server leaves the rest
 * alone. The project and the project list are refreshed so the header and the home page agree.
 */
export function useUpdateProject(slug: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (change: ProjectChange) =>
      apiFetch<Project>(`/api/v1/projects/${encodeURIComponent(slug)}`, {
        method: "PUT",
        body: JSON.stringify(change),
      }),
    onSuccess: (updated) => {
      queryClient.setQueryData<Project>(
        queryKeys.project(slug),
        (previous) => previous ? { ...previous, ...updated } : updated,
      );
      void queryClient.invalidateQueries({ queryKey: queryKeys.projects() });
    },
    meta: { success: "Project saved" },
  });
}
