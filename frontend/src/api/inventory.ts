import type { Artifact, Environment, Target } from "@/types/api";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "./client";

/** What the project's scans described: environments, scan targets, and build artifacts. Any member can read them. */
export function useEnvironments(slug: string) {
  return useQuery({
    queryKey: ["environments", slug] as const,
    queryFn: () =>
      apiFetch<Environment[] | null>(`/api/v1/projects/${encodeURIComponent(slug)}/environments`),
    enabled: !!slug,
  });
}

export function useTargets(slug: string) {
  return useQuery({
    queryKey: ["targets", slug] as const,
    queryFn: () =>
      apiFetch<Target[] | null>(`/api/v1/projects/${encodeURIComponent(slug)}/targets`),
    enabled: !!slug,
  });
}

export function useArtifacts(slug: string) {
  return useQuery({
    queryKey: ["artifacts", slug] as const,
    queryFn: () =>
      apiFetch<Artifact[] | null>(`/api/v1/projects/${encodeURIComponent(slug)}/artifacts`),
    enabled: !!slug,
  });
}

/** The three settings of an environment. The server replaces all of them at once. */
export interface EnvironmentSettings {
  readonly tier: string;
  readonly internet_facing: boolean;
  readonly data_sensitivity: string;
}

/** Classifies one environment. For a project admin; the list refetches so every row shows the stored values. */
export function useUpdateEnvironment(slug: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, settings }: { id: string; settings: EnvironmentSettings; }) =>
      apiFetch<Environment>(
        `/api/v1/projects/${encodeURIComponent(slug)}/environments/${encodeURIComponent(id)}`,
        { method: "PUT", body: JSON.stringify(settings) },
      ),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["environments", slug] }),
  });
}
