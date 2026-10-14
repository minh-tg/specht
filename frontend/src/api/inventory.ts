import type { Artifact, Environment, Target } from "@/types/api";
import { useQuery } from "@tanstack/react-query";
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
