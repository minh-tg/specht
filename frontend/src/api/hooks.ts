import type {
  Finding,
  GateStatus,
  Project,
  ReachabilityAssessment,
  Report,
  TriageResponse,
} from "@/types/api";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "./client";

export function useProjects() {
  return useQuery({
    queryKey: ["projects"],
    queryFn: () => apiFetch<Project[]>("/api/v1/projects"),
  });
}

export function useFindings(
  projectSlug: string,
  filters: { severity?: string; status?: string; kind?: string; offset?: number; limit?: number; },
) {
  return useQuery({
    queryKey: ["findings", projectSlug, filters],
    queryFn: () => {
      const params = new URLSearchParams();
      if (filters.severity) params.set("severity", filters.severity);
      if (filters.status) params.set("status", filters.status);
      if (filters.kind) params.set("kind", filters.kind);
      if (filters.offset != null) params.set("offset", String(filters.offset));
      if (filters.limit != null) params.set("limit", String(filters.limit));
      const qs = params.toString();
      return apiFetch<Finding[]>(`/api/v1/projects/${projectSlug}/findings${qs ? `?${qs}` : ""}`);
    },
  });
}

export function useFinding(findingId: string) {
  return useQuery({
    queryKey: ["finding", findingId],
    queryFn: () => apiFetch<Finding>(`/api/v1/findings/${findingId}`),
    enabled: !!findingId,
  });
}

export function useReports(projectSlug: string) {
  return useQuery({
    queryKey: ["reports", projectSlug],
    queryFn: () => apiFetch<Report[]>(`/api/v1/projects/${projectSlug}/reports`),
  });
}

export function useGateStatus(projectSlug: string) {
  return useQuery({
    queryKey: ["gate", projectSlug],
    queryFn: () => apiFetch<GateStatus>(`/api/v1/projects/${projectSlug}/gate`),
    enabled: !!projectSlug,
  });
}

export function useTriageFinding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      findingId,
      analysisState,
      reason,
      analysisExpiresAt,
    }: {
      findingId: string;
      analysisState: string;
      reason?: string;
      analysisExpiresAt?: string;
    }) =>
      apiFetch<TriageResponse>(`/api/v1/findings/${findingId}`, {
        method: "PATCH",
        body: JSON.stringify({
          analysis_state: analysisState,
          reason: reason ?? "",
          analysis_expires_at: analysisExpiresAt ?? null,
        }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["finding"] });
      queryClient.invalidateQueries({ queryKey: ["gate"] });
    },
  });
}

export function useReachability(findingId: string) {
  return useQuery({
    queryKey: ["reachability", findingId],
    queryFn: () => apiFetch<ReachabilityAssessment[]>(`/api/v1/findings/${findingId}/reachability`),
    enabled: !!findingId,
  });
}

export function useUpsertReachability() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (
      { findingId, state, evidence }: { findingId: string; state: string; evidence?: string; },
    ) =>
      apiFetch<ReachabilityAssessment>(`/api/v1/findings/${findingId}/reachability`, {
        method: "POST",
        body: JSON.stringify({ state, evidence: evidence ?? "" }),
      }),
    onSuccess: (_data, vars) => {
      queryClient.invalidateQueries({ queryKey: ["reachability", vars.findingId] });
      queryClient.invalidateQueries({ queryKey: ["gate"] });
      queryClient.invalidateQueries({ queryKey: ["finding"] });
    },
  });
}
