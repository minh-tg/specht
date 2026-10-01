import type { AnalysisState, ReachabilityState } from "@/lib/enums";
import type {
  Finding,
  FindingEvent,
  GateStatus,
  Project,
  ReachabilityAssessment,
  Report,
  ScannerDescriptor,
  TriageResponse,
} from "@/types/api";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "./client";

export const queryKeys = {
  projects: () => ["projects"] as const,
  scanners: () => ["scanners"] as const,
  findings: (
    projectSlug?: string,
    filters?: {
      severity?: string;
      status?: string;
      kind?: string;
      offset?: number;
      limit?: number;
    },
  ) =>
    projectSlug === undefined
      ? (["findings"] as const)
      : (["findings", projectSlug, filters ?? {}] as const),
  finding: (findingId?: string) =>
    findingId === undefined ? (["finding"] as const) : (["finding", findingId] as const),
  reports: (projectSlug?: string) =>
    projectSlug === undefined ? (["reports"] as const) : (["reports", projectSlug] as const),
  gate: (projectSlug?: string) =>
    projectSlug === undefined ? (["gate"] as const) : (["gate", projectSlug] as const),
  reachability: (findingId?: string) =>
    findingId === undefined ? (["reachability"] as const) : (["reachability", findingId] as const),
  findingEvents: (findingId?: string) =>
    findingId === undefined
      ? (["finding-events"] as const)
      : (["finding-events", findingId] as const),
};

export function useProjects() {
  return useQuery({
    queryKey: queryKeys.projects(),
    queryFn: () => apiFetch<Project[]>("/api/v1/projects"),
  });
}

export function useScanners() {
  return useQuery({
    queryKey: queryKeys.scanners(),
    queryFn: () => apiFetch<ScannerDescriptor[]>("/api/v1/scanners"),
  });
}

export function useFindings(
  projectSlug: string,
  filters: { severity?: string; status?: string; kind?: string; offset?: number; limit?: number; },
) {
  return useQuery({
    queryKey: queryKeys.findings(projectSlug, filters),
    queryFn: () => {
      const params = new URLSearchParams();
      if (filters.severity) params.set("severity", filters.severity);
      if (filters.status) params.set("status", filters.status);
      if (filters.kind) params.set("kind", filters.kind);
      if (filters.offset != null) params.set("offset", String(filters.offset));
      if (filters.limit != null) params.set("limit", String(filters.limit));
      const qs = params.toString();
      const query = qs ? `?${qs}` : "";
      return apiFetch<Finding[]>(`/api/v1/projects/${projectSlug}/findings${query}`);
    },
    enabled: !!projectSlug,
    placeholderData: keepPreviousData,
  });
}

export function useFinding(findingId: string) {
  return useQuery({
    queryKey: queryKeys.finding(findingId),
    queryFn: () => apiFetch<Finding>(`/api/v1/findings/${findingId}`),
    enabled: !!findingId,
  });
}

export function useReports(projectSlug: string) {
  return useQuery({
    queryKey: queryKeys.reports(projectSlug),
    queryFn: () => apiFetch<Report[]>(`/api/v1/projects/${projectSlug}/reports`),
    enabled: !!projectSlug,
  });
}

export function useGateStatus(projectSlug: string) {
  return useQuery({
    queryKey: queryKeys.gate(projectSlug),
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
      analysisState: AnalysisState;
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
      queryClient.invalidateQueries({ queryKey: queryKeys.reachability() });
      queryClient.invalidateQueries({ queryKey: queryKeys.findings() });
      queryClient.invalidateQueries({ queryKey: queryKeys.finding() });
      queryClient.invalidateQueries({ queryKey: queryKeys.findingEvents() });
      queryClient.invalidateQueries({ queryKey: queryKeys.gate() });
    },
  });
}

export function useReachability(findingId: string) {
  return useQuery({
    queryKey: queryKeys.reachability(findingId),
    queryFn: () => apiFetch<ReachabilityAssessment[]>(`/api/v1/findings/${findingId}/reachability`),
    enabled: !!findingId,
  });
}

export function useFindingEvents(findingId: string) {
  return useQuery({
    queryKey: queryKeys.findingEvents(findingId),
    queryFn: () => apiFetch<FindingEvent[]>(`/api/v1/findings/${findingId}/events`),
    enabled: !!findingId,
  });
}

export function useUpsertReachability() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (
      { findingId, state, evidence }: {
        findingId: string;
        state: ReachabilityState;
        evidence?: string;
      },
    ) =>
      apiFetch<ReachabilityAssessment>(`/api/v1/findings/${findingId}/reachability`, {
        method: "POST",
        body: JSON.stringify({ state, evidence: evidence ?? "" }),
      }),
    onSuccess: (_data, vars) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reachability(vars.findingId) });
      queryClient.invalidateQueries({ queryKey: queryKeys.gate() });
      queryClient.invalidateQueries({ queryKey: queryKeys.finding() });
      queryClient.invalidateQueries({ queryKey: queryKeys.findingEvents(vars.findingId) });
    },
  });
}
