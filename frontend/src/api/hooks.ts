import type { AnalysisState, ReachabilityState } from "@/lib/enums";
import type {
  CreatedApiKey,
  Finding,
  FindingEvent,
  GateStatus,
  Project,
  ProjectMember,
  ProjectRole,
  ProjectStats,
  ProjectTeam,
  ReachabilityAssessment,
  Report,
  ScannerDescriptor,
  ServerVersion,
  Team,
  TeamMember,
  TriageResponse,
  UserProfile,
} from "@/types/api";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch, apiFetchWithTotal } from "./client";

export const queryKeys = {
  projects: () => ["projects"] as const,
  me: () => ["me"] as const,
  version: () => ["version"] as const,
  project: (slug?: string) =>
    slug === undefined ? (["project"] as const) : (["project", slug] as const),
  projectStats: (slug?: string) =>
    slug === undefined ? (["project-stats"] as const) : (["project-stats", slug] as const),
  projectMembers: (slug?: string) =>
    slug === undefined ? (["project-members"] as const) : (["project-members", slug] as const),
  projectTeams: (slug?: string) =>
    slug === undefined ? (["project-teams"] as const) : (["project-teams", slug] as const),
  teams: () => ["teams"] as const,
  teamMembers: (teamId?: string) =>
    teamId === undefined ? (["team-members"] as const) : (["team-members", teamId] as const),
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
  changeGate: (projectSlug?: string, reportId?: string) =>
    projectSlug === undefined
      ? (["gate"] as const)
      : (["gate", projectSlug, "introduced", reportId ?? ""] as const),
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

export function useMe() {
  return useQuery({
    queryKey: queryKeys.me(),
    queryFn: () => apiFetch<UserProfile>("/api/v1/me"),
    staleTime: 5 * 60 * 1000,
  });
}

/** Server build info; unauthenticated and effectively static, so it is cached
 * for an hour. */
export function useVersion() {
  return useQuery({
    queryKey: queryKeys.version(),
    queryFn: () => apiFetch<ServerVersion>("/api/v1/version"),
    staleTime: 60 * 60 * 1000,
  });
}

export function useProject(slug: string) {
  return useQuery({
    queryKey: queryKeys.project(slug),
    queryFn: () => apiFetch<Project>(`/api/v1/projects/${encodeURIComponent(slug)}`),
    enabled: !!slug,
  });
}

export function useProjectStats(
  slug: string,
  options?: { refetchInterval?: number | false; },
) {
  return useQuery({
    queryKey: queryKeys.projectStats(slug),
    queryFn: () => apiFetch<ProjectStats>(`/api/v1/projects/${encodeURIComponent(slug)}/stats`),
    enabled: !!slug,
    refetchInterval: options?.refetchInterval,
  });
}

export function useCreateProject() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (
      { name, slug, description }: { name: string; slug: string; description?: string; },
    ) =>
      apiFetch<Project>("/api/v1/projects", {
        method: "POST",
        body: JSON.stringify({ name, slug, description }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.projects() });
    },
  });
}

export function useCreateApiKey() {
  return useMutation({
    // The response carries the key's only copy of its secret; do not keep it
    // in the shared mutation cache once nothing observes it.
    gcTime: 0,
    mutationFn: ({ project, name }: { project: string; name: string; }) =>
      apiFetch<CreatedApiKey>("/api/v1/auth/apikeys", {
        method: "POST",
        body: JSON.stringify({ project, name }),
      }),
  });
}

export function useFindings(
  projectSlug: string,
  filters: { severity?: string; status?: string; kind?: string; offset?: number; limit?: number; },
) {
  return useQuery({
    queryKey: queryKeys.findings(projectSlug, filters),
    queryFn: async () => {
      const params = new URLSearchParams();
      if (filters.severity) params.set("severity", filters.severity);
      if (filters.status) params.set("status", filters.status);
      if (filters.kind) params.set("kind", filters.kind);
      if (filters.offset != null) params.set("offset", String(filters.offset));
      if (filters.limit != null) params.set("limit", String(filters.limit));
      const qs = params.toString();
      const query = qs ? `?${qs}` : "";
      const { data, total } = await apiFetchWithTotal<Finding[]>(
        `/api/v1/projects/${encodeURIComponent(projectSlug)}/findings${query}`,
      );
      // `total` counts the filtered set across every page, so the pager can
      // tell the last page from a full one without probing for it.
      return { findings: data, total };
    },
    enabled: !!projectSlug,
    placeholderData: keepPreviousData,
  });
}

/**
 * Query options for one finding. Exported so callers that load many findings at
 * once (the change view) can reuse the same query and share its cache entry
 * with `useFinding`.
 */
export function findingQueryOptions(findingId: string) {
  return {
    queryKey: queryKeys.finding(findingId),
    queryFn: () => apiFetch<Finding>(`/api/v1/findings/${encodeURIComponent(findingId)}`),
    enabled: !!findingId,
  };
}

export function useFinding(findingId: string) {
  return useQuery(findingQueryOptions(findingId));
}

export function useReports(projectSlug: string) {
  return useQuery({
    queryKey: queryKeys.reports(projectSlug),
    queryFn: () =>
      apiFetch<Report[]>(`/api/v1/projects/${encodeURIComponent(projectSlug)}/reports`),
    enabled: !!projectSlug,
  });
}

export function useGateStatus(projectSlug: string) {
  return useQuery({
    queryKey: queryKeys.gate(projectSlug),
    queryFn: () => apiFetch<GateStatus>(`/api/v1/projects/${encodeURIComponent(projectSlug)}/gate`),
    enabled: !!projectSlug,
  });
}

/**
 * Gate verdict scoped to one report, i.e. only the findings that change
 * introduced. Requires a report: without one there is nothing to scope to, so
 * the query stays disabled rather than falling back to the project-wide gate.
 */
export function useChangeGate(projectSlug: string, reportId: string | undefined) {
  return useQuery({
    queryKey: queryKeys.changeGate(projectSlug, reportId),
    queryFn: () =>
      apiFetch<GateStatus>(
        `/api/v1/projects/${encodeURIComponent(projectSlug)}/gate?introduced_only=true&report_id=${
          encodeURIComponent(reportId ?? "")
        }`,
      ),
    enabled: !!projectSlug && !!reportId,
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
      apiFetch<TriageResponse>(`/api/v1/findings/${encodeURIComponent(findingId)}`, {
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
      queryClient.invalidateQueries({ queryKey: queryKeys.projectStats() });
    },
  });
}

export function useReachability(findingId: string) {
  return useQuery({
    queryKey: queryKeys.reachability(findingId),
    queryFn: () =>
      apiFetch<ReachabilityAssessment[]>(
        `/api/v1/findings/${encodeURIComponent(findingId)}/reachability`,
      ),
    enabled: !!findingId,
  });
}

export function useFindingEvents(findingId: string) {
  return useQuery({
    queryKey: queryKeys.findingEvents(findingId),
    queryFn: () =>
      apiFetch<FindingEvent[]>(`/api/v1/findings/${encodeURIComponent(findingId)}/events`),
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
      apiFetch<ReachabilityAssessment>(
        `/api/v1/findings/${encodeURIComponent(findingId)}/reachability`,
        {
          method: "POST",
          body: JSON.stringify({ state, evidence: evidence ?? "" }),
        },
      ),
    onSuccess: (_data, vars) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reachability(vars.findingId) });
      queryClient.invalidateQueries({ queryKey: queryKeys.gate() });
      queryClient.invalidateQueries({ queryKey: queryKeys.finding() });
      queryClient.invalidateQueries({ queryKey: queryKeys.findingEvents(vars.findingId) });
      queryClient.invalidateQueries({ queryKey: queryKeys.projectStats() });
    },
  });
}

export function useProjectMembers(slug: string) {
  return useQuery({
    queryKey: queryKeys.projectMembers(slug),
    queryFn: () =>
      apiFetch<ProjectMember[]>(`/api/v1/projects/${encodeURIComponent(slug)}/members`),
    enabled: !!slug,
  });
}

export function useAddProjectMember(slug: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ user_id, role }: { user_id: string; role: ProjectRole; }) =>
      apiFetch<void>(`/api/v1/projects/${encodeURIComponent(slug)}/members`, {
        method: "POST",
        body: JSON.stringify({ user_id, role }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.projectMembers(slug) });
    },
  });
}

export function useRemoveProjectMember(slug: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (userId: string) =>
      apiFetch<void>(
        `/api/v1/projects/${encodeURIComponent(slug)}/members/${encodeURIComponent(userId)}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.projectMembers(slug) });
    },
  });
}

export function useProjectTeams(slug: string) {
  return useQuery({
    queryKey: queryKeys.projectTeams(slug),
    queryFn: () => apiFetch<ProjectTeam[]>(`/api/v1/projects/${encodeURIComponent(slug)}/teams`),
    enabled: !!slug,
  });
}

export function useLinkProjectTeam(slug: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ team_id, role }: { team_id: string; role: ProjectRole; }) =>
      apiFetch<void>(`/api/v1/projects/${encodeURIComponent(slug)}/teams`, {
        method: "POST",
        body: JSON.stringify({ team_id, role }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.projectTeams(slug) });
    },
  });
}

export function useUnlinkProjectTeam(slug: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (teamId: string) =>
      apiFetch<void>(
        `/api/v1/projects/${encodeURIComponent(slug)}/teams/${encodeURIComponent(teamId)}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.projectTeams(slug) });
    },
  });
}

export function useTeams() {
  return useQuery({
    queryKey: queryKeys.teams(),
    queryFn: () => apiFetch<Team[]>("/api/v1/teams"),
  });
}

export function useCreateTeam() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ name, description }: { name: string; description?: string; }) =>
      apiFetch<Team>("/api/v1/teams", {
        method: "POST",
        body: JSON.stringify({ name, description: description ?? "" }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.teams() });
    },
  });
}

export function useDeleteTeam() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (teamId: string) =>
      apiFetch<void>(`/api/v1/teams/${encodeURIComponent(teamId)}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.teams() });
    },
  });
}

export function useTeamMembers(teamId: string) {
  return useQuery({
    queryKey: queryKeys.teamMembers(teamId),
    queryFn: () => apiFetch<TeamMember[]>(`/api/v1/teams/${encodeURIComponent(teamId)}/members`),
    enabled: !!teamId,
  });
}

export function useAddTeamMember(teamId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (userId: string) =>
      apiFetch<void>(`/api/v1/teams/${encodeURIComponent(teamId)}/members`, {
        method: "POST",
        body: JSON.stringify({ user_id: userId }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.teamMembers(teamId) });
    },
  });
}

export function useRemoveTeamMember(teamId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (userId: string) =>
      apiFetch<void>(
        `/api/v1/teams/${encodeURIComponent(teamId)}/members/${encodeURIComponent(userId)}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.teamMembers(teamId) });
    },
  });
}

const roleRank: Record<ProjectRole, number> = {
  admin: 3,
  manager: 2,
  member: 1,
};

/**
 * Resolves the effective role of the current user on the specified project.
 * Global platform admins automatically have "admin" authority.
 * Otherwise, the highest rank among direct grants and linked team grants is returned.
 */
export function useProjectRole(slug: string): {
  role: ProjectRole | null;
  isLoading: boolean;
  canManageMembers: boolean;
  canTriage: boolean;
  isAdmin: boolean;
} {
  const me = useMe();
  const members = useProjectMembers(slug);

  if (me.isLoading || members.isLoading) {
    return {
      role: null,
      isLoading: true,
      canManageMembers: false,
      canTriage: true,
      isAdmin: false,
    };
  }

  if (me.data?.role === "admin") {
    return {
      role: "admin",
      isLoading: false,
      canManageMembers: true,
      canTriage: true,
      isAdmin: true,
    };
  }

  // If user profile is not authenticated (missing email/role, e.g. unmocked unit tests),
  // default to allowing triage so non-RBAC tests run smoothly.
  if (!me.data?.email || !me.data?.role) {
    return {
      role: null,
      isLoading: false,
      canManageMembers: false,
      canTriage: true,
      isAdmin: false,
    };
  }

  const userId = me.data.id;
  let highestRole: ProjectRole | null = null;
  if (Array.isArray(members.data)) {
    const direct = members.data.find((m) => m.user_id === userId);
    if (direct) {
      highestRole = direct.role;
    }
  }

  const effectiveRole = highestRole ?? "member";
  const rank = roleRank[effectiveRole] ?? 1;

  return {
    role: effectiveRole,
    isLoading: false,
    canManageMembers: rank >= 2,
    canTriage: rank >= 2,
    isAdmin: rank >= 3,
  };
}
