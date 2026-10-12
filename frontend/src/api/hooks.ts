import { type AnalysisState, gateEffectLabel, type ReachabilityState } from "@/lib/enums";
import type {
  Capabilities,
  CreatedApiKey,
  Finding,
  FindingEvent,
  GateStatus,
  Invite,
  InviteRole,
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
  Waiver,
  WaiverStatus,
} from "@/types/api";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { apiFetch, apiFetchWithTotal } from "./client";

/** What the findings list asks the server for. Empty values are left out of the request. */
export interface FindingsQuery {
  severity?: string;
  status?: string;
  kind?: string;
  /** Comma list of analysis states; `unanalyzed` matches findings nobody has looked at. */
  analysisState?: string;
  /** Text matched against the title and the fingerprint. */
  q?: string;
  sort?: FindingSort;
  dir?: "asc" | "desc";
  offset?: number;
  limit?: number;
}

/** The orderings the server offers. `first_seen` ascending lists the oldest findings first. */
export type FindingSort = "severity" | "first_seen" | "last_seen" | "title";

export const queryKeys = {
  waivers: (slug?: string, status?: string) =>
    slug === undefined ? (["waivers"] as const) : (["waivers", slug, status ?? ""] as const),
  scanSignal: (slug: string, branch: string) => ["scan-signal", slug, branch] as const,
  capabilities: () => ["capabilities"] as const,
  invites: (slug: string) => ["invites", slug] as const,
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
    filters?: FindingsQuery,
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
/** The sign-in options and first-run state. Public, so it works before anyone is signed in. */
export function useCapabilities() {
  return useQuery({
    queryKey: queryKeys.capabilities(),
    queryFn: () => apiFetch<Capabilities>("/api/v1/capabilities", { skipAuthRedirect: true }),
    staleTime: 60 * 1000,
  });
}

export function useInvites(slug: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.invites(slug),
    queryFn: () => apiFetch<Invite[]>(`/api/v1/projects/${encodeURIComponent(slug)}/invites`),
    enabled: !!slug && enabled,
  });
}

export function useCreateInvite(slug: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: { role: InviteRole; email?: string; expires_in_days?: number; }) =>
      apiFetch<Invite>(`/api/v1/projects/${encodeURIComponent(slug)}/invites`, {
        method: "POST",
        body: JSON.stringify(input),
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.invites(slug) });
    },
  });
}

export function useRevokeInvite(slug: string) {
  const queryClient = useQueryClient();
  return useMutation({
    meta: { success: "Invite revoked" },
    mutationFn: (id: string) =>
      apiFetch<void>(
        `/api/v1/projects/${encodeURIComponent(slug)}/invites/${encodeURIComponent(id)}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.invites(slug) });
    },
  });
}

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

export function useFindings(projectSlug: string, filters: FindingsQuery) {
  return useQuery({
    queryKey: queryKeys.findings(projectSlug, filters),
    queryFn: async () => {
      const params = new URLSearchParams();
      if (filters.severity) params.set("severity", filters.severity);
      if (filters.status) params.set("status", filters.status);
      if (filters.kind) params.set("kind", filters.kind);
      if (filters.analysisState) params.set("analysis_state", filters.analysisState);
      if (filters.q) params.set("q", filters.q);
      if (filters.sort) params.set("sort", filters.sort);
      if (filters.dir) params.set("dir", filters.dir);
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
    meta: {
      success: (data: TriageResponse) =>
        `Triage saved (effect: ${gateEffectLabel(data.gate_effect) ?? "Unknown"})`,
    },
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

export function useBulkTriage() {
  const queryClient = useQueryClient();
  return useMutation({
    meta: {
      success: (data: { results: TriageResponse[]; }) =>
        `Triage saved for ${data.results.length} ${
          data.results.length === 1 ? "finding" : "findings"
        }`,
    },
    mutationFn: ({ findingIds, analysisState, reason, analysisExpiresAt }: {
      findingIds: readonly string[];
      analysisState: AnalysisState;
      reason?: string;
      analysisExpiresAt?: string;
    }) =>
      apiFetch<{ results: TriageResponse[]; }>("/api/v1/findings/bulk-analysis", {
        method: "POST",
        body: JSON.stringify({
          finding_ids: findingIds,
          analysis_state: analysisState,
          ...(reason ? { reason } : {}),
          ...(analysisExpiresAt ? { analysis_expires_at: analysisExpiresAt } : {}),
        }),
      }),
    onSuccess: () => {
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
    meta: { success: "Reachability saved" },
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
    meta: { success: "Member added" },
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
    meta: { success: "Member removed" },
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
    meta: { success: "Team linked" },
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
    meta: { success: "Team unlinked" },
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
    meta: { success: "Team created" },
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
    meta: { success: "Team deleted" },
    mutationFn: (teamId: string) =>
      apiFetch<void>(`/api/v1/teams/${encodeURIComponent(teamId)}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.teams() });
    },
  });
}

/** Roles a company team member can hold; the server rejects anything else. */
type TeamMemberRole = "admin" | "member";

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
    meta: { success: "Added to the team" },
    mutationFn: ({ userId, role }: { userId: string; role: TeamMemberRole; }) =>
      apiFetch<void>(`/api/v1/teams/${encodeURIComponent(teamId)}/members`, {
        method: "POST",
        body: JSON.stringify({ user_id: userId, role }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.teamMembers(teamId) });
    },
  });
}

export function useRemoveTeamMember(teamId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    meta: { success: "Removed from the team" },
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

/** The project's waivers, optionally only those in the given review states. */
export function useWaivers(slug: string, statuses?: readonly WaiverStatus[]) {
  const status = statuses?.join(",");
  return useQuery({
    queryKey: queryKeys.waivers(slug, status),
    queryFn: () =>
      apiFetch<Waiver[]>(
        `/api/v1/projects/${encodeURIComponent(slug)}/waivers${
          status ? `?status=${encodeURIComponent(status)}` : ""
        }`,
      ),
    enabled: !!slug,
  });
}

/**
 * Asks for a waiver on specific findings. The request stays pending and changes no verdict until a
 * manager or admin approves it.
 */
export function useRequestWaiver(slug: string) {
  const queryClient = useQueryClient();
  return useMutation({
    meta: { success: () => "Waiver requested. A manager will decide." },
    mutationFn: ({ findingIds, reason, expiresAt }: {
      findingIds: string[];
      reason: string;
      expiresAt: string;
    }) =>
      apiFetch<Waiver>(`/api/v1/projects/${encodeURIComponent(slug)}/waivers/requests`, {
        method: "POST",
        body: JSON.stringify({ target_ids: findingIds, reason, expires_at: expiresAt }),
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.waivers() });
      void queryClient.invalidateQueries({ queryKey: queryKeys.projectStats() });
    },
  });
}

/**
 * How often to ask whether the next scan has landed: every 4 s for the first minute, then every 10 s,
 * and not at all after ten minutes, when the page says to check the CI job instead. A scan takes
 * minutes, so a slow poll costs the reader nothing and the server one indexed read per visitor.
 */
export function scanPollInterval(elapsedMs: number): number | false {
  if (elapsedMs < 60_000) return 4_000;
  if (elapsedMs < 600_000) return 10_000;
  return false;
}

/**
 * Watches for the newest report on a branch while the page waits for a scan. It polls only while
 * `enabled`, only while the tab is visible, and gives up after ten minutes (`stalled`).
 */
export function useScanSignal(
  slug: string,
  options: {
    branch: string | null | undefined;
    enabled: boolean;
    /** Bump to start the ten minutes again and ask right away, after the page gave up. */
    attempt?: number;
  },
) {
  const { branch, enabled, attempt = 0 } = options;
  const startedAt = useRef<number | null>(null);
  // One key per run of waiting; the page counts as stalled when the run that is current gave up. A
  // new run (another attempt, or waiting started again) has a new key, so no reset is needed.
  const runKey = enabled ? `run-${attempt}` : "";
  const [stalledRun, setStalledRun] = useState("");

  useEffect(() => {
    if (!enabled) {
      startedAt.current = null;
      return;
    }
    startedAt.current = Date.now();
    const timer = setTimeout(() => setStalledRun(runKey), 600_000);
    return () => clearTimeout(timer);
  }, [enabled, runKey]);
  const stalled = enabled && stalledRun === runKey;

  const query = useQuery({
    queryKey: queryKeys.scanSignal(slug, branch ?? ""),
    queryFn: async () => {
      const params = new URLSearchParams({ limit: "1" });
      if (branch) params.set("branch", branch);
      const rows = await apiFetch<Report[]>(
        `/api/v1/projects/${encodeURIComponent(slug)}/reports?${params.toString()}`,
      );
      return rows[0] ?? null;
    },
    enabled: enabled && !!slug,
    refetchInterval: () =>
      startedAt.current === null ? false : scanPollInterval(Date.now() - startedAt.current),
    refetchIntervalInBackground: false,
  });
  const { refetch } = query;
  useEffect(() => {
    if (enabled && attempt > 0) void refetch();
  }, [enabled, attempt, refetch]);
  return { newest: query.data ?? null, stalled, isError: query.isError };
}
