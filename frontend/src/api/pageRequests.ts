import type {
  AcceptInviteResponse,
  GateStatus,
  IngestResponse,
  InviteLookup,
  JoinInviteResponse,
  LoginResponse,
  ProjectStats,
  ProjectSummary,
  RegisterResponse,
} from "@/types/api";
import {
  queryOptions,
  skipToken,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { apiFetch } from "./client";
import { normalizeGateStatus, normalizeProjectStats, queryKeys } from "./hooks";

/** Keys for requests that only one page makes. Shared keys come from `queryKeys` in hooks.ts. */
export const pageKeys = {
  invite: (token: string) => ["invite", token] as const,
};

/** The project and role an invite link is for. Stale at once so a revisit asks the server again. */
export function useInviteLookup(token: string) {
  return useQuery({
    queryKey: pageKeys.invite(token),
    queryFn: () =>
      apiFetch<InviteLookup>(`/api/v1/invites/${encodeURIComponent(token)}`, {
        skipAuthRedirect: true,
      }),
    retry: false,
    staleTime: 0,
  });
}

export interface AcceptInviteBody {
  email: string;
  password: string;
  display_name?: string;
}

/** Creates the account an invite is for and joins it. The caller handles the error. */
export function useAcceptInvite(token: string) {
  return useMutation({
    mutationFn: (body: AcceptInviteBody) =>
      apiFetch<AcceptInviteResponse>(`/api/v1/invites/${encodeURIComponent(token)}/accept`, {
        method: "POST",
        body: JSON.stringify(body),
        skipAuthRedirect: true,
      }),
  });
}

/** Uploads one scanner report to a project. The caller handles the error and refreshes the project. */
export function useUploadReport(slug: string) {
  return useMutation({
    mutationFn: (report: { scanner: string; raw_data: unknown; }) =>
      apiFetch<IngestResponse>("/api/v1/reports", {
        method: "POST",
        body: JSON.stringify({ project: slug, scanner: report.scanner, raw_data: report.raw_data }),
      }),
  });
}

/** Creates an account on a server that allows self-registration. The caller handles the error. */
export function useRegister() {
  return useMutation({
    mutationFn: (body: { email: string; password: string; }) =>
      apiFetch<RegisterResponse>("/api/v1/auth/register", {
        method: "POST",
        body: JSON.stringify(body),
        skipAuthRedirect: true,
      }),
  });
}

export interface SetupBody {
  token: string;
  email: string;
  password: string;
  display_name?: string;
}

/** Creates the first administrator of a new server. The caller handles the error. */
export function useSetup() {
  return useMutation({
    mutationFn: (body: SetupBody) =>
      apiFetch<LoginResponse>("/api/v1/setup", {
        method: "POST",
        body: JSON.stringify(body),
        skipAuthRedirect: true,
      }),
  });
}

/** Joins the signed-in account to the project an invite is for. The caller handles the error. */
export function useJoinInvite(token: string) {
  return useMutation({
    mutationFn: () =>
      apiFetch<JoinInviteResponse>(`/api/v1/invites/${encodeURIComponent(token)}/join`, {
        method: "POST",
      }),
  });
}

/**
 * The gate and stats of every project the caller can see, in one request. Each row also fills
 * the per-project gate and stats cache entries, so a project page opened from the list starts
 * with them.
 */
export function useProjectSummaries() {
  const queryClient = useQueryClient();
  return useQuery({
    queryKey: queryKeys.projectSummaries(),
    queryFn: async () => {
      const rows = await apiFetch<ProjectSummary[] | null>("/api/v1/project-summaries");
      const summaries = (rows ?? []).map((row) => ({
        slug: row.slug,
        gate: normalizeGateStatus(row.gate),
        stats: normalizeProjectStats(row.stats),
      }));
      for (const summary of summaries) {
        queryClient.setQueryData(queryKeys.gate(summary.slug), summary.gate);
        queryClient.setQueryData(queryKeys.projectStats(summary.slug), summary.stats);
      }
      return summaries;
    },
  });
}

/**
 * Reads one project's gate from the cache without fetching it. The project list renders from
 * these entries, which the summaries request fills, so a change made on a project page shows in
 * the list as soon as that page has the new answer.
 */
export function cachedProjectGate(slug: string) {
  return queryOptions<GateStatus>({ queryKey: queryKeys.gate(slug), queryFn: skipToken });
}

/** Reads one project's stats from the cache without fetching them, like `cachedProjectGate`. */
export function cachedProjectStats(slug: string) {
  return queryOptions<ProjectStats>({ queryKey: queryKeys.projectStats(slug), queryFn: skipToken });
}
