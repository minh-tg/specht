import { useQuery } from "@tanstack/react-query"
import { apiFetch } from "./client"
import type { Project, Finding, Report } from "@/types/api"

export function useProjects() {
  return useQuery({
    queryKey: ["projects"],
    queryFn: () => apiFetch<Project[]>("/api/v1/projects"),
  })
}

export function useFindings(
  projectSlug: string,
  filters: { severity?: string; status?: string; offset?: number; limit?: number },
) {
  return useQuery({
    queryKey: ["findings", projectSlug, filters],
    queryFn: () => {
      const params = new URLSearchParams()
      if (filters.severity) params.set("severity", filters.severity)
      if (filters.status) params.set("status", filters.status)
      if (filters.offset != null) params.set("offset", String(filters.offset))
      if (filters.limit != null) params.set("limit", String(filters.limit))
      const qs = params.toString()
      return apiFetch<Finding[]>(`/api/v1/projects/${projectSlug}/findings${qs ? `?${qs}` : ""}`)
    },
  })
}

export function useReports(projectSlug: string) {
  return useQuery({
    queryKey: ["reports", projectSlug],
    queryFn: () => apiFetch<Report[]>(`/api/v1/projects/${projectSlug}/reports`),
  })
}
