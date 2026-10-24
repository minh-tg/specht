import { pluralize } from "@/lib/format";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch, apiFetchResponse } from "./client";
import { queryKeys } from "./hooks";

export interface ReportDeletionPreview {
  affected: number;
  archived: number;
}

export interface DeleteReportResult {
  archived: number;
}

/** The success toast after a report is deleted, naming how many findings were archived. */
export function archivedFindingsMessage(result: DeleteReportResult): string {
  return `Report deleted. ${pluralize(result.archived, "finding")} archived.`;
}

function parseArchivedCount(header: string | null | undefined): number {
  const count = Number.parseInt(header ?? "", 10);
  return Number.isFinite(count) && count >= 0 ? count : 0;
}

/**
 * What deleting a report would settle, read when the confirm dialog opens.
 * Advisory: the delete itself remains authoritative, so a failed preview must
 * not block it.
 */
export function useReportDeletionPreview(projectSlug: string, reportId: string | null) {
  return useQuery({
    queryKey: queryKeys.reportDeletionPreview(projectSlug, reportId ?? ""),
    enabled: reportId !== null,
    staleTime: 0,
    queryFn: async (): Promise<ReportDeletionPreview> => {
      const body = await apiFetch<{ affected_findings: unknown; archived_findings: unknown; }>(
        `/api/v1/projects/${encodeURIComponent(projectSlug)}/reports/${
          encodeURIComponent(reportId ?? "")
        }/deletion-preview`,
        { method: "GET" },
      );
      const affected = Number(body?.affected_findings);
      const archived = Number(body?.archived_findings);
      if (
        !Number.isInteger(affected) || !Number.isInteger(archived) || affected < 0 || archived < 0
      ) throw new Error("report deletion preview has no counts");
      return { affected, archived };
    },
  });
}

/** What the confirm dialog says once the preview arrives. */
export function deletionImpactMessage({ affected, archived }: ReportDeletionPreview): string {
  const lost = archived === 0
    ? "No finding loses its only evidence."
    : `This archives ${pluralize(archived, "finding")} that no other report shows.`;
  const gate = affected === 0
    ? "No finding cites this report."
    : `Gate results can change for the ${pluralize(affected, "finding")} this report observed.`;
  return `${lost} ${gate} This cannot be undone.`;
}

/** Deletes one report of a project. The server archives findings it was the only evidence for. */
export function useDeleteReport(projectSlug: string) {
  const queryClient = useQueryClient();
  return useMutation({
    meta: {
      success: (data: DeleteReportResult) => archivedFindingsMessage(data),
      sound: "none",
    },
    mutationFn: async (reportId: string): Promise<DeleteReportResult> => {
      const { response } = await apiFetchResponse<void>(
        `/api/v1/projects/${encodeURIComponent(projectSlug)}/reports/${
          encodeURIComponent(reportId)
        }`,
        { method: "DELETE" },
      );
      return { archived: parseArchivedCount(response.headers?.get("X-Archived-Findings")) };
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.reports(projectSlug) });
      void queryClient.invalidateQueries({ queryKey: queryKeys.projectStats(projectSlug) });
      void queryClient.invalidateQueries({ queryKey: queryKeys.findings(projectSlug) });
      void queryClient.invalidateQueries({ queryKey: queryKeys.gate(projectSlug) });
      void queryClient.invalidateQueries({ queryKey: queryKeys.finding() });
      void queryClient.invalidateQueries({ queryKey: queryKeys.findingEvents() });
    },
  });
}
