import { pluralize } from "@/lib/format";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetchResponse } from "./client";
import { queryKeys } from "./hooks";

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
