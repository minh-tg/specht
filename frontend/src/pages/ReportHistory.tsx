import { useReports } from "@/api/hooks";
import { Skeleton } from "@/components/ui/skeleton";
import { formatDateTime, pluralize } from "@/lib/format";
import { cn } from "@/lib/utils";
import { isReportInProgress } from "@/lib/verdict";
import type { ReportStatus } from "@/types/api";
import { Link, useParams } from "react-router-dom";

const STATUS_LABELS: Record<ReportStatus, string> = {
  processing: "Processing",
  pending: "Processing",
  completed: "Completed",
  failed: "Failed",
};

const STATUS_STYLES: Record<ReportStatus, string> = {
  processing: "bg-muted text-muted-foreground",
  pending: "bg-muted text-muted-foreground",
  completed: "bg-sev-success-bg text-sev-success-fg",
  failed: "bg-destructive/10 text-destructive",
};

function isReportStatus(status: string): status is ReportStatus {
  return Object.hasOwn(STATUS_LABELS, status);
}

function statusMeta(status: string): { label: string; style: string; } {
  return isReportStatus(status)
    ? { label: STATUS_LABELS[status], style: STATUS_STYLES[status] }
    : { label: status, style: "bg-muted text-muted-foreground" };
}

export function ReportHistory() {
  const { slug } = useParams<{ slug: string; }>();
  const { data: reports, isLoading, isError, error, refetch } = useReports(slug ?? "");

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-16 rounded" />)}
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex flex-col items-center gap-2 py-16">
        <p className="text-destructive text-sm">{error?.message ?? "Failed to load reports"}</p>
        <button
          className="text-action text-sm underline hover:no-underline"
          onClick={() => refetch()}
        >
          Retry
        </button>
      </div>
    );
  }

  if (!reports?.length) {
    return (
      <div className="flex flex-col items-center gap-2 py-16">
        <p className="text-muted-foreground text-sm">No reports yet.</p>
        <Link
          to={`/${slug}/reports/upload`}
          className="text-action text-sm underline hover:no-underline"
        >
          Upload a report
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <Link
          to={`/${slug}/reports/upload`}
          className="bg-primary text-primary-foreground hover:bg-primary/90 inline-flex items-center rounded-md px-3 py-1.5 text-sm font-medium"
        >
          Upload report
        </Link>
      </div>

      {reports.map((r) => {
        const status = statusMeta(r.status);

        return (
          <div
            key={r.id}
            className={cn(
              "bg-card rounded-lg border p-4",
              r.status === "failed" && "border-destructive",
            )}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="bg-muted text-muted-foreground inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium">
                  {r.tool_name}
                </span>
                {r.scan_target && <p className="text-muted-foreground text-xs">{r.scan_target}</p>}
              </div>
              <span
                className={cn(
                  "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium",
                  status.style,
                )}
              >
                {isReportInProgress(r.status) && (
                  <span className="mr-1 h-1.5 w-1.5 animate-pulse rounded-full bg-current" />
                )}
                {status.label}
              </span>
            </div>
            {r.status === "failed" && r.error_message && (
              <p className="text-muted-foreground mt-1 text-xs break-words">{r.error_message}</p>
            )}
            {(r.branch || r.commit_sha) && (
              <p className="text-muted-foreground mt-1 font-mono text-xs">
                {r.branch && <span>{r.branch}</span>}
                {r.branch && r.commit_sha && " · "}
                {r.commit_sha && (
                  <Link
                    to={`/${encodeURIComponent(slug ?? "")}/changes/${
                      encodeURIComponent(r.commit_sha)
                    }?report=${encodeURIComponent(r.id)}`}
                    className="text-action underline underline-offset-2 hover:no-underline"
                  >
                    {r.commit_sha.slice(0, 7)}
                  </Link>
                )}
              </p>
            )}
            <div className="text-muted-foreground mt-2 text-xs">
              {formatDateTime(r.created_at)}
              {r.total_findings != null && (
                <span className="ml-3">{pluralize(r.total_findings, "finding")}</span>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
