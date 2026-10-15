import { APIError } from "@/api/client";
import { MAX_PAGE_SIZE, useProjectRole, useReports } from "@/api/hooks";
import { useDeleteReport } from "@/api/reportActions";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState } from "@/components/ErrorState";
import { INLINE_LINK } from "@/components/inlineLink";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { buttonVariants } from "@/components/ui/button-variants";
import { Skeleton } from "@/components/ui/skeleton";
import { formatDateTime, pluralize } from "@/lib/format";
import { cn } from "@/lib/utils";
import { isReportInProgress } from "@/lib/verdict";
import type { Report, ReportStatus } from "@/types/api";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";

const CONFLICT_MESSAGE = "This report is still being processed. Try again when it finishes.";

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

const PAGE_SIZE = 20;

export function ReportHistory() {
  const { slug } = useParams<{ slug: string; }>();
  const [limit, setLimit] = useState(PAGE_SIZE);
  const { data: reports, isLoading, isError, error, refetch, isFetching } = useReports(
    slug ?? "",
    limit,
  );
  const { isAdmin } = useProjectRole(slug ?? "");
  const deleteMutation = useDeleteReport(slug ?? "");
  const [pendingDelete, setPendingDelete] = useState<Report | null>(null);

  let deleteError: string | null = null;
  if (deleteMutation.isError) {
    const err = deleteMutation.error;
    deleteError = err instanceof APIError && err.status === 409 ? CONFLICT_MESSAGE : err.message;
  }

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-16 rounded" />)}
      </div>
    );
  }

  if (isError) {
    return (
      <ErrorState
        title="Could not load reports."
        detail={error?.message}
        onRetry={() => refetch()}
      />
    );
  }

  if (!reports?.length) {
    return (
      <EmptyState
        title="No reports yet."
        description="Upload a scanner report and its findings appear here."
        action={
          <Link to={`/${slug}/reports/upload`} className={buttonVariants()}>
            Upload a report
          </Link>
        }
      />
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <Link to={`/${slug}/reports/upload`} className={buttonVariants()}>
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
                    className={INLINE_LINK}
                  >
                    {r.commit_sha.slice(0, 7)}
                  </Link>
                )}
              </p>
            )}
            <div className="mt-2 flex items-center justify-between">
              <div className="text-muted-foreground text-xs tabular-nums">
                {formatDateTime(r.created_at)}
                {r.total_findings != null && (
                  <span className="ml-3 tabular-nums">
                    {pluralize(r.total_findings, "finding")}
                  </span>
                )}
              </div>
              {isAdmin && !isReportInProgress(r.status) && (
                <button
                  type="button"
                  aria-label={`Delete ${r.tool_name} report from ${formatDateTime(r.created_at)}`}
                  onClick={() => {
                    deleteMutation.reset();
                    setPendingDelete(r);
                  }}
                  className="text-destructive hover:text-destructive/80 text-xs font-medium"
                >
                  Delete
                </button>
              )}
            </div>
          </div>
        );
      })}

      {reports.length >= limit && limit < MAX_PAGE_SIZE && (
        <div>
          <Button
            variant="outline"
            type="button"
            disabled={isFetching}
            onClick={() => setLimit((current) => Math.min(current + PAGE_SIZE, MAX_PAGE_SIZE))}
          >
            Show more reports
          </Button>
        </div>
      )}

      <AlertDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => {
          if (!open && !deleteMutation.isPending) setPendingDelete(null);
        }}
        onOpenChangeComplete={(open) => {
          if (!open) deleteMutation.reset();
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete this report?</AlertDialogTitle>
            <AlertDialogDescription>
              This removes the report's occurrences and package list. Findings that only this report
              showed are archived, so they stop blocking the gate. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          {deleteError && <p role="alert" className="text-destructive text-sm">{deleteError}</p>}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deleteMutation.isPending}
              onClick={async (event) => {
                event.preventDefault();
                if (!pendingDelete) return;
                try {
                  await deleteMutation.mutateAsync(pendingDelete.id);
                  setPendingDelete(null);
                } catch {}
              }}
            >
              {deleteMutation.isPending ? "Deleting..." : "Delete report"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
