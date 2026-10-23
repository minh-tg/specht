import { RelativeTime } from "@/components/RelativeTime";
import { isReportInProgress } from "@/lib/verdict";
import type { Report } from "@/types/api";

/** Report receipt/processing times are distinct from the browser's fetch time. */
export function ReportFreshness({ latest, latestCompleted }: {
  readonly latest?: Report;
  readonly latestCompleted?: Report;
}) {
  const completed = latestCompleted?.status === "completed"
    ? latestCompleted
    : latest?.status === "completed"
    ? latest
    : undefined;
  if (!latest && !completed) return null;

  const attemptStatus = latest?.status === "failed"
    ? "Failed"
    : isReportInProgress(latest?.status)
    ? "Processing"
    : latest?.status === "completed"
    ? "Completed"
    : "Unknown";

  return (
    <section aria-label="Report freshness" className="text-muted-foreground mt-2 space-y-1 text-sm">
      {completed
        ? (
          <p>
            Latest completed report · {completed.tool_name} ·{" "}
            {completed.completed_at ? "completed" : "received"}{" "}
            <RelativeTime iso={completed.completed_at ?? completed.created_at} />
            {!completed.completed_at && " (completion time unavailable)"}
          </p>
        )
        : <p>No completed report available.</p>}
      {latest && latest.id !== completed?.id && (
        <p>
          Latest attempt · {attemptStatus} · {latest.tool_name} · received{" "}
          <RelativeTime iso={latest.created_at} />
        </p>
      )}
      <p className="text-xs">Report times describe receipt and processing in Specht.</p>
    </section>
  );
}
