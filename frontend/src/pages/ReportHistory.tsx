import { useReports } from "@/api/hooks";
import { useParams } from "react-router-dom";

const statusStyles: Record<string, string> = {
  completed: "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
  processing: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400",
  failed: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
};

export function ReportHistory() {
  const { slug } = useParams<{ slug: string; }>();
  const { data: reports, isLoading, isError, error, refetch } = useReports(slug ?? "");

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="bg-muted h-16 animate-pulse rounded" />
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex flex-col items-center gap-2 py-16">
        <p className="text-destructive text-sm">{error?.message ?? "Failed to load reports"}</p>
        <button
          className="text-primary text-sm underline hover:no-underline"
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
        <p className="text-muted-foreground text-sm">No reports yet</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {reports.map((r) => (
        <div key={r.id} className="bg-card rounded-lg border p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">{r.tool_name}</p>
              {r.scan_target && <p className="text-muted-foreground text-xs">{r.scan_target}</p>}
            </div>
            <span
              className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${
                statusStyles[r.status] ?? ""
              }`}
            >
              {r.status === "processing" && (
                <span className="mr-1 h-1.5 w-1.5 animate-pulse rounded-full bg-current" />
              )}
              {r.status}
            </span>
          </div>
          <div className="text-muted-foreground mt-2 text-xs">
            {new Date(r.created_at).toLocaleString()}
            {r.total_findings != null && <span className="ml-3">{r.total_findings} findings</span>}
          </div>
        </div>
      ))}
    </div>
  );
}
