import { INLINE_LINK } from "@/components/inlineLink";
import { VerdictBadge } from "@/components/VerdictBadge";
import { pluralize } from "@/lib/format";
import type { IngestResponse } from "@/types/api";
import { Link } from "react-router-dom";

interface UploadResultCardProps {
  result: IngestResponse;
  slug: string;
  onReset: () => void;
}

/** The gate verdict shown after a report is ingested. */
export function UploadResultCard({ result, slug, onReset }: UploadResultCardProps) {
  return (
    <div role="status" className="bg-card mb-6 rounded-lg border p-4">
      <div className="flex items-center gap-3">
        <span className="text-body font-medium tabular-nums">
          {pluralize(result.total_findings, "finding")} found
        </span>
        <VerdictBadge verdict={result.threshold_breached ? "blocked" : "passing"} />
      </div>
      <p className="text-muted-foreground mt-2 text-body">
        {result.threshold_breached ? "The gate would block this project." : "The gate passes."}
      </p>
      {result.replayed && (
        <p className="text-muted-foreground mt-2 text-body">
          This exact report was already ingested for this commit; showing its result.
        </p>
      )}
      <div className="mt-3 flex items-center gap-4 text-body">
        <Link to={`/${slug}/findings`} className={INLINE_LINK}>
          View findings
        </Link>
        <Link to={`/${slug}/reports`} className={INLINE_LINK}>
          Back to reports
        </Link>
        <button
          type="button"
          onClick={onReset}
          className={INLINE_LINK}
        >
          Upload another
        </button>
      </div>
    </div>
  );
}
