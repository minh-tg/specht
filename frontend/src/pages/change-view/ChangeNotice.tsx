import { RelativeTime } from "@/components/RelativeTime";
import { formatClockTime } from "@/lib/format";
import type { ReactNode } from "react";

/**
 * A boxed sentence or two under the verdict, for a reason the verdict on screen may not be the
 * latest. It has no live region of its own: the verdict header around it already announces changes.
 */
function Notice({ title, children }: { readonly title?: string; readonly children: ReactNode; }) {
  return (
    <div className="bg-card mt-4 grid max-w-[68ch] gap-1 rounded-lg border px-3.5 py-3 text-body">
      {title && <p className="font-semibold">{title}</p>}
      <p className={title ? "text-muted-foreground" : undefined}>{children}</p>
    </div>
  );
}

/** The browser has no connection, so the verdict on screen is the last one that was fetched. */
export function OfflineNotice({ verdictAt }: { readonly verdictAt: string; }) {
  return (
    <Notice>
      You are offline. This is the verdict from{" "}
      {formatClockTime(verdictAt)}; it updates when the connection is back.
    </Notice>
  );
}

/**
 * Ten minutes of watching found no newer report. It points at the CI job, since Specht scans only
 * what a job or a watcher sends it, and says that the page keeps checking.
 */
export function StalledNotice(
  { reportAt, checkedAt }: { readonly reportAt: string; readonly checkedAt: number; },
) {
  return (
    <Notice title={`No new report since ${formatClockTime(reportAt)}`}>
      Check that the CI job ran on your last push and that its scan step uploads to Specht. Still
      watching{checkedAt > 0
        ? (
          <>
            ; checked <RelativeTime iso={new Date(checkedAt).toISOString()} frozen />
          </>
        )
        : null}.
    </Notice>
  );
}
