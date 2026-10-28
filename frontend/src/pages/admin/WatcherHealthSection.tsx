import { useWatcherHealth } from "@/api/admin";
import { ErrorState } from "@/components/ErrorState";
import { RelativeTime } from "@/components/RelativeTime";
import { SkeletonLines } from "@/components/SkeletonLines";
import { StatusPill } from "@/components/StatusPill";
import { formatDateTime, pluralize } from "@/lib/format";
import type { ReactNode } from "react";
import { watcherHealthState } from "./watcherHealth";

function Row({ label, children }: { readonly label: string; readonly children: ReactNode; }) {
  return (
    <div className="border-border grid gap-x-6 gap-y-1 border-b px-0.5 py-3 sm:grid-cols-[12rem_minmax(0,1fr)]">
      <dt className="text-muted-foreground text-[0.8125rem]">{label}</dt>
      <dd className="m-0 text-[0.9375rem] tabular-nums">{children}</dd>
    </div>
  );
}

/** The CVE watcher across the whole server. A project's own page points here when its polls fail. */
export function WatcherHealthSection() {
  const { data, isLoading, isError, refetch } = useWatcherHealth();
  const state = data ? watcherHealthState(data) : null;

  return (
    <section aria-labelledby="watcher-health-heading" className="grid gap-3">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h3 id="watcher-health-heading" className="text-body font-semibold">CVE watcher</h3>
          <p className="text-muted-foreground mt-0.5 text-[0.8125rem]">
            One watcher serves every project. Each project switches it on and sets its own interval.
          </p>
        </div>
        {state && <StatusPill tone={state.tone}>{state.label}</StatusPill>}
      </div>

      {isLoading
        ? <SkeletonLines label="Loading the watcher" />
        : isError || !data
        ? <ErrorState title="Could not load the watcher." onRetry={() => void refetch()} />
        : (
          <dl className="border-foreground m-0 border-t-2">
            <Row label="Last successful poll">
              {data.last_successful_poll_at
                ? (
                  <>
                    {formatDateTime(data.last_successful_poll_at)}{" "}
                    (<RelativeTime iso={data.last_successful_poll_at} />)
                  </>
                )
                : "None yet"}
            </Row>
            <Row label="Last attempt">
              {data.last_poll_attempt_at ? formatDateTime(data.last_poll_attempt_at) : "None yet"}
            </Row>
            <Row label="Failures in a row">{data.consecutive_failures}</Row>
            {data.last_error && (
              <Row label="Last error">
                <code className="font-mono text-[0.8125rem] break-words">{data.last_error}</code>
              </Row>
            )}
            {data.stale && data.staleness_window && (
              <Row label="Counted as stale after">{data.staleness_window}</Row>
            )}
          </dl>
        )}
      {data && data.consecutive_failures > 0 && (
        <p className="text-muted-foreground text-[0.8125rem]">
          {pluralize(data.consecutive_failures, "poll")}{" "}
          in a row failed, so new CVEs are not being checked until one succeeds.
        </p>
      )}
    </section>
  );
}
