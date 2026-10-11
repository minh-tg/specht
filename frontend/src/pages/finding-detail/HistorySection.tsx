import { useMe } from "@/api/hooks";
import { actorLabel, useUserDirectory } from "@/api/users";
import { ErrorState } from "@/components/ErrorState";
import { SkeletonLines } from "@/components/SkeletonLines";
import { formatDateTime } from "@/lib/format";
import type { FindingEvent } from "@/types/api";
import type { ReactNode } from "react";
import { eventTypeLabel } from "./format";

/** Lifecycle event history for one finding. */
export function HistorySection({
  events,
  isLoading,
  isError,
}: {
  readonly events?: FindingEvent[];
  readonly isLoading: boolean;
  readonly isError: boolean;
}) {
  const { data: me } = useMe();
  const { data: directory } = useUserDirectory();

  let body: ReactNode;
  if (isLoading) {
    body = <SkeletonLines label="Loading history" />;
  } else if (isError) {
    body = <ErrorState title="Could not load history." />;
  } else if (!Array.isArray(events) || events.length === 0) {
    body = <p className="text-muted-foreground text-sm">No history yet.</p>;
  } else {
    body = (
      <ul className="space-y-2 text-sm">
        {events.map((event) => (
          <li key={event.id} className="flex flex-wrap items-baseline gap-x-2">
            <span className="font-medium">{eventTypeLabel(event.event_type)}</span>
            {event.old_value != null || event.new_value != null
              ? (
                <span className="text-muted-foreground font-mono text-xs">
                  {event.old_value || "–"} → {event.new_value || "–"}
                </span>
              )
              : null}
            <span className="text-muted-foreground text-xs">
              by {actorLabel(event, { me, directory })}
            </span>
            <span className="text-muted-foreground text-xs">
              {formatDateTime(event.created_at)}
            </span>
            {event.comment && (
              <p className="text-muted-foreground w-full text-xs break-words">
                &ldquo;{event.comment}&rdquo;
              </p>
            )}
          </li>
        ))}
      </ul>
    );
  }

  return (
    <div className="mt-8 rounded-lg border p-4">
      <h2 className="mb-3 text-sm font-semibold">History</h2>
      {body}
    </div>
  );
}
