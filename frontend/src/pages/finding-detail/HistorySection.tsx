import { useMe } from "@/api/hooks";
import { actorLabel } from "@/api/users";
import { ErrorState } from "@/components/ErrorState";
import { Section } from "@/components/Section";
import { SkeletonLines } from "@/components/SkeletonLines";
import { EMPTY_VALUE, formatDateTime } from "@/lib/format";
import type { FindingEvent } from "@/types/api";
import type { ReactNode } from "react";
import { eventTypeLabel, eventValueLabel } from "./format";

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

  let body: ReactNode;
  if (isLoading) {
    body = <SkeletonLines label="Loading history" />;
  } else if (isError) {
    body = <ErrorState title="Could not load history." />;
  } else if (!Array.isArray(events) || events.length === 0) {
    body = <p className="text-muted-foreground text-body">No history yet.</p>;
  } else {
    body = (
      <ol className="border-border space-y-3 border-l pl-4 text-body">
        {events.map((event) => (
          <li key={event.id} className="flex flex-wrap items-baseline gap-x-2">
            <span className="font-medium">{eventTypeLabel(event.event_type)}</span>
            {event.old_value != null || event.new_value != null
              ? (
                <span className="text-muted-foreground text-meta">
                  {event.old_value
                    ? eventValueLabel(event.event_type, event.old_value)
                    : EMPTY_VALUE}
                  {" → "}
                  {event.new_value
                    ? eventValueLabel(event.event_type, event.new_value)
                    : EMPTY_VALUE}
                </span>
              )
              : null}
            <span className="text-muted-foreground text-meta">
              by {actorLabel(event, { me })}
            </span>
            <span className="text-muted-foreground text-meta tabular-nums">
              {formatDateTime(event.created_at)}
            </span>
            {event.comment && (
              <p className="text-muted-foreground w-full text-meta break-words">
                &ldquo;{event.comment}&rdquo;
              </p>
            )}
          </li>
        ))}
      </ol>
    );
  }

  return (
    <Section
      title="History"
      isEmpty={!isLoading && !isError && (!Array.isArray(events) || events.length === 0)}
      empty="No history yet."
    >
      {body}
    </Section>
  );
}
