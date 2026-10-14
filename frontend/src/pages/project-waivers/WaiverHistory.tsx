import { type ActorContext, actorLabel } from "@/api/users";
import { useWaiverEvents } from "@/api/waiverActions";
import { ErrorState } from "@/components/ErrorState";
import { SkeletonLines } from "@/components/SkeletonLines";
import { formatDateTime } from "@/lib/format";
import { waiverEventLabel } from "./classify";

/**
 * A waiver's audit trail, loaded when the row's History disclosure opens. The region has `id` so
 * the disclosure button can point at it with aria-controls.
 */
export function WaiverHistory({ id, slug, waiverId, who }: {
  readonly id: string;
  readonly slug: string;
  readonly waiverId: string;
  readonly who: ActorContext;
}) {
  const { data: events, isLoading, isError, refetch } = useWaiverEvents(slug, waiverId, true);

  let body;
  if (isLoading) {
    body = <SkeletonLines label="Loading history" lines={2} />;
  } else if (isError) {
    body = <ErrorState title="Could not load history." onRetry={() => void refetch()} />;
  } else if (!Array.isArray(events) || events.length === 0) {
    body = <p className="text-muted-foreground text-sm">No history yet.</p>;
  } else {
    body = (
      <ol className="border-border m-0 list-none space-y-2 border-l p-0 pl-3 text-[0.8125rem]">
        {events.map((event) => (
          <li key={event.id} className="flex flex-wrap items-baseline gap-x-2">
            <span className="font-medium">{waiverEventLabel(event.event_type)}</span>
            <span className="text-muted-foreground">
              by {actorLabel({ user_id: event.actor_id ?? "" }, who)}
            </span>
            <span className="text-muted-foreground">{formatDateTime(event.created_at)}</span>
          </li>
        ))}
      </ol>
    );
  }

  return (
    <div id={id} className="mt-2">
      {body}
    </div>
  );
}
