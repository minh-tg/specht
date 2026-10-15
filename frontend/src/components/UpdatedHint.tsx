import { Button } from "@/components/ui/button";
import { useEffect, useState } from "react";

const TICK_MS = 5 * 1000;

/** "just now", "40 seconds ago", "3 minutes ago". The seconds step is why it ticks every 5 s. */
function updatedAgo(elapsedMs: number): string {
  const seconds = Math.max(0, Math.floor(elapsedMs / 1000));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds} seconds ago`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes} ${minutes === 1 ? "minute" : "minutes"} ago`;
}

/**
 * "Updated 40 seconds ago" with a Refresh button, for a page that polls. The text is not a live
 * region: a counter that changes every few seconds would be read out continuously. A separate polite
 * status says "New changes" the first time a refetch brings data that differs from what was shown,
 * and then stays quiet for as long as the page is open. The clock stops while the tab is hidden.
 */
export function UpdatedHint({ updatedAt, watch, isFetching, onRefresh, className }: {
  /** `dataUpdatedAt` of the query: when data last arrived. 0 means nothing has loaded yet. */
  readonly updatedAt: number;
  /**
   * The query data to watch. TanStack Query keeps the same reference when a refetch returns equal
   * data, so a new reference after the first load means something changed.
   */
  readonly watch: readonly unknown[];
  readonly isFetching: boolean;
  readonly onRefresh: () => void;
  readonly className?: string;
}) {
  const [now, setNow] = useState(() => Date.now());
  const [announced, setAnnounced] = useState(false);
  const [seen, setSeen] = useState(watch);

  useEffect(() => {
    let timer: ReturnType<typeof setInterval> | undefined;
    const start = () => {
      if (timer === undefined) timer = setInterval(() => setNow(Date.now()), TICK_MS);
    };
    const stop = () => {
      if (timer !== undefined) clearInterval(timer);
      timer = undefined;
    };
    const onVisibility = () => {
      if (document.hidden) {
        stop();
        return;
      }
      setNow(Date.now());
      start();
    };
    if (!document.hidden) start();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      stop();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);

  // Compared while rendering rather than in an effect: the watched values are already in hand, so
  // there is nothing to wait for.
  const differs = watch.some((value, i) => seen[i] !== value);
  if (differs) {
    const changed = watch.some((value, i) =>
      seen[i] !== undefined && value !== undefined && seen[i] !== value
    );
    setSeen(watch);
    if (changed) setAnnounced(true);
  }

  if (updatedAt === 0) return null;
  return (
    <div className={className ?? "text-muted-foreground flex items-center gap-2 text-xs"}>
      <span>Updated {updatedAgo(now - updatedAt)}</span>
      {/* aria-disabled, not disabled: a disabled button drops the focus the person just put on it. */}
      <Button
        variant="ghost"
        size="sm"
        aria-disabled={isFetching}
        aria-busy={isFetching}
        className="aria-disabled:opacity-50"
        onClick={() => {
          if (!isFetching) onRefresh();
        }}
      >
        Refresh
      </Button>
      <span role="status" aria-label="Page updates" className="sr-only">
        {announced ? "New changes" : ""}
      </span>
    </div>
  );
}
