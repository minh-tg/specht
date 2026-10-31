import { Drum } from "@/components/Drum";
import { RelativeTime } from "@/components/RelativeTime";
import { cn } from "@/lib/utils";

/** What the page knows about its own watching, for the strip and the notices around it. */
export interface WatchState {
  /** The browser has a connection. Checks pause while it has none. */
  readonly online: boolean;
  /** Ten minutes passed with no newer report. */
  readonly stalled: boolean;
  /** When the last check succeeded, in epoch milliseconds; 0 before the first. */
  readonly checkedAt: number;
  /** The last check failed. The next one is already scheduled. */
  readonly failing: boolean;
}

/**
 * The one line that says the page is watching for a scan: what it waits for and when it last
 * asked. The label is a polite status region, so a screen reader hears it when it changes. The
 * "checked" time sits outside that region and is not announced, because it changes with every
 * check. Pass `announce={false}` where a live region around it already speaks (the verdict header),
 * so the same change is not read twice.
 */
export function WatchStrip(
  { label, watch, announce = true, className }: {
    readonly label: string;
    readonly watch: WatchState;
    readonly announce?: boolean;
    readonly className?: string;
  },
) {
  const paused = !watch.online;
  return (
    <p
      className={cn(
        "text-muted-foreground flex flex-wrap items-center gap-x-2 gap-y-0.5 text-meta",
        className,
      )}
    >
      {!paused && <Drum />}
      <span role={announce ? "status" : undefined}>
        {paused ? "Paused while you are offline" : label}
      </span>
      <span aria-live="off" className="tabular-nums">
        {watch.failing && !paused ? "· last check failed, trying again" : null}
        {!watch.failing && watch.checkedAt > 0
          ? (
            <>
              · checked <RelativeTime iso={new Date(watch.checkedAt).toISOString()} frozen />
            </>
          )
          : null}
      </span>
    </p>
  );
}
