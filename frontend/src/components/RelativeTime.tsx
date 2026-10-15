import { EMPTY_VALUE, formatDateTime, formatRelativeTime } from "@/lib/format";
import { useSyncExternalStore } from "react";

const TICK_MS = 60 * 1000;

let tickedAt = Date.now();
const listeners = new Set<() => void>();
let timer: ReturnType<typeof setInterval> | undefined;

function tick() {
  tickedAt = Date.now();
  for (const listener of listeners) listener();
}

function startTimer() {
  if (timer === undefined && !document.hidden) timer = setInterval(tick, TICK_MS);
}

function stopTimer() {
  if (timer !== undefined) clearInterval(timer);
  timer = undefined;
}

function onVisibilityChange() {
  if (document.hidden) {
    stopTimer();
    return;
  }
  // The tab was away for an unknown time: refresh at once, then resume the minute timer.
  tick();
  startTimer();
}

/**
 * One timer serves every relative time on the page, not one interval per row. It runs only while
 * something is subscribed and the tab is visible.
 */
function subscribe(listener: () => void) {
  if (listeners.size === 0) {
    tickedAt = Date.now();
    document.addEventListener("visibilitychange", onVisibilityChange);
    startTimer();
  }
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) {
      stopTimer();
      document.removeEventListener("visibilitychange", onVisibilityChange);
    }
  };
}

function getSnapshot() {
  // With nobody subscribed the stored time can be stale, so a row that mounts reads a fresh one.
  if (listeners.size === 0 && Date.now() - tickedAt > 1000) tickedAt = Date.now();
  return tickedAt;
}

function Time({ iso, text, spellOut = false }: {
  readonly iso: string;
  readonly text: string;
  /** Adds the exact time as visually hidden text, for readers that never see the `title`. */
  readonly spellOut?: boolean;
}) {
  const exact = formatDateTime(iso);
  return (
    // `relative` makes the hidden text positioned inside this element. Without it the absolutely
    // positioned span escapes the clipping of a scrolling table and widens the whole page.
    <time
      dateTime={iso}
      title={exact}
      className={spellOut ? "relative tabular-nums" : "tabular-nums"}
    >
      {text}
      {spellOut && <span className="sr-only">&nbsp;({exact})</span>}
    </time>
  );
}

function LiveTime({ iso }: { readonly iso: string; }) {
  const now = useSyncExternalStore(subscribe, getSnapshot);
  return <Time iso={iso} text={formatRelativeTime(iso, new Date(now))} spellOut />;
}

/**
 * A timestamp as a phrase ("3 h ago"), in a `<time>` element whose `title` holds the exact local
 * date and time. The refreshing form also carries the exact time as visually hidden text, because
 * touch, keyboard and screen reader users cannot reach a `title`. It refreshes every minute while
 * the tab is visible. Pass `frozen` (or `now`) to stop that, which is what a live region needs: a
 * text that changes every minute would be announced every minute. Those two forms also leave out
 * the hidden text, so a live region announces no more than the phrase. Empty or unparsable input renders the shared empty value.
 */
export function RelativeTime({ iso, now, frozen = false }: {
  readonly iso: string | null | undefined;
  /** Fixes the reference time and stops the refresh. */
  readonly now?: Date;
  /** Stops the refresh and measures from the moment of rendering. */
  readonly frozen?: boolean;
}) {
  if (!iso || formatRelativeTime(iso) === EMPTY_VALUE) return <>{EMPTY_VALUE}</>;
  if (now || frozen) return <Time iso={iso} text={formatRelativeTime(iso, now ?? new Date())} />;
  return <LiveTime iso={iso} />;
}
