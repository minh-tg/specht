import { type QueryClient, useQueryClient } from "@tanstack/react-query";
import { type FocusEvent, type PointerEvent, useCallback, useEffect, useRef } from "react";

/** How long the pointer rests on a link before its data is fetched, so a sweep over a list fetches nothing. */
export const PREFETCH_DWELL_MS = 120;
/** Prefetches allowed in flight at once, across every link on the page. */
export const MAX_PREFETCHES_IN_FLIGHT = 3;

let inFlight = 0;

interface NetworkInformation {
  saveData?: boolean;
  effectiveType?: string;
}

/** Chromium only, and missing from the DOM typings, so it is read through a narrow cast. */
function connectionAllowsPrefetch(): boolean {
  const connection = (navigator as Navigator & { connection?: NetworkInformation; }).connection;
  if (!connection) return true;
  if (connection.saveData) return false;
  return connection.effectiveType !== "slow-2g" && connection.effectiveType !== "2g";
}

/** Keyboard focus only: a mouse click focuses the link too, but the click navigates anyway. */
function isKeyboardFocus(target: HTMLElement): boolean {
  try {
    return target.matches(":focus-visible");
  } catch {
    return false;
  }
}

/**
 * Event handlers for a link that warms the cache for the page it opens. The fetch starts after
 * the pointer (a mouse, not touch or pen) or keyboard focus has rested on the link for
 * `PREFETCH_DWELL_MS`; leaving or blurring first drops the pending fetch. A fetch already sent is
 * left to finish, because the query functions ignore abort signals and cancelling would also
 * revert a query a page is waiting on. Skipped on Save-Data or a 2G connection, and when
 * `MAX_PREFETCHES_IN_FLIGHT` are already running.
 */
export function usePrefetchOnIntent(prefetch: (queryClient: QueryClient) => Promise<unknown>) {
  const queryClient = useQueryClient();
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const latest = useRef(prefetch);
  useEffect(() => {
    latest.current = prefetch;
  });

  const cancel = useCallback(() => {
    clearTimeout(timer.current);
    timer.current = undefined;
  }, []);

  const schedule = useCallback(() => {
    cancel();
    timer.current = setTimeout(() => {
      timer.current = undefined;
      if (inFlight >= MAX_PREFETCHES_IN_FLIGHT || !connectionAllowsPrefetch()) return;
      inFlight += 1;
      void latest.current(queryClient).finally(() => {
        inFlight -= 1;
      });
    }, PREFETCH_DWELL_MS);
  }, [cancel, queryClient]);

  useEffect(() => cancel, [cancel]);

  return {
    onPointerEnter: (event: PointerEvent<HTMLElement>) => {
      if (event.pointerType === "mouse") schedule();
    },
    onPointerLeave: cancel,
    onFocus: (event: FocusEvent<HTMLElement>) => {
      if (isKeyboardFocus(event.currentTarget)) schedule();
    },
    onBlur: cancel,
  };
}
