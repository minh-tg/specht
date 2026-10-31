import { useEffect, useState } from "react";

/**
 * False for the first `delayMs` after mount, then true. A loading indicator that waits this long
 * never flashes for a response that arrives quickly.
 */
export function useDelayedFlag(delayMs: number): boolean {
  const [elapsed, setElapsed] = useState(false);
  useEffect(() => {
    const timer = setTimeout(() => setElapsed(true), delayMs);
    return () => clearTimeout(timer);
  }, [delayMs]);
  return elapsed;
}
