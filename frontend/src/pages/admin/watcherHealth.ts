import type { StatusTone } from "@/components/StatusPill";
import type { WatcherHealth } from "@/types/api";

/** One word for the server-wide watcher: failing beats stale, and a watcher that never polled is not healthy yet. */
export function watcherHealthState(health: WatcherHealth): { label: string; tone: StatusTone; } {
  if (health.consecutive_failures > 0) return { label: "Failing", tone: "bad" };
  if (health.stale) return { label: "Stale", tone: "warn" };
  if (!health.last_successful_poll_at) return { label: "No poll yet", tone: "off" };
  return { label: "Healthy", tone: "ok" };
}
