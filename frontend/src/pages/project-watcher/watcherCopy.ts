import type { StatusTone } from "@/components/StatusPill";
import type { ProjectWatcher, WatcherStatus } from "@/types/api";

const MINUTE = 60;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

function amount(seconds: number): { n: number; one: string; many: string; } {
  if (seconds % DAY === 0) return { n: seconds / DAY, one: "day", many: "days" };
  if (seconds % HOUR === 0) return { n: seconds / HOUR, one: "hour", many: "hours" };
  if (seconds % MINUTE === 0) return { n: seconds / MINUTE, one: "minute", many: "minutes" };
  return { n: seconds, one: "second", many: "seconds" };
}

/** "1 hour", "6 hours", "7 days": a length of time in the largest whole unit. */
export function durationLabel(seconds: number): string {
  const { n, one, many } = amount(seconds);
  return `${n} ${n === 1 ? one : many}`;
}

/** "every hour", "every 6 hours", "every 2 days": how often a poll runs. */
export function intervalLabel(seconds: number): string {
  const { n, one, many } = amount(seconds);
  return n === 1 ? `every ${one}` : `every ${n} ${many}`;
}

const PRESETS = [HOUR, 6 * HOUR, DAY, 7 * DAY];

/**
 * The intervals the picker offers: the presets the server accepts, plus the one the project has now
 * when it is something else, so the control never shows a value it cannot name.
 */
export function intervalOptions(
  watcher: Pick<
    ProjectWatcher,
    "interval_seconds" | "min_interval_seconds" | "max_interval_seconds"
  >,
): { value: string; label: string; }[] {
  const allowed = PRESETS.filter((s) =>
    s >= watcher.min_interval_seconds && s <= watcher.max_interval_seconds
  );
  const all = [...new Set([...allowed, watcher.interval_seconds])].sort((a, b) => a - b);
  return all.map((s) => ({ value: String(s), label: intervalLabel(s) }));
}

export interface StatusPresentation {
  readonly label: string;
  readonly tone: StatusTone;
  /** What the person should know, when there is something to say. */
  readonly notice?: string;
  /** The notice is a problem, not just information. */
  readonly problem?: boolean;
}

export const STATUS: Record<WatcherStatus, StatusPresentation> = {
  ok: { label: "Working", tone: "ok" },
  waiting: {
    label: "Waiting for the first poll",
    tone: "off",
    notice: "No poll has finished yet. The first one comes with the watcher's next cycle.",
  },
  stale: {
    label: "Stale",
    tone: "warn",
    problem: true,
    notice:
      "The last poll is older than it should be. The watcher may be stuck. An operator can check the server log.",
  },
  failing: {
    label: "Failing",
    tone: "bad",
    problem: true,
    notice:
      "Recent polls are failing, so new CVEs are not being checked. An operator can see the error under Admin.",
  },
  server_off: {
    label: "Off on the server",
    tone: "off",
    notice:
      "The server has the watcher turned off. This project's setting is kept and takes effect when the server runs it.",
  },
  disabled: { label: "Off for this project", tone: "off" },
};
