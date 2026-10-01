const EMPTY = "–";

const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

const DATE_TIME_FORMATTER = new Intl.DateTimeFormat(undefined, {
  day: "numeric",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});

const DATE_FORMATTER = new Intl.DateTimeFormat(undefined, {
  day: "numeric",
  month: "short",
  year: "numeric",
});

/** Parses an ISO timestamp, returning null for empty or invalid input. */
function parseDate(iso: string | null | undefined): Date | null {
  if (!iso) return null;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? null : date;
}

/**
 * Human-friendly age of a timestamp: "just now", "5 min ago", "2 h ago" or
 * "3 d ago" for anything up to 30 days, then an absolute date. Empty or
 * unparsable input yields an em-dash rather than "Invalid Date".
 */
export function formatRelativeTime(
  iso: string | null | undefined,
  now: Date = new Date(),
): string {
  const date = parseDate(iso);
  if (!date) return EMPTY;

  const elapsed = now.getTime() - date.getTime();
  if (elapsed < MINUTE_MS) return "just now";
  if (elapsed < HOUR_MS) return `${Math.floor(elapsed / MINUTE_MS)} min ago`;
  if (elapsed < DAY_MS) return `${Math.floor(elapsed / HOUR_MS)} h ago`;

  const days = Math.floor(elapsed / DAY_MS);
  if (days <= 30) return `${days} d ago`;
  return formatDate(iso);
}

/** Absolute date and 24 h time, e.g. "1 Oct 2026, 04:24". */
export function formatDateTime(iso: string | null | undefined): string {
  const date = parseDate(iso);
  return date ? DATE_TIME_FORMATTER.format(date) : EMPTY;
}

/** Absolute date without the time; see formatDateTime. */
export function formatDate(iso: string | null | undefined): string {
  const date = parseDate(iso);
  return date ? DATE_FORMATTER.format(date) : EMPTY;
}

/** "1 finding" / "2 findings"; pass `other` for irregular plurals. */
export function pluralize(count: number, one: string, other?: string): string {
  return `${count} ${count === 1 ? one : (other ?? `${one}s`)}`;
}
