const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * How long something has left, in the largest unit that fits. Days round to the nearest, so a
 * 30 day waiver asked for a minute ago reads "30 days" rather than 29.
 */
export function expiresIn(expiresAt: string, now: number = Date.now()): string {
  const left = new Date(expiresAt).getTime() - now;
  if (left <= 0) return "expired";
  if (left >= DAY_MS) {
    const days = Math.round(left / DAY_MS);
    return `${days} ${days === 1 ? "day" : "days"}`;
  }
  const hours = Math.max(1, Math.floor(left / (60 * 60 * 1000)));
  return `${hours} ${hours === 1 ? "hour" : "hours"}`;
}
