const DAY_MS = 24 * 60 * 60 * 1000;

/** How long an invite has left, in the largest whole unit. */
export function expiresIn(expiresAt: string, now: number = Date.now()): string {
  const left = new Date(expiresAt).getTime() - now;
  if (left <= 0) return "expired";
  if (left >= DAY_MS) {
    const days = Math.floor(left / DAY_MS);
    return `${days} ${days === 1 ? "day" : "days"}`;
  }
  const hours = Math.max(1, Math.floor(left / (60 * 60 * 1000)));
  return `${hours} ${hours === 1 ? "hour" : "hours"}`;
}
