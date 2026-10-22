/** An expiry hint only. The server still verifies the token and its signature. */
export function tokenExpiry(token: string): number | null {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const claims = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/"))) as {
      exp?: unknown;
    };
    if (typeof claims.exp !== "number") return null;
    const milliseconds = claims.exp * 1000;
    return Number.isFinite(milliseconds) ? milliseconds : null;
  } catch {
    return null;
  }
}
