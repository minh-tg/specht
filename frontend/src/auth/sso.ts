// SSO session-token delivery. The OIDC callback redirects the browser to
// "/#sso_token=<token>" after a successful login. Fragments are never sent to
// the server, so the callback can hand the SPA its session token without it
// leaking through Referer headers, logs, or browser history. The SPA consumes
// the fragment at boot and keeps the token in memory.
export const SSO_SESSION_KEY = "sso_token";

// A token in the fragment is only accepted while an SSO login that this browser
// started is pending. Without that, anyone could send a link ending in
// "#sso_token=<their own token>" and sign the recipient into the sender's account.
// The marker is short-lived (the server's state cookie lasts as long) and lives in
// localStorage so a login opened in a new tab still completes.
const SSO_ATTEMPT_KEY = "specht.sso_attempt";
const SSO_ATTEMPT_MAX_AGE_MS = 10 * 60 * 1000;

/** Records that this browser is starting an SSO login. */
export function markSsoAttempt(now: number = Date.now()): void {
  try {
    localStorage.setItem(SSO_ATTEMPT_KEY, String(now));
  } catch {
    // Without storage the login cannot be recognised later; it is simply not accepted.
  }
}

/** True while an SSO login started here is still within its time window. */
export function hasPendingSsoAttempt(now: number = Date.now()): boolean {
  try {
    const started = Number(localStorage.getItem(SSO_ATTEMPT_KEY));
    const age = now - started;
    return Number.isFinite(started) && started > 0 && age >= 0 && age <= SSO_ATTEMPT_MAX_AGE_MS;
  } catch {
    return false;
  }
}

/** Forgets the pending login; each attempt can be used once. */
export function clearSsoAttempt(): void {
  try {
    localStorage.removeItem(SSO_ATTEMPT_KEY);
  } catch {
    // Nothing to forget.
  }
}

export interface SsoTokenClaims {
  sub?: string;
  email?: string;
}

function decodePayload(token: string): SsoTokenClaims | null {
  const dot = token.indexOf(".");
  if (dot <= 0) return null;
  const end = token.indexOf(".", dot + 1);
  if (end <= dot + 1) return null;
  try {
    const binary = atob(token.slice(dot + 1, end).replaceAll("-", "+").replaceAll("_", "/"));
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    const json = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return JSON.parse(json) as SsoTokenClaims;
  } catch {
    return null;
  }
}

/**
 * Reads an SSO session token from a URL fragment ("#sso_token=<token>") and
 * verifies it carries a subject claim. Returns null when the fragment has no
 * sso_token parameter or the token is not a usable JWT.
 */
export function ssoTokenFromHash(hash: string): { token: string; claims: SsoTokenClaims; } | null {
  if (!hash.startsWith("#")) return null;
  const params = new URLSearchParams(hash.slice(1));
  const token = params.get(SSO_SESSION_KEY);
  if (!token) return null;
  const claims = decodePayload(token);
  if (!claims || typeof claims.sub !== "string" || claims.sub === "") return null;
  return { token, claims };
}
