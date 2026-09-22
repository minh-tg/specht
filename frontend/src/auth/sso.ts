// SSO session-token delivery. The OIDC callback redirects the browser to
// "/#sso_token=<token>" after a successful login. Fragments are never sent to
// the server, so the callback can hand the SPA its session token without it
// leaking through Referer headers, logs, or browser history. The SPA consumes
// the fragment at boot and keeps the token in memory.
export const SSO_SESSION_KEY = "sso_token";

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
    const json = atob(token.slice(dot + 1, end).replaceAll("-", "+").replaceAll("_", "/"));
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
