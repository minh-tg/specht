const BASE_URL = "";

const SESSION_STORAGE_KEY = "specht.session";

export class APIError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "APIError";
    this.status = status;
    this.code = code;
  }
}

interface StoredSession {
  accessToken: string;
  refreshToken: string | null;
  user: { userId: string | null; email: string | null; };
}

export interface Session {
  token: string;
  refreshToken: string | null;
  userId: string | null;
  email: string | null;
}

/** Persists a session so a page reload keeps the user signed in. */
export function setStoredSession(
  accessToken: string,
  refreshToken: string | null,
  user: { userId: string | null; email: string | null; },
): void {
  const session: StoredSession = { accessToken, refreshToken, user };
  sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
}

/** Reads the persisted session, or null when none is stored. */
export function getStoredSession(): Session | null {
  try {
    const raw = sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    const stored = JSON.parse(raw) as Partial<StoredSession>;
    if (typeof stored.accessToken !== "string" || stored.accessToken === "") return null;
    return {
      token: stored.accessToken,
      refreshToken: stored.refreshToken ?? null,
      userId: stored.user?.userId ?? null,
      email: stored.user?.email ?? null,
    };
  } catch {
    return null;
  }
}

/** The persisted refresh token, or null when none is stored. */
export function getStoredRefreshToken(): string | null {
  return getStoredSession()?.refreshToken ?? null;
}

/** Clears the persisted session. */
export function clearStoredSession(): void {
  sessionStorage.removeItem(SESSION_STORAGE_KEY);
}

let authToken: string | null = null;
let onUnauthorized: (() => void) | null = null;
let onRefreshFailed: (() => void) | null = null;

export function setAuthToken(token: string | null) {
  authToken = token;
}

export function getAuthToken(): string | null {
  return authToken;
}

export function setUnauthorizedHandler(cb: (() => void) | null) {
  onUnauthorized = cb;
}

export function setRefreshFailedHandler(cb: (() => void) | null) {
  onRefreshFailed = cb;
}

export { setUnauthorizedHandler as setOnUnauthorized };

interface ApiFetchOptions extends RequestInit {
  skipAuthRedirect?: boolean;
}

function withAuthHeaders(
  headers: Record<string, string>,
  token: string | null,
): Record<string, string> {
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

async function send<T>(
  path: string,
  options: ApiFetchOptions,
  token: string | null,
): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(options.headers as Record<string, string>),
  };
  withAuthHeaders(headers, token);

  if (options.body && typeof options.body === "string") {
    headers["Content-Type"] = "application/json";
  }

  const res = await fetch(`${BASE_URL}${path}`, { ...options, headers });

  if (!res.ok) {
    let code = "unknown";
    let message = "Request failed";
    try {
      const body = await res.json();
      code = body.error?.code ?? code;
      message = body.error?.message ?? message;
    } catch {}
    throw new APIError(res.status, code, message);
  }

  if (res.status === 204) {
    return undefined as T;
  }

  return res.json();
}

export async function refreshAccessToken(refreshToken: string): Promise<Session> {
  const { token, refresh_token: newRefresh, user_id, email } = await send<{
    token: string;
    refresh_token: string;
    user_id: string;
    email: string;
  }>(
    "/api/v1/auth/refresh",
    { method: "POST", body: JSON.stringify({ refresh_token: refreshToken }) },
    null,
  );
  const session: Session = {
    token,
    refreshToken: newRefresh,
    userId: user_id,
    email,
  };
  setStoredSession(token, newRefresh, { userId: user_id, email });
  return session;
}

/** Revokes the refresh token server-side so the session cannot be resumed. */
export async function revokeRefreshToken(refreshToken: string): Promise<void> {
  try {
    await send<void>(
      "/api/v1/auth/logout",
      { method: "POST", body: JSON.stringify({ refresh_token: refreshToken }) },
      null,
    );
  } catch {
    // Local sign-out must always succeed; the server also expires sessions.
  }
}

/** Tears the session down and bounces to the sign-in page. */
function sessionExpired(): never {
  setAuthToken(null);
  clearStoredSession();
  onUnauthorized?.();
  onRefreshFailed?.();
  const redirect = encodeURIComponent(window.location.pathname + window.location.search);
  window.location.href = `/login?redirect=${redirect}`;
  throw new APIError(401, "unauthorized", "Session expired");
}

export async function apiFetch<T>(
  path: string,
  options: ApiFetchOptions = {},
): Promise<T> {
  const { skipAuthRedirect = false, ...fetchOptions } = options;
  const attempt = (token: string | null): Promise<T> => send<T>(path, fetchOptions, token);
  const unauthorized = (err: unknown): boolean => err instanceof APIError && err.status === 401;

  const token = authToken ?? getStoredSession()?.token ?? null;
  if (token) {
    try {
      return await attempt(token);
    } catch (err) {
      // An authenticated 401 means the access token expired: refresh once
      // and retry before falling back to the sign-in redirect. Request
      // errors opt out of the redirect when they opted out of auth.
      if (!unauthorized(err) || skipAuthRedirect) throw err;
    }

    const refreshToken = getStoredRefreshToken();
    if (refreshToken) {
      try {
        const session = await refreshAccessToken(refreshToken);
        setAuthToken(session.token);
        return await attempt(session.token);
      } catch (err) {
        // A failed refresh (network, invalid, revoked) or a retried request
        // the server still rejects ends the session. Clear local state via
        // the callbacks, bounce to sign-in, and surface the error to the
        // caller that triggered it.
        if (!unauthorized(err)) throw err;
        setAuthToken(null);
        clearStoredSession();
        onUnauthorized?.();
        onRefreshFailed?.();
        const redirect = encodeURIComponent(window.location.pathname + window.location.search);
        window.location.href = `/login?redirect=${redirect}`;
        throw err;
      }
    }
    return sessionExpired();
  }

  // Anonymous request: a 401 redirects to sign-in unless opted out
  // (e.g. login/register, which surface the error inline).
  try {
    return await attempt(null);
  } catch (err) {
    if (unauthorized(err) && !skipAuthRedirect) return sessionExpired();
    throw err;
  }
}
