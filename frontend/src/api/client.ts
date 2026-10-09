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

export function setUnauthorizedHandler(cb: (() => void) | null) {
  onUnauthorized = cb;
}

export function setRefreshFailedHandler(cb: (() => void) | null) {
  onRefreshFailed = cb;
}

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

interface SendResult<T> {
  data: T;
  response: Response;
}

async function send<T>(
  path: string,
  options: ApiFetchOptions,
  token: string | null,
): Promise<SendResult<T>> {
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
    return { data: undefined as T, response: res };
  }

  return { data: await res.json() as T, response: res };
}

export async function refreshAccessToken(refreshToken: string): Promise<Session> {
  const { data: { token, refresh_token: newRefresh, user_id, email } } = await send<{
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

/** Tears the session down, bounces to the sign-in page, and rethrows. */
function endSession(err: unknown): never {
  setAuthToken(null);
  clearStoredSession();
  onUnauthorized?.();
  onRefreshFailed?.();
  const redirect = encodeURIComponent(window.location.pathname + window.location.search);
  window.location.href = `/login?redirect=${redirect}`;
  throw err;
}

function sessionExpired(): never {
  endSession(new APIError(401, "unauthorized", "Session expired"));
}

const unauthorized = (err: unknown): boolean => err instanceof APIError && err.status === 401;

/** The refresh in progress, shared by every request that 401s while it runs.
 * The server rotates refresh tokens and treats a reused one as replay, so two
 * refreshes from the same token would revoke the whole session family. */
let inFlightRefresh: Promise<Session> | null = null;

/** Spends the stored refresh token once. A rejected refresh ends the session,
 * so the sign-in redirect runs once no matter how many requests were waiting. */
async function startRefresh(): Promise<Session> {
  const refreshToken = getStoredRefreshToken();
  if (!refreshToken) sessionExpired();
  try {
    const session = await refreshAccessToken(refreshToken);
    setAuthToken(session.token);
    return session;
  } catch (err) {
    if (unauthorized(err)) endSession(err);
    throw err;
  }
}

function refreshSharedSession(): Promise<Session> {
  if (!inFlightRefresh) {
    inFlightRefresh = startRefresh().finally(() => {
      inFlightRefresh = null;
    });
  }
  return inFlightRefresh;
}

/** Refreshes once, shared across concurrent 401s, then retries this request.
 * A request whose 401 arrived after another request already refreshed reuses
 * that token. A rejected retry with a 401 means the new token was refused too:
 * end the session and surface the error to the caller. */
async function refreshAndRetry<T>(
  attempt: (token: string | null) => Promise<T>,
  failedToken: string,
): Promise<T> {
  const current = authToken;
  const token = current !== null && current !== failedToken
    ? current
    : (await refreshSharedSession()).token;
  try {
    return await attempt(token);
  } catch (err) {
    if (!unauthorized(err)) throw err;
    endSession(err);
  }
}

async function withAuth<T>(
  attempt: (token: string | null) => Promise<T>,
  skipAuthRedirect: boolean,
): Promise<T> {
  const token = authToken ?? getStoredSession()?.token ?? null;

  // Anonymous request: a 401 redirects to sign-in unless opted out
  // (e.g. login/register, which surface the error inline).
  if (!token) {
    try {
      return await attempt(null);
    } catch (err) {
      if (unauthorized(err) && !skipAuthRedirect) sessionExpired();
      throw err;
    }
  }

  try {
    return await attempt(token);
  } catch (err) {
    // An authenticated 401 means the access token expired: refresh once
    // and retry before falling back to the sign-in redirect. Request
    // errors opt out of the redirect when they opted out of auth.
    if (!unauthorized(err) || skipAuthRedirect) throw err;
  }

  return refreshAndRetry(attempt, token);
}

/** A response body paired with the count of rows the filter matched, when the
 * server reports one through the `X-Total-Count` header. */
export interface ApiResponseWithTotal<T> {
  data: T;
  total: number | null;
}

/** Parses `X-Total-Count`; a missing, non-integer or negative value is unknown. */
function parseTotalCount(header: string | null): number | null {
  if (header === null) return null;
  const value = header.trim();
  if (!/^\d+$/.test(value)) return null;
  const total = Number.parseInt(value, 10);
  return Number.isSafeInteger(total) ? total : null;
}

/** Runs a request through the shared auth/refresh path and keeps the response
 * metadata that [`apiFetch`] discards. */
async function apiFetchResponse<T>(
  path: string,
  options: ApiFetchOptions,
): Promise<SendResult<T>> {
  const { skipAuthRedirect = false, ...fetchOptions } = options;
  const attempt = (token: string | null): Promise<SendResult<T>> =>
    send<T>(path, fetchOptions, token);
  return withAuth(attempt, skipAuthRedirect);
}

export async function apiFetch<T>(
  path: string,
  options: ApiFetchOptions = {},
): Promise<T> {
  const { data } = await apiFetchResponse<T>(path, options);
  return data;
}

/** Like [`apiFetch`], but also surfaces the `X-Total-Count` header (the size of
 * the filtered set across every page) so list views can page honestly. */
export async function apiFetchWithTotal<T>(
  path: string,
  options: ApiFetchOptions = {},
): Promise<ApiResponseWithTotal<T>> {
  const { data, response } = await apiFetchResponse<T>(path, options);
  const header = response.headers?.get("X-Total-Count") ?? null;
  return { data, total: parseTotalCount(header) };
}
