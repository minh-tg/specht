const BASE_URL = "";

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

let authToken: string | null = null;
let onUnauthorized: (() => void) | null = null;

export function setAuthToken(token: string | null) {
  authToken = token;
}

export function getAuthToken(): string | null {
  return authToken;
}

export function setOnUnauthorized(cb: (() => void) | null) {
  onUnauthorized = cb;
}

interface ApiFetchOptions extends RequestInit {
  skipAuthRedirect?: boolean;
}

export async function apiFetch<T>(
  path: string,
  options: ApiFetchOptions = {},
): Promise<T> {
  const { skipAuthRedirect = false, ...fetchOptions } = options;

  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(fetchOptions.headers as Record<string, string>),
  };

  if (authToken) {
    headers["Authorization"] = `Bearer ${authToken}`;
  }

  if (fetchOptions.body && typeof fetchOptions.body === "string") {
    headers["Content-Type"] = "application/json";
  }

  const res = await fetch(`${BASE_URL}${path}`, { ...fetchOptions, headers });

  if (res.status === 401 && !skipAuthRedirect) {
    setAuthToken(null);
    onUnauthorized?.();
    const redirect = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.href = `/login?redirect=${redirect}`;
    throw new APIError(401, "unauthorized", "Session expired");
  }

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
