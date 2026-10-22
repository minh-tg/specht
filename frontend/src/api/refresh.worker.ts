import type { LoginResponse } from "@/types/api";
import { createRefreshBroker } from "./refreshBroker";

class RefreshFailure extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryAfter?: number;

  constructor(status: number, code: string, message: string, retryAfter?: number) {
    super(message);
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

const broker = createRefreshBroker(async (token) => {
  const response = await fetch("/api/v1/auth/refresh", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: token }),
    signal: AbortSignal.timeout(60_000),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as {
      error?: { code?: string; message?: string; };
    };
    const retryAfter = Number(response.headers.get("Retry-After"));
    throw new RefreshFailure(
      response.status,
      body.error?.code ?? "unknown",
      body.error?.message ?? "Session refresh failed",
      Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : undefined,
    );
  }
  return await response.json() as LoginResponse;
});

self.addEventListener("connect", (event) => {
  const port = (event as MessageEvent).ports[0];
  port.onmessage = (message: MessageEvent<unknown>) => {
    const request = message.data as { id?: number; token?: string; forget?: boolean; };
    if (typeof request?.token !== "string" || !request.token || request.token.length > 4096) return;
    if (request.forget) {
      broker.forget(request.token);
      return;
    }
    if (!Number.isSafeInteger(request.id)) return;
    void broker.rotate(request.token).then((session) => {
      port.postMessage({ id: request.id, session });
    }).catch((error: unknown) => {
      const failure = error instanceof RefreshFailure
        ? error
        : new RefreshFailure(
          503,
          "refresh_unavailable",
          "Session refresh was interrupted; retry or sign in again",
        );
      if (failure.status === 401) broker.forget(request.token!);
      port.postMessage({
        id: request.id,
        error: {
          status: failure.status,
          code: failure.code,
          message: failure.message,
          retryAfter: failure.retryAfter,
        },
      });
    });
  };
  port.start();
});
