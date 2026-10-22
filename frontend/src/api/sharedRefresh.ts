import type { LoginResponse } from "@/types/api";
import { forgetLockedRefresh, lockedRefresh } from "./lockedRefresh";

export class SharedRefreshError extends Error {
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

interface Reply {
  id: number;
  session?: LoginResponse;
  error?: { status: number; code: string; message: string; retryAfter?: number; };
}

let worker: SharedWorker | undefined;
let nextId = 0;
const pending = new Map<
  number,
  { resolve: (value: LoginResponse) => void; reject: (error: Error) => void; }
>();

function failPending() {
  for (const request of pending.values()) {
    request.reject(
      new SharedRefreshError(
        503,
        "refresh_unavailable",
        "Session refresh was interrupted; retry or sign in again",
      ),
    );
  }
  pending.clear();
  worker?.port.close();
  worker = undefined;
}

function refreshWorker(): SharedWorker | undefined {
  if (typeof SharedWorker === "undefined") return undefined;
  if (!worker) {
    worker = new SharedWorker(new URL("./refresh.worker.ts", import.meta.url), {
      type: "module",
      name: "specht-session-refresh",
    });
    worker.onerror = (event) => {
      event.preventDefault();
      failPending();
    };
    worker.port.onmessageerror = failPending;
    worker.port.onmessage = ({ data }: MessageEvent<Reply>) => {
      const request = pending.get(data.id);
      if (!request) return;
      pending.delete(data.id);
      if (data.error) {
        request.reject(
          new SharedRefreshError(
            data.error.status,
            data.error.code,
            data.error.message,
            data.error.retryAfter,
          ),
        );
      } else if (data.session) {
        request.resolve(data.session);
      } else {
        request.reject(
          new SharedRefreshError(
            503,
            "refresh_unavailable",
            "Session refresh returned no credentials",
          ),
        );
      }
    };
    worker.port.start();
  }
  return worker;
}

/** All tabs use one worker for rotation. No credentials enter persistent storage. */
export function sharedRefresh(
  token: string,
  refresh: (token: string) => Promise<LoginResponse>,
): Promise<LoginResponse> | undefined {
  const owner = refreshWorker();
  if (!owner) return lockedRefresh(token, refresh);
  const id = ++nextId;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    owner.port.postMessage({ id, token });
  });
}

export function forgetSharedRefresh(token: string): void {
  worker?.port.postMessage({ token, forget: true });
  forgetLockedRefresh(token);
}
