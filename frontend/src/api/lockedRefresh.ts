import type { LoginResponse } from "@/types/api";
import { createRefreshBroker } from "./refreshBroker";

const PREFIX = "specht.refresh.used.";
let channel: BroadcastChannel | undefined;
let loader: ((token: string) => Promise<LoginResponse>) | undefined;
const broker = createRefreshBroker(async (token) => {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  const key = PREFIX
    + Array.from(new Uint8Array(digest), (v) => v.toString(16).padStart(2, "0")).join("");
  return navigator.locks.request("specht-session-refresh", async () => {
    const cached = broker.peek(token);
    if (cached) return cached;
    const used = localStorage.getItem(key);
    if (used && !(Number(used) <= Date.now())) {
      channel!.postMessage({ kind: "query", token });
      await new Promise((resolve) => setTimeout(resolve, 150));
      const result = broker.peek(token);
      if (result) return result;
      // A tab can close or suspend after spending a token. Never replay it
      // merely because its successor could not be obtained from a peer.
      throw new Error("Session could not synchronize with another tab; retry or sign in again");
    }
    const now = Date.now();
    for (const old of Object.keys(localStorage)) {
      if (old.startsWith(PREFIX) && Number(localStorage.getItem(old)) < now) {
        localStorage.removeItem(old);
      }
    }
    let expires = now + 86_400_000;
    try {
      const claims = JSON.parse(
        atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")),
      ) as { exp?: number; };
      if (typeof claims.exp === "number" && Number.isFinite(claims.exp)) {
        expires = claims.exp * 1000;
      }
    } catch { /* Invalid tokens are rejected by the server. */ }
    // Only a one-way digest and its expiry persist. Tokens stay in memory and
    // sessionStorage. Mark before sending, including an uncertain transport.
    localStorage.setItem(key, String(expires));
    const session = await loader!(token);
    channel!.postMessage({ kind: "rotation", token, session });
    return session;
  });
});

function connect(): boolean {
  if (channel) return true;
  if (typeof BroadcastChannel === "undefined" || !navigator.locks || !crypto.subtle) return false;
  channel = new BroadcastChannel("specht-session-refresh");
  channel.onmessage = (
    { data }: MessageEvent<{ kind: string; token: string; session?: LoginResponse; }>,
  ) => {
    if (typeof data?.token !== "string") return;
    if (data.kind === "query") {
      const session = broker.peek(data.token);
      if (session) channel!.postMessage({ kind: "rotation", token: data.token, session });
    } else if (data.kind === "rotation" && data.session) {
      broker.adopt(data.token, data.session);
    } else if (data.kind === "forget") {
      broker.forget(data.token);
    }
  };
  return true;
}

// Listen before the first expiry so a background tab receives earlier rotations.
if (typeof SharedWorker === "undefined") connect();

export function lockedRefresh(
  token: string,
  refresh: (token: string) => Promise<LoginResponse>,
): Promise<LoginResponse> | undefined {
  if (!connect()) return undefined;
  loader = refresh;
  return broker.rotate(token);
}

export function forgetLockedRefresh(token: string) {
  broker.forget(token);
  channel?.postMessage({ kind: "forget", token });
}
