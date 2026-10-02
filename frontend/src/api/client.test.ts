import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  apiFetch,
  apiFetchWithTotal,
  clearStoredSession,
  getStoredRefreshToken,
  getStoredSession,
  setAuthToken,
  setStoredSession,
  setUnauthorizedHandler,
} from "./client";

const KEY = "specht.session";

interface Stored {
  accessToken: string;
  refreshToken: string;
  user: { userId: string; email: string; };
}

function readStore(): Stored | null {
  const raw = sessionStorage.getItem(KEY);
  return raw ? (JSON.parse(raw) as Stored) : null;
}

beforeEach(() => {
  sessionStorage.clear();
  window.location.hash = "";
  vi.unstubAllGlobals();
});

afterEach(() => {
  sessionStorage.clear();
  setAuthToken(null);
  setUnauthorizedHandler(null);
  vi.unstubAllGlobals();
});

describe("session persistence", () => {
  it("stores and restores the session through the storage layer", () => {
    setStoredSession("access-1", "refresh-1", { userId: "u1", email: "a@b.c" });

    expect(readStore()).toEqual({
      accessToken: "access-1",
      refreshToken: "refresh-1",
      user: { userId: "u1", email: "a@b.c" },
    });
    expect(getStoredSession()).toEqual({
      token: "access-1",
      refreshToken: "refresh-1",
      userId: "u1",
      email: "a@b.c",
    });
    expect(getStoredRefreshToken()).toBe("refresh-1");
  });

  it("restores an empty session from empty storage", () => {
    expect(getStoredSession()).toBeNull();
    expect(getStoredRefreshToken()).toBeNull();
  });

  it("clears the stored session", () => {
    setStoredSession("a", "r", { userId: "u1", email: "a@b.c" });
    clearStoredSession();

    expect(readStore()).toBeNull();
    expect(getStoredSession()).toBeNull();
    expect(getStoredRefreshToken()).toBeNull();
  });
});

describe("apiFetch auth header", () => {
  it("sends the module-level token when present", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({}),
    } as unknown as Response);
    vi.stubGlobal("fetch", fetchMock);

    setAuthToken("tok-123");
    await apiFetch("/api/v1/projects");

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/projects");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok-123");
  });

  it("does not send an Authorization header without a token", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({}),
    } as unknown as Response);
    vi.stubGlobal("fetch", fetchMock);

    setAuthToken(null);
    await apiFetch("/api/v1/projects");

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined();
  });
});

/** A JSON `Response` with extra headers, for the total-count cases. */
function responseWithHeaders(
  body: unknown,
  headers: Record<string, string> = {},
  status = 200,
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

describe("apiFetchWithTotal", () => {
  it("returns the body and the parsed X-Total-Count", async () => {
    const findings = [{ id: "f1" }, { id: "f2" }];
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(responseWithHeaders(findings, { "X-Total-Count": "45" })),
    );

    const result = await apiFetchWithTotal<typeof findings>("/api/v1/projects/p1/findings");

    expect(result.data).toEqual(findings);
    expect(result.total).toBe(45);
  });

  it("reports an unknown total when the header is missing", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(responseWithHeaders([])));

    const result = await apiFetchWithTotal("/api/v1/projects/p1/findings");

    expect(result).toEqual({ data: [], total: null });
  });

  it.each([["garbage", "many"], ["a non-integer", "1.5"], ["negative", "-3"], ["empty", ""]])(
    "reports an unknown total for %s header",
    async (_name, header) => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(responseWithHeaders([], { "X-Total-Count": header })),
      );

      const result = await apiFetchWithTotal("/api/v1/projects/p1/findings");

      expect(result.total).toBeNull();
    },
  );

  it("still refreshes and retries once after a 401", async () => {
    const calls: Array<{ url: string; headers: Record<string, string>; }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const headers = (init?.headers as Record<string, string>) ?? {};
        calls.push({ url, headers });
        if (url === "/api/v1/auth/refresh") {
          return Promise.resolve(
            responseWithHeaders({
              token: "access-2",
              refresh_token: "refresh-2",
              user_id: "u1",
              email: "a@b.c",
            }),
          );
        }
        if (headers.Authorization === "Bearer access-2") {
          return Promise.resolve(responseWithHeaders([{ id: "f1" }], { "X-Total-Count": "45" }));
        }
        return Promise.resolve(
          responseWithHeaders(
            { error: { code: "unauthorized", message: "expired" } },
            {},
            401,
          ),
        );
      }),
    );

    setStoredSession("access-1", "refresh-1", { userId: "u1", email: "a@b.c" });

    const result = await apiFetchWithTotal("/api/v1/projects/p1/findings");

    expect(result).toEqual({ data: [{ id: "f1" }], total: 45 });
    expect(calls.map((call) => call.url)).toEqual([
      "/api/v1/projects/p1/findings",
      "/api/v1/auth/refresh",
      "/api/v1/projects/p1/findings",
    ]);
    expect(calls.at(-1)?.headers.Authorization).toBe("Bearer access-2");
  });
});
