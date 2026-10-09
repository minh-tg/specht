import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  apiFetch,
  apiFetchWithTotal,
  clearStoredSession,
  getStoredRefreshToken,
  getStoredSession,
  setAuthToken,
  setRefreshFailedHandler,
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
  setRefreshFailedHandler(null);
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

/** A stand-in for the API's refresh flow: each refresh token is single-use and
 * a reused or unknown one is refused, as the server does after rotation. */
function mockAuthServer(refresh: string) {
  const state = {
    access: null as string | null,
    refresh,
    refreshBodies: [] as string[],
    rejectRefresh: false,
    serial: 1,
    resourceAuth: [] as string[],
  };
  const fetchMock = vi.fn().mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const headers = (init?.headers as Record<string, string>) ?? {};
    if (url === "/api/v1/auth/refresh") {
      const { refresh_token: presented } = JSON.parse(String(init?.body)) as {
        refresh_token: string;
      };
      state.refreshBodies.push(presented);
      if (state.rejectRefresh || presented !== state.refresh) {
        return Promise.resolve(
          responseWithHeaders({ error: { code: "unauthorized", message: "refused" } }, {}, 401),
        );
      }
      state.serial += 1;
      state.access = `access-${state.serial}`;
      state.refresh = `refresh-${state.serial}`;
      return Promise.resolve(
        responseWithHeaders({
          token: state.access,
          refresh_token: state.refresh,
          user_id: "u1",
          email: "a@b.c",
        }),
      );
    }
    const auth = headers.Authorization ?? "";
    state.resourceAuth.push(auth);
    if (state.access !== null && auth === `Bearer ${state.access}`) {
      return Promise.resolve(responseWithHeaders([{ url }]));
    }
    return Promise.resolve(
      responseWithHeaders({ error: { code: "unauthorized", message: "expired" } }, {}, 401),
    );
  });
  return { fetchMock, state };
}

describe("concurrent 401 handling", () => {
  const paths = ["/api/v1/projects", "/api/v1/projects/p1/stats", "/api/v1/projects/p1/gate"];

  it("shares one refresh across parallel requests that all get 401", async () => {
    const { fetchMock, state } = mockAuthServer("refresh-1");
    vi.stubGlobal("fetch", fetchMock);
    setStoredSession("access-1", "refresh-1", { userId: "u1", email: "a@b.c" });

    const results = await Promise.all(paths.map((path) => apiFetch<{ url: string; }[]>(path)));

    expect(state.refreshBodies).toEqual(["refresh-1"]);
    expect(results).toEqual(paths.map((path) => [{ url: path }]));
    const retries = state.resourceAuth.filter((auth) => auth === "Bearer access-2");
    expect(retries).toHaveLength(paths.length);
    expect(getStoredRefreshToken()).toBe("refresh-2");
  });

  it("ends the session once when the shared refresh is rejected", async () => {
    const { fetchMock, state } = mockAuthServer("refresh-1");
    state.rejectRefresh = true;
    vi.stubGlobal("fetch", fetchMock);
    const refreshFailed = vi.fn();
    const unauthorized = vi.fn();
    setRefreshFailedHandler(refreshFailed);
    setUnauthorizedHandler(unauthorized);
    setStoredSession("access-1", "refresh-1", { userId: "u1", email: "a@b.c" });

    const outcomes = await Promise.allSettled(paths.map((path) => apiFetch(path)));

    expect(outcomes.map((outcome) => outcome.status)).toEqual(["rejected", "rejected", "rejected"]);
    expect(state.refreshBodies).toEqual(["refresh-1"]);
    expect(refreshFailed).toHaveBeenCalledTimes(1);
    expect(unauthorized).toHaveBeenCalledTimes(1);
    expect(readStore()).toBeNull();
  });

  it("starts a new refresh for a later expiry after a completed refresh", async () => {
    const { fetchMock, state } = mockAuthServer("refresh-1");
    vi.stubGlobal("fetch", fetchMock);
    setStoredSession("access-1", "refresh-1", { userId: "u1", email: "a@b.c" });

    await Promise.all(paths.map((path) => apiFetch(path)));
    state.access = null;
    await apiFetch("/api/v1/projects/p1/findings");

    expect(state.refreshBodies).toEqual(["refresh-1", "refresh-2"]);
    expect(state.resourceAuth.at(-1)).toBe("Bearer access-3");
  });
});
