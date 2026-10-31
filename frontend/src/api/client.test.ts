import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  APIError,
  apiFetch,
  apiFetchWithTotal,
  clearStoredSession,
  getStoredRefreshToken,
  getStoredSession,
  refreshAccessToken,
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

describe("refresh session ownership", () => {
  it.each([-1, 2, 3600])(
    "advances only an expired or near-expiry cached successor (%s seconds)",
    async (seconds) => {
      const cached = `header.${
        btoa(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + seconds }))
      }.signature`;
      const fresh = `header.${
        btoa(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600 }))
      }.signature`;
      const fetchMock = vi.fn()
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({
              token: cached,
              refresh_token: "refresh-2",
              user_id: "u1",
              email: "u1@example.com",
            }),
            { status: 200 },
          ),
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({
              token: fresh,
              refresh_token: "refresh-3",
              user_id: "u1",
              email: "u1@example.com",
            }),
            { status: 200 },
          ),
        );
      vi.stubGlobal("fetch", fetchMock);
      setStoredSession("old-access", "refresh-1", { userId: "u1", email: "u1@example.com" });
      const result = await refreshAccessToken("refresh-1");
      const bodies = fetchMock.mock.calls.map((call) =>
        JSON.parse(String(call[1]?.body)).refresh_token
      );
      expect(bodies).toEqual(seconds <= 5 ? ["refresh-1", "refresh-2"] : ["refresh-1"]);
      expect(result.refreshToken).toBe(seconds <= 5 ? "refresh-3" : "refresh-2");
      expect(getStoredRefreshToken()).toBe(result.refreshToken);
    },
  );

  it("keeps logout in effect while an expired successor is advancing", async () => {
    const expired = `header.${btoa(JSON.stringify({ exp: 1 }))}.signature`;
    let finish!: (value: Response) => void;
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            token: expired,
            refresh_token: "refresh-2",
            user_id: "u1",
            email: "u1@example.com",
          }),
          { status: 200 },
        ),
      )
      .mockImplementationOnce(() =>
        new Promise<Response>((resolve) => {
          finish = resolve;
        })
      );
    vi.stubGlobal("fetch", fetchMock);
    setStoredSession("old-access", "refresh-1", { userId: "u1", email: "u1@example.com" });
    const pending = refreshAccessToken("refresh-1");
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    clearStoredSession();
    finish(
      new Response(
        JSON.stringify({
          token: "fresh-access",
          refresh_token: "refresh-3",
          user_id: "u1",
          email: "u1@example.com",
        }),
        { status: 200 },
      ),
    );
    await expect(pending).rejects.toMatchObject({ status: 409, code: "session_changed" });
    expect(getStoredRefreshToken()).toBeNull();
  });

  it.each(["logout", "new-login"])(
    "does not overwrite a %s while refresh is pending",
    async (change) => {
      let finish!: (value: Response) => void;
      vi.stubGlobal(
        "fetch",
        vi.fn(() =>
          new Promise<Response>((resolve) => {
            finish = resolve;
          })
        ),
      );
      setStoredSession("old-access", "old-refresh", { userId: "u1", email: "u1@example.com" });
      const pending = refreshAccessToken("old-refresh");
      if (change === "logout") clearStoredSession();
      else {setStoredSession("other-access", "other-refresh", {
          userId: "u2",
          email: "u2@example.com",
        });}
      finish(
        new Response(
          JSON.stringify({
            token: "rotated",
            refresh_token: "rotated-refresh",
            user_id: "u1",
            email: "u1@example.com",
          }),
          { status: 200 },
        ),
      );
      await expect(pending).rejects.toMatchObject({ status: 409, code: "session_changed" });
      expect(getStoredRefreshToken()).toBe(change === "logout" ? null : "other-refresh");
    },
  );
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

describe("Retry-After on error responses", () => {
  it("carries the header's seconds on the APIError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        responseWithHeaders(
          { error: { code: "too_many_attempts", message: "wait" } },
          { "Retry-After": "45" },
          429,
        ),
      ),
    );

    const err = await apiFetch("/api/v1/auth/login").catch((e: unknown) => e);

    expect(err).toBeInstanceOf(APIError);
    expect(err).toMatchObject({ status: 429, code: "too_many_attempts", retryAfter: 45 });
  });

  it("leaves retryAfter undefined when the header is missing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        responseWithHeaders({ error: { code: "rate_limited", message: "slow" } }, {}, 429),
      ),
    );

    const err = await apiFetch("/api/v1/auth/login").catch((e: unknown) => e);

    expect(err).toBeInstanceOf(APIError);
    expect((err as APIError).retryAfter).toBeUndefined();
  });

  it("treats an HTTP-date Retry-After as absent", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        responseWithHeaders(
          { error: { code: "too_many_attempts", message: "wait" } },
          { "Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT" },
          429,
        ),
      ),
    );

    const err = await apiFetch("/api/v1/auth/login").catch((e: unknown) => e);

    expect((err as APIError).retryAfter).toBeUndefined();
  });
});

describe("X-Request-Id on error responses", () => {
  it("carries the header on the APIError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        responseWithHeaders(
          { error: { code: "internal", message: "boom" } },
          { "X-Request-Id": "7f3a9c2e-41d8-4b1e-9c55-2d0e8b1fa0c2" },
          500,
        ),
      ),
    );

    const err = await apiFetch("/api/v1/projects/p1/gate").catch((e: unknown) => e);

    expect(err).toBeInstanceOf(APIError);
    expect((err as APIError).requestId).toBe("7f3a9c2e-41d8-4b1e-9c55-2d0e8b1fa0c2");
  });

  it("leaves requestId undefined when the response has no header", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        responseWithHeaders({ error: { code: "internal", message: "boom" } }, {}, 500),
      ),
    );

    const err = await apiFetch("/api/v1/projects/p1/gate").catch((e: unknown) => e);

    expect((err as APIError).requestId).toBeUndefined();
  });
});

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

describe("a reused refresh token", () => {
  function reusedServer() {
    const refreshBodies: string[] = [];
    const fetchMock = vi.fn().mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === "/api/v1/auth/refresh") {
        refreshBodies.push(JSON.parse(String(init?.body)).refresh_token as string);
        return Promise.resolve(
          responseWithHeaders(
            { error: { code: "refresh_reused", message: "refresh token was already used" } },
            {},
            401,
          ),
        );
      }
      return Promise.resolve(
        responseWithHeaders({ error: { code: "unauthorized", message: "expired" } }, {}, 401),
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    return { fetchMock, refreshBodies };
  }

  function stubLocation() {
    const location = { pathname: "/projects/p1", search: "?tab=findings", href: "" };
    vi.stubGlobal("location", location);
    return location;
  }

  it("signs the user out with the reason and does not retry", async () => {
    const { fetchMock, refreshBodies } = reusedServer();
    const location = stubLocation();
    const unauthorized = vi.fn();
    setUnauthorizedHandler(unauthorized);
    setStoredSession("access-1", "refresh-1", { userId: "u1", email: "a@b.c" });

    await expect(apiFetch("/api/v1/projects")).rejects.toMatchObject({ code: "refresh_reused" });

    expect(refreshBodies).toEqual(["refresh-1"]);
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "/api/v1/projects",
      "/api/v1/auth/refresh",
    ]);
    expect(getStoredSession()).toBeNull();
    expect(unauthorized).toHaveBeenCalledTimes(1);
    expect(location.href).toBe(
      `/login?redirect=${encodeURIComponent("/projects/p1?tab=findings")}&reason=session_reused`,
    );
  });

  it("ends the session once for requests that were waiting on the same refresh", async () => {
    const { refreshBodies } = reusedServer();
    stubLocation();
    const refreshFailed = vi.fn();
    setRefreshFailedHandler(refreshFailed);
    setStoredSession("access-1", "refresh-1", { userId: "u1", email: "a@b.c" });

    const results = await Promise.allSettled([
      apiFetch("/api/v1/projects"),
      apiFetch("/api/v1/teams"),
    ]);

    expect(results.every((r) => r.status === "rejected")).toBe(true);
    expect(refreshBodies).toEqual(["refresh-1"]);
    expect(refreshFailed).toHaveBeenCalledTimes(1);
  });

  it("keeps the plain redirect for any other refresh failure", async () => {
    stubLocation();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(() =>
        Promise.resolve(
          responseWithHeaders({ error: { code: "refresh_failed", message: "invalid" } }, {}, 401),
        )
      ),
    );
    setStoredSession("access-1", "refresh-1", { userId: "u1", email: "a@b.c" });

    await expect(apiFetch("/api/v1/projects")).rejects.toMatchObject({ code: "refresh_failed" });

    expect(window.location.href).toBe(
      `/login?redirect=${encodeURIComponent("/projects/p1?tab=findings")}`,
    );
  });
});
