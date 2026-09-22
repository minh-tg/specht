import { apiFetch, setStoredSession, setUnauthorizedHandler } from "@/api/client";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "./AuthContext";
import { useAuth } from "./useAuth";

const STORAGE_KEY = "specht.session";

interface Persisted {
  accessToken: string;
  refreshToken: string;
  user: { userId: string; email: string; };
}

function persist(session: Persisted): void {
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(session));
}

function Probe() {
  const auth = useAuth();
  return (
    <div>
      <span data-testid="token">{auth.token ?? "none"}</span>
      <span data-testid="refresh">{auth.refreshToken ?? "none"}</span>
      <span data-testid="user-id">{auth.userId ?? "none"}</span>
      <span data-testid="email">{auth.email ?? "none"}</span>
      <button onClick={() => void auth.login("a@b.c", "password")}>login</button>
      <button onClick={auth.logout}>logout</button>
    </div>
  );
}

function renderAuth() {
  return render(
    <AuthProvider>
      <Probe />
    </AuthProvider>,
  );
}

function response(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
  } as Response;
}

function fetchMock(fn: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  const mock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) =>
    fn(String(input), init)
  );
  vi.stubGlobal("fetch", mock);
  return mock;
}

beforeEach(() => {
  sessionStorage.clear();
  window.history.replaceState(null, "", "/");
});

afterEach(() => {
  sessionStorage.clear();
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

describe("AuthProvider restore", () => {
  it("restores token, refresh token and identity from sessionStorage on mount", () => {
    persist({
      accessToken: "access-1",
      refreshToken: "refresh-1",
      user: { userId: "u1", email: "a@b.c" },
    });

    renderAuth();

    expect(screen.getByTestId("token")).toHaveTextContent("access-1");
    expect(screen.getByTestId("refresh")).toHaveTextContent("refresh-1");
    expect(screen.getByTestId("user-id")).toHaveTextContent("u1");
    expect(screen.getByTestId("email")).toHaveTextContent("a@b.c");
  });

  it("restores nothing when storage is empty", () => {
    renderAuth();

    expect(screen.getByTestId("token")).toHaveTextContent("none");
    expect(screen.getByTestId("refresh")).toHaveTextContent("none");
    expect(screen.getByTestId("user-id")).toHaveTextContent("none");
    expect(screen.getByTestId("email")).toHaveTextContent("none");
  });
});

describe("AuthProvider login", () => {
  it("persists the login response so a reload keeps the session", async () => {
    fetchMock(() =>
      response(200, {
        token: "access-1",
        refresh_token: "refresh-1",
        user_id: "u1",
        email: "a@b.c",
      })
    );

    const first = renderAuth();
    await userEvent.click(screen.getByRole("button", { name: "login" }));

    expect(await screen.findByTestId("token")).toHaveTextContent("access-1");
    expect(screen.getByTestId("refresh")).toHaveTextContent("refresh-1");
    expect(screen.getByTestId("user-id")).toHaveTextContent("u1");
    expect(screen.getByTestId("email")).toHaveTextContent("a@b.c");

    // Simulated reload: unmount the live tree and boot a fresh provider in
    // the same tab — it must rebuild the session from sessionStorage.
    first.unmount();
    renderAuth();

    expect(screen.getByTestId("token")).toHaveTextContent("access-1");
    expect(screen.getByTestId("refresh")).toHaveTextContent("refresh-1");
    expect(screen.getByTestId("user-id")).toHaveTextContent("u1");
    expect(screen.getByTestId("email")).toHaveTextContent("a@b.c");
  });
});

describe("AuthProvider refresh flow", () => {
  it("refreshes with the stored refresh_token before an expired token is used", async () => {
    const calls: Array<{ url: string; init?: RequestInit; }> = [];
    fetchMock((url, init) => {
      calls.push({ url, init });
      if (url === "/api/v1/auth/refresh") {
        return response(200, {
          token: "access-2",
          refresh_token: "refresh-2",
          user_id: "u1",
          email: "a@b.c",
        });
      }
      // The stored (expired) access token is rejected; the refreshed token
      // succeeds on the retried request.
      const authorization = (init?.headers as Record<string, string> | undefined)?.Authorization;
      if (authorization === "Bearer expired-access") {
        return response(401, { error: { code: "unauthorized" } });
      }
      return response(200, { ok: true });
    });
    // A stored session whose access token has already expired: the next API
    // call must transparently refresh instead of hitting the API with it.
    persist({
      accessToken: "expired-access",
      refreshToken: "refresh-1",
      user: { userId: "u1", email: "a@b.c" },
    });

    renderAuth();
    await apiFetch("/api/v1/data");

    await waitFor(() => {
      expect(calls.some((c) => c.url === "/api/v1/auth/refresh")).toBe(true);
    });
    const refreshCall = calls.find((c) => c.url === "/api/v1/auth/refresh")!;
    expect(refreshCall.init?.method ?? "GET").toBe("POST");
    expect(refreshCall.init?.body).toBe(JSON.stringify({ refresh_token: "refresh-1" }));
    expect((refreshCall.init?.headers as Record<string, string> | undefined)?.Authorization)
      .toBeUndefined();

    // The refreshed pair replaced the stored one.
    expect(sessionStorage.getItem(STORAGE_KEY)).toContain("access-2");
    expect(sessionStorage.getItem(STORAGE_KEY)).toContain("refresh-2");

    // The original request was retried with the new access token.
    const dataCalls = calls.filter((c) => c.url === "/api/v1/data");
    expect(dataCalls).toHaveLength(2);
    expect((dataCalls[1].init?.headers as Record<string, string> | undefined)?.Authorization).toBe(
      "Bearer access-2",
    );
  });

  it("logs out when refresh fails with an invalid refresh token", async () => {
    fetchMock((url, init) => {
      if (url === "/api/v1/auth/refresh") {
        return response(401, { error: { code: "refresh_failed" } });
      }
      const authorization = (init?.headers as Record<string, string> | undefined)?.Authorization;
      if (authorization === "Bearer expired-access") {
        return response(401, { error: { code: "unauthorized" } });
      }
      return response(200, { ok: true });
    });
    persist({
      accessToken: "expired-access",
      refreshToken: "bad-refresh",
      user: { userId: "u1", email: "a@b.c" },
    });

    renderAuth();
    let failure: Error | null = null;
    try {
      await apiFetch("/api/v1/data");
    } catch (err) {
      failure = err as Error;
    }
    expect(failure).toBeTruthy();

    await waitFor(() => {
      expect(screen.getByTestId("token")).toHaveTextContent("none");
      expect(screen.getByTestId("refresh")).toHaveTextContent("none");
      expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull();
    });
  });
});

describe("AuthProvider logout", () => {
  it("calls the server logout endpoint to revoke the refresh token, then clears state", async () => {
    const calls: Array<{ url: string; init?: RequestInit; }> = [];
    const fetchMocked = fetchMock((url, init) => {
      calls.push({ url, init });
      if (url === "/api/v1/auth/logout") {
        return response(204, undefined);
      }
      return response(200, { ok: true });
    });
    persist({
      accessToken: "access-1",
      refreshToken: "refresh-1",
      user: { userId: "u1", email: "a@b.c" },
    });

    renderAuth();
    expect(screen.getByTestId("token")).toHaveTextContent("access-1");

    await userEvent.click(screen.getByRole("button", { name: "logout" }));

    await waitFor(() => {
      const call = calls.find((c) => c.url === "/api/v1/auth/logout");
      expect(call).toBeTruthy();
      expect(call!.init?.method).toBe("POST");
      expect(call!.init?.body).toBe(JSON.stringify({ refresh_token: "refresh-1" }));
    });
    // The logout POST must not carry an Authorization header.
    const logoutCall = calls.find((c) => c.url === "/api/v1/auth/logout")!;
    expect((logoutCall.init?.headers as Record<string, string> | undefined)?.Authorization)
      .toBeUndefined();

    expect(screen.getByTestId("token")).toHaveTextContent("none");
    expect(screen.getByTestId("refresh")).toHaveTextContent("none");
    expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull();

    // Nothing else may be fetched after the logout call.
    expect(fetchMocked).toHaveBeenCalledTimes(1);
  });

  it("clears local state even when the server logout request fails", async () => {
    fetchMock((url) => {
      if (url === "/api/v1/auth/logout") {
        return response(500, { error: { code: "logout_failed" } });
      }
      return response(200, { ok: true });
    });
    persist({
      accessToken: "access-1",
      refreshToken: "refresh-1",
      user: { userId: "u1", email: "a@b.c" },
    });

    renderAuth();
    await userEvent.click(screen.getByRole("button", { name: "logout" }));

    await waitFor(() => {
      expect(screen.getByTestId("token")).toHaveTextContent("none");
      expect(screen.getByTestId("refresh")).toHaveTextContent("none");
      expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull();
    });
  });

  it("does not call the server when there is no refresh token (e.g. SSO session)", async () => {
    const fetchMocked = fetchMock(() => response(200, { ok: true }));
    setStoredSession("access-1", null, { userId: "u1", email: "a@b.c" });

    renderAuth();
    expect(screen.getByTestId("token")).toHaveTextContent("access-1");

    await userEvent.click(screen.getByRole("button", { name: "logout" }));

    await waitFor(() => {
      expect(screen.getByTestId("token")).toHaveTextContent("none");
      expect(screen.getByTestId("refresh")).toHaveTextContent("none");
    });
    expect(fetchMocked).not.toHaveBeenCalled();
    expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull();
  });
});

describe("AuthProvider unauthorized callback", () => {
  it("clears the session when the API reports an unauthorized response", async () => {
    fetchMock((url) => {
      if (url === "/api/v1/data") {
        return response(401, { error: { code: "unauthorized" } });
      }
      return response(200, { ok: true });
    });
    persist({
      accessToken: "access-1",
      refreshToken: "refresh-1",
      user: { userId: "u1", email: "a@b.c" },
    });
    window.history.replaceState(null, "", "/page");

    renderAuth();
    let failure: Error | null = null;
    setUnauthorizedHandler(() => {});
    try {
      await apiFetch("/api/v1/data");
    } catch (err) {
      failure = err as Error;
    }

    expect(failure).toBeTruthy();
    await waitFor(() => {
      expect(screen.getByTestId("token")).toHaveTextContent("none");
      expect(screen.getByTestId("refresh")).toHaveTextContent("none");
      expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull();
    });
  });
});
