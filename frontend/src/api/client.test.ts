import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  apiFetch,
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
