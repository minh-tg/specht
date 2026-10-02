import { createTestQueryClient, jsonResponse } from "@/test/utils";
import type { FindingEvent, UserProfile } from "@/types/api";
import { QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ActorContext } from "./users";
import { actorLabel, useUserDirectory } from "./users";

const ME: UserProfile = {
  id: "u-me",
  email: "me@example.test",
  role: "member",
  created_at: "2025-01-01T00:00:00Z",
};

const ADMIN: UserProfile = { ...ME, role: "admin" };

const ADA: UserProfile = {
  id: "u-ada",
  email: "ada@example.test",
  display_name: "Ada Lovelace",
  role: "admin",
  created_at: "2025-01-01T00:00:00Z",
};

const GRACE: UserProfile = {
  id: "u-grace",
  email: "grace@example.test",
  role: "member",
  created_at: "2025-01-01T00:00:00Z",
};

function wrapper({ children }: { children: React.ReactNode; }) {
  const qc = createTestQueryClient();
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

let requested: string[];

/** Serves /me and the directory, recording every request URL. */
function mockApi(me: UserProfile, directory: Response) {
  globalThis.fetch = vi.fn().mockImplementation((input: RequestInfo | URL) => {
    const url = String(input);
    requested.push(url);
    if (url === "/api/v1/me") return Promise.resolve(jsonResponse(me));
    if (url === "/api/v1/users?limit=500") return Promise.resolve(directory);
    return Promise.resolve(jsonResponse({ error: { code: "not_found" } }, 404));
  });
}

beforeEach(() => {
  requested = [];
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("actorLabel", () => {
  const cases: Array<{
    name: string;
    event: Pick<FindingEvent, "user_id">;
    context: ActorContext;
    expected: string;
  }> = [
    {
      name: "System",
      event: { user_id: "" },
      context: { me: ME, directory: [ADA] },
      expected: "System",
    },
    {
      name: "You",
      event: { user_id: "u-me" },
      context: { me: ME, directory: [ADA] },
      expected: "You",
    },
    {
      name: "display name",
      event: { user_id: "u-ada" },
      context: { me: ME, directory: [ADA] },
      expected: "Ada Lovelace",
    },
    {
      name: "email fallback",
      event: { user_id: "u-grace" },
      context: { me: ME, directory: [GRACE] },
      expected: "grace@example.test",
    },
    {
      name: "unknown actor",
      event: { user_id: "u-someone" },
      context: { me: ME, directory: [ADA, GRACE] },
      expected: "A team member",
    },
    {
      name: "missing directory",
      event: { user_id: "u-someone" },
      context: { me: ME },
      expected: "A team member",
    },
  ];

  it.each(cases)("labels a $name event", ({ event, context, expected }) => {
    expect(actorLabel(event, context)).toBe(expected);
  });

  it("never falls back to the raw user id", () => {
    const id = "11111111-2222-3333-4444-555555555555";
    expect(actorLabel({ user_id: id }, { me: ME, directory: [] })).toBe("A team member");
  });

  it("names the viewer even when they are not in the directory", () => {
    expect(actorLabel({ user_id: ME.id }, { me: ME, directory: [] })).toBe("You");
  });
});

describe("useUserDirectory", () => {
  it("does not fetch the directory for a member", async () => {
    mockApi(ME, jsonResponse([]));
    const { result } = renderHook(() => useUserDirectory(), { wrapper });

    await waitFor(() => expect(requested).toContain("/api/v1/me"));
    await act(async () => {
      await Promise.resolve();
    });

    expect(requested.filter((url) => url.startsWith("/api/v1/users"))).toHaveLength(0);
    expect(result.current.data).toBeUndefined();
  });

  it("fetches the directory with limit=500 for an admin", async () => {
    mockApi(ADMIN, jsonResponse([ADA, GRACE]));
    const { result } = renderHook(() => useUserDirectory(), { wrapper });

    await waitFor(() => expect(result.current.data).toEqual([ADA, GRACE]));
    expect(requested).toContain("/api/v1/users?limit=500");
  });

  it.each([403, 500])("yields no names when the directory answers %i", async (status) => {
    mockApi(ADMIN, jsonResponse({ error: { code: "forbidden" } }, status));
    const { result } = renderHook(() => useUserDirectory(), { wrapper });

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.data).toBeUndefined();
    expect(actorLabel({ user_id: "u-ada" }, { me: ADMIN, directory: result.current.data }))
      .toBe("A team member");
  });
});
