import { createTestQueryClient, jsonResponse } from "@/test/utils";
import type { UserProfile } from "@/types/api";
import { QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  type PersonSuggestion,
  suggestFromDirectory,
  useMemberSuggestions,
} from "./memberSuggestions";

function person(id: string, email: string, extra: Partial<UserProfile> = {}): UserProfile {
  return { id, email, role: "member", created_at: "2025-01-01T00:00:00Z", ...extra };
}

const DIRECTORY: UserProfile[] = [
  person("u-adam", "adam@acme.example"),
  person("u-ada", "ada@acme.example", { display_name: "Ada Lovelace" }),
  person("u-grace", "grace@acme.example", { display_name: "Grace Hopper" }),
  person("u-bob", "bob@acme.example", { display_name: "Hopperson Smith" }),
  person("u-pct", "a%b@acme.example"),
  person("u-gone", "adrian@acme.example", { disabled: true, disabled_at: "2025-02-01T00:00:00Z" }),
  person("u-system", "system@specht.local", { display_name: "System" }),
];

function emails(query: string, exclude: string[] = []) {
  return suggestFromDirectory(DIRECTORY, query, new Set(exclude)).map((p) => p.email);
}

describe("suggestFromDirectory", () => {
  it("matches the start of the email, ignoring case, ordered by email", () => {
    expect(emails("ADA")).toEqual(["ada@acme.example", "adam@acme.example"]);
    expect(emails("acme")).toEqual([]);
  });

  it("matches the start of any display-name word, not the middle of one", () => {
    expect(emails("love")).toEqual(["ada@acme.example"]);
    expect(emails("hop")).toEqual(["bob@acme.example", "grace@acme.example"]);
    expect(emails("pper")).toEqual([]);
  });

  it("matches text that spans words from the start of a word, like the server", () => {
    expect(emails("ada lov")).toEqual(["ada@acme.example"]);
    expect(emails("ada lovelace")).toEqual(["ada@acme.example"]);
    expect(emails("lov")).toEqual(["ada@acme.example"]);
    expect(emails("da lov")).toEqual([]);
  });

  it("needs three characters after trimming", () => {
    expect(emails("  ad  ")).toEqual([]);
    expect(emails("  ada  ")).toEqual(["ada@acme.example", "adam@acme.example"]);
  });

  it("treats % and _ as plain characters", () => {
    expect(emails("a%b")).toEqual(["a%b@acme.example"]);
    expect(emails("a_b")).toEqual([]);
  });

  it("leaves out disabled and system accounts and people already in the team", () => {
    expect(emails("adr")).toEqual([]);
    expect(emails("sys")).toEqual([]);
    expect(emails("ada", ["u-ada"])).toEqual(["adam@acme.example"]);
  });

  it("offers at most eight people", () => {
    const many = Array.from(
      { length: 12 },
      (_, i) => person(`u-${i}`, `bulk${String(i).padStart(2, "0")}@acme.example`),
    );
    const got = suggestFromDirectory(many, "bulk", new Set());
    expect(got).toHaveLength(8);
    expect(got[0]).toEqual({ user_id: "u-0", email: "bulk00@acme.example", display_name: "" });
  });

  it("offers nobody before the directory loads", () => {
    expect(suggestFromDirectory(undefined, "ada", new Set())).toEqual([]);
  });
});

describe("useMemberSuggestions", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  function mockApi(registrationEnabled: boolean) {
    const calls: Array<{ url: string; signal: AbortSignal | null | undefined; }> = [];
    globalThis.fetch = vi.fn().mockImplementation(
      (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === "/api/v1/capabilities") {
          return Promise.resolve(jsonResponse({ registration: { enabled: registrationEnabled } }));
        }
        calls.push({ url, signal: init?.signal });
        return Promise.resolve(
          jsonResponse([{ user_id: "u-ada", email: "ada@acme.example", display_name: "Ada" }]),
        );
      },
    );
    return calls;
  }

  function wrapper({ children }: { children: React.ReactNode; }) {
    return <QueryClientProvider client={createTestQueryClient()}>{children}</QueryClientProvider>;
  }

  it("asks the server once the typing settles and passes the query signal", async () => {
    const calls = mockApi(false);
    const { result, rerender } = renderHook(({ q }) => useMemberSuggestions("my app", q), {
      wrapper,
      initialProps: { q: "a" },
    });
    rerender({ q: "ad" });
    rerender({ q: " ada&x " });

    await waitFor(() => expect(result.current.data).toHaveLength(1));
    expect(calls.map((c) => c.url)).toEqual([
      "/api/v1/projects/my%20app/member-suggestions?q=ada%26x",
    ]);
    expect(calls[0]?.signal).toBeInstanceOf(AbortSignal);
  });

  it("waits 200 ms before asking", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const calls = mockApi(false);
    const { rerender } = renderHook(({ q }) => useMemberSuggestions("app", q), {
      wrapper,
      initialProps: { q: "" },
    });
    rerender({ q: "ada" });
    await vi.advanceTimersByTimeAsync(150);
    expect(calls).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(100);
    await waitFor(() => expect(calls).toHaveLength(1));
  });

  it("asks nothing for fewer than three characters, counting a surrogate pair as one", async () => {
    const calls = mockApi(false);
    const { result } = renderHook(() => useMemberSuggestions("app", "𝒜𝒷"), { wrapper });
    await new Promise((r) => setTimeout(r, 300));
    expect(result.current.active).toBe(false);
    expect(calls).toHaveLength(0);
  });

  /** Answers each member-suggestion request only when the test releases it. */
  function mockDeferredApi() {
    const pending: Array<
      {
        url: string;
        signal: AbortSignal | null | undefined;
        resolve: (people: PersonSuggestion[]) => void;
      }
    > = [];
    globalThis.fetch = vi.fn().mockImplementation(
      (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === "/api/v1/capabilities") {
          return Promise.resolve(jsonResponse({ registration: { enabled: false } }));
        }
        return new Promise((resolve) => {
          pending.push({
            url,
            signal: init?.signal,
            resolve: (people) => resolve(jsonResponse(people)),
          });
        });
      },
    );
    return pending;
  }

  const ADA_HIT: PersonSuggestion = {
    user_id: "u-ada",
    email: "ada@acme.example",
    display_name: "Ada",
  };
  const ZED_HIT: PersonSuggestion = {
    user_id: "u-zed",
    email: "zed@acme.example",
    display_name: "Zed",
  };

  it("offers nothing selectable for text that no longer matches the answer on screen", async () => {
    const pending = mockDeferredApi();
    const { result, rerender } = renderHook(({ q }) => useMemberSuggestions("app", q), {
      wrapper,
      initialProps: { q: "ada" },
    });
    await waitFor(() => expect(pending).toHaveLength(1));
    pending[0]?.resolve([ADA_HIT]);
    await waitFor(() => expect(result.current.suggestions).toEqual([ADA_HIT]));
    expect(result.current.searching).toBe(false);

    // Typing on: the answer for "ada" is stale at once, during the debounce...
    rerender({ q: "zed" });
    expect(result.current.suggestions).toEqual([]);
    expect(result.current.searching).toBe(true);

    // ...and while the request for "zed" is in flight.
    await waitFor(() => expect(pending).toHaveLength(2));
    expect(result.current.isPlaceholderData).toBe(true);
    expect(result.current.suggestions).toEqual([]);
    expect(result.current.searching).toBe(true);

    pending[1]?.resolve([ZED_HIT]);
    await waitFor(() => expect(result.current.suggestions).toEqual([ZED_HIT]));
    expect(result.current.searching).toBe(false);
  });

  it("stops offering people as soon as the text drops below the minimum length", async () => {
    const pending = mockDeferredApi();
    const { result, rerender } = renderHook(({ q }) => useMemberSuggestions("app", q), {
      wrapper,
      initialProps: { q: "ada" },
    });
    await waitFor(() => expect(pending).toHaveLength(1));
    pending[0]?.resolve([ADA_HIT]);
    await waitFor(() => expect(result.current.suggestions).toEqual([ADA_HIT]));

    rerender({ q: "ad" });
    expect(result.current.active).toBe(false);
    expect(result.current.suggestions).toEqual([]);
    await new Promise((r) => setTimeout(r, 300));
    expect(result.current.active).toBe(false);
    expect(result.current.suggestions).toEqual([]);
    expect(pending).toHaveLength(1);
  });

  it("asks nothing while sign-up is open", async () => {
    const calls = mockApi(true);
    const { result } = renderHook(() => useMemberSuggestions("app", "ada"), { wrapper });
    await new Promise((r) => setTimeout(r, 300));
    expect(result.current.active).toBe(false);
    expect(calls).toHaveLength(0);
  });
});
