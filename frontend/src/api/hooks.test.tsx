import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setAuthToken } from "./client";
import {
  useFinding,
  useFindings,
  useGateStatus,
  useReachability,
  useTriageFinding,
  useUpsertReachability,
} from "./hooks";

const ASSESSMENT = {
  id: "r1",
  finding_id: "f1",
  state: "not_reachable",
  evidence: "",
  assessed_by: "u1",
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-01T00:00:00Z",
};

let findingFetchCount: number;
let reachabilityFetchCount: number;
let gateFetchCount: number;
let mutationCalls: Array<
  { method: string; url: string; headers: Record<string, string>; body: string; }
>;

function wrapper({ children }: { children: React.ReactNode; }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      {children}
    </QueryClientProvider>
  );
}

beforeEach(() => {
  findingFetchCount = 0;
  reachabilityFetchCount = 0;
  gateFetchCount = 0;
  mutationCalls = [];
  setAuthToken(null);
  globalThis.fetch = vi.fn().mockImplementation(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url === "/api/v1/findings/f1" && method === "GET") {
        findingFetchCount += 1;
      }
      if (url === "/api/v1/findings/f1/reachability" && method === "GET") {
        reachabilityFetchCount += 1;
      }
      if (url === "/api/v1/projects/p1/gate" && method === "GET") {
        gateFetchCount += 1;
      }
      if (url.endsWith("/findings/f1") && method === "PATCH") {
        mutationCalls.push({
          method,
          url,
          headers: (init?.headers as Record<string, string>) ?? {},
          body: String(init?.body ?? ""),
        });
        return {
          ok: true,
          json: () =>
            Promise.resolve({
              finding_id: "f1",
              analysis_state: "accepted_risk",
              gate_effect: "ignore",
            }),
        } as Response;
      }
      if (url.endsWith("/reachability") && method === "POST") {
        mutationCalls.push({
          method,
          url,
          headers: (init?.headers as Record<string, string>) ?? {},
          body: String(init?.body ?? ""),
        });
        return {
          ok: true,
          json: () =>
            Promise.resolve({ ...ASSESSMENT, state: JSON.parse(String(init?.body)).state }),
        } as Response;
      }
      return { ok: true, json: () => Promise.resolve([]) } as Response;
    },
  );
});

afterEach(() => {
  setAuthToken(null);
  vi.unstubAllGlobals();
});

describe("useTriageFinding", () => {
  it("invalidates the finding's reachability list after a triage succeeds", async () => {
    const { result } = renderHook(
      () => {
        useReachability("f1");
        useFinding("f1");
        return useTriageFinding();
      },
      { wrapper },
    );

    // Initial reachability load must settle before the mutation runs.
    await waitFor(() => {
      expect(reachabilityFetchCount).toBeGreaterThanOrEqual(1);
      expect(findingFetchCount).toBeGreaterThanOrEqual(1);
    });

    await act(async () => {
      await result.current.mutateAsync({
        findingId: "f1",
        analysisState: "accepted_risk",
        reason: "acceptable for now",
        analysisExpiresAt: "2025-06-01T00:00:00.000Z",
      });
    });

    await waitFor(() => {
      expect(reachabilityFetchCount).toBeGreaterThanOrEqual(2);
    });
    // The triage PATCH must also re-fetch the finding detail it changed.
    expect(findingFetchCount).toBeGreaterThanOrEqual(2);
  });
});

describe("mutation CSRF hardening", () => {
  it("sends the session token explicitly on every triage mutation", async () => {
    setAuthToken("access-tok-1");
    const { result } = renderHook(() => useTriageFinding(), { wrapper });

    await act(async () => {
      await result.current.mutateAsync({
        findingId: "f1",
        analysisState: "accepted_risk",
        reason: "acceptable",
      });
    });

    expect(mutationCalls.length).toBeGreaterThanOrEqual(1);
    for (const call of mutationCalls) {
      expect(call.headers.Authorization).toBe("Bearer access-tok-1");
    }
  });

  it("invalidates the finding and gate after a reachability mutation", async () => {
    const { result } = renderHook(
      () => {
        useFinding("f1");
        useGateStatus("p1");
        return useUpsertReachability();
      },
      { wrapper },
    );

    await waitFor(() => {
      expect(findingFetchCount).toBeGreaterThanOrEqual(1);
      expect(gateFetchCount).toBeGreaterThanOrEqual(1);
    });

    await act(async () => {
      await result.current.mutateAsync({ findingId: "f1", state: "not_reachable" });
    });

    await waitFor(() => {
      expect(findingFetchCount).toBeGreaterThanOrEqual(2);
      expect(gateFetchCount).toBeGreaterThanOrEqual(2);
    });
  });

  it("sends the session token explicitly on every reachability mutation", async () => {
    setAuthToken("access-tok-2");
    const { result } = renderHook(() => useUpsertReachability(), { wrapper });

    await act(async () => {
      await result.current.mutateAsync({
        findingId: "f1",
        state: "not_reachable",
        evidence: "traced to prod data flow",
      });
    });

    expect(mutationCalls).toHaveLength(1);
    expect(mutationCalls[0].method).toBe("POST");
    expect(mutationCalls[0].headers.Authorization).toBe("Bearer access-tok-2");
    expect(JSON.parse(mutationCalls[0].body)).toEqual({
      state: "not_reachable",
      evidence: "traced to prod data flow",
    });
  });

  it("never relies on ambient credentials: an anonymous mutation sends no Authorization header", async () => {
    const { result } = renderHook(() => useUpsertReachability(), { wrapper });

    await act(async () => {
      await result.current.mutateAsync({ findingId: "f1", state: "unknown", evidence: "" });
    });

    expect(mutationCalls).toHaveLength(1);
    // The request goes out without cookies or ambient credentials; the server
    // rejects it (missing_token). A cookie-based CSRF can never be forged this way.
    expect(mutationCalls[0].headers.Authorization).toBeUndefined();
    expect(mutationCalls[0].headers.Cookie).toBeUndefined();
  });
});

describe("useFindings", () => {
  it("keeps the previous page of findings while a filtered refetch is pending", async () => {
    const previousPage = [{ id: "f1" }, { id: "f2" }];
    const requested: string[] = [];
    let releaseFiltered: ((response: Response) => void) | undefined;
    globalThis.fetch = vi.fn().mockImplementation((input: RequestInfo | URL) => {
      requested.push(String(input));
      if (requested.length === 1) {
        return Promise.resolve(jsonResponse(previousPage));
      }
      return new Promise<Response>((resolve) => {
        releaseFiltered = resolve;
      });
    });

    const { result, rerender } = renderHook(
      ({ severity }: { severity?: string; }) => useFindings("p1", { severity, limit: 20 }),
      { wrapper, initialProps: { severity: undefined as string | undefined } },
    );

    await waitFor(() => expect(result.current.data).toEqual(previousPage));
    expect(requested[0]).toContain("/api/v1/projects/p1/findings?limit=20");

    rerender({ severity: "critical" });

    await waitFor(() => expect(result.current.isPlaceholderData).toBe(true));
    // The old page stays mounted while the filtered request is in flight, so the
    // filter controls the user is touching do not unmount under them.
    expect(result.current.data).toEqual(previousPage);
    expect(result.current.isLoading).toBe(false);

    await act(async () => {
      releaseFiltered?.(jsonResponse([]));
    });

    await waitFor(() => expect(result.current.data).toEqual([]));
    expect(result.current.isPlaceholderData).toBe(false);
    expect(requested.at(-1)).toContain("severity=critical");
  });
});

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    headers: { "Content-Type": "application/json" },
  });
}
