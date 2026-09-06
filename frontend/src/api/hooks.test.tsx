import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useFinding, useReachability, useTriageFinding } from "./hooks";

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
      if (url.endsWith("/findings/f1") && method === "PATCH") {
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
      return { ok: true, json: () => Promise.resolve([]) } as Response;
    },
  );
});

afterEach(() => {
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
