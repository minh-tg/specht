import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { scanPollInterval, useRequestWaiver, useScanSignal, useWaivers } from "./hooks";

let calls: Array<{ url: string; method: string; body: string; }>;
let reportsAnswer: unknown[];

function wrapper({ children }: { children: React.ReactNode; }) {
  return <QueryClientProvider client={createTestQueryClient()}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  calls = [];
  reportsAnswer = [];
  globalThis.fetch = vi.fn().mockImplementation(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({
        url,
        method: (init?.method ?? "GET").toUpperCase(),
        body: String(init?.body ?? ""),
      });
      if (url.includes("/waivers/requests")) {
        return jsonResponse({ id: "w1", status: "pending", targets: [] }, 201);
      }
      if (url.includes("/waivers")) return jsonResponse([]);
      return jsonResponse(reportsAnswer);
    },
  );
});

afterEach(() => {
  vi.useRealTimers();
});

describe("scanPollInterval", () => {
  it("asks every four seconds for the first minute", () => {
    expect(scanPollInterval(0)).toBe(4_000);
    expect(scanPollInterval(59_999)).toBe(4_000);
  });

  it("slows to ten seconds after that", () => {
    expect(scanPollInterval(60_000)).toBe(10_000);
    expect(scanPollInterval(599_999)).toBe(10_000);
  });

  it("stops after ten minutes", () => {
    expect(scanPollInterval(600_000)).toBe(false);
    expect(scanPollInterval(3_600_000)).toBe(false);
  });
});

describe("useWaivers", () => {
  it("asks for the given review states", async () => {
    const { result } = renderHook(() => useWaivers("acme", ["pending", "approved"]), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(calls[0].url).toBe("/api/v1/projects/acme/waivers?status=pending%2Capproved");
  });

  it("lists every waiver when no state is given", async () => {
    const { result } = renderHook(() => useWaivers("acme"), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(calls[0].url).toBe("/api/v1/projects/acme/waivers");
  });
});

describe("useRequestWaiver", () => {
  it("posts the findings, the reason and the expiry", async () => {
    const { result } = renderHook(() => useRequestWaiver("acme"), { wrapper });

    await act(async () => {
      await result.current.mutateAsync({
        findingIds: ["f1", "f2"],
        reason: "not reachable",
        expiresAt: "2030-01-01T00:00:00.000Z",
      });
    });

    expect(calls[0].url).toBe("/api/v1/projects/acme/waivers/requests");
    expect(calls[0].method).toBe("POST");
    expect(JSON.parse(calls[0].body)).toEqual({
      target_ids: ["f1", "f2"],
      reason: "not reachable",
      expires_at: "2030-01-01T00:00:00.000Z",
    });
  });
});

describe("useScanSignal", () => {
  it("does nothing until waiting starts", async () => {
    renderHook(() => useScanSignal("acme", { branch: "main", enabled: false }), { wrapper });
    await act(async () => {
      await Promise.resolve();
    });
    expect(calls).toHaveLength(0);
  });

  it("asks for the newest report on the branch", async () => {
    reportsAnswer = [{ id: "r9", status: "completed" }];
    const { result } = renderHook(
      () => useScanSignal("acme", { branch: "feature/refund", enabled: true }),
      { wrapper },
    );

    await waitFor(() => expect(result.current.newest?.id).toBe("r9"));
    expect(calls[0].url).toBe("/api/v1/projects/acme/reports?limit=1&branch=feature%2Frefund");
  });

  it("asks across every branch for a report with no branch", async () => {
    const { result } = renderHook(() => useScanSignal("acme", { branch: null, enabled: true }), {
      wrapper,
    });
    await waitFor(() => expect(result.current.newest).toBeNull());
    expect(calls[0].url).toBe("/api/v1/projects/acme/reports?limit=1");
  });

  it("polls again while it waits, then reports a stall after ten minutes", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const { result } = renderHook(() => useScanSignal("acme", { branch: "main", enabled: true }), {
      wrapper,
    });
    await waitFor(() => expect(calls.length).toBeGreaterThanOrEqual(1));
    const first = calls.length;

    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_100);
    });
    expect(calls.length).toBeGreaterThan(first);
    expect(result.current.stalled).toBe(false);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(600_000);
    });
    expect(result.current.stalled).toBe(true);
    const settled = calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000);
    });
    expect(calls.length).toBe(settled);
  });

  it("starts another run when the attempt changes", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const { result, rerender } = renderHook(
      ({ attempt }) => useScanSignal("acme", { branch: "main", enabled: true, attempt }),
      { wrapper, initialProps: { attempt: 0 } },
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(601_000);
    });
    expect(result.current.stalled).toBe(true);

    rerender({ attempt: 1 });

    expect(result.current.stalled).toBe(false);
  });
});
