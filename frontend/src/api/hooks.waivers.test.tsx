import { createTestQueryClient, jsonResponse } from "@/test/utils";
import type { Waiver } from "@/types/api";
import { QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  queryKeys,
  SCAN_POLL_CAP_MS,
  scanPollInterval,
  useRequestWaiver,
  useRestoreWaiver,
  useRevokeWaiver,
  useScanSignal,
  useWaivers,
} from "./hooks";

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
      if (url.endsWith("/revoke") || url.endsWith("/restore")) {
        return jsonResponse({ id: "w1", status: "approved", enabled: url.endsWith("/restore") });
      }
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

  it("never stops, and never waits more than thirty seconds", () => {
    expect(scanPollInterval(600_000)).toBe(30_000);
    expect(scanPollInterval(3_600_000)).toBe(30_000);
    expect(scanPollInterval(86_400_000)).toBe(SCAN_POLL_CAP_MS);
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

describe("useRevokeWaiver and useRestoreWaiver", () => {
  const shown = {
    id: "w 1",
    status: "approved",
    enabled: true,
    updated_at: "2026-10-15T09:12:44.123456Z",
  } as Waiver;

  it("revokes by POST to the revoke path with the version the screen showed", async () => {
    const { result } = renderHook(() => useRevokeWaiver("acme"), { wrapper });
    await act(async () => {
      await result.current.mutateAsync(shown);
    });
    expect(calls[0].url).toBe("/api/v1/projects/acme/waivers/w%201/revoke");
    expect(calls[0].method).toBe("POST");
    expect(JSON.parse(calls[0].body)).toEqual({
      expected_updated_at: "2026-10-15T09:12:44.123456Z",
    });
  });

  it("restores by POST to the restore path with the version the screen showed", async () => {
    const { result } = renderHook(() => useRestoreWaiver("acme"), { wrapper });
    await act(async () => {
      await result.current.mutateAsync({ ...shown, enabled: false });
    });
    expect(calls[0].url).toBe("/api/v1/projects/acme/waivers/w%201/restore");
    expect(JSON.parse(calls[0].body)).toEqual({
      expected_updated_at: "2026-10-15T09:12:44.123456Z",
    });
  });

  it("refreshes the waivers, their history, the gate and the project numbers after a restore", async () => {
    const client = createTestQueryClient();
    const invalidated: unknown[] = [];
    const original = client.invalidateQueries.bind(client);
    client.invalidateQueries = ((filters: { queryKey?: unknown; }) => {
      invalidated.push(filters.queryKey);
      return original(filters as never);
    }) as typeof client.invalidateQueries;
    const { result } = renderHook(() => useRestoreWaiver("acme"), {
      wrapper: ({ children }) => (
        <QueryClientProvider client={client}>{children}</QueryClientProvider>
      ),
    });
    await act(async () => {
      await result.current.mutateAsync({ ...shown, enabled: false });
    });
    expect(invalidated).toEqual(
      expect.arrayContaining([
        queryKeys.waivers(),
        ["waiver-events", "acme"],
        queryKeys.gate("acme"),
        queryKeys.projectStats("acme"),
        queryKeys.project("acme"),
      ]),
    );
  });

  it("fetches the list again when the server refuses the switch", async () => {
    globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      calls.push({ url: String(input), method: "POST", body: "" });
      return jsonResponse({ error: { code: "waiver_changed", message: "changed" } }, 409);
    });
    const client = createTestQueryClient();
    const spy = vi.spyOn(client, "invalidateQueries");
    const { result } = renderHook(() => useRestoreWaiver("acme"), {
      wrapper: ({ children }) => (
        <QueryClientProvider client={client}>{children}</QueryClientProvider>
      ),
    });
    await act(async () => {
      await result.current.mutateAsync({ ...shown, enabled: false }).catch(() => {});
    });
    expect(spy).toHaveBeenCalledWith({ queryKey: queryKeys.waivers() });
    await waitFor(() =>
      expect(result.current.error?.message).toContain("The waiver changed since this list loaded")
    );
  });
});

describe("useScanSignal", () => {
  const current = { id: "r1", createdAt: "2025-01-01T00:00:00Z" };

  it("does nothing while it is disabled", async () => {
    renderHook(() => useScanSignal("acme", { branch: "main", enabled: false }), { wrapper });
    await act(async () => {
      await Promise.resolve();
    });
    expect(calls).toHaveLength(0);
  });

  it("asks for the newest report on the branch", async () => {
    reportsAnswer = [{ id: "r1", status: "completed", created_at: "2025-01-01T00:00:00Z" }];
    const { result } = renderHook(
      () => useScanSignal("acme", { branch: "feature/refund", enabled: true, current }),
      { wrapper },
    );

    await waitFor(() => expect(result.current.dataUpdatedAt).toBeGreaterThan(0));
    expect(calls[0].url).toBe("/api/v1/projects/acme/reports?limit=1&branch=feature%2Frefund");
    expect(result.current.newer).toBeNull();
    expect(result.current.superseded).toBe(false);
  });

  it("asks across every branch for a report with no branch", async () => {
    const { result } = renderHook(() => useScanSignal("acme", { branch: null, enabled: true }), {
      wrapper,
    });
    await waitFor(() => expect(result.current.dataUpdatedAt).toBeGreaterThan(0));
    expect(calls[0].url).toBe("/api/v1/projects/acme/reports?limit=1");
  });

  it("reports a report that appears after the first answer as newer", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    reportsAnswer = [{ id: "r1", status: "completed", created_at: "2025-01-01T00:00:00Z" }];
    const { result } = renderHook(
      () => useScanSignal("acme", { branch: "main", enabled: true, current }),
      { wrapper },
    );
    await waitFor(() => expect(result.current.dataUpdatedAt).toBeGreaterThan(0));
    expect(result.current.newer).toBeNull();

    reportsAnswer = [{ id: "r2", status: "processing", created_at: "2025-01-02T00:00:00Z" }];
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_100);
    });

    expect(result.current.newer?.id).toBe("r2");
  });

  it("ignores a report that is older than the one on screen", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    reportsAnswer = [{ id: "r1", status: "completed", created_at: "2025-01-01T00:00:00Z" }];
    const { result } = renderHook(
      () => useScanSignal("acme", { branch: "main", enabled: true, current }),
      { wrapper },
    );
    await waitFor(() => expect(result.current.dataUpdatedAt).toBeGreaterThan(0));

    reportsAnswer = [{ id: "r0", status: "completed", created_at: "2024-12-01T00:00:00Z" }];
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_100);
    });

    expect(result.current.newer).toBeNull();
  });

  it("stops asking when a newer report was already there, because the page shows an old change", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    reportsAnswer = [{ id: "r2", status: "completed", created_at: "2025-01-02T00:00:00Z" }];
    const { result } = renderHook(
      () => useScanSignal("acme", { branch: "main", enabled: true, current }),
      { wrapper },
    );
    await waitFor(() => expect(result.current.superseded).toBe(true));
    expect(result.current.newer).toBeNull();
    const settled = calls.length;

    await act(async () => {
      await vi.advanceTimersByTimeAsync(120_000);
    });

    expect(calls.length).toBe(settled);
    expect(result.current.watching).toBe(false);
  });

  it("keeps asking after the stall, at the capped interval", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    reportsAnswer = [{ id: "r1", status: "completed", created_at: "2025-01-01T00:00:00Z" }];
    const { result } = renderHook(
      () => useScanSignal("acme", { branch: "main", enabled: true, current }),
      { wrapper },
    );
    await waitFor(() => expect(calls.length).toBeGreaterThanOrEqual(1));
    expect(result.current.stalled).toBe(false);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(600_500);
    });
    expect(result.current.stalled).toBe(true);
    expect(result.current.watching).toBe(true);

    const settled = calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(SCAN_POLL_CAP_MS * 2 + 500);
    });
    expect(calls.length - settled).toBeGreaterThanOrEqual(2);
    expect(calls.length - settled).toBeLessThanOrEqual(3);
  });

  it("starts the ten minutes again when the report on screen changes", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    reportsAnswer = [{ id: "r1", status: "completed", created_at: "2025-01-01T00:00:00Z" }];
    const { result, rerender } = renderHook(
      ({ report }) => useScanSignal("acme", { branch: "main", enabled: true, current: report }),
      { wrapper, initialProps: { report: current } },
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(601_000);
    });
    expect(result.current.stalled).toBe(true);

    rerender({ report: { id: "r2", createdAt: "2025-01-02T00:00:00Z" } });

    expect(result.current.stalled).toBe(false);
  });

  it("flags a failed check and recovers on the next one", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    reportsAnswer = [{ id: "r1", status: "completed", created_at: "2025-01-01T00:00:00Z" }];
    const { result } = renderHook(
      () => useScanSignal("acme", { branch: "main", enabled: true, current }),
      { wrapper },
    );
    await waitFor(() => expect(result.current.dataUpdatedAt).toBeGreaterThan(0));
    const ok = result.current.dataUpdatedAt;
    vi.mocked(globalThis.fetch).mockImplementationOnce(async () =>
      jsonResponse({ error: { code: "boom", message: "down" } }, 500)
    );

    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_100);
    });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.dataUpdatedAt).toBe(ok);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_100);
    });
    await waitFor(() => expect(result.current.isError).toBe(false));
  });
});
