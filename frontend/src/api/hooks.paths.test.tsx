import { createTestQueryClient } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { setAuthToken } from "./client";
import {
  useFinding,
  useFindingEvents,
  useFindings,
  useGateStatus,
  useProject,
  useProjectStats,
  useReachability,
  useReports,
  useTriageFinding,
  useUpsertReachability,
} from "./hooks";

/**
 * Route params are percent-decoded by the router, so a crafted link can put
 * `/`, `..`, `?` or `#` into them. They must be encoded before they reach an
 * API path, or the request (which carries the user's bearer token) can be
 * redirected to a different endpoint.
 */
const HOSTILE = "../../api/v1/me?x=1#frag";
const ENCODED = encodeURIComponent(HOSTILE);

let urls: string[];

function wrapper({ children }: { children: React.ReactNode; }) {
  const qc = createTestQueryClient();
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  urls = [];
  setAuthToken(null);
  globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
    urls.push(String(input));
    return new Response(JSON.stringify([]), { headers: { "Content-Type": "application/json" } });
  });
});

describe("API paths built from route params", () => {
  it.each([
    ["project", () => useProject(HOSTILE), `/api/v1/projects/${ENCODED}`],
    ["project stats", () => useProjectStats(HOSTILE), `/api/v1/projects/${ENCODED}/stats`],
    ["gate", () => useGateStatus(HOSTILE), `/api/v1/projects/${ENCODED}/gate`],
    ["reports", () => useReports(HOSTILE), `/api/v1/projects/${ENCODED}/reports`],
    ["finding", () => useFinding(HOSTILE), `/api/v1/findings/${ENCODED}`],
    [
      "reachability",
      () => useReachability(HOSTILE),
      `/api/v1/findings/${ENCODED}/reachability`,
    ],
    ["events", () => useFindingEvents(HOSTILE), `/api/v1/findings/${ENCODED}/events`],
  ])("encodes the %s path", async (_name, hook, expected) => {
    renderHook(hook, { wrapper });

    await waitFor(() => expect(urls).toContain(expected));
    expect(urls.every((url) => url.startsWith("/api/v1/"))).toBe(true);
    expect(urls.some((url) => url.includes("../"))).toBe(false);
  });

  it("encodes the project slug of the findings list and keeps its query string intact", async () => {
    renderHook(() => useFindings(HOSTILE, { severity: "high", limit: 20 }), { wrapper });

    await waitFor(() => expect(urls).toHaveLength(1));
    expect(urls[0]).toBe(`/api/v1/projects/${ENCODED}/findings?severity=high&limit=20`);
  });

  it("encodes the finding id on triage and reachability writes", async () => {
    const triage = renderHook(() => useTriageFinding(), { wrapper });
    const reachability = renderHook(() => useUpsertReachability(), { wrapper });

    await triage.result.current.mutateAsync({ findingId: HOSTILE, analysisState: "exploitable" });
    await reachability.result.current.mutateAsync({ findingId: HOSTILE, state: "reachable" });

    expect(urls).toContain(`/api/v1/findings/${ENCODED}`);
    expect(urls).toContain(`/api/v1/findings/${ENCODED}/reachability`);
  });

  it("leaves ordinary slugs and ids unchanged", async () => {
    renderHook(() => useProject("payments-api"), { wrapper });
    renderHook(() => useFinding("0b9c2f4e-1111-4222-8333-444455556666"), { wrapper });

    await waitFor(() => expect(urls).toHaveLength(2));
    expect(urls).toContain("/api/v1/projects/payments-api");
    expect(urls).toContain("/api/v1/findings/0b9c2f4e-1111-4222-8333-444455556666");
  });
});
