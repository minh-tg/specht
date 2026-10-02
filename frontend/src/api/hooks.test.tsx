import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setAuthToken } from "./client";
import {
  findingQueryOptions,
  queryKeys,
  useChangeGate,
  useCreateApiKey,
  useCreateProject,
  useFinding,
  useFindings,
  useGateStatus,
  useMe,
  useProject,
  useProjects,
  useProjectStats,
  useReachability,
  useTriageFinding,
  useUpsertReachability,
  useVersion,
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
let statsFetchCount: number;
let mutationCalls: Array<
  { method: string; url: string; headers: Record<string, string>; body: string; }
>;

function wrapper({ children }: { children: React.ReactNode; }) {
  const qc = createTestQueryClient();
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
  statsFetchCount = 0;
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
      if (url === "/api/v1/projects/p1/stats" && method === "GET") {
        statsFetchCount += 1;
        return {
          ok: true,
          json: () =>
            Promise.resolve({
              total_findings: 1,
              blocking_count: 1,
              waiver_count: 0,
              report_count: 1,
              by_severity: [],
            }),
        } as Response;
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

  it("an anonymous mutation sends no Authorization header", async () => {
    const { result } = renderHook(() => useUpsertReachability(), { wrapper });

    await act(async () => {
      await result.current.mutateAsync({ findingId: "f1", state: "unknown", evidence: "" });
    });

    expect(mutationCalls).toHaveLength(1);
    // No bearer token is attached when there is no session; the server rejects
    // the anonymous request.
    expect(mutationCalls[0].headers.Authorization).toBeUndefined();
  });
});

describe("useFindings", () => {
  it("reads the filtered total from X-Total-Count", async () => {
    const findings = [{ id: "f21" }, { id: "f22" }];
    globalThis.fetch = vi.fn().mockImplementation(() => {
      return Promise.resolve(
        new Response(JSON.stringify(findings), {
          status: 200,
          headers: { "Content-Type": "application/json", "X-Total-Count": "45" },
        }),
      );
    });

    const { result } = renderHook(() => useFindings("p1", { offset: 20, limit: 20 }), {
      wrapper,
    });

    await waitFor(() => expect(result.current.data).toEqual({ findings, total: 45 }));
  });

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

    await waitFor(() =>
      expect(result.current.data).toEqual({ findings: previousPage, total: null })
    );
    expect(requested[0]).toContain("/api/v1/projects/p1/findings?limit=20");

    rerender({ severity: "critical" });

    await waitFor(() => expect(result.current.isPlaceholderData).toBe(true));
    // The old page stays mounted while the filtered request is in flight, so the
    // filter controls the user is touching do not unmount under them.
    expect(result.current.data).toEqual({ findings: previousPage, total: null });
    expect(result.current.isLoading).toBe(false);

    await act(async () => {
      releaseFiltered?.(jsonResponse([]));
    });

    await waitFor(() => expect(result.current.data).toEqual({ findings: [], total: null }));
    expect(result.current.isPlaceholderData).toBe(false);
    expect(requested.at(-1)).toContain("severity=critical");
  });
});

describe("stats invalidation", () => {
  it("refreshes project stats after a triage mutation", async () => {
    const { result } = renderHook(
      () => {
        useProjectStats("p1");
        return useTriageFinding();
      },
      { wrapper },
    );

    await waitFor(() => expect(statsFetchCount).toBeGreaterThanOrEqual(1));

    await act(async () => {
      await result.current.mutateAsync({ findingId: "f1", analysisState: "accepted_risk" });
    });

    await waitFor(() => expect(statsFetchCount).toBeGreaterThanOrEqual(2));
  });

  it("refreshes project stats after a reachability mutation", async () => {
    const { result } = renderHook(
      () => {
        useProjectStats("p1");
        return useUpsertReachability();
      },
      { wrapper },
    );

    await waitFor(() => expect(statsFetchCount).toBeGreaterThanOrEqual(1));

    await act(async () => {
      await result.current.mutateAsync({ findingId: "f1", state: "not_reachable" });
    });

    await waitFor(() => expect(statsFetchCount).toBeGreaterThanOrEqual(2));
  });
});

describe("useMe", () => {
  it("reads the signed-in profile from /api/v1/me", async () => {
    const profile = {
      id: "u1",
      email: "me@test.com",
      role: "admin",
      created_at: "2025-01-01T00:00:00Z",
    };
    const requested: string[] = [];
    globalThis.fetch = vi.fn().mockImplementation((input: RequestInfo | URL) => {
      requested.push(String(input));
      return Promise.resolve(jsonResponse(profile));
    });

    const { result } = renderHook(() => useMe(), { wrapper });

    await waitFor(() => expect(result.current.data).toEqual(profile));
    expect(requested[0]).toBe("/api/v1/me");
  });
});

describe("useVersion", () => {
  it("reads the server build info from /api/v1/version", async () => {
    const version = { version: "0.1.0", commit: "4f93c32a1b2c" };
    const requested: string[] = [];
    globalThis.fetch = vi.fn().mockImplementation((input: RequestInfo | URL) => {
      requested.push(String(input));
      return Promise.resolve(jsonResponse(version));
    });

    const { result } = renderHook(() => useVersion(), { wrapper });

    await waitFor(() => expect(result.current.data).toEqual(version));
    expect(requested[0]).toBe("/api/v1/version");
  });
});

describe("useProject", () => {
  it("reads a project by slug", async () => {
    const project = {
      id: "p1",
      slug: "payments",
      name: "Payments",
      description: null,
      created_at: "2025-01-01T00:00:00Z",
      updated_at: "2025-01-01T00:00:00Z",
    };
    const requested: string[] = [];
    globalThis.fetch = vi.fn().mockImplementation((input: RequestInfo | URL) => {
      requested.push(String(input));
      return Promise.resolve(jsonResponse(project));
    });

    const { result } = renderHook(() => useProject("payments"), { wrapper });

    await waitFor(() => expect(result.current.data).toEqual(project));
    expect(requested[0]).toBe("/api/v1/projects/payments");
  });
});

describe("useProjectStats", () => {
  it("reads the project roll-up", async () => {
    const stats = {
      total_findings: 3,
      blocking_count: 1,
      waiver_count: 0,
      report_count: 2,
      by_severity: [{ severity: "high", count: 3, blocking_count: 1 }],
    };
    const requested: string[] = [];
    globalThis.fetch = vi.fn().mockImplementation((input: RequestInfo | URL) => {
      requested.push(String(input));
      return Promise.resolve(jsonResponse(stats));
    });

    const { result } = renderHook(() => useProjectStats("payments"), { wrapper });

    await waitFor(() => expect(result.current.data).toEqual(stats));
    expect(requested[0]).toBe("/api/v1/projects/payments/stats");
  });
});

describe("useCreateProject", () => {
  it("posts the project and invalidates the projects list", async () => {
    let projectsFetchCount = 0;
    const mutations: Array<{ url: string; body: string; }> = [];
    globalThis.fetch = vi.fn().mockImplementation(
      (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        if (url === "/api/v1/projects" && method === "POST") {
          mutations.push({ url, body: String(init?.body ?? "") });
          return Promise.resolve(jsonResponse({
            id: "p9",
            slug: "payments",
            name: "Payments",
            description: null,
            created_at: "2025-01-01T00:00:00Z",
            updated_at: "2025-01-01T00:00:00Z",
          }));
        }
        projectsFetchCount += 1;
        return Promise.resolve(jsonResponse([]));
      },
    );

    const { result } = renderHook(
      () => {
        useProjects();
        return useCreateProject();
      },
      { wrapper },
    );

    await waitFor(() => expect(projectsFetchCount).toBeGreaterThanOrEqual(1));

    await act(async () => {
      await result.current.mutateAsync({ name: "Payments", slug: "payments" });
    });

    expect(mutations).toHaveLength(1);
    expect(mutations[0].url).toBe("/api/v1/projects");
    expect(JSON.parse(mutations[0].body)).toEqual({ name: "Payments", slug: "payments" });
    await waitFor(() => expect(projectsFetchCount).toBeGreaterThanOrEqual(2));
  });
});

describe("useCreateApiKey", () => {
  it("mints a project key and returns the raw secret", async () => {
    const created = {
      id: "k1",
      name: "ci",
      key_prefix: "vuln",
      raw_key: "vuln_secret",
      created_at: "2025-01-01T00:00:00Z",
    };
    const mutations: Array<{ url: string; body: string; }> = [];
    globalThis.fetch = vi.fn().mockImplementation(
      (input: RequestInfo | URL, init?: RequestInit) => {
        mutations.push({ url: String(input), body: String(init?.body ?? "") });
        return Promise.resolve(jsonResponse(created));
      },
    );

    const { result } = renderHook(() => useCreateApiKey(), { wrapper });

    let data: typeof created | undefined;
    await act(async () => {
      data = await result.current.mutateAsync({ project: "payments", name: "ci" });
    });

    expect(data?.raw_key).toBe("vuln_secret");
    expect(mutations[0].url).toBe("/api/v1/auth/apikeys");
    expect(JSON.parse(mutations[0].body)).toEqual({ project: "payments", name: "ci" });
  });
});

describe("useChangeGate", () => {
  it("scopes the gate to one report and encodes every parameter", async () => {
    const urls: string[] = [];
    globalThis.fetch = vi.fn().mockImplementation((input: RequestInfo | URL) => {
      urls.push(String(input));
      return Promise.resolve(jsonResponse({ threshold_breached: true, blocking_count: 1 }));
    });

    const { result } = renderHook(() => useChangeGate("p/1", "r 1/2"), { wrapper });

    await waitFor(() => expect(result.current.data?.threshold_breached).toBe(true));
    expect(urls[0]).toBe("/api/v1/projects/p%2F1/gate?introduced_only=true&report_id=r%201%2F2");
  });

  it("stays disabled without a report", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({}));
    globalThis.fetch = fetchMock;

    renderHook(() => useChangeGate("p1", undefined), { wrapper });

    // Give React Query a tick to settle, then prove no request went out.
    await act(async () => {
      await Promise.resolve();
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("findingQueryOptions", () => {
  it("shares one cache entry with useFinding", async () => {
    const qc = createTestQueryClient();
    globalThis.fetch = vi.fn().mockResolvedValue(jsonResponse({ id: "f1" }));
    const localWrapper = ({ children }: { children: React.ReactNode; }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    );

    const { result } = renderHook(() => useFinding("f1"), { wrapper: localWrapper });
    await waitFor(() => expect(result.current.data).toEqual({ id: "f1" }));

    const options = findingQueryOptions("f1");
    expect(options.queryKey).toEqual(queryKeys.finding("f1"));
    expect(qc.getQueryData(options.queryKey)).toEqual({ id: "f1" });
  });
});
