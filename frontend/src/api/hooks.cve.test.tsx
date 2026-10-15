import { createTestQueryClient, jsonResponse } from "@/test/utils";
import type { CveDetail } from "@/types/cve";
import { QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { normalizeCveDetail, queryKeys, useFindingCve } from "./hooks";

function detail(pending: boolean): CveDetail {
  return {
    cve_id: "CVE-2024-3094",
    pending,
    cvss: [],
    epss: null,
    kev: null,
    cwes: [],
    published_at: null,
    modified_at: null,
    references: [],
    providers: [],
  };
}

let cveFetches: number;
let answers: Response[];

/** Moves the fake clock inside `act`, so React commits what the timers set off. */
async function advance(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

function setup() {
  const client = createTestQueryClient();
  const wrapper = ({ children }: { children: React.ReactNode; }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
  return { client, wrapper };
}

beforeEach(() => {
  cveFetches = 0;
  answers = [];
  globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
    if (String(input) === "/api/v1/findings/f1/cve") {
      cveFetches += 1;
      return answers.shift() ?? jsonResponse(detail(false));
    }
    return jsonResponse({}, 404);
  });
});

afterEach(() => {
  vi.useRealTimers();
});

describe("useFindingCve", () => {
  it("reads the CVE endpoint under a key outside the finding prefix", async () => {
    answers = [jsonResponse(detail(false))];
    const { client, wrapper } = setup();
    const { result } = renderHook(() => useFindingCve("f1"), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.cve_id).toBe("CVE-2024-3094");
    expect(client.getQueryData(["finding-cve", "f1"])).toBeDefined();

    // Triage invalidates every ["finding", ...] query. The CVE details must not refetch with them.
    await client.invalidateQueries({ queryKey: queryKeys.finding() });
    expect(cveFetches).toBe(1);
    expect(client.getQueryState(["finding-cve", "f1"])?.isInvalidated).toBe(false);
  });

  it("keeps an answer fresh for ten minutes", async () => {
    answers = [jsonResponse(detail(false))];
    const { client, wrapper } = setup();
    const { result } = renderHook(() => useFindingCve("f1"), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    const query = client.getQueryCache().find({ queryKey: ["finding-cve", "f1"] });
    expect(query?.observers[0]?.options.staleTime).toBe(10 * 60 * 1000);
  });

  it("does not poll an answer that is not pending", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    answers = [jsonResponse(detail(false))];
    const { wrapper } = setup();
    const { result } = renderHook(() => useFindingCve("f1"), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    await advance(60_000);
    expect(cveFetches).toBe(1);
  });

  it("asks once more about fifteen seconds after a pending answer, then stops", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    answers = [jsonResponse(detail(true)), jsonResponse(detail(true))];
    const { wrapper } = setup();
    const { result } = renderHook(() => useFindingCve("f1"), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.pending).toBe(true);
    expect(cveFetches).toBe(1);

    await advance(14_000);
    expect(cveFetches).toBe(1);
    await advance(2_000);
    await waitFor(() => expect(cveFetches).toBe(2));

    // The second answer is still pending, and no third request follows.
    await advance(120_000);
    expect(cveFetches).toBe(2);
  });

  it("polls only a pending answer, and only until the recheck has happened", async () => {
    answers = [jsonResponse(detail(true))];
    const { client, wrapper } = setup();
    const { result } = renderHook(() => useFindingCve("f1"), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    const query = client.getQueryCache().find({ queryKey: ["finding-cve", "f1"] });
    const interval = query?.observers[0]?.options.refetchInterval;
    if (typeof interval !== "function") throw new Error("refetchInterval should be a function");
    const at = (data: CveDetail | undefined, dataUpdateCount: number) =>
      interval({ state: { data, dataUpdateCount } } as never);

    expect(at(detail(true), 1)).toBe(15_000);
    expect(at(detail(true), 2)).toBe(false);
    expect(at(detail(false), 1)).toBe(false);
    expect(at(undefined, 0)).toBe(false);
  });

  it("does not retry the 404 a finding without a CVE answers with", async () => {
    answers = [jsonResponse({ error: { code: "not_cve", message: "No CVE" } }, 404)];
    const { wrapper } = setup();
    const { result } = renderHook(() => useFindingCve("f1"), { wrapper });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(cveFetches).toBe(1);
  });
});

describe("normalizeCveDetail", () => {
  it("turns the lists the server encodes as null into empty ones", () => {
    const wire = {
      ...detail(false),
      cvss: null,
      cwes: null,
      references: null,
      providers: null,
    } as unknown as CveDetail;
    expect(normalizeCveDetail(wire)).toMatchObject({
      cvss: [],
      cwes: [],
      references: [],
      providers: [],
    });
  });

  it("gives a vector that did not parse an empty metric list", () => {
    const wire = {
      ...detail(false),
      cvss: [{
        version: "3.1",
        vector: "CVSS:3.1/x",
        base_score: null,
        reported_score: 5,
        severity: "medium",
        valid: false,
        metrics: null,
        provenance: { kind: "scan_report" },
      }],
    } as unknown as CveDetail;
    expect(normalizeCveDetail(wire).cvss[0].metrics).toEqual([]);
  });

  it("rejects a body without a CVE identifier", () => {
    expect(() => normalizeCveDetail({} as CveDetail)).toThrow(/no CVE identifier/);
  });

  it("shows a malformed body as an error rather than as data", async () => {
    answers = [jsonResponse({})];
    const { wrapper } = setup();
    const { result } = renderHook(() => useFindingCve("f1"), { wrapper });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.data).toBeUndefined();
  });
});
