import { TRIAGE_REQUIREMENTS } from "@/pages/finding-detail/options";
import { jsonResponse } from "@/test/utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { REASONLESS_STATES, triageUndoPlan } from "./undoPlans";

interface Call {
  method: string;
  url: string;
  body?: unknown;
}

let calls: Call[] = [];
/** The state the server reports for the finding when the plan reads it. */
let serverState = "exploitable";

beforeEach(() => {
  calls = [];
  serverState = "exploitable";
  globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    calls.push({
      method,
      url: String(url),
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    });
    if (method === "GET") return jsonResponse({ id: "f1", analysis_state: serverState });
    return jsonResponse({ finding_id: "f1", analysis_state: "unanalyzed", gate_effect: "block" });
  });
});

describe("REASONLESS_STATES", () => {
  it("lists exactly the states the triage form accepts without a reason or an expiry", () => {
    const needNothing = Object.entries(TRIAGE_REQUIREMENTS)
      .filter(([, r]) => !r.requiresReason && !r.requiresExpiry)
      .map(([state]) => state);
    expect([...REASONLESS_STATES].sort()).toEqual(needNothing.sort());
  });
});

describe("triageUndoPlan", () => {
  const refresh = vi.fn();
  beforeEach(() => refresh.mockClear());

  it.each(["unanalyzed", "in_triage", "exploitable"] as const)(
    "offers an inverse when the finding was %s",
    (from) => {
      expect(triageUndoPlan({ findingId: "f1", from, to: "false_positive", refresh }))
        .toBeDefined();
    },
  );

  it.each(["false_positive", "not_affected", "accepted_risk", "wont_fix"] as const)(
    "offers none when the finding was %s, which needs a reason the API does not return",
    (from) => {
      expect(triageUndoPlan({ findingId: "f1", from, to: "exploitable", refresh }))
        .toBeUndefined();
    },
  );

  it("offers none when the previous state is unknown or unchanged", () => {
    expect(triageUndoPlan({ findingId: "f1", from: undefined, to: "exploitable", refresh }))
      .toBeUndefined();
    expect(triageUndoPlan({ findingId: "f1", from: "exploitable", to: "exploitable", refresh }))
      .toBeUndefined();
  });

  it("reads the finding, then sends the previous state as a second PATCH", async () => {
    serverState = "false_positive";
    const plan = triageUndoPlan({
      findingId: "f1",
      from: "in_triage",
      to: "false_positive",
      refresh,
    })!;
    await plan.run();
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      "GET /api/v1/findings/f1",
      "PATCH /api/v1/findings/f1",
    ]);
    expect(calls[1]!.body).toEqual({
      analysis_state: "in_triage",
      reason: "",
      analysis_expires_at: null,
    });
    expect(plan.done).toBe("Triage restored to In triage");
  });

  it("refuses, and sends nothing, when someone triaged the finding again meanwhile", async () => {
    serverState = "wont_fix";
    const plan = triageUndoPlan({
      findingId: "f1",
      from: "in_triage",
      to: "false_positive",
      refresh,
    })!;
    await expect(plan.run()).rejects.toThrow(
      "This finding was triaged again in the meantime, so Undo did nothing.",
    );
    expect(calls.map((c) => c.method)).toEqual(["GET"]);
  });

  it("hands its refresh to the caller", () => {
    const plan = triageUndoPlan({
      findingId: "f1",
      from: "in_triage",
      to: "exploitable",
      refresh,
    })!;
    plan.refresh();
    expect(refresh).toHaveBeenCalledOnce();
  });
});
