import { TRIAGE_REQUIREMENTS } from "@/pages/finding-detail/options";
import { jsonResponse } from "@/test/utils";
import type { Waiver } from "@/types/api";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { REASONLESS_STATES, revokeUndoPlan, triageUndoPlan } from "./undoPlans";

interface Call {
  method: string;
  url: string;
  body?: unknown;
}

let calls: Call[] = [];
/** The state the server reports for the finding when the plan reads it. */
let serverState = "exploitable";
/** The waiver the server reports when a plan reads it. */
let serverWaiver: Partial<Waiver> = {};

beforeEach(() => {
  calls = [];
  serverWaiver = { id: "w1", status: "approved", enabled: false };
  serverState = "exploitable";
  globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    calls.push({
      method,
      url: String(url),
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    });
    if (method === "GET" && String(url).includes("/waivers/")) return jsonResponse(serverWaiver);
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

describe("revokeUndoPlan", () => {
  const refresh = vi.fn();
  const revoked = { id: "w1", status: "approved", enabled: false } as Waiver;
  beforeEach(() => refresh.mockClear());

  it.each(
    [
      ["still in force", { status: "approved", enabled: true }],
      ["pending", { status: "pending", enabled: false }],
      ["rejected", { status: "rejected", enabled: false }],
    ] as const,
  )("offers none when the revoke left the waiver %s", (_name, over) => {
    expect(revokeUndoPlan({ slug: "pay", waiver: { ...revoked, ...over } as Waiver, refresh }))
      .toBeUndefined();
  });

  it("reads the waiver, then toggles it back", async () => {
    const plan = revokeUndoPlan({ slug: "pay", waiver: revoked, refresh })!;
    await plan.run();
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      "GET /api/v1/projects/pay/waivers/w1",
      "POST /api/v1/projects/pay/waivers/w1/toggle",
    ]);
    expect(plan.done).toBe("Waiver back in force");
  });

  it.each(
    [
      ["someone switched it back on", { status: "approved", enabled: true }],
      ["it was withdrawn or closed", { status: "rejected", enabled: false }],
    ] as const,
  )("refuses, and toggles nothing, when %s", async (_name, over) => {
    serverWaiver = { id: "w1", ...over };
    const plan = revokeUndoPlan({ slug: "pay", waiver: revoked, refresh })!;
    await expect(plan.run()).rejects.toThrow(
      "The waiver changed in the meantime, so Undo did nothing.",
    );
    expect(calls.map((c) => c.method)).toEqual(["GET"]);
  });
});
