import { jsonResponse } from "@/test/utils";
import type { Waiver } from "@/types/api";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { restoreMemberPlan, revokeUndoPlan, triageUndoPlan } from "./undoPlans";

interface Call {
  method: string;
  url: string;
  body?: unknown;
}

let calls: Call[] = [];
/** The waiver the server reports when a plan reads it. */
let serverWaiver: Partial<Waiver> = {};

beforeEach(() => {
  calls = [];
  serverWaiver = { id: "w1", status: "approved", enabled: false };
  globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    calls.push({
      method,
      url: String(url),
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    });
    if (method === "GET" && String(url).includes("/waivers/")) return jsonResponse(serverWaiver);
    if (method === "GET") return jsonResponse({ id: "f1" });
    return jsonResponse({ finding_id: "f1", analysis_state: "unanalyzed", gate_effect: "block" });
  });
});

describe("triageUndoPlan", () => {
  const refresh = vi.fn();
  beforeEach(() => refresh.mockClear());

  it.each(
    [
      "unanalyzed",
      "in_triage",
      "exploitable",
      "false_positive",
      "not_affected",
      "accepted_risk",
      "wont_fix",
    ] as const,
  )("offers an inverse when the finding was %s, whatever it needed", (from) => {
    expect(triageUndoPlan({ findingId: "f1", eventId: "e1", from, to: "exploitable", refresh }))
      .toBeDefined();
  });

  it("offers an inverse when the previous state is unknown or unchanged", () => {
    expect(
      triageUndoPlan({
        findingId: "f1",
        eventId: "e1",
        from: undefined,
        to: "exploitable",
        refresh,
      }),
    )
      .toBeDefined();
    expect(
      triageUndoPlan({
        findingId: "f1",
        eventId: "e1",
        from: "exploitable",
        to: "exploitable",
        refresh,
      }),
    )
      .toBeDefined();
  });

  it("offers none without the event the triage wrote", () => {
    expect(
      triageUndoPlan({
        findingId: "f1",
        eventId: undefined,
        from: "in_triage",
        to: "exploitable",
        refresh,
      }),
    )
      .toBeUndefined();
  });

  it("sends one undo request naming the event, with no read or second write first", async () => {
    const plan = triageUndoPlan({
      findingId: "f/1",
      eventId: "e1",
      from: "in_triage",
      to: "false_positive",
      refresh,
    })!;
    await plan.run();
    expect(calls).toEqual([
      { method: "POST", url: "/api/v1/findings/f%2F1/analysis/undo", body: { event_id: "e1" } },
    ]);
  });

  it("names the restored state in the confirmation when it is known and changed", () => {
    const plan = (from?: "in_triage" | "exploitable") =>
      triageUndoPlan({ findingId: "f1", eventId: "e1", from, to: "exploitable", refresh })!.done;
    expect(plan("in_triage")).toBe("Triage restored to In triage");
    expect(plan(undefined)).toBe("Triage change undone");
    expect(plan("exploitable")).toBe("Triage change undone");
  });

  it.each([
    [
      "analysis_conflict",
      "This is no longer the latest triage change on the finding, so it cannot be undone.",
    ],
    ["undo_unavailable", "This change was recorded without the details needed to undo it."],
    ["previous_expiry_passed", "The previous decision has expired, so it cannot be restored."],
  ])("shows the server's own message when it answers %s", async (code, message) => {
    globalThis.fetch = vi.fn().mockResolvedValue(jsonResponse({ error: { code, message } }, 409));
    const plan = triageUndoPlan({
      findingId: "f1",
      eventId: "e1",
      from: "in_triage",
      to: "exploitable",
      refresh,
    })!;
    await expect(plan.run()).rejects.toThrow(message);
  });

  it("hands its refresh to the caller", () => {
    const plan = triageUndoPlan({
      findingId: "f1",
      eventId: "e1",
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
  const revoked = {
    id: "w1",
    status: "approved",
    enabled: false,
    updated_at: "2026-10-15T09:12:44.123456Z",
  } as Waiver;
  beforeEach(() => refresh.mockClear());

  /** Answers every restore with this refusal, as the server does when the waiver moved on. */
  function refuseRestoreWith(code: string) {
    const base = globalThis.fetch;
    globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
      if (String(url).endsWith("/restore")) {
        calls.push({
          method: init?.method ?? "GET",
          url: String(url),
          body: init?.body ? JSON.parse(String(init.body)) : undefined,
        });
        return jsonResponse({ error: { code, message: `refused: ${code}` } }, 409);
      }
      return (base as typeof fetch)(url, init);
    });
  }

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

  it("sends one restore carrying the version the revoke returned, and reads nothing first", async () => {
    const plan = revokeUndoPlan({ slug: "pay", waiver: revoked, refresh })!;
    await plan.run();
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      "POST /api/v1/projects/pay/waivers/w1/restore",
    ]);
    expect(calls[0]!.body).toEqual({ expected_updated_at: "2026-10-15T09:12:44.123456Z" });
    expect(plan.done).toBe("Waiver back in force");
  });

  it.each(["waiver_changed", "waiver_not_approved"])(
    "refuses with a plain sentence when the server answers %s",
    async (code) => {
      refuseRestoreWith(code);
      const plan = revokeUndoPlan({ slug: "pay", waiver: revoked, refresh })!;
      await expect(plan.run()).rejects.toThrow(
        "The waiver changed in the meantime, so Undo did nothing.",
      );
    },
  );

  it("says the waiver has expired when the server refuses for that reason", async () => {
    refuseRestoreWith("waiver_expired");
    const plan = revokeUndoPlan({ slug: "pay", waiver: revoked, refresh })!;
    await expect(plan.run()).rejects.toThrow("The waiver has expired. Extend its expiry first.");
  });

  it("lets an error that is not a refusal through unchanged", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(
      jsonResponse({ error: { code: "internal_error", message: "boom" } }, 500),
    );
    const plan = revokeUndoPlan({ slug: "pay", waiver: revoked, refresh })!;
    await expect(plan.run()).rejects.toThrow("boom");
  });
});

describe("restoreMemberPlan", () => {
  const refresh = vi.fn();
  let roster: { user_id: string; }[] = [];
  beforeEach(() => {
    refresh.mockClear();
    roster = [{ user_id: "u1" }];
    const base = globalThis.fetch;
    globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
      if (String(url).endsWith("/members") && (init?.method ?? "GET") === "GET") {
        calls.push({ method: "GET", url: String(url) });
        return jsonResponse(roster);
      }
      return (base as typeof fetch)(url, init);
    });
  });

  it("reads the roster, then grants the same role again", async () => {
    const plan = restoreMemberPlan({ slug: "pay", userId: "u2", role: "manager", refresh });
    await plan.run();
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      "GET /api/v1/projects/pay/members",
      "POST /api/v1/projects/pay/members",
    ]);
    expect(calls[1]!.body).toEqual({ user_id: "u2", role: "manager" });
  });

  it("refuses, and grants nothing, when the person is a member again", async () => {
    roster = [{ user_id: "u1" }, { user_id: "u2" }];
    const plan = restoreMemberPlan({ slug: "pay", userId: "u2", role: "manager", refresh });
    await expect(plan.run()).rejects.toThrow("They are a member again, so Undo did nothing.");
    expect(calls.map((c) => c.method)).toEqual(["GET"]);
  });
});
