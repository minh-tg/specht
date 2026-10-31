import { describe, expect, it } from "vitest";
import { dayFromNow, exemptsFromGate, reachEffect, triageWrite } from "./decision";
import { TRIAGE_REQUIREMENTS } from "./options";

describe("decide-first answers", () => {
  const now = new Date(2026, 0, 30, 9, 0, 0);

  it("counts days on the local calendar, across a month end", () => {
    expect(dayFromNow(30, now)).toBe("2026-03-01");
  });

  it("writes exploitable for a real issue, without a reason or an expiry", () => {
    expect(triageWrite("real", null, now)).toEqual({ state: "exploitable", needsReason: false });
  });

  it("takes the first kind when none is picked, and an expiry only where the server needs one", () => {
    expect(triageWrite("not_a_problem", null, now)).toEqual({
      state: "false_positive",
      expiresAt: undefined,
      needsReason: true,
    });
    const accepted = triageWrite("accept", "90", now);
    expect(accepted.state).toBe("accepted_risk");
    expect(accepted.expiresAt).toBe(new Date(2026, 3, 30, 23, 59, 59, 999).toISOString());
  });

  it("asks for a reason and an expiry exactly where the server does", () => {
    const writes = [
      triageWrite("real", null, now),
      triageWrite("not_a_problem", "fp", now),
      triageWrite("not_a_problem", "na", now),
      triageWrite("accept", "30", now),
      triageWrite("accept", "wont", now),
    ];
    for (const write of writes) {
      const required = TRIAGE_REQUIREMENTS[write.state]!;
      expect(write.needsReason).toBe(required.requiresReason);
      expect(write.expiresAt !== undefined).toBe(required.requiresExpiry);
    }
  });

  it("treats only not reachable and does not apply as a gate exemption", () => {
    expect(exemptsFromGate("not_reachable")).toBe(true);
    expect(exemptsFromGate("not_applicable")).toBe(true);
    expect(exemptsFromGate("unknown")).toBe(false);
    expect(exemptsFromGate("reachable")).toBe(false);
    expect(reachEffect("unknown", false)).toBe("Not assessed still counts toward blocking.");
  });
});
