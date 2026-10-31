import { describe, expect, it } from "vitest";
import { NOT_A_MEMBER_REASON, waiverAction } from "./waiverRequest";

const base = {
  permissions: true,
  loading: false,
  pending: false,
  blocking: { blocks: true },
  gateRechecking: false,
} as const;

describe("waiverAction", () => {
  it("is available to a member for a finding that blocks the gate", () => {
    expect(waiverAction(base)).toEqual({ kind: "available" });
  });

  it("says the caller is not a member when the server grants no request right", () => {
    expect(waiverAction({ ...base, permissions: false })).toEqual({
      kind: "disabled",
      reason: NOT_A_MEMBER_REASON,
    });
    expect(waiverAction({ ...base, permissions: undefined })).toEqual({
      kind: "disabled",
      reason: NOT_A_MEMBER_REASON,
    });
  });

  it("does not claim non-membership while the project is still loading", () => {
    const action = waiverAction({ ...base, permissions: undefined, loading: true });
    expect(action).toMatchObject({ kind: "disabled" });
    expect(action).not.toEqual({ kind: "disabled", reason: NOT_A_MEMBER_REASON });
  });

  it("shows the pending state instead of a second request", () => {
    expect(waiverAction({ ...base, pending: true })).toEqual({ kind: "pending" });
  });

  it.each([
    [{ blocks: false, reason: "waived" as const }, "already waived"],
    [{ blocks: false, reason: "ignored" as const }, "ignore this finding"],
    [{ blocks: false, reason: "below_floor" as const }, "below the severity floor"],
    [{ blocks: false }, "does not block the gate"],
    [null, "Checking whether"],
  ])("explains a finding that does not block (%j)", (blocking, text) => {
    const action = waiverAction({ ...base, blocking });
    expect(action.kind).toBe("disabled");
    expect(action).toMatchObject({ reason: expect.stringContaining(text) });
  });

  it("waits for the gate to recheck after a triage", () => {
    expect(waiverAction({ ...base, blocking: null, gateRechecking: true })).toEqual({
      kind: "disabled",
      reason: "The gate is rechecking after your triage.",
    });
  });
});
