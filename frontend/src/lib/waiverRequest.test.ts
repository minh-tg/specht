import { APIError } from "@/api/client";
import { describe, expect, it } from "vitest";
import {
  NOT_A_MEMBER_REASON,
  reasonLength,
  waiverAction,
  waiverRequestFailure,
  waiverWithdrawFailure,
} from "./waiverRequest";

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

describe("reasonLength", () => {
  it("counts characters of the trimmed text, as the server does", () => {
    expect(reasonLength("  abc  ")).toBe(3);
    // One emoji is two UTF-16 units but one character to the server.
    expect(reasonLength("\u{1F600}\u{1F600}")).toBe(2);
  });
});

describe("waiverRequestFailure", () => {
  it("names the existing request and keeps the request id", () => {
    const error = new APIError(409, "waiver_request_exists", "x", undefined, "req-9");
    const failure = waiverRequestFailure(error);
    expect(failure.detail).toMatch(/already waiting for a manager/);
    expect(failure.detail).toMatch(/Your text is kept/);
    expect(failure.requestId).toBe("req-9");
  });

  it("shows the server's own words for a validation refusal", () => {
    const failure = waiverRequestFailure(
      new APIError(400, "invalid_body", "reason is longer than 1000 characters"),
    );
    expect(failure.detail).toBe("Reason is longer than 1000 characters. Your text is kept.");
    expect(failure.requestId).toBeUndefined();
  });

  it("maps a 422 and other client errors to the server message", () => {
    const failure = waiverRequestFailure(new APIError(422, "unprocessable", "Cannot do that."));
    expect(failure.detail).toBe("Cannot do that. Your text is kept.");
  });

  it("covers forbidden, rate limit, server error and a lost connection", () => {
    expect(waiverRequestFailure(new APIError(403, "forbidden", "no")).detail)
      .toMatch(/Only project members/);
    expect(waiverRequestFailure(new APIError(429, "rate_limited", "slow", 12)).detail)
      .toMatch(/Wait 12 seconds/);
    expect(waiverRequestFailure(new APIError(500, "internal_error", "boom")).detail)
      .toMatch(/server had a problem/);
    expect(waiverRequestFailure(new TypeError("Failed to fetch")).detail)
      .toMatch(/could not be reached/);
  });
});

describe("waiverWithdrawFailure", () => {
  it("says someone decided first on a conflict", () => {
    const failure = waiverWithdrawFailure(
      new APIError(409, "waiver_not_pending", "x", undefined, "req-1"),
    );
    expect(failure.detail).toMatch(/already decided/);
    expect(failure.requestId).toBe("req-1");
  });

  it("covers forbidden, missing and server errors", () => {
    expect(waiverWithdrawFailure(new APIError(403, "forbidden", "no")).detail)
      .toMatch(/Only the person who asked/);
    expect(waiverWithdrawFailure(new APIError(404, "not_found", "no")).detail)
      .toMatch(/no longer exists/);
    expect(waiverWithdrawFailure(new APIError(502, "bad", "no")).detail)
      .toMatch(/server had a problem/);
  });
});
