import { APIError } from "@/api/client";
import { describe, expect, it } from "vitest";
import { tooManyAttemptsMessage, tooManyAttemptsWait, waitPhrase } from "./retryWait";

describe("waitPhrase", () => {
  it("names whole seconds below a minute", () => {
    expect(waitPhrase(1)).toBe("1 second");
    expect(waitPhrase(45)).toBe("45 seconds");
    expect(waitPhrase(59)).toBe("59 seconds");
  });

  it("switches to whole minutes at 60 seconds, rounding up", () => {
    expect(waitPhrase(60)).toBe("1 minute");
    expect(waitPhrase(61)).toBe("2 minutes");
    expect(waitPhrase(120)).toBe("2 minutes");
    expect(waitPhrase(121)).toBe("3 minutes");
  });
});

describe("tooManyAttemptsMessage", () => {
  it("uses the sign-in copy with the wait", () => {
    expect(tooManyAttemptsMessage(45)).toBe("Too many attempts. Try again in 45 seconds.");
    expect(tooManyAttemptsMessage(120)).toBe("Too many attempts. Try again in 2 minutes.");
  });
});

describe("tooManyAttemptsWait", () => {
  it("rounds a fractional Retry-After up to whole seconds", () => {
    expect(tooManyAttemptsWait(new APIError(429, "too_many_attempts", "x", 44.2))).toBe(45);
  });

  it("returns the seconds for a too_many_attempts error with a header", () => {
    expect(tooManyAttemptsWait(new APIError(429, "too_many_attempts", "x", 45))).toBe(45);
  });

  it("returns null without a header", () => {
    expect(tooManyAttemptsWait(new APIError(429, "too_many_attempts", "x"))).toBeNull();
  });

  it("returns null for other codes, even with a header", () => {
    expect(tooManyAttemptsWait(new APIError(429, "rate_limited", "x", 30))).toBeNull();
  });

  it("returns null for errors that are not APIError", () => {
    expect(tooManyAttemptsWait(new Error("network"))).toBeNull();
  });
});
