import { APIError } from "@/api/client";
import { describe, expect, it } from "vitest";
import {
  findingRetryDelay,
  RATE_LIMIT_MAX_DELAY_MS,
  RATE_LIMIT_RETRIES,
  retryFindingRequest,
} from "./useBlockerFindings";

const limited = (retryAfter?: number) =>
  new APIError(429, "rate_limited", "rate limit exceeded", retryAfter);

describe("retryFindingRequest", () => {
  it("tries a 429 again a few times, then gives up", () => {
    expect(retryFindingRequest(0, limited())).toBe(true);
    expect(retryFindingRequest(RATE_LIMIT_RETRIES - 1, limited())).toBe(true);
    expect(retryFindingRequest(RATE_LIMIT_RETRIES, limited())).toBe(false);
  });

  it("leaves other errors to the app's usual rule", () => {
    expect(retryFindingRequest(0, new APIError(404, "not_found", "missing"))).toBe(false);
    expect(retryFindingRequest(0, new APIError(500, "boom", "server"))).toBe(true);
    expect(retryFindingRequest(2, new APIError(500, "boom", "server"))).toBe(false);
  });
});

describe("findingRetryDelay", () => {
  it("doubles from one second when the server names no wait", () => {
    expect([0, 1, 2, 3].map((count) => findingRetryDelay(count, limited()))).toEqual([
      1000,
      2000,
      4000,
      8000,
    ]);
  });

  it("caps the doubling", () => {
    expect(findingRetryDelay(10, limited())).toBe(RATE_LIMIT_MAX_DELAY_MS);
  });

  it("waits as long as Retry-After says, up to the cap", () => {
    expect(findingRetryDelay(0, limited(3))).toBe(3000);
    expect(findingRetryDelay(3, limited(2))).toBe(2000);
    expect(findingRetryDelay(0, limited(600))).toBe(RATE_LIMIT_MAX_DELAY_MS);
  });
});
