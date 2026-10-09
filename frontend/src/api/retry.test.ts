import { describe, expect, it } from "vitest";
import { APIError } from "./client";
import { shouldRetryQuery } from "./retry";

describe("shouldRetryQuery", () => {
  it.each([400, 401, 403, 404, 409, 422, 499])("never retries a %i response", (status) => {
    const error = new APIError(status, "client_error", "rejected");

    expect(shouldRetryQuery(0, error)).toBe(false);
  });

  it.each([500, 502, 503])("retries a %i response twice", (status) => {
    const error = new APIError(status, "server_error", "unavailable");

    expect(shouldRetryQuery(0, error)).toBe(true);
    expect(shouldRetryQuery(1, error)).toBe(true);
    expect(shouldRetryQuery(2, error)).toBe(false);
  });

  it("retries network failures twice", () => {
    const error = new TypeError("Failed to fetch");

    expect(shouldRetryQuery(0, error)).toBe(true);
    expect(shouldRetryQuery(1, error)).toBe(true);
    expect(shouldRetryQuery(2, error)).toBe(false);
  });
});
