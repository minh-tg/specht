import { describe, expect, it } from "vitest";
import { isUuid } from "./uuid";

describe("isUuid", () => {
  it("accepts canonical UUIDs in either letter case", () => {
    expect(isUuid("3f9c1d2e-6b7a-4c1e-9f0a-2d8e5b6c7a8f")).toBe(true);
    expect(isUuid("3F9C1D2E-6B7A-4C1E-9F0A-2D8E5B6C7A8F")).toBe(true);
  });

  it("rejects email addresses and other free text", () => {
    expect(isUuid("alex@acme.corp")).toBe(false);
    expect(isUuid("user-uuid")).toBe(false);
    expect(isUuid("")).toBe(false);
  });

  it("rejects malformed UUIDs", () => {
    expect(isUuid("3f9c1d2e6b7a4c1e9f0a2d8e5b6c7a8f")).toBe(false);
    expect(isUuid("3f9c1d2e-6b7a-4c1e-9f0a-2d8e5b6c7a8")).toBe(false);
    expect(isUuid("3f9c1d2e-6b7a-4c1e-9f0a-2d8e5b6c7a8fa")).toBe(false);
    expect(isUuid("3f9c1d2g-6b7a-4c1e-9f0a-2d8e5b6c7a8f")).toBe(false);
  });
});
