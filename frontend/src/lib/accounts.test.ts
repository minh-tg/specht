import { describe, expect, it } from "vitest";
import { isSystemAccount } from "./accounts";

describe("isSystemAccount", () => {
  it("recognises the seeded account whatever its case", () => {
    expect(isSystemAccount({ email: "system@specht.local" })).toBe(true);
    expect(isSystemAccount({ email: "System@Specht.Local" })).toBe(true);
  });

  it("does not mistake a person for it", () => {
    expect(isSystemAccount({ email: "ada@acme.example" })).toBe(false);
    expect(isSystemAccount({ email: "system@acme.example" })).toBe(false);
  });
});
