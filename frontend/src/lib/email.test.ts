import { describe, expect, it } from "vitest";
import { looksLikeEmail } from "./email";

describe("looksLikeEmail", () => {
  it("accepts a plain address", () => {
    expect(looksLikeEmail("ada@acme.example")).toBe(true);
    expect(looksLikeEmail("ada+ci@sub.acme.example")).toBe(true);
  });

  it("rejects text that is not an address", () => {
    for (
      const value of [
        "",
        "ada",
        "ada@acme",
        "@acme.example",
        "ada @acme.example",
        "Ada <ada@acme.example>",
      ]
    ) {
      expect(looksLikeEmail(value), value).toBe(false);
    }
  });
});
