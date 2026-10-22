import { describe, expect, it } from "vitest";
import { tokenExpiry } from "./tokenExpiry";

function jwt(claims: unknown) {
  return `header.${
    btoa(JSON.stringify(claims)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
  }.signature`;
}

describe("token expiry hint", () => {
  it("reads NumericDate seconds without treating them as authentication", () => {
    expect(tokenExpiry(jwt({ exp: 1234 }))).toBe(1_234_000);
  });

  it.each([
    "opaque",
    "header.!bad!.signature",
    jwt(null),
    jwt({}),
    jwt({ exp: "1234" }),
    jwt({ exp: 1e308 }),
  ])("ignores malformed or unavailable expiry %s", (token) => {
    expect(tokenExpiry(token)).toBeNull();
  });
});
