import { describe, expect, it } from "vitest";
import { SSO_SESSION_KEY, ssoTokenFromHash } from "./sso";

function tokenWithPayload(payload: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const encoded = btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  return `header.${encoded}.signature`;
}

describe("ssoTokenFromHash", () => {
  it("extracts the session token and UTF-8 claims from a JWT fragment", () => {
    const token = tokenWithPayload({ sub: "user-1", email: "josé@example.com" });

    expect(ssoTokenFromHash(`#${SSO_SESSION_KEY}=${encodeURIComponent(token)}`)).toEqual({
      token,
      claims: { sub: "user-1", email: "josé@example.com" },
    });
  });

  it.each(["", "login", "#other=value", "#sso_token="])(
    "ignores fragments that do not carry a token (%s)",
    (hash) => {
      expect(ssoTokenFromHash(hash)).toBeNull();
    },
  );

  it.each([
    "not-a-jwt",
    "header.payload",
    "header..signature",
    "header.%%%25.signature",
    "header.__8.signature",
    `header.${btoa("not JSON")}.signature`,
  ])("ignores malformed tokens (%s)", (token) => {
    expect(ssoTokenFromHash(`#${SSO_SESSION_KEY}=${encodeURIComponent(token)}`)).toBeNull();
  });

  it.each([{ email: "user@example.com" }, { sub: "" }, { sub: 12 }])(
    "requires a non-empty string subject (%o)",
    (claims) => {
      const token = tokenWithPayload(claims);
      expect(ssoTokenFromHash(`#${SSO_SESSION_KEY}=${encodeURIComponent(token)}`)).toBeNull();
    },
  );
});
