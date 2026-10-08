import { beforeEach, describe, expect, it } from "vitest";
import {
  clearSsoAttempt,
  hasPendingSsoAttempt,
  markSsoAttempt,
  SSO_CODE_KEY,
  SSO_SESSION_KEY,
  ssoCodeFromHash,
  ssoTokenFromHash,
} from "./sso";

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

describe("ssoCodeFromHash", () => {
  it("extracts code from hash", () => {
    expect(ssoCodeFromHash(`#${SSO_CODE_KEY}=my-code-123`)).toBe("my-code-123");
  });

  it.each(["", "login", "#other=value", "#sso_code=", "#sso_code=   "])(
    "ignores fragments without a valid code (%s)",
    (hash) => {
      expect(ssoCodeFromHash(hash)).toBeNull();
    },
  );
});

describe("SSO attempt marker", () => {
  const MINUTE = 60 * 1000;

  beforeEach(() => {
    localStorage.clear();
  });

  it("is absent until a login is started", () => {
    expect(hasPendingSsoAttempt()).toBe(false);
  });

  it("is pending right after a login is started", () => {
    markSsoAttempt(1_000_000);
    expect(hasPendingSsoAttempt(1_000_000 + MINUTE)).toBe(true);
  });

  it("expires after ten minutes, like the server's state cookie", () => {
    markSsoAttempt(1_000_000);
    expect(hasPendingSsoAttempt(1_000_000 + 10 * MINUTE)).toBe(true);
    expect(hasPendingSsoAttempt(1_000_000 + 10 * MINUTE + 1)).toBe(false);
  });

  it("is not pending when its timestamp lies in the future or is not a number", () => {
    markSsoAttempt(2_000_000);
    expect(hasPendingSsoAttempt(1_000_000)).toBe(false);
    localStorage.setItem("specht.sso_attempt", "yesterday");
    expect(hasPendingSsoAttempt()).toBe(false);
  });

  it("is forgotten once cleared", () => {
    markSsoAttempt();
    clearSsoAttempt();
    expect(hasPendingSsoAttempt()).toBe(false);
  });
});
