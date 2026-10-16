import { beforeEach, describe, expect, it } from "vitest";
import {
  clearSsoAttempt,
  hasPendingSsoAttempt,
  markSsoAttempt,
  SSO_CODE_KEY,
  ssoCodeFromHash,
} from "./sso";

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
