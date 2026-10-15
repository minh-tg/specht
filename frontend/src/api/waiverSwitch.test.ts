import { describe, expect, it } from "vitest";
import { APIError } from "./client";
import { waiverSwitchError } from "./waiverSwitch";

const refusal = (code: string, status = 409) => new APIError(status, code, `server: ${code}`);

describe("waiverSwitchError", () => {
  it("explains a changed waiver differently for a button and for Undo", () => {
    expect(String(waiverSwitchError(refusal("waiver_changed"), "button"))).toContain(
      "The waiver changed since this list loaded, so nothing was done.",
    );
    expect(String(waiverSwitchError(refusal("waiver_changed"), "undo"))).toContain(
      "The waiver changed in the meantime, so Undo did nothing.",
    );
  });

  it("treats a waiver that is no longer approved as a change", () => {
    expect(String(waiverSwitchError(refusal("waiver_not_approved"), "undo"))).toContain(
      "changed in the meantime",
    );
  });

  it("tells the person to extend the expiry of an expired waiver", () => {
    for (const origin of ["button", "undo"] as const) {
      expect(String(waiverSwitchError(refusal("waiver_expired"), origin))).toContain(
        "The waiver has expired. Extend its expiry first.",
      );
    }
  });

  it("returns other errors as they came, with their own message", () => {
    const other = refusal("something_else");
    expect(waiverSwitchError(other, "button")).toBe(other);
    const server = refusal("waiver_changed", 500);
    expect(waiverSwitchError(server, "button")).toBe(server);
    const plain = new Error("offline");
    expect(waiverSwitchError(plain, "undo")).toBe(plain);
  });
});
