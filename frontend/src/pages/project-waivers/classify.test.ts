import type { Waiver } from "@/types/api";
import { describe, expect, it } from "vitest";
import {
  closedReason,
  countByBucket,
  waiverBucket,
  waiverEventLabel,
  waiverTitle,
} from "./classify";

const now = new Date("2026-10-12T12:00:00Z");

function waiver(extra: Partial<Waiver>): Waiver {
  return {
    id: "w",
    project_id: "p",
    name: "Waiver request: Heap overflow",
    description: "",
    enabled: true,
    status: "pending",
    scope_all: false,
    reason: "",
    decision_note: "",
    targets: [],
    created_at: "2026-10-01T00:00:00Z",
    updated_at: "2026-10-01T00:00:00Z",
    ...extra,
  };
}

describe("waiverBucket", () => {
  it("keeps a request that has not been decided in the waiting list", () => {
    expect(waiverBucket(waiver({ status: "pending" }), now)).toBe("pending");
  });

  it("puts an approved, switched-on waiver in force", () => {
    expect(waiverBucket(waiver({ status: "approved" }), now)).toBe("in_force");
    expect(
      waiverBucket(waiver({ status: "approved", expires_at: "2026-10-20T00:00:00Z" }), now),
    ).toBe("in_force");
  });

  it("closes an approved waiver that was switched off or has run out", () => {
    expect(waiverBucket(waiver({ status: "approved", enabled: false }), now)).toBe("closed");
    expect(
      waiverBucket(waiver({ status: "approved", expires_at: "2026-10-12T11:59:59Z" }), now),
    ).toBe("closed");
  });

  it("closes rejected and withdrawn requests", () => {
    expect(waiverBucket(waiver({ status: "rejected" }), now)).toBe("closed");
    expect(waiverBucket(waiver({ status: "withdrawn" }), now)).toBe("closed");
  });

  it("treats an unreadable expiry as no expiry rather than as already over", () => {
    expect(waiverBucket(waiver({ status: "approved", expires_at: "soon" }), now)).toBe("in_force");
  });
});

describe("closedReason", () => {
  it("names why each closed waiver is closed", () => {
    expect(closedReason(waiver({ status: "rejected" }), now)).toBe("Rejected");
    expect(closedReason(waiver({ status: "withdrawn" }), now)).toBe("Withdrawn");
    expect(closedReason(waiver({ status: "approved", enabled: false }), now)).toBe("Revoked");
    expect(
      closedReason(waiver({ status: "approved", expires_at: "2026-10-01T00:00:00Z" }), now),
    ).toBe("Expired");
  });
});

describe("closedReason for a waiver the sweeper switched off", () => {
  // The sweeper disables an expired waiver and leaves it approved, so it is also "off". Expiry has
  // to win, or a waiver that can no longer be restored would be labelled as one that can.
  it("calls an approved, switched-off waiver past its expiry Expired, not Revoked", () => {
    expect(
      closedReason(
        waiver({ status: "approved", enabled: false, expires_at: "2026-10-12T11:59:59Z" }),
        now,
      ),
    ).toBe("Expired");
  });

  it("still calls a switched-off waiver with time left Revoked", () => {
    expect(
      closedReason(
        waiver({ status: "approved", enabled: false, expires_at: "2026-10-20T00:00:00Z" }),
        now,
      ),
    ).toBe("Revoked");
    expect(closedReason(waiver({ status: "approved", enabled: false }), now)).toBe("Revoked");
  });

  it("keeps Rejected and Withdrawn ahead of an old expiry", () => {
    expect(closedReason(waiver({ status: "rejected", expires_at: "2026-10-01T00:00:00Z" }), now))
      .toBe("Rejected");
    expect(closedReason(waiver({ status: "withdrawn", expires_at: "2026-10-01T00:00:00Z" }), now))
      .toBe("Withdrawn");
  });
});

describe("waiverEventLabel", () => {
  it("names the revoke and restore events", () => {
    expect(waiverEventLabel("revoked")).toBe("Revoked");
    expect(waiverEventLabel("restored")).toBe("Restored");
  });
});

describe("waiverTitle and countByBucket", () => {
  it("drops the request prefix and falls back when nothing is left", () => {
    expect(waiverTitle(waiver({}))).toBe("Heap overflow");
    expect(waiverTitle(waiver({ name: "Waiver request:" }))).toBe("Waiver");
    expect(waiverTitle(waiver({ name: "Temporary bucket" }))).toBe("Temporary bucket");
  });

  it("counts each list", () => {
    const all = [
      waiver({ id: "1" }),
      waiver({ id: "2" }),
      waiver({ id: "3", status: "approved" }),
      waiver({ id: "4", status: "rejected" }),
    ];
    expect(countByBucket(all, now)).toEqual({ pending: 2, in_force: 1, closed: 1 });
  });
});
