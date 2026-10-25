import { afterEach, describe, expect, it, vi } from "vitest";

const originalTZ = process.env.TZ;

afterEach(() => {
  process.env.TZ = originalTZ;
});

/**
 * Loads the expiry helpers fresh under the given zone. The date formatter is built when its
 * module loads and keeps the zone of that moment, as it does in a browser tab.
 */
async function inZone(tz: string) {
  process.env.TZ = tz;
  vi.resetModules();
  const [{ toExpiryTimestamp }, { expiryDateValue }, { formatDate }] = await Promise.all([
    import("./format"),
    import("../project-waivers/waiverEdit"),
    import("@/lib/format"),
  ]);
  return { toExpiryTimestamp, expiryDateValue, formatDate };
}

describe("date-only expiry across time zones", () => {
  it.each([
    ["UTC", "2026-11-01T23:59:59.999Z"],
    ["Europe/Berlin", "2026-11-01T22:59:59.999Z"],
    ["America/Los_Angeles", "2026-11-02T07:59:59.999Z"],
    ["Asia/Tokyo", "2026-11-01T14:59:59.999Z"],
  ])("stores a picked day as the end of that day in %s", async (tz, expected) => {
    const { toExpiryTimestamp } = await inZone(tz);
    expect(toExpiryTimestamp("2026-11-01")).toBe(expected);
  });

  it.each(["Europe/Berlin", "America/Los_Angeles", "Asia/Tokyo", "Pacific/Honolulu"])(
    "shows and re-edits the picked day unchanged in %s",
    async (tz) => {
      const { toExpiryTimestamp, expiryDateValue, formatDate } = await inZone(tz);
      const iso = toExpiryTimestamp("2026-11-01");
      expect(expiryDateValue(iso)).toBe("2026-11-01");
      expect(formatDate(iso)).toBe(formatDate(new Date(2026, 10, 1, 12).toISOString()));
      expect(formatDate(iso)).toMatch(/\b1\b/);
      expect(toExpiryTimestamp(expiryDateValue(iso))).toBe(iso);
    },
  );
});
