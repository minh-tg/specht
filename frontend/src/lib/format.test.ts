import { describe, expect, it } from "vitest";
import { formatDate, formatDateTime, formatRelativeTime, pluralize } from "./format";

// Fixed reference point so relative formatting never depends on the wall clock.
const NOW = new Date("2026-10-01T12:00:00Z");

describe("formatRelativeTime", () => {
  it("reads a sub-minute age as just now", () => {
    expect(formatRelativeTime("2026-10-01T11:59:30Z", NOW)).toBe("just now");
    expect(formatRelativeTime("2026-10-01T12:00:00Z", NOW)).toBe("just now");
  });

  it("treats a future timestamp as just now instead of a negative age", () => {
    expect(formatRelativeTime("2026-10-01T12:05:00Z", NOW)).toBe("just now");
  });

  it("counts minutes under an hour", () => {
    expect(formatRelativeTime("2026-10-01T11:59:00Z", NOW)).toBe("1 min ago");
    expect(formatRelativeTime("2026-10-01T11:55:00Z", NOW)).toBe("5 min ago");
    expect(formatRelativeTime("2026-10-01T11:01:00Z", NOW)).toBe("59 min ago");
  });

  it("counts hours under a day", () => {
    expect(formatRelativeTime("2026-10-01T11:00:00Z", NOW)).toBe("1 h ago");
    expect(formatRelativeTime("2026-10-01T10:00:00Z", NOW)).toBe("2 h ago");
    expect(formatRelativeTime("2026-09-30T13:00:00Z", NOW)).toBe("23 h ago");
  });

  it("counts days through the thirtieth", () => {
    expect(formatRelativeTime("2026-09-30T12:00:00Z", NOW)).toBe("1 d ago");
    expect(formatRelativeTime("2026-09-28T12:00:00Z", NOW)).toBe("3 d ago");
    expect(formatRelativeTime("2026-09-01T12:00:00Z", NOW)).toBe("30 d ago");
  });

  it("switches to the absolute date past 30 days", () => {
    const iso = "2026-08-31T12:00:00Z";
    const result = formatRelativeTime(iso, NOW);
    expect(result).not.toContain("ago");
    expect(result).toBe(formatDate(iso));
  });

  it("uses an em-dash for empty or invalid input", () => {
    expect(formatRelativeTime(undefined, NOW)).toBe("–");
    expect(formatRelativeTime(null, NOW)).toBe("–");
    expect(formatRelativeTime("", NOW)).toBe("–");
    expect(formatRelativeTime("not-a-date", NOW)).toBe("–");
  });
});

describe("formatDateTime", () => {
  it("renders a month word, the year and a 24 h clock", () => {
    const iso = "2026-10-01T04:24:00Z";
    const local = new Date(iso);
    const out = formatDateTime(iso);
    const monthWord = new Intl.DateTimeFormat(undefined, { month: "short" }).format(local);
    const hh = String(local.getHours()).padStart(2, "0");
    const mm = String(local.getMinutes()).padStart(2, "0");

    expect(out).toContain(monthWord);
    expect(out).toContain(String(local.getFullYear()));
    expect(out).toContain(`${hh}:${mm}`);
  });

  it("uses an em-dash for empty or invalid input", () => {
    expect(formatDateTime(undefined)).toBe("–");
    expect(formatDateTime(null)).toBe("–");
    expect(formatDateTime("")).toBe("–");
    expect(formatDateTime("nonsense")).toBe("–");
  });
});

describe("formatDate", () => {
  it("renders the day, month word and year without a time", () => {
    const iso = "2026-10-01T04:24:00Z";
    const local = new Date(iso);
    const out = formatDate(iso);
    const monthWord = new Intl.DateTimeFormat(undefined, { month: "short" }).format(local);

    expect(out).toContain(monthWord);
    expect(out).toContain(String(local.getFullYear()));
    expect(out).toContain(String(local.getDate()));
    expect(out).not.toMatch(/\d{2}:\d{2}/);
  });

  it("uses an em-dash for empty or invalid input", () => {
    expect(formatDate(undefined)).toBe("–");
    expect(formatDate(null)).toBe("–");
    expect(formatDate("")).toBe("–");
    expect(formatDate("13/13/2026")).toBe("–");
  });
});

describe("pluralize", () => {
  it("keeps the singular for one", () => {
    expect(pluralize(1, "finding")).toBe("1 finding");
  });

  it("adds an s by default", () => {
    expect(pluralize(0, "finding")).toBe("0 findings");
    expect(pluralize(2, "finding")).toBe("2 findings");
  });

  it("uses an explicit irregular plural", () => {
    expect(pluralize(1, "match", "matches")).toBe("1 match");
    expect(pluralize(3, "match", "matches")).toBe("3 matches");
  });
});
