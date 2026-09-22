import { describe, expect, it } from "vitest";
import { truncateText } from "./utils";

describe("truncateText", () => {
  it("returns short text unchanged", () => {
    expect(truncateText("short evidence", 100)).toBe("short evidence");
  });

  it("truncates text longer than the cap with an ellipsis", () => {
    const long = "x".repeat(500);
    const out = truncateText(long, 240);
    expect(out.length).toBeLessThan(500);
    expect(out.endsWith("…")).toBe(true);
    expect(out).toHaveLength(240);
  });

  it("keeps the result within the cap, ellipsis included", () => {
    const out = truncateText("a".repeat(50), 10);
    expect(out).toBe("aaaaaaaaa…");
    expect(out.length).toBeLessThanOrEqual(10);
  });

  it("caps by grapheme, not UTF-16 code unit, so multi-byte text cannot be split mid-character", () => {
    const out = truncateText("😀".repeat(300), 120);
    // Truncation must never produce an unpaired surrogate.
    for (const ch of out) {
      expect(ch.codePointAt(0)).toBeGreaterThanOrEqual(0);
    }
    expect([...out]).toHaveLength(120);
  });

  it("returns empty input unchanged", () => {
    expect(truncateText("", 240)).toBe("");
  });
});
