import { describe, expect, it } from "vitest";
import { chromaticDistance, contrastRatio, parseColour } from "./colour";

describe("parseColour", () => {
  it("reads short and long hex", () => {
    expect(parseColour("#fff")).toEqual(parseColour("#ffffff"));
    const [r, g, b] = parseColour("#000000");
    expect([r, g, b]).toEqual([0, 0, 0]);
  });

  it("reads oklch with a fraction or a percentage for lightness", () => {
    const fraction = parseColour("oklch(0.5 0.1 200)");
    const percent = parseColour("oklch(50% 0.1 200)");
    expect(percent[0]).toBeCloseTo(fraction[0], 10);
    expect(percent[2]).toBeCloseTo(fraction[2], 10);
  });

  it("treats oklch white as white and keeps out-of-gamut colours inside sRGB", () => {
    const white = parseColour("oklch(1 0 0)");
    white.forEach((v) => expect(v).toBeCloseTo(1, 3));
    const vivid = parseColour("oklch(0.48 0.3 195)");
    vivid.forEach((v) => {
      expect(v).toBeGreaterThanOrEqual(-1e-3);
      expect(v).toBeLessThanOrEqual(1.001);
    });
  });

  it("rejects colours it cannot measure", () => {
    expect(() => parseColour("oklch(1 0 0 / 10%)")).toThrow(/Unsupported/);
    expect(() => parseColour("rebeccapurple")).toThrow(/Unsupported/);
  });
});

describe("contrastRatio", () => {
  it("matches the WCAG reference values", () => {
    expect(contrastRatio(parseColour("#000"), parseColour("#fff"))).toBeCloseTo(21, 5);
    expect(contrastRatio(parseColour("#fff"), parseColour("#fff"))).toBeCloseTo(1, 5);
    // #767676 on white is the well-known 4.54:1 grey that just passes AA.
    expect(contrastRatio(parseColour("#767676"), parseColour("#fff"))).toBeCloseTo(4.54, 1);
  });

  it("is symmetric", () => {
    const a = parseColour("#b42318");
    const b = parseColour("#f6e3e2");
    expect(contrastRatio(a, b)).toBeCloseTo(contrastRatio(b, a), 10);
  });
});

describe("chromaticDistance", () => {
  const red = parseColour("oklch(0.55 0.2 25)");
  const green = parseColour("oklch(0.55 0.15 145)");

  it("is zero for the same colour and grows with the hue gap", () => {
    expect(chromaticDistance(red, red, "normal")).toBe(0);
    expect(chromaticDistance(red, green, "normal")).toBeGreaterThan(15);
  });

  it("collapses red and green for red-green colour blindness", () => {
    expect(chromaticDistance(red, green, "deuteranopia")).toBeLessThan(
      chromaticDistance(red, green, "normal") / 2,
    );
    expect(chromaticDistance(red, green, "protanopia")).toBeLessThan(
      chromaticDistance(red, green, "normal") / 2,
    );
  });
});
