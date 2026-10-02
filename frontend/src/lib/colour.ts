/**
 * Colour maths for the design-token tests: parse the colours the stylesheet declares,
 * measure WCAG contrast, and measure how far apart two colours stay for people with
 * red-green colour blindness. Pure functions; nothing here runs in the app.
 */

/** Linear-light sRGB, each channel 0 to 1. */
export type LinearRgb = readonly [number, number, number];

export type Vision = "normal" | "protanopia" | "deuteranopia";

type Matrix = readonly [
  readonly [number, number, number],
  readonly [number, number, number],
  readonly [number, number, number],
];

// Machado, Oliveira and Fernandes (2009), severity 1.0, applied in linear sRGB.
const VISION_MATRIX: Record<Exclude<Vision, "normal">, Matrix> = {
  protanopia: [
    [0.152286, 1.052583, -0.204868],
    [0.114503, 0.786281, 0.099216],
    [-0.003882, -0.048116, 1.051998],
  ],
  deuteranopia: [
    [0.367322, 0.860646, -0.227968],
    [0.280085, 0.672501, 0.047413],
    [-0.01182, 0.04294, 0.968881],
  ],
};

const clamp01 = (v: number): number => Math.min(1, Math.max(0, v));

function oklchToLinear(l: number, c: number, hueDeg: number): LinearRgb {
  const a = c * Math.cos((hueDeg * Math.PI) / 180);
  const b = c * Math.sin((hueDeg * Math.PI) / 180);
  const l_ = (l + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m_ = (l - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s_ = (l - 0.0894841775 * a - 1.291485548 * b) ** 3;
  return [
    4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_,
    -1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_,
    -0.0041960863 * l_ - 0.7034186147 * m_ + 1.7076147010 * s_,
  ];
}

const inGamut = (rgb: LinearRgb): boolean => rgb.every((v) => v >= -1e-4 && v <= 1 + 1e-4);

/** OKLCH to linear sRGB; an out-of-gamut colour loses chroma until it fits, as browsers do. */
function oklchToLinearInGamut(l: number, c: number, hueDeg: number): LinearRgb {
  const direct = oklchToLinear(l, c, hueDeg);
  if (inGamut(direct)) return direct;
  let lo = 0;
  let hi = c;
  for (let i = 0; i < 24; i++) {
    const mid = (lo + hi) / 2;
    if (inGamut(oklchToLinear(l, mid, hueDeg))) lo = mid;
    else hi = mid;
  }
  return oklchToLinear(l, lo, hueDeg);
}

function srgbToLinear(v: number): number {
  return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
}

/**
 * Parses `#rgb`, `#rrggbb` and `oklch(L C H)` (L as a number or a percentage).
 * Colours with an alpha channel are rejected: contrast against an unknown backdrop is meaningless.
 */
export function parseColour(value: string): LinearRgb {
  const text = value.trim().toLowerCase();

  const hex = /^#([0-9a-f]{3}|[0-9a-f]{6})$/.exec(text);
  if (hex) {
    const digits = hex[1].length === 3
      ? hex[1].split("").map((d) => d + d).join("")
      : hex[1];
    const channel = (i: number): number => srgbToLinear(parseInt(digits.slice(i, i + 2), 16) / 255);
    return [channel(0), channel(2), channel(4)];
  }

  const oklch = /^oklch\(\s*([\d.]+)(%?)\s+([\d.]+)\s+([\d.]+)\s*\)$/.exec(text);
  if (oklch) {
    const lightness = oklch[2] === "%" ? Number(oklch[1]) / 100 : Number(oklch[1]);
    return oklchToLinearInGamut(lightness, Number(oklch[3]), Number(oklch[4]));
  }

  throw new Error(`Unsupported colour: ${value}`);
}

function luminance(rgb: LinearRgb): number {
  return 0.2126 * clamp01(rgb[0]) + 0.7152 * clamp01(rgb[1]) + 0.0722 * clamp01(rgb[2]);
}

/** WCAG 2 contrast ratio, from 1 to 21. */
export function contrastRatio(a: LinearRgb, b: LinearRgb): number {
  const la = luminance(a);
  const lb = luminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

function simulate(rgb: LinearRgb, vision: Vision): LinearRgb {
  const c = [clamp01(rgb[0]), clamp01(rgb[1]), clamp01(rgb[2])] as const;
  if (vision === "normal") return c;
  const m = VISION_MATRIX[vision];
  return [
    m[0][0] * c[0] + m[0][1] * c[1] + m[0][2] * c[2],
    m[1][0] * c[0] + m[1][1] * c[1] + m[1][2] * c[2],
    m[2][0] * c[0] + m[2][1] * c[1] + m[2][2] * c[2],
  ];
}

/** The a and b axes of OKLab (the colour plane, lightness ignored). */
function oklabAB(rgb: LinearRgb): readonly [number, number] {
  const [r, g, b] = [clamp01(rgb[0]), clamp01(rgb[1]), clamp01(rgb[2])];
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  return [
    1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s,
    0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s,
  ];
}

/**
 * How different two colours still look as colours, not as light and dark, to someone with the
 * given vision. OKLab a/b distance times 100: about 2 is barely noticeable, under 5 is hard to
 * tell apart side by side, above 8 is clearly different.
 */
export function chromaticDistance(a: LinearRgb, b: LinearRgb, vision: Vision): number {
  const [aa, ab] = oklabAB(simulate(a, vision));
  const [ba, bb] = oklabAB(simulate(b, vision));
  return Math.hypot(aa - ba, ab - bb) * 100;
}
