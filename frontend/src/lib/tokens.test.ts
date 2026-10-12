import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  chroma,
  contrastRatio,
  type LinearRgb,
  parseColour,
  perceptualDistance,
  type Vision,
} from "./colour";

/**
 * Guards the design tokens in index.css. A palette change must keep text readable and must not
 * make the accent look like a severity or verdict colour to people with red-green colour blindness.
 * To re-skin the app, change the palette tokens at the top of index.css and run this file.
 */

type Tokens = ReadonlyMap<string, string>;
type Theme = "light" | "dark";

// Vitest blanks CSS imports, so the stylesheet is read from disk. `import.meta.url` is bound to a
// variable first for the same reason as in indexHtml.test.ts.
const moduleUrl = import.meta.url;
const css = readFileSync(new URL("../index.css", moduleUrl), "utf8");
const source = css.replace(/\/\*[\s\S]*?\*\//g, "");

function declarations(selector: string): Map<string, string> {
  const out = new Map<string, string>();
  const escaped = selector.replace(/[.]/g, "\\.");
  const block = new RegExp(`(?:^|\\n)${escaped}\\s*\\{([^}]*)\\}`, "g");
  for (const match of source.matchAll(block)) {
    for (const decl of match[1].matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) {
      out.set(decl[1], decl[2].trim());
    }
  }
  return out;
}

const root = declarations(":root");
const dark = declarations(".dark");
const themes: Record<Theme, Tokens> = {
  light: root,
  dark: new Map([...root, ...dark]),
};

function resolve(tokens: Tokens, name: string): string {
  const raw = tokens.get(name);
  if (raw === undefined) throw new Error(`Token ${name} is not declared`);
  return raw.replace(/var\((--[\w-]+)\)/g, (_, ref: string) => resolve(tokens, ref));
}

const colour = (theme: Theme, name: string): LinearRgb => parseColour(resolve(themes[theme], name));

const AA_TEXT = 4.5;
const AA_UI = 3;

/** [text, surface] pairs that carry readable text. */
const TEXT_PAIRS: ReadonlyArray<readonly [string, string]> = [
  ["--foreground", "--background"],
  ["--foreground", "--card"],
  ["--card-foreground", "--card"],
  ["--popover-foreground", "--popover"],
  ["--muted-foreground", "--background"],
  ["--muted-foreground", "--card"],
  ["--muted-foreground", "--muted"],
  ["--primary-foreground", "--primary"],
  ["--secondary-foreground", "--secondary"],
  ["--accent-foreground", "--accent"],
  // Links and accent text sit on the page, on cards and on tinted surfaces.
  ["--action", "--background"],
  ["--action", "--card"],
  ["--action", "--muted"],
  // The pairing rule: a severity -fg is calibrated only against its own -bg.
  ["--sev-critical-fg", "--sev-critical-bg"],
  ["--sev-high-fg", "--sev-high-bg"],
  ["--sev-medium-fg", "--sev-medium-bg"],
  ["--sev-low-fg", "--sev-low-bg"],
  ["--sev-success-fg", "--sev-success-bg"],
  ["--verdict-block-fg", "--verdict-block"],
  ["--verdict-pass-fg", "--verdict-pass"],
  ["--verdict-indeterminate-fg", "--verdict-indeterminate"],
  ["--sev-none-fg", "--background"],
];

/** Non-text parts that must still be visible: the focus ring is drawn with --action. */
const UI_PAIRS: ReadonlyArray<readonly [string, string]> = [
  ["--action", "--background"],
  ["--action", "--card"],
  ["--ring", "--background"],
];

describe.each(["light", "dark"] as const)("design tokens: %s theme", (theme) => {
  it.each(TEXT_PAIRS)("%s on %s reaches 4.5:1", (text, surface) => {
    expect(contrastRatio(colour(theme, text), colour(theme, surface))).toBeGreaterThanOrEqual(
      AA_TEXT,
    );
  });

  it.each(UI_PAIRS)("%s against %s reaches 3:1", (part, surface) => {
    expect(contrastRatio(colour(theme, part), colour(theme, surface))).toBeGreaterThanOrEqual(
      AA_UI,
    );
  });
});

/**
 * The accent is ink, so it carries no hue of its own. That keeps colour free to mean something
 * (severity and verdict) but means the accent can only be told apart from them by lightness and
 * by how coloured they are. Two things are checked: the accent stays neutral, and every colour that
 * already means something stays clearly different from it, overall and for people with red-green
 * colour blindness (who lose hue, so lightness has to hold up).
 */
const MEANING_COLOURS = [
  "--sev-critical-fg",
  "--sev-high-fg",
  "--sev-medium-fg",
  "--sev-low-fg",
  "--sev-success-fg",
  "--verdict-block",
  "--verdict-pass",
  // Grey means "no severity". It differs from ink by lightness.
  "--sev-none-fg",
] as const;
// --verdict-indeterminate is left out on purpose: an unknown or in-progress verdict is drawn in
// ink, the same family as the accent, and is told apart by its outline and its words.

const ACCENTS = ["--primary", "--action"] as const;
const VISIONS: readonly Vision[] = ["normal", "protanopia", "deuteranopia"];

/** An ink or chalk accent measures about 1 here; anything above this has become a colour. */
const MAX_ACCENT_CHROMA = 3;
/**
 * OKLab distance times 100. Under 10 two colours are hard to tell apart side by side. The closest pair
 * is chalk against the light green of a passing verdict under protanopia, at about 13; the rest are
 * above 20.
 */
const MIN_PERCEPTUAL_DISTANCE = 12;

describe.each(["light", "dark"] as const)("accent colour safety: %s theme", (theme) => {
  it.each(ACCENTS)("%s stays neutral", (accent) => {
    expect(chroma(colour(theme, accent))).toBeLessThanOrEqual(MAX_ACCENT_CHROMA);
  });

  const cases = ACCENTS.flatMap((accent) =>
    MEANING_COLOURS.flatMap((meaning) =>
      VISIONS.map((vision) => [accent, meaning, vision] as const)
    )
  );

  it.each(cases)("%s stays distinct from %s for %s vision", (accent, meaning, vision) => {
    expect(perceptualDistance(colour(theme, accent), colour(theme, meaning), vision))
      .toBeGreaterThanOrEqual(MIN_PERCEPTUAL_DISTANCE);
  });
});
