import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

/**
 * Source-level guards for the shell rules in index.css that no component test can reach: pseudo
 * elements and media queries are not evaluated by jsdom, so the stylesheet is read from disk.
 */
const moduleUrl = import.meta.url;
const css = readFileSync(new URL("./index.css", moduleUrl), "utf8");

/** The declarations of the first rule whose selector list is exactly `selector`. */
function rule(selector: string): string {
  const start = css.indexOf(`${selector} {`);
  if (start === -1) throw new Error(`No rule for ${selector}`);
  return css.slice(css.indexOf("{", start) + 1, css.indexOf("}", start));
}

describe("theme cross-fade", () => {
  const fade = rule("::view-transition-old(root),\n::view-transition-new(root)");

  it("takes its length and curve from the motion tokens, not the 250ms browser default", () => {
    expect(fade).toContain("animation-duration: var(--dur-quick)");
    expect(fade).toContain("animation-timing-function: var(--ease-entering)");
  });

  it("only fades: nothing in the rule moves or scales the snapshots", () => {
    expect(fade).not.toMatch(/transform|scale|translate/);
  });
});

/** Everything inside the first `@media (query) { ... }` block, with nested braces kept. */
function media(query: string): string {
  const start = css.indexOf(`@media ${query} {`);
  if (start === -1) throw new Error(`No @media ${query}`);
  let depth = 0;
  for (let i = css.indexOf("{", start); i < css.length; i++) {
    if (css[i] === "{") depth++;
    if (css[i] === "}" && --depth === 0) return css.slice(css.indexOf("{", start) + 1, i);
  }
  throw new Error(`Unclosed @media ${query}`);
}

describe("sticky header fallbacks", () => {
  it("goes solid and unblurred when the person asks for reduced transparency", () => {
    const block = media("(prefers-reduced-transparency: reduce)");

    expect(block).toContain(".site-header");
    expect(block).toContain("background-color: var(--background)");
    expect(block).toContain("backdrop-filter: none");
  });

  it("goes to the system canvas without a blur in forced-colors mode", () => {
    const block = media("(forced-colors: active)");

    expect(block).toContain(".site-header");
    expect(block).toContain("background-color: Canvas");
    expect(block).toContain("backdrop-filter: none");
  });

  it("keeps the fallback rules outside every @layer so they beat the translucent utilities", () => {
    // Unlayered rules win over the utilities layer whatever their specificity.
    const bare = css.replace(/\/\*[\s\S]*?\*\//g, "");
    for (const query of ["(prefers-reduced-transparency: reduce)", "(forced-colors: active)"]) {
      const before = bare.slice(0, bare.indexOf(`@media ${query}`));
      const depth = [...before].reduce(
        (open, ch) => open + (ch === "{" ? 1 : ch === "}" ? -1 : 0),
        0,
      );
      expect(depth, `@media ${query} is nested in another block`).toBe(0);
    }
  });
});

describe("scroll padding under the sticky header", () => {
  it("offsets anchors and focus by the measured header height from sm up only", () => {
    const block = media("(min-width: 40rem)");

    expect(block).toMatch(/html\s*\{[^}]*scroll-padding-top:\s*calc\(var\(--header-h, 0px\)/);
  });
});

describe("dark mode colour details", () => {
  it("draws the text selection in ink instead of the browser's blue", () => {
    const selection = rule("::selection");

    expect(selection).toMatch(
      /background-color:\s*color-mix\(in oklab, var\(--foreground\) \d+%, transparent\)/,
    );
    expect(selection).not.toMatch(/#|rgb|hsl|oklch/);
  });

  it("repaints autofilled fields in a token colour so the browser's own fill never shows", () => {
    const autofill = rule(
      "input:-webkit-autofill,\ntextarea:-webkit-autofill,\nselect:-webkit-autofill",
    );

    expect(autofill).toContain("box-shadow: 0 0 0 1000px var(--muted) inset");
    expect(autofill).toContain("-webkit-text-fill-color: var(--foreground)");
    expect(autofill).not.toMatch(/#|rgb|hsl|oklch/);
  });
});
