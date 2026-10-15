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
