import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type LinearRgb, parseColour } from "./colour";
import { applyTheme } from "./theme";
import { applyThemeColour, THEME_COLOUR } from "./themeColour";

const moduleUrl = import.meta.url;
const css = readFileSync(new URL("../index.css", moduleUrl), "utf8").replace(
  /\/\*[\s\S]*?\*\//g,
  "",
);
const themeInit = readFileSync(new URL("../../public/theme-init.js", moduleUrl), "utf8");

/** The `--background` declared by the first block that opens with `selector` at the line start. */
function backgroundToken(selector: string): string {
  const block = new RegExp(`(?:^|\\n)${selector.replace(".", "\\.")}\\s*\\{([^}]*)\\}`);
  const value = /--background\s*:\s*([^;]+);/.exec(block.exec(css)?.[1] ?? "")?.[1];
  if (!value) throw new Error(`${selector} declares no --background`);
  return value.trim();
}

/** The 8-bit sRGB hex a browser paints for a linear colour. */
function toHex(rgb: LinearRgb): string {
  const channel = (v: number) => {
    const c = Math.min(1, Math.max(0, v));
    const encoded = c <= 0.0031308 ? 12.92 * c : 1.055 * c ** (1 / 2.4) - 0.055;
    return Math.round(encoded * 255).toString(16).padStart(2, "0");
  };
  return `#${rgb.map(channel).join("")}`;
}

describe("theme-color values", () => {
  it("equal the --background token of each theme", () => {
    expect(THEME_COLOUR.light).toBe(toHex(parseColour(backgroundToken(":root"))));
    expect(THEME_COLOUR.dark).toBe(toHex(parseColour(backgroundToken(".dark"))));
  });

  it("are repeated by the pre-paint script", () => {
    expect(themeInit).toContain(`"${THEME_COLOUR.light}"`);
    expect(themeInit).toContain(`"${THEME_COLOUR.dark}"`);
  });
});

function addMetas(): HTMLMetaElement[] {
  return [
    ["(prefers-color-scheme: light)", THEME_COLOUR.light],
    ["(prefers-color-scheme: dark)", THEME_COLOUR.dark],
  ].map(([media, content]) => {
    const meta = document.createElement("meta");
    meta.name = "theme-color";
    meta.setAttribute("media", media);
    meta.setAttribute("content", content);
    document.head.append(meta);
    return meta;
  });
}

const contents = (metas: HTMLMetaElement[]) => metas.map((m) => m.getAttribute("content"));

describe("applyThemeColour", () => {
  let metas: HTMLMetaElement[];

  beforeEach(() => {
    metas = addMetas();
  });

  afterEach(() => {
    for (const meta of metas) meta.remove();
  });

  it("leaves each meta on its own scheme's colour for the system choice", () => {
    applyThemeColour("system");

    expect(contents(metas)).toEqual([THEME_COLOUR.light, THEME_COLOUR.dark]);
  });

  it("points both metas at the chosen theme, whatever the operating system prefers", () => {
    applyThemeColour("dark");
    expect(contents(metas)).toEqual([THEME_COLOUR.dark, THEME_COLOUR.dark]);

    applyThemeColour("light");
    expect(contents(metas)).toEqual([THEME_COLOUR.light, THEME_COLOUR.light]);
  });

  it("restores the media-scoped values when the choice returns to system", () => {
    applyThemeColour("dark");

    applyThemeColour("system");

    expect(contents(metas)).toEqual([THEME_COLOUR.light, THEME_COLOUR.dark]);
  });

  it("runs whenever the theme is applied to the page", () => {
    applyTheme("dark");

    expect(contents(metas)).toEqual([THEME_COLOUR.dark, THEME_COLOUR.dark]);
  });

  it("ignores a theme-color meta that has no media query", () => {
    const plain = document.createElement("meta");
    plain.name = "theme-color";
    plain.setAttribute("content", "#123456");
    document.head.append(plain);

    applyThemeColour("dark");

    expect(plain.getAttribute("content")).toBe("#123456");
    plain.remove();
  });

  it("does nothing on a page without the metas", () => {
    for (const meta of metas) meta.remove();

    expect(() => applyThemeColour("dark")).not.toThrow();
  });
});

describe("the pre-paint script", () => {
  let metas: HTMLMetaElement[];

  beforeEach(() => {
    metas = addMetas();
    window.localStorage.clear();
  });

  afterEach(() => {
    for (const meta of metas) meta.remove();
    document.documentElement.classList.remove("dark");
    document.documentElement.style.colorScheme = "";
  });

  const run = () => new Function(themeInit)();

  it("sets both metas for a stored manual choice", () => {
    window.localStorage.setItem("specht.theme", "dark");

    run();

    expect(contents(metas)).toEqual([THEME_COLOUR.dark, THEME_COLOUR.dark]);
    window.localStorage.setItem("specht.theme", "light");
    run();
    expect(contents(metas)).toEqual([THEME_COLOUR.light, THEME_COLOUR.light]);
  });

  it("leaves the shipped values alone for the system choice", () => {
    run();

    expect(contents(metas)).toEqual([THEME_COLOUR.light, THEME_COLOUR.dark]);
  });
});
