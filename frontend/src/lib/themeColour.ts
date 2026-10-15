import type { Theme } from "./theme";

/**
 * The page surface (`--background`) as hex, which is what `<meta name="theme-color">` needs: a
 * meta tag cannot read a CSS variable or an oklch value. themeColour.test.ts pins both values
 * against the tokens in index.css, and public/theme-init.js (a classic script that cannot import)
 * repeats them, which the same test checks.
 */
export const THEME_COLOUR = { light: "#f6f4ef", dark: "#110e0b" } as const;

/**
 * Points the browser chrome at the surface of the active theme. The page ships one meta per
 * colour scheme, each scoped by a media query, so with the choice "system" every meta keeps its
 * own scheme's colour and the browser picks by the operating system. A manual choice can differ
 * from the system, so both metas take the chosen colour; returning to "system" restores them.
 */
export function applyThemeColour(choice: Theme): void {
  const metas = document.querySelectorAll<HTMLMetaElement>("meta[name=\"theme-color\"]");
  for (const meta of metas) {
    const media = meta.getAttribute("media") ?? "";
    const own = media.includes("dark") ? "dark" : media.includes("light") ? "light" : null;
    if (own === null) continue;
    meta.setAttribute("content", THEME_COLOUR[choice === "system" ? own : choice]);
  }
}
