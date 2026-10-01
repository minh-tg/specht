import { useCallback, useEffect, useState } from "react";

export type Theme = "system" | "light" | "dark";

export const THEME_STORAGE_KEY = "specht.theme";

const THEMES: readonly Theme[] = ["system", "light", "dark"];
const DARK_QUERY = "(prefers-color-scheme: dark)";

export function isTheme(value: unknown): value is Theme {
  return typeof value === "string" && (THEMES as readonly string[]).includes(value);
}

/** The stored choice; "system" when nothing valid is stored or storage is unavailable. */
export function readStoredTheme(): Theme {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    return isTheme(stored) ? stored : "system";
  } catch {
    return "system";
  }
}

export function storeTheme(theme: Theme): void {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Storage can be blocked (private mode, site settings); the choice then
    // only lasts for this page view.
  }
}

export function resolveTheme(theme: Theme, systemPrefersDark: boolean): "light" | "dark" {
  if (theme === "system") return systemPrefersDark ? "dark" : "light";
  return theme;
}

/** The theme a click moves to: system, then light, then dark, then system again. */
export function nextTheme(theme: Theme): Theme {
  return THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];
}

function systemPrefersDark(): boolean {
  return typeof window.matchMedia === "function" && window.matchMedia(DARK_QUERY).matches;
}

/** Applies the theme to the document: the `dark` class and the native colour scheme. */
export function applyTheme(theme: Theme): void {
  const resolved = resolveTheme(theme, systemPrefersDark());
  const root = document.documentElement;
  root.classList.toggle("dark", resolved === "dark");
  root.style.colorScheme = resolved;
}

/**
 * The user's theme choice. Applies it to the page, remembers it, and while the
 * choice is "system" follows the operating system when it changes.
 */
export function useTheme(): { theme: Theme; setTheme: (theme: Theme) => void; } {
  const [theme, setThemeState] = useState<Theme>(readStoredTheme);

  useEffect(() => {
    applyTheme(theme);
    if (theme !== "system" || typeof window.matchMedia !== "function") return;

    const query = window.matchMedia(DARK_QUERY);
    const onChange = () => applyTheme("system");
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, [theme]);

  const setTheme = useCallback((next: Theme) => {
    storeTheme(next);
    setThemeState(next);
  }, []);

  return { theme, setTheme };
}
