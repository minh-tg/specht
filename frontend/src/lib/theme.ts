import { useSyncExternalStore } from "react";
import { applyThemeColour } from "./themeColour";

export type Theme = "system" | "light" | "dark";

export const THEME_STORAGE_KEY = "specht.theme";

const THEMES: readonly Theme[] = ["system", "light", "dark"];
const DARK_QUERY = "(prefers-color-scheme: dark)";
const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";

export function isTheme(value: unknown): value is Theme {
  return typeof value === "string" && (THEMES as readonly string[]).includes(value);
}

/** The choice made while storage was blocked; it only lasts for this page view. */
let unsavedTheme: Theme | null = null;

/**
 * The current choice: the one that could not be saved, else the stored one; "system" when nothing
 * valid is stored or storage is unavailable. Reads storage every time, so it is a stable snapshot
 * for `useSyncExternalStore` and never holds state of its own beyond the unsaved choice.
 */
export function readStoredTheme(): Theme {
  if (unsavedTheme !== null) return unsavedTheme;
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
    unsavedTheme = null;
  } catch {
    // Storage can be blocked (private mode, site settings); keep the choice in memory so the
    // toggle and the palette still agree for the rest of this page view.
    unsavedTheme = theme;
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

/** Applies the theme to the document: the `dark` class, the native colour scheme and the browser chrome. */
export function applyTheme(theme: Theme): void {
  const resolved = resolveTheme(theme, systemPrefersDark());
  const root = document.documentElement;
  root.classList.toggle("dark", resolved === "dark");
  root.style.colorScheme = resolved;
  applyThemeColour(theme);
}

const listeners = new Set<() => void>();
let systemQuery: MediaQueryList | null = null;

function notify(): void {
  for (const listener of [...listeners]) listener();
}

function onSystemChange(): void {
  applyTheme("system");
}

/**
 * Keeps exactly one operating-system listener, and only while somebody is subscribed and the
 * choice is "system". An explicit light or dark ignores the system, so nothing listens then.
 */
function syncSystemListener(): void {
  const wanted = listeners.size > 0 && readStoredTheme() === "system"
    && typeof window.matchMedia === "function";
  if (wanted && systemQuery === null) {
    systemQuery = window.matchMedia(DARK_QUERY);
    systemQuery.addEventListener("change", onSystemChange);
  } else if (!wanted && systemQuery !== null) {
    systemQuery.removeEventListener("change", onSystemChange);
    systemQuery = null;
  }
}

/** Another tab changed the stored choice (`key === null` means the storage was cleared). */
function onStorage(event: StorageEvent): void {
  if (event.key !== null && event.key !== THEME_STORAGE_KEY) return;
  if (event.key === null) unsavedTheme = null;
  applyTheme(readStoredTheme());
  syncSystemListener();
  notify();
}

function subscribe(listener: () => void): () => void {
  if (listeners.size === 0) {
    window.addEventListener("storage", onStorage);
    applyTheme(readStoredTheme());
  }
  listeners.add(listener);
  syncSystemListener();
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) window.removeEventListener("storage", onStorage);
    syncSystemListener();
  };
}

/**
 * Runs the visible part of a manual theme change inside a view transition, which cross-fades the
 * page (index.css sets the length and curve). The class switch has to happen synchronously inside
 * the callback, because the browser captures the old and the new page around it. Without view
 * transitions, or when the person asks for reduced motion, the change just happens. The CSS
 * reduced-motion rule does not reach `::view-transition-*`, so the preference is checked here.
 */
function runWithFade(change: () => void): void {
  const reduced = typeof window.matchMedia === "function"
    && window.matchMedia(REDUCED_MOTION_QUERY).matches;
  if (reduced || typeof document.startViewTransition !== "function") {
    change();
    return;
  }
  // `ready` rejects when the browser skips the transition (hidden tab, a newer transition).
  // The callback still runs then, so there is nothing to recover.
  document.startViewTransition(change).ready.catch(() => {});
}

/**
 * Remembers and applies a choice made by the person. The `storage` event does not fire in the tab
 * that wrote the value, so this tab's subscribers are notified here.
 */
export function setTheme(next: Theme): void {
  storeTheme(next);
  runWithFade(() => {
    applyTheme(next);
    syncSystemListener();
    notify();
  });
}

/** Forgets the unsaved choice and every subscription. For tests that share the module. */
export function resetThemeStore(): void {
  unsavedTheme = null;
  listeners.clear();
  window.removeEventListener("storage", onStorage);
  syncSystemListener();
}

/**
 * The user's theme choice, shared by every component that calls it (the header toggle, the account
 * menu, the command palette), so they always agree. It follows other tabs, and while the choice is
 * "system" it follows the operating system.
 */
export function useTheme(): { theme: Theme; setTheme: (theme: Theme) => void; } {
  const theme = useSyncExternalStore(subscribe, readStoredTheme);
  return { theme, setTheme };
}
