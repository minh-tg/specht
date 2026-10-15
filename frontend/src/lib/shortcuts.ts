import { useSyncExternalStore } from "react";

/** Where a shortcut works. The help sheet groups by this so a scoped key never reads as global. */
export const SHORTCUT_SCOPES = ["Everywhere", "In a findings list", "In the waivers tabs"] as const;
export type ShortcutScope = typeof SHORTCUT_SCOPES[number];

export interface Shortcut {
  readonly id: string;
  readonly scope: ShortcutScope;
  readonly description: string;
  /** Alternative key combinations that do the same thing. `Mod` is Ctrl, or ⌘ on macOS. */
  readonly combos: readonly (readonly string[])[];
  /**
   * The key is also accepted with Ctrl on macOS, where the sheet names both. Safari binds ⌘/ to a
   * menu item that can win over the page, so Ctrl+/ stays a working way in.
   */
  readonly alsoCtrl?: boolean;
}

/**
 * Every keyboard shortcut the app has. The command palette and the help sheet both read this list,
 * and a test checks the grid and tab keys against the code that handles them, so the sheet cannot
 * describe a key that does nothing.
 */
export const SHORTCUTS: readonly Shortcut[] = [
  {
    id: "palette",
    scope: "Everywhere",
    description: "Open the command palette",
    combos: [["Mod", "K"]],
  },
  {
    id: "help",
    scope: "Everywhere",
    description: "Show keyboard shortcuts",
    combos: [["Mod", "/"]],
    alsoCtrl: true,
  },
  {
    id: "grid-next",
    scope: "In a findings list",
    description: "Next row",
    combos: [["J"], ["↓"]],
  },
  {
    id: "grid-previous",
    scope: "In a findings list",
    description: "Previous row",
    combos: [["K"], ["↑"]],
  },
  {
    id: "grid-select",
    scope: "In a findings list",
    description: "Select the row",
    combos: [["X"], ["Space"]],
  },
  {
    id: "grid-open",
    scope: "In a findings list",
    description: "Open the row",
    combos: [["Enter"]],
  },
  { id: "grid-first", scope: "In a findings list", description: "First row", combos: [["Home"]] },
  { id: "grid-last", scope: "In a findings list", description: "Last row", combos: [["End"]] },
  {
    id: "waiver-tabs",
    scope: "In the waivers tabs",
    description: "Move between the tabs",
    combos: [["←"], ["→"]],
  },
];

export function shortcut(id: string): Shortcut {
  const found = SHORTCUTS.find((s) => s.id === id);
  if (!found) throw new Error(`unknown shortcut ${id}`);
  return found;
}

/** The shortcuts of one scope, in registry order. */
export function shortcutsIn(scope: ShortcutScope): Shortcut[] {
  return SHORTCUTS.filter((s) => s.scope === scope);
}

export const isMacPlatform = () =>
  typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform ?? "");

/** One key as it is printed: `Mod` becomes ⌘ or Ctrl. */
export function keyLabel(key: string, mac: boolean = isMacPlatform()): string {
  return key === "Mod" ? (mac ? "⌘" : "Ctrl") : key;
}

/** A combination as one string, such as "Ctrl+K" or "⌘K". */
export function comboLabel(combo: readonly string[], mac: boolean = isMacPlatform()): string {
  // A spelled-out Ctrl always reads "Ctrl+/", even where ⌘ is printed without a separator.
  const compact = mac && !combo.includes("Ctrl");
  return combo.map((key) => keyLabel(key, mac)).join(compact ? "" : "+");
}

/** The combinations to print for a shortcut: the primary ones, plus Ctrl on macOS when it is also accepted. */
export function displayCombos(
  item: Shortcut,
  mac: boolean = isMacPlatform(),
): readonly (readonly string[])[] {
  if (!(mac && item.alsoCtrl)) return item.combos;
  return [...item.combos, ...item.combos.map((c) => c.map((k) => k === "Mod" ? "Ctrl" : k))];
}

/**
 * Whether a keydown is a registered `Mod`+key shortcut. An event that is mid-composition, already
 * handled, or an auto-repeat never matches, and Alt turns it into something else.
 */
export function matchesModShortcut(
  event: Pick<
    KeyboardEvent,
    "key" | "ctrlKey" | "metaKey" | "altKey" | "isComposing" | "defaultPrevented" | "repeat"
  >,
  id: string,
): boolean {
  if (event.isComposing || event.defaultPrevented || event.repeat || event.altKey) return false;
  if (!(event.ctrlKey || event.metaKey)) return false;
  const combo = shortcut(id).combos.find((c) => c[0] === "Mod");
  return combo !== undefined && event.key.toLowerCase() === combo[1]!.toLowerCase();
}

let helpOpen = false;
let helpReturnTo: HTMLElement | null = null;
const listeners = new Set<() => void>();

function setHelpOpen(next: boolean) {
  if (helpOpen === next) return;
  helpOpen = next;
  for (const listener of listeners) listener();
}

/** Opens or closes the shortcut sheet from anywhere, such as a palette command. */
export const shortcutHelp = {
  /** `from` is where focus goes when the sheet closes; it defaults to the focused element. */
  open: (from?: HTMLElement | null) => {
    const active = document.activeElement;
    helpReturnTo = from
      ?? (active instanceof HTMLElement && active !== document.body ? active : null);
    setHelpOpen(true);
  },
  close: () => setHelpOpen(false),
  toggle: () => (helpOpen ? setHelpOpen(false) : shortcutHelp.open()),
};

/** The element to focus when the sheet closes, or null to leave it to the dialog. */
export const helpReturnTarget = () => helpReturnTo?.isConnected ? helpReturnTo : null;

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function useShortcutHelpOpen(): boolean {
  return useSyncExternalStore(subscribe, () => helpOpen, () => false);
}
