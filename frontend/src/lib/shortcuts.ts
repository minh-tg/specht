import { type KeyboardEvent as ReactKeyboardEvent, useSyncExternalStore } from "react";
import { isSingleKeyEnabled } from "./singleKeyShortcuts";

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
    id: "help-key",
    scope: "Everywhere",
    description: "Show this sheet",
    combos: [["?"]],
  },
  {
    id: "notifications",
    scope: "Everywhere",
    description: "Focus notifications",
    combos: [["Alt", "T"]],
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

/** The shortcuts of one scope that do something now: with `singleKeys` off, a one-character-only key is dropped. */
export function activeShortcutsIn(scope: ShortcutScope, singleKeys: boolean): Shortcut[] {
  return shortcutsIn(scope).filter((s) => singleKeys || s.combos.some((c) => !isSingleKeyCombo(c)));
}

export const isMacPlatform = () =>
  typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform ?? "");

/** One key as it is printed: `Mod` becomes ⌘ or Ctrl, and `Alt` becomes ⌥ on macOS. */
export function keyLabel(key: string, mac: boolean = isMacPlatform()): string {
  if (key === "Mod") return mac ? "⌘" : "Ctrl";
  if (key === "Alt") return mac ? "⌥" : "Alt";
  return key;
}

/** A combination as one string, such as "Ctrl+K" or "⌘K". */
export function comboLabel(combo: readonly string[], mac: boolean = isMacPlatform()): string {
  // A spelled-out Ctrl always reads "Ctrl+/", even where ⌘ is printed without a separator.
  const compact = mac && !combo.includes("Ctrl");
  return combo.map((key) => keyLabel(key, mac)).join(compact ? "" : "+");
}

/** Whether a combination is one printable character, the kind WCAG 2.1.4 lets a person switch off. */
export const isSingleKeyCombo = (combo: readonly string[]): boolean =>
  combo.length === 1 && /^[A-Za-z?]$/.test(combo[0]!);

/**
 * The combinations to print for a shortcut: the primary ones, plus Ctrl on macOS when it is also
 * accepted. With `singleKeys` off the one-character combinations are left out, because they do
 * nothing then.
 */
export function displayCombos(
  item: Shortcut,
  mac: boolean = isMacPlatform(),
  singleKeys: boolean = true,
): readonly (readonly string[])[] {
  const combos = singleKeys ? item.combos : item.combos.filter((c) => !isSingleKeyCombo(c));
  if (!(mac && item.alsoCtrl)) return combos;
  return [...combos, ...combos.map((c) => c.map((k) => k === "Mod" ? "Ctrl" : k))];
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

/** Elements where a typed character belongs to the field, so a bare-key shortcut must not fire. */
const TEXT_TARGET =
  "input, textarea, select, [contenteditable]:not([contenteditable=\"false\"]), [role=\"combobox\"], [role=\"textbox\"]";
/** An open menu or dialog owns the keyboard. */
const OPEN_LAYER = "[role=\"dialog\"], [role=\"alertdialog\"], [role=\"menu\"]";

/**
 * Whether a keydown is a bare modifier-free key press that a one-character shortcut may react to:
 * not mid-composition (keyCode 229 is how some browsers report it), not an auto-repeat, not already
 * handled, and not with Ctrl, Meta or Alt held. AltGr counts as plain, because it types characters
 * such as `?` on some layouts; Windows reports it as Ctrl+Alt, so it is told apart by the
 * `AltGraph` modifier state. Shift is never rejected, since `?` needs it on US and DE layouts.
 */
function isPlainKeyPress(event: KeyboardEvent, allowRepeat: boolean): boolean {
  if (event.isComposing || event.keyCode === 229 || event.defaultPrevented) return false;
  if (event.repeat && !allowRepeat) return false;
  if (event.metaKey) return false;
  if (event.ctrlKey || event.altKey) {
    const altGraph = typeof event.getModifierState === "function"
      && event.getModifierState("AltGraph");
    if (!altGraph) return false;
  }
  return true;
}

/**
 * Whether a keydown is the bare `?` that opens the shortcut sheet: the switch is on, the key press
 * is plain, focus is not in a field, and no menu or dialog is open. Compared by `event.key`, never
 * the physical key, because the keyboard layout decides where `?` is.
 */
export function matchesHelpKey(event: KeyboardEvent): boolean {
  if (event.key !== "?" || !isSingleKeyEnabled()) return false;
  if (!isPlainKeyPress(event, false)) return false;
  const target = event.target;
  if (target instanceof Element && target.closest(TEXT_TARGET)) return false;
  return document.querySelector(OPEN_LAYER) === null;
}

/**
 * Whether a keydown may drive a one-character shortcut inside a component that owns the focus,
 * such as the findings grid. Keys with a modifier or mid-composition never do, so Ctrl+K still
 * reaches the command palette. Holding the key repeats, which is wanted for moving a cursor.
 */
export const isPlainGridKey = (event: ReactKeyboardEvent): boolean =>
  isPlainKeyPress(event.nativeEvent, true);

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
