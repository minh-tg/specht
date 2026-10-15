import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  comboLabel,
  keyLabel,
  matchesModShortcut,
  shortcut,
  SHORTCUT_SCOPES,
  SHORTCUTS,
  shortcutsIn,
} from "./shortcuts";

const SRC = join(import.meta.dirname, "..");
const read = (path: string) => readFileSync(join(SRC, path), "utf8");

const key = (over: Partial<Parameters<typeof matchesModShortcut>[0]> = {}) => ({
  key: "/",
  ctrlKey: true,
  metaKey: false,
  altKey: false,
  isComposing: false,
  defaultPrevented: false,
  repeat: false,
  ...over,
});

describe("shortcut registry", () => {
  it("has unique ids and puts every shortcut in a known scope", () => {
    expect(new Set(SHORTCUTS.map((s) => s.id)).size).toBe(SHORTCUTS.length);
    for (const s of SHORTCUTS) expect(SHORTCUT_SCOPES).toContain(s.scope);
    for (const scope of SHORTCUT_SCOPES) expect(shortcutsIn(scope).length).toBeGreaterThan(0);
  });

  it("has no bare printable character outside a scope that owns the focus", () => {
    // WCAG 2.1.4: a single-character key must be scoped to a focused component.
    for (const s of SHORTCUTS) {
      if (s.scope !== "Everywhere") continue;
      for (const combo of s.combos) expect(combo).toContain("Mod");
    }
  });

  it("formats Mod per platform", () => {
    expect(keyLabel("Mod", false)).toBe("Ctrl");
    expect(keyLabel("Mod", true)).toBe("⌘");
    expect(comboLabel(["Mod", "K"], false)).toBe("Ctrl+K");
    expect(comboLabel(["Mod", "K"], true)).toBe("⌘K");
  });

  it("matches Ctrl or Meta plus the registered key", () => {
    expect(matchesModShortcut(key(), "help")).toBe(true);
    expect(matchesModShortcut(key({ ctrlKey: false, metaKey: true }), "help")).toBe(true);
    expect(matchesModShortcut(key({ key: "k" }), "palette")).toBe(true);
    expect(matchesModShortcut(key({ key: "K" }), "palette")).toBe(true);
  });

  it.each([
    ["no modifier", { ctrlKey: false }],
    ["Alt held", { altKey: true }],
    ["IME composition", { isComposing: true }],
    ["already handled", { defaultPrevented: true }],
    ["auto-repeat", { repeat: true }],
    ["another key", { key: "j" }],
  ])("ignores the event with %s", (_name, over) => {
    expect(matchesModShortcut(key(over), "help")).toBe(false);
  });
});

describe("shortcut registry against the code that handles the keys", () => {
  const grid = read("components/ui/data-grid.tsx");
  const waivers = read("pages/ProjectWaivers.tsx");

  const gridKeys: Record<string, string[]> = {
    "grid-next": ["j", "ArrowDown"],
    "grid-previous": ["k", "ArrowUp"],
    "grid-select": ["x", " "],
    "grid-open": ["Enter"],
    "grid-first": ["Home"],
    "grid-last": ["End"],
  };

  it.each(Object.entries(gridKeys))("%s is handled by the data grid", (id, keys) => {
    expect(shortcut(id).scope).toBe("In a findings list");
    for (const k of keys) expect(grid).toContain(`case "${k}":`);
  });

  it("covers every key the data grid handles", () => {
    const handled = [...grid.matchAll(/case "([^"]+)":/g)].map((m) => m[1]);
    const registered = Object.values(gridKeys).flat();
    for (const k of handled) expect(registered).toContain(k);
  });

  it("lists the waiver tab arrows that the tab list handles", () => {
    expect(waivers).toContain("\"ArrowRight\"");
    expect(waivers).toContain("\"ArrowLeft\"");
    expect(shortcut("waiver-tabs").combos).toEqual([["←"], ["→"]]);
  });

  it("reads the palette shortcut key from the registry", () => {
    expect(read("components/CommandPalette.tsx")).toContain(
      "matchesModShortcut(event, \"palette\")",
    );
    expect(read("components/KeyboardShortcuts.tsx")).toContain(
      "matchesModShortcut(event, \"help\")",
    );
  });
});
