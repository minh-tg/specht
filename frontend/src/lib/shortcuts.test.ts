import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  activeShortcutsIn,
  comboLabel,
  displayCombos,
  isSingleKeyCombo,
  keyLabel,
  matchesHelpKey,
  matchesModShortcut,
  matchesPageKey,
  shortcut,
  SHORTCUT_SCOPES,
  SHORTCUTS,
  shortcutsIn,
} from "./shortcuts";
import { resetSingleKeyForTests, setSingleKeyEnabled } from "./singleKeyShortcuts";

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

  it("has a bare printable character outside a scope that owns the focus only for the switchable ?", () => {
    // WCAG 2.1.4: a global single-character key needs the off switch. Only the help key is one.
    for (const s of SHORTCUTS) {
      if (s.scope !== "Everywhere") continue;
      for (const combo of s.combos) {
        const bare = !combo.some((k) => k === "Mod" || k === "Alt");
        expect(bare).toBe(isSingleKeyCombo(combo));
        if (bare) expect(s.id).toBe("help-key");
      }
    }
  });

  it("marks exactly ?, 1 to 3, J, K and X as single-key combinations", () => {
    const single = SHORTCUTS.flatMap((s) => s.combos.filter(isSingleKeyCombo).map((c) => c[0]));
    expect([...new Set(single)].sort()).toEqual(["1", "2", "3", "?", "J", "K", "X"]);
    expect(isSingleKeyCombo(["↓"])).toBe(false);
    expect(isSingleKeyCombo(["Home"])).toBe(false);
    expect(isSingleKeyCombo(["Space"])).toBe(false);
    expect(isSingleKeyCombo(["Mod", "K"])).toBe(false);
  });

  it("drops the single-key combinations and the shortcuts left empty when the switch is off", () => {
    const labels = (id: string) =>
      displayCombos(shortcut(id), false, false).map((c) => comboLabel(c, false));
    expect(labels("grid-next")).toEqual(["↓"]);
    expect(labels("grid-previous")).toEqual(["↑"]);
    expect(labels("grid-select")).toEqual(["Space"]);
    expect(labels("help-key")).toEqual([]);
    expect(labels("help")).toEqual(["Ctrl+/"]);
    const off = activeShortcutsIn("Everywhere", false).map((s) => s.id);
    expect(off).not.toContain("help-key");
    expect(off).toContain("help");
    expect(activeShortcutsIn("Everywhere", true).map((s) => s.id)).toContain("help-key");
  });

  it("formats Alt per platform", () => {
    expect(comboLabel(["Alt", "T"], false)).toBe("Alt+T");
    expect(comboLabel(["Alt", "T"], true)).toBe("⌥T");
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

  it("names Ctrl as well on macOS for the sheet shortcut only", () => {
    const labels = (id: string, mac: boolean) =>
      displayCombos(shortcut(id), mac).map((c) => comboLabel(c, mac));
    expect(labels("help", true)).toEqual(["⌘/", "Ctrl+/"]);
    expect(labels("help", false)).toEqual(["Ctrl+/"]);
    expect(labels("palette", true)).toEqual(["⌘K"]);
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

  it("gates exactly the registry's single-character grid keys on the switch", () => {
    expect(grid).toContain("new Set([\"j\", \"k\", \"x\"])");
    const registered = SHORTCUTS.filter((s) => s.scope === "In a findings list")
      .flatMap((s) => s.combos.filter(isSingleKeyCombo).map((c) => c[0]!.toLowerCase()));
    expect(registered.sort()).toEqual(["j", "k", "x"]);
  });

  it("covers every key the data grid handles", () => {
    const handled = [...grid.matchAll(/case "([^"]+)":/g)].map((m) => m[1]);
    const registered = Object.values(gridKeys).flat();
    for (const k of handled) expect(registered).toContain(k);
  });

  it("lists the finding page keys that the queue and the decision form handle", () => {
    const queue = read("pages/finding-detail/QueueNav.tsx");
    const form = read("pages/finding-detail/DecisionForm.tsx");
    expect(shortcut("queue-next")).toMatchObject({ scope: "On a finding", combos: [["J"]] });
    expect(shortcut("queue-previous")).toMatchObject({ scope: "On a finding", combos: [["K"]] });
    expect(queue).toContain("key === \"j\"");
    expect(queue).toContain("key === \"k\"");
    expect(shortcut("decide-pick").combos).toEqual([["1"], ["2"], ["3"]]);
    expect(form).toContain("/^[1-3]$/");
    for (const source of [queue, form]) expect(source).toContain("matchesPageKey(event)");
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

describe("the bare ? help key", () => {
  beforeEach(() => {
    window.localStorage.clear();
    resetSingleKeyForTests();
  });
  afterEach(() => {
    document.body.innerHTML = "";
  });

  /** Dispatches a keydown at `target` and returns whether the help key matched it. */
  function press(init: KeyboardEventInit & { keyCode?: number; } = {}, target?: Element) {
    let result = false;
    const listener = (e: KeyboardEvent) => {
      result = matchesHelpKey(e);
    };
    document.addEventListener("keydown", listener);
    const event = new KeyboardEvent("keydown", {
      key: "?",
      bubbles: true,
      cancelable: true,
      ...init,
    });
    if (init.keyCode !== undefined) {
      Object.defineProperty(event, "keyCode", { value: init.keyCode });
    }
    (target ?? document.body).dispatchEvent(event);
    document.removeEventListener("keydown", listener);
    return result;
  }

  it("matches a plain ? and one typed with Shift", () => {
    expect(press()).toBe(true);
    expect(press({ shiftKey: true })).toBe(true);
  });

  it("compares event.key, so another key or a physical position never matches", () => {
    expect(press({ key: "/", shiftKey: true, code: "Slash" })).toBe(false);
    expect(press({ key: "h" })).toBe(false);
    expect(press({ key: "/", code: "Slash" })).toBe(false);
  });

  it("does nothing while the switch is off", () => {
    setSingleKeyEnabled(false);
    expect(press()).toBe(false);
  });

  it.each([
    ["IME composition", { isComposing: true }],
    ["keyCode 229", { keyCode: 229 }],
    ["auto-repeat", { repeat: true }],
    ["Ctrl", { ctrlKey: true }],
    ["Meta", { metaKey: true }],
    ["Alt without AltGraph", { altKey: true }],
  ])("ignores a ? with %s", (_name, init) => {
    expect(press(init)).toBe(false);
  });

  it("ignores an event something else already handled", () => {
    let result = true;
    const first = (e: KeyboardEvent) => e.preventDefault();
    const second = (e: KeyboardEvent) => {
      result = matchesHelpKey(e);
    };
    document.addEventListener("keydown", first);
    document.addEventListener("keydown", second);
    document.body.dispatchEvent(
      new KeyboardEvent("keydown", { key: "?", bubbles: true, cancelable: true }),
    );
    document.removeEventListener("keydown", first);
    document.removeEventListener("keydown", second);
    expect(result).toBe(false);
  });

  it("accepts AltGr, which Windows reports as Ctrl+Alt, and still rejects plain Ctrl+Alt", () => {
    expect(press({ ctrlKey: true, altKey: true, modifierAltGraph: true })).toBe(true);
    expect(press({ ctrlKey: true, altKey: true })).toBe(false);
    expect(press({ metaKey: true, modifierAltGraph: true })).toBe(false);
  });

  it.each([
    ["input", "<input />"],
    ["textarea", "<textarea></textarea>"],
    ["select", "<select><option>a</option></select>"],
    ["contenteditable", "<div contenteditable=\"true\"></div>"],
    ["combobox", "<div role=\"combobox\" tabindex=\"0\"></div>"],
    ["textbox", "<div role=\"textbox\" tabindex=\"0\"></div>"],
  ])("ignores a ? typed in a %s", (_name, html) => {
    document.body.innerHTML = `<div id="host">${html}</div>`;
    const field = document.querySelector("#host")!.firstElementChild!;
    expect(press({}, field)).toBe(false);
  });

  it("ignores a ? typed in an element inside a field", () => {
    document.body.innerHTML = "<div role=\"combobox\"><span id=\"inner\">x</span></div>";
    expect(press({}, document.querySelector("#inner")!)).toBe(false);
  });

  it("matches on a button and on contenteditable=false", () => {
    document.body.innerHTML = "<button>b</button><div contenteditable=\"false\" id=\"c\"></div>";
    expect(press({}, document.querySelector("button")!)).toBe(true);
    expect(press({}, document.querySelector("#c")!)).toBe(true);
  });

  it.each(["dialog", "alertdialog", "menu"])("ignores a ? while a %s is open", (role) => {
    document.body.innerHTML = `<div role="${role}"></div><button>b</button>`;
    expect(press({}, document.querySelector("button")!)).toBe(false);
  });
});

describe("the finding page keys", () => {
  beforeEach(() => {
    window.localStorage.clear();
    resetSingleKeyForTests();
  });
  afterEach(() => {
    document.body.innerHTML = "";
  });

  function press(key: string, target: Element, init: KeyboardEventInit = {}) {
    let result = false;
    const listener = (e: KeyboardEvent) => {
      result = matchesPageKey(e);
    };
    document.addEventListener("keydown", listener);
    target.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true, ...init }));
    document.removeEventListener("keydown", listener);
    return result;
  }

  it("works on the page, a button and a picked radio, where typing goes nowhere", () => {
    document.body.innerHTML = "<button>b</button><input type=\"radio\" id=\"r\" />";
    expect(press("j", document.body)).toBe(true);
    expect(press("1", document.querySelector("button")!)).toBe(true);
    expect(press("2", document.querySelector("#r")!)).toBe(true);
  });

  it.each([
    ["text input", "<input id=\"f\" />"],
    ["textarea", "<textarea id=\"f\"></textarea>"],
    ["combobox", "<div role=\"combobox\" tabindex=\"0\" id=\"f\"></div>"],
  ])("ignores a key typed in a %s", (_name, html) => {
    document.body.innerHTML = html;
    expect(press("j", document.querySelector("#f")!)).toBe(false);
  });

  it("ignores keys while a dialog is open, with a modifier, and when single keys are off", () => {
    document.body.innerHTML = "<div role=\"dialog\"></div>";
    expect(press("k", document.body)).toBe(false);
    document.body.innerHTML = "";
    expect(press("k", document.body, { ctrlKey: true })).toBe(false);
    setSingleKeyEnabled(false);
    expect(press("k", document.body)).toBe(false);
  });
});
