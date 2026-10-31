import { shortcutHelp } from "@/lib/shortcuts";
import { resetSingleKeyForTests, setSingleKeyEnabled } from "@/lib/singleKeyShortcuts";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { KeyboardShortcuts } from "./KeyboardShortcuts";

afterEach(() => {
  shortcutHelp.close();
  window.localStorage.clear();
  resetSingleKeyForTests();
  vi.unstubAllGlobals();
});

function stubPlatform(platform: string) {
  vi.stubGlobal("navigator", { ...navigator, platform });
}

function setup() {
  render(
    <>
      <button type="button">Before</button>
      <input aria-label="Name" />
      <KeyboardShortcuts />
    </>,
  );
  return userEvent.setup();
}

describe("KeyboardShortcuts", () => {
  it("opens with Ctrl+/ from anywhere, including a text field", async () => {
    const user = setup();
    await user.click(screen.getByRole("textbox", { name: "Name" }));
    await user.keyboard("{Control>}/{/Control}");
    expect(await screen.findByRole("dialog", { name: "Keyboard shortcuts" })).toBeInTheDocument();
  });

  it("opens with Meta+/ as well", async () => {
    const user = setup();
    await user.keyboard("{Meta>}/{/Meta}");
    expect(await screen.findByRole("dialog", { name: "Keyboard shortcuts" })).toBeInTheDocument();
  });

  it("opens with Ctrl+/ on a macOS platform", async () => {
    stubPlatform("MacIntel");
    const user = setup();
    await user.keyboard("{Control>}/{/Control}");
    expect(await screen.findByRole("dialog", { name: "Keyboard shortcuts" })).toBeInTheDocument();
  });

  it("opens with Meta+/ on a non-macOS platform", async () => {
    stubPlatform("Linux x86_64");
    const user = setup();
    await user.keyboard("{Meta>}/{/Meta}");
    expect(await screen.findByRole("dialog", { name: "Keyboard shortcuts" })).toBeInTheDocument();
  });

  it("names both combinations on macOS and only Ctrl+/ elsewhere", async () => {
    stubPlatform("MacIntel");
    const user = setup();
    await user.keyboard("{Control>}/{/Control}");
    let dialog = await screen.findByRole("dialog");
    const row = within(dialog).getByText("Show keyboard shortcuts").parentElement!;
    expect(row).toHaveTextContent("⌘/ or Ctrl+/");
    await user.keyboard("{Escape}");

    stubPlatform("Linux x86_64");
    await user.keyboard("{Control>}/{/Control}");
    dialog = await screen.findByRole("dialog");
    const other = within(dialog).getByText("Show keyboard shortcuts").parentElement!;
    expect(other).toHaveTextContent(/^Show keyboard shortcutsCtrl\+\/$/);
  });

  it("opens with a bare ? and ignores a bare /", async () => {
    const user = setup();
    await user.keyboard("/");
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.keyboard("?");
    expect(await screen.findByRole("dialog", { name: "Keyboard shortcuts" })).toBeInTheDocument();
  });

  it("does not open from a ? typed in a text field", async () => {
    const user = setup();
    await user.click(screen.getByRole("textbox", { name: "Name" }));
    await user.keyboard("why?");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("textbox", { name: "Name" })).toHaveValue("why?");
  });

  it("does not open from a ? while the switch is off, but Ctrl+/ still does", async () => {
    setSingleKeyEnabled(false);
    const user = setup();
    await user.keyboard("?");
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.keyboard("{Control>}/{/Control}");
    expect(await screen.findByRole("dialog", { name: "Keyboard shortcuts" })).toBeInTheDocument();
  });

  it("lists ?, J, K, X and 1 to 3 while the switch is on", async () => {
    const user = setup();
    await user.keyboard("?");
    const dialog = await screen.findByRole("dialog");
    for (const name of ["?", "J", "K", "X", "1", "2", "3"]) {
      expect(within(dialog).getAllByText(name, { selector: "kbd" })).not.toHaveLength(0);
    }
    // The finding page keys have their own group, so J and K never read as list keys there.
    const finding = within(dialog).getByRole("region", { name: "On a finding" });
    expect(within(finding).getByText("Next finding in the list you opened it from"))
      .toBeInTheDocument();
    expect(within(finding).getByText("Previous finding in the list you opened it from"))
      .toBeInTheDocument();
    expect(within(finding).getByText("Pick Real issue, Not a problem or Accept for now"))
      .toBeInTheDocument();
    expect(dialog).not.toHaveTextContent("Single-key shortcuts are off");
  });

  it("hides ?, J, K, X and 1 to 3 and says how to turn them on while the switch is off", async () => {
    setSingleKeyEnabled(false);
    const user = setup();
    await user.keyboard("{Control>}/{/Control}");
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).queryByRole("region", { name: "On a finding" })).toBeNull();
    for (const name of ["?", "J", "K", "X", "1", "2", "3"]) {
      expect(within(dialog).queryByText(name, { selector: "kbd" })).toBeNull();
    }
    expect(within(dialog).queryByText("Show this sheet")).toBeNull();
    // The keys that are not characters stay.
    expect(within(dialog).getByText("↓", { selector: "kbd" })).toBeInTheDocument();
    expect(within(dialog).getByText("Space", { selector: "kbd" })).toBeInTheDocument();
    expect(dialog).toHaveTextContent(
      "Single-key shortcuts are off. Turn them on in the account menu.",
    );
  });

  it("does not react to a ? while the sheet is already open", async () => {
    const user = setup();
    await user.keyboard("?");
    await screen.findByRole("dialog");
    await user.keyboard("?");
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("does not open while a key is held down or an IME is composing", async () => {
    setup();
    const held = new KeyboardEvent("keydown", {
      key: "/",
      ctrlKey: true,
      repeat: true,
      bubbles: true,
    });
    const composing = new KeyboardEvent("keydown", {
      key: "/",
      ctrlKey: true,
      isComposing: true,
      bubbles: true,
    });
    document.dispatchEvent(held);
    document.dispatchEvent(composing);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("groups the keys by the scope they work in", async () => {
    const user = setup();
    await user.keyboard("{Control>}/{/Control}");
    const dialog = await screen.findByRole("dialog");
    for (const scope of ["Everywhere", "In a findings list", "In the waivers tabs"]) {
      expect(within(dialog).getByRole("heading", { name: scope })).toBeInTheDocument();
    }
    const findings = within(dialog).getByRole("region", { name: "In a findings list" });
    expect(within(findings).getByText("Next row")).toBeInTheDocument();
    const everywhere = within(dialog).getByRole("region", { name: "Everywhere" });
    expect(within(everywhere).queryByText("Next row")).toBeNull();
    expect(within(everywhere).getByText("Open the command palette")).toBeInTheDocument();
  });

  it("returns focus to where it was when it closes", async () => {
    const user = setup();
    const before = screen.getByRole("button", { name: "Before" });
    before.focus();
    await user.keyboard("{Control>}/{/Control}");
    await screen.findByRole("dialog");
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(before).toHaveFocus();
  });

  it("closes again on a second Ctrl+/", async () => {
    const user = setup();
    await user.keyboard("{Control>}/{/Control}");
    await screen.findByRole("dialog");
    await user.keyboard("{Control>}/{/Control}");
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});
