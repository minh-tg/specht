import { shortcutHelp } from "@/lib/shortcuts";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { KeyboardShortcuts } from "./KeyboardShortcuts";

afterEach(() => shortcutHelp.close());

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

  it("does not react to a bare ? or /", async () => {
    const user = setup();
    await user.keyboard("?/");
    expect(screen.queryByRole("dialog")).toBeNull();
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
