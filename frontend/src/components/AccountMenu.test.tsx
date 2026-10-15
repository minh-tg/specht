import { resetThemeStore } from "@/lib/theme";
import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AccountMenu } from "./AccountMenu";
import { ThemeToggle } from "./ThemeToggle";

function renderMenu(onLogout = vi.fn()) {
  render(
    <MemoryRouter>
      <ThemeToggle />
      <AccountMenu email="ada@acme.example" onLogout={onLogout} />
    </MemoryRouter>,
  );
  return userEvent.setup();
}

async function openMenu(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: "Account menu, ada@acme.example" }));
  return screen.findByRole("group", { name: "Appearance" });
}

beforeEach(() => {
  resetThemeStore();
  window.localStorage.clear();
  document.documentElement.classList.remove("dark");
});

describe("AccountMenu appearance", () => {
  it("offers System, Light and Dark as radio items in a labelled group", async () => {
    const user = renderMenu();

    const group = await openMenu(user);

    expect(
      within(group).getAllByRole("menuitemradio").map((item) => item.textContent),
    ).toEqual(["System", "Light", "Dark"]);
  });

  it("shows the stored choice as checked, with a mark that does not rely on colour", async () => {
    window.localStorage.setItem("specht.theme", "dark");
    const user = renderMenu();

    const group = await openMenu(user);

    const dark = within(group).getByRole("menuitemradio", { name: "Dark" });
    expect(dark).toHaveAttribute("aria-checked", "true");
    expect(dark.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
    for (const name of ["System", "Light"]) {
      const other = within(group).getByRole("menuitemradio", { name });
      expect(other).toHaveAttribute("aria-checked", "false");
      expect(other.querySelector("svg")).toBeNull();
    }
  });

  it("applies the choice, keeps the menu open and updates the header toggle", async () => {
    const user = renderMenu();
    const group = await openMenu(user);

    await user.click(within(group).getByRole("menuitemradio", { name: "Dark" }));

    expect(document.documentElement).toHaveClass("dark");
    expect(window.localStorage.getItem("specht.theme")).toBe("dark");
    expect(screen.getByRole("menuitemradio", { name: "Dark" })).toHaveAttribute(
      "aria-checked",
      "true",
    );
    expect(screen.getByRole("menuitemradio", { name: "System" })).toHaveAttribute(
      "aria-checked",
      "false",
    );
    expect(screen.getByRole("button", { name: "Theme: dark. Switch to system" }))
      .toBeInTheDocument();
  });

  it("follows the header toggle while the menu is closed", async () => {
    const user = renderMenu();

    await user.click(screen.getByRole("button", { name: /^Theme: system/ }));
    const group = await openMenu(user);

    expect(within(group).getByRole("menuitemradio", { name: "Light" })).toHaveAttribute(
      "aria-checked",
      "true",
    );
  });

  it("follows a change from another tab while it is open", async () => {
    const user = renderMenu();
    const group = await openMenu(user);

    act(() => {
      window.localStorage.setItem("specht.theme", "dark");
      window.dispatchEvent(new StorageEvent("storage", { key: "specht.theme", newValue: "dark" }));
    });

    expect(within(group).getByRole("menuitemradio", { name: "Dark" })).toHaveAttribute(
      "aria-checked",
      "true",
    );
  });

  it("is operable from the keyboard", async () => {
    const user = renderMenu();
    screen.getByRole("button", { name: "Account menu, ada@acme.example" }).focus();
    await user.keyboard("{Enter}");
    await screen.findByRole("group", { name: "Appearance" });

    // Opening from the keyboard highlights Profile; two more steps reach Light.
    await user.keyboard("{ArrowDown}{ArrowDown}{Enter}");

    expect(screen.getByRole("menuitemradio", { name: "Light" })).toHaveAttribute(
      "aria-checked",
      "true",
    );
    expect(window.localStorage.getItem("specht.theme")).toBe("light");
  });

  it("still signs out from the last item", async () => {
    const onLogout = vi.fn();
    const user = renderMenu(onLogout);
    await openMenu(user);

    await user.click(screen.getByRole("menuitem", { name: "Sign out" }));

    expect(onLogout).toHaveBeenCalledOnce();
  });
});
