import { resetSingleKeyForTests, SINGLE_KEY_STORAGE_KEY } from "@/lib/singleKeyShortcuts";
import { Menu } from "@base-ui/react/menu";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import { AccountMenu } from "./AccountMenu";
import { SingleKeySetting } from "./SingleKeySetting";

beforeEach(() => {
  window.localStorage.clear();
  resetSingleKeyForTests();
});

function renderOpenMenu() {
  return render(
    <Menu.Root open>
      <Menu.Portal>
        <Menu.Positioner>
          <Menu.Popup>
            <SingleKeySetting />
          </Menu.Popup>
        </Menu.Positioner>
      </Menu.Portal>
    </Menu.Root>,
  );
}

describe("SingleKeySetting", () => {
  it("is checked by default", () => {
    renderOpenMenu();
    expect(screen.getByRole("menuitemcheckbox", { name: "Single-key shortcuts" }))
      .toHaveAttribute("aria-checked", "true");
  });

  it("unchecking stores off and checking again stores on", async () => {
    renderOpenMenu();
    const item = screen.getByRole("menuitemcheckbox", { name: "Single-key shortcuts" });
    await userEvent.click(item);
    expect(window.localStorage.getItem(SINGLE_KEY_STORAGE_KEY)).toBe("off");
    expect(item).toHaveAttribute("aria-checked", "false");
    await userEvent.click(item);
    expect(window.localStorage.getItem(SINGLE_KEY_STORAGE_KEY)).toBe("on");
  });

  it("shows a stored off", () => {
    window.localStorage.setItem(SINGLE_KEY_STORAGE_KEY, "off");
    renderOpenMenu();
    expect(screen.getByRole("menuitemcheckbox", { name: "Single-key shortcuts" }))
      .toHaveAttribute("aria-checked", "false");
  });

  it("is in the account menu", async () => {
    render(
      <MemoryRouter>
        <AccountMenu email="a@example.corp" onLogout={() => {}} />
      </MemoryRouter>,
    );
    await userEvent.click(screen.getByRole("button", { name: /Account menu/ }));
    expect(await screen.findByRole("menuitemcheckbox", { name: "Single-key shortcuts" }))
      .toBeInTheDocument();
  });
});
