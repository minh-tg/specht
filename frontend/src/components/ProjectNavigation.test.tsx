import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { ProjectNavigation } from "./ProjectNavigation";

function Location() {
  return <p data-testid="location">{useLocation().pathname}</p>;
}

function renderNavigation(currentTab = "findings", isAdmin = false) {
  return render(
    <MemoryRouter initialEntries={[`/alpha/${currentTab}`]}>
      <ProjectNavigation slug="alpha" currentTab={currentTab} isAdmin={isAdmin} />
      <Location />
    </MemoryRouter>,
  );
}

describe("project navigation", () => {
  it("keeps daily work visible and configuration out of the tab row", () => {
    renderNavigation();
    const nav = screen.getByRole("navigation", { name: "Project sections" });
    expect(within(nav).getAllByRole("link").map((link) => link.textContent)).toEqual([
      "Findings",
      "Reports",
      "Waivers",
      "Insights",
    ]);
    expect(screen.getByRole("link", { name: "Findings" })).toHaveAttribute("aria-current", "page");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("retains member access to policy, watcher and membership pages", async () => {
    renderNavigation();
    await userEvent.setup().click(screen.getByRole("button", { name: "Configuration" }));
    const menu = await screen.findByRole("menu", { name: "Configuration" });
    for (
      const [name, path] of [["Policy", "policy"], ["Watcher", "watcher"], [
        "Access & Members",
        "access",
      ]]
    ) {
      expect(within(menu).getByRole("menuitem", { name })).toHaveAttribute(
        "href",
        `/alpha/${path}`,
      );
    }
    expect(within(menu).queryByRole("menuitem", { name: "Settings" })).not.toBeInTheDocument();
  });

  it("offers settings to admins and navigates when it is chosen", async () => {
    renderNavigation("findings", true);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Configuration" }));
    await user.click(await screen.findByRole("menuitem", { name: "Settings" }));
    expect(screen.getByTestId("location")).toHaveTextContent("/alpha/settings");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it.each(["policy", "watcher", "access", "settings"])(
    "keeps the active %s page discoverable with the menu closed",
    async (tab) => {
      renderNavigation(tab, true);
      const trigger = screen.getByRole("button", { name: /^Configuration/ });
      expect(trigger).toHaveAttribute("aria-current", "location");
      expect(trigger.textContent).not.toBe("Configuration");
      await userEvent.setup().click(trigger);
      await screen.findByRole("menu");
      const active = screen.getAllByRole("menuitem").filter((item) =>
        item.getAttribute("aria-current") === "page"
      );
      expect(active).toHaveLength(1);
      expect(active[0]).toHaveAttribute("href", `/alpha/${tab}`);
    },
  );

  it("opens by keyboard and restores focus after Escape", async () => {
    renderNavigation();
    const user = userEvent.setup();
    const trigger = screen.getByRole("button", { name: "Configuration" });
    trigger.focus();
    await user.keyboard("{ArrowDown}");
    expect(await screen.findByRole("menu")).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Policy" })).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });
});
