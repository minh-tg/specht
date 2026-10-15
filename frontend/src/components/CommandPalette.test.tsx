import { AuthContext, type AuthContextValue } from "@/auth/context";
import { resetThemeStore } from "@/lib/theme";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CommandPalette } from "./CommandPalette";
import { ThemeToggle } from "./ThemeToggle";

let role: "admin" | "member";
let logout: ReturnType<typeof vi.fn>;

function Where() {
  const { pathname } = useLocation();
  return <output data-testid="where">{pathname}</output>;
}

function renderPalette(at = "/", withToggle = false) {
  const auth: AuthContextValue = {
    token: "t",
    userId: "u1",
    email: "ada@acme.example",
    login: async () => {},
    logout: logout as unknown as AuthContextValue["logout"],
    adopt: () => {},
    loading: false,
  };
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={[at]}>
          {withToggle && <ThemeToggle />}
          <CommandPalette />
          <Routes>
            <Route path="*" element={<Where />} />
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

async function openWithShortcut(user: ReturnType<typeof userEvent.setup>) {
  await user.keyboard("{Control>}k{/Control}");
  return screen.findByRole("combobox", { name: "Search commands" });
}

const labels = () => screen.getAllByRole("option").map((o) => o.textContent);

describe("CommandPalette", () => {
  beforeEach(() => {
    role = "admin";
    logout = vi.fn();
    resetThemeStore();
    window.localStorage.clear();
    globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/v1/me")) return jsonResponse({ id: "u1", email: "a@b.c", role });
      if (url.endsWith("/api/v1/projects")) {
        return jsonResponse([
          { id: "p1", slug: "payments", name: "Payments API" },
          { id: "p2", slug: "billing", name: "Billing" },
        ]);
      }
      if (url.endsWith("/payments/members")) return jsonResponse([]);
      throw new Error(`unexpected request ${url}`);
    });
  });

  it("offers project settings in the project group only to admins", async () => {
    const user = userEvent.setup();
    const { unmount } = renderPalette("/payments/findings");
    await openWithShortcut(user);
    expect(screen.getByRole("option", { name: "Project settings" })).toBeInTheDocument();
    unmount();

    role = "member";
    renderPalette("/payments/findings");
    await openWithShortcut(user);
    await waitFor(() =>
      expect(screen.getByRole("group", { name: "This project" })).toBeInTheDocument()
    );
    expect(screen.queryByRole("option", { name: "Project settings" })).not.toBeInTheDocument();
  });

  it("opens from the keyboard anywhere and closes with Escape", async () => {
    const user = userEvent.setup();
    renderPalette();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    const input = await openWithShortcut(user);
    expect(screen.getByRole("dialog", { name: "Command palette" })).toBeInTheDocument();
    expect(input).toHaveFocus();
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("also opens from its button, and the shortcut toggles it", async () => {
    const user = userEvent.setup();
    renderPalette();
    await user.click(screen.getByRole("button", { name: "Open command palette" }));
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    await user.keyboard("{Control>}k{/Control}");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("offers a project's own pages only while you are inside it", async () => {
    const user = userEvent.setup();
    const { unmount } = renderPalette("/payments/findings");
    await openWithShortcut(user);
    const own = screen.getByRole("group", { name: "This project" });
    expect(within(own).getAllByRole("option").map((o) => o.textContent)).toEqual(
      expect.arrayContaining(["Findings", "Policy", "Watcher"]),
    );
    await waitFor(() =>
      expect(screen.getByRole("group", { name: "Projects" })).toBeInTheDocument()
    );
    expect(within(screen.getByRole("group", { name: "Projects" })).getAllByRole("option"))
      .toHaveLength(1);
    unmount();

    renderPalette("/");
    await openWithShortcut(user);
    expect(screen.queryByRole("group", { name: "This project" })).not.toBeInTheDocument();
  });

  it("narrows as you type and goes to the highlighted result with Enter", async () => {
    const user = userEvent.setup();
    renderPalette();
    const input = await openWithShortcut(user);
    await waitFor(() => expect(labels().some((l) => l?.startsWith("Billing"))).toBe(true));
    await user.type(input, "bill");
    expect(labels()).toEqual(["Billingbilling"]);
    expect(screen.getByRole("option")).toHaveAttribute("aria-selected", "true");
    await user.keyboard("{Enter}");
    expect(screen.getByTestId("where")).toHaveTextContent("/billing/findings");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("moves with the arrow keys, wraps round, and tells a screen reader which one is active", async () => {
    const user = userEvent.setup();
    renderPalette();
    const input = await openWithShortcut(user);
    await user.type(input, "t");
    const options = screen.getAllByRole("option");
    expect(options.length).toBeGreaterThan(1);
    expect(input).toHaveAttribute("aria-activedescendant", options[0]!.id);
    await user.keyboard("{ArrowDown}");
    expect(options[1]).toHaveAttribute("aria-selected", "true");
    expect(input).toHaveAttribute("aria-activedescendant", options[1]!.id);
    await user.keyboard("{ArrowUp}{ArrowUp}");
    expect(options.at(-1)).toHaveAttribute("aria-selected", "true");
    await user.keyboard("{Home}");
    expect(options[0]).toHaveAttribute("aria-selected", "true");
  });

  it("goes where a click points", async () => {
    const user = userEvent.setup();
    renderPalette();
    await openWithShortcut(user);
    await user.click(await screen.findByRole("option", { name: "Teams" }));
    expect(screen.getByTestId("where")).toHaveTextContent("/teams");
  });

  it("offers the profile page to everyone, and finds it by what you do there", async () => {
    role = "member";
    const user = userEvent.setup();
    renderPalette();
    const input = await openWithShortcut(user);
    await user.type(input, "password");
    await user.click(await screen.findByRole("option", { name: "Profile" }));
    expect(screen.getByTestId("where")).toHaveTextContent("/profile");
  });

  it("leaves out the places only an admin can use", async () => {
    role = "member";
    const user = userEvent.setup();
    renderPalette();
    await openWithShortcut(user);
    await screen.findByRole("option", { name: "Teams" });
    await waitFor(() =>
      expect(screen.queryByRole("option", { name: "Admin" })).not.toBeInTheDocument()
    );
    expect(screen.queryByRole("option", { name: "New project" })).not.toBeInTheDocument();
  });

  it("offers API keys to a member, who manages keys for their own projects", async () => {
    role = "member";
    const user = userEvent.setup();
    renderPalette();
    await openWithShortcut(user);
    expect(await screen.findByRole("option", { name: "API keys" })).toBeInTheDocument();
  });

  it("shows the admin places to an admin", async () => {
    const user = userEvent.setup();
    renderPalette();
    await openWithShortcut(user);
    expect(await screen.findByRole("option", { name: "Admin" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "API keys" })).toBeInTheDocument();
  });

  it("signs out and switches the theme", async () => {
    const user = userEvent.setup();
    renderPalette();
    let input = await openWithShortcut(user);
    await user.type(input, "dark mode");
    await user.keyboard("{Enter}");
    expect(window.localStorage.getItem("specht.theme")).toBe("light");

    input = await openWithShortcut(user);
    await user.type(input, "logout");
    await user.keyboard("{Enter}");
    expect(logout).toHaveBeenCalledOnce();
  });

  it("changes the theme the header toggle shows, because both read one store", async () => {
    const user = userEvent.setup();
    renderPalette("/", true);
    expect(screen.getByRole("button", { name: "Theme: system. Switch to light" }))
      .toBeInTheDocument();

    const input = await openWithShortcut(user);
    await user.type(input, "dark mode");
    await user.keyboard("{Enter}");

    expect(screen.getByRole("button", { name: "Theme: light. Switch to dark" }))
      .toBeInTheDocument();
  });

  it("says when nothing matches, and keeps the dialog open", async () => {
    const user = userEvent.setup();
    renderPalette();
    const input = await openWithShortcut(user);
    await user.type(input, "zzzzqq");
    expect(await screen.findByRole("status")).toHaveTextContent("Nothing matches “zzzzqq”.");
    await user.keyboard("{Enter}");
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByTestId("where")).toHaveTextContent("/");
  });

  it("starts fresh each time it opens", async () => {
    const user = userEvent.setup();
    renderPalette();
    let input = await openWithShortcut(user);
    await user.type(input, "teams");
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    input = await openWithShortcut(user);
    expect(input).toHaveValue("");
  });

  it("opens the shortcut sheet from the Keyboard shortcuts entry and hands focus back", async () => {
    renderPalette();
    const user = userEvent.setup();
    const opener = screen.getByRole("button", { name: "Open command palette" });
    opener.focus();
    await user.keyboard("{Control>}k{/Control}");
    await user.type(await screen.findByRole("combobox", { name: "Search commands" }), "shortcuts");
    expect(labels()).toEqual(["Keyboard shortcutsCtrl+/"]);
    await user.keyboard("{Enter}");
    expect(await screen.findByRole("dialog", { name: "Keyboard shortcuts" })).toBeInTheDocument();
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(opener).toHaveFocus();
  });
});
