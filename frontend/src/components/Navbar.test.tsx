import { queryKeys } from "@/api/hooks";
import { AuthContext, type AuthContextValue } from "@/auth/context";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Navbar } from "./Navbar";

const signedOut: AuthContextValue = {
  token: null,
  userId: null,
  email: null,
  login: async () => {},
  logout: () => {},
  adopt: () => {},
  loading: false,
};

function signedIn(email = "user@example.com"): AuthContextValue {
  return {
    token: "session-token",
    userId: "user-1",
    email,
    login: async () => {},
    logout: () => {},
    adopt: () => {},
    loading: false,
  };
}

let meCalls: string[];
let meRole: "admin" | "member";
let meSettled: boolean;
let mePending: boolean;
let capabilitiesMode: "open" | "closed" | "pending" | "error";
let capabilitiesCalls: string[];

beforeEach(() => {
  meCalls = [];
  meRole = "admin";
  meSettled = false;
  mePending = false;
  capabilitiesMode = "open";
  capabilitiesCalls = [];
  globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/v1/capabilities")) {
      capabilitiesCalls.push(url);
      if (capabilitiesMode === "pending") {
        // Never resolves: keeps the public capabilities query loading.
        return await new Promise<Response>(() => {});
      }
      if (capabilitiesMode === "error") {
        return jsonResponse({ error: { code: "unavailable", message: "Unavailable" } }, 503);
      }
      return jsonResponse({
        registration: { enabled: capabilitiesMode === "open" },
        sso: { enabled: false },
        setup: { required: false },
        version: "test",
        commit: "none",
      });
    }
    if (url.endsWith("/api/v1/projects")) return jsonResponse([]);
    if (url.includes("/api/v1/me")) {
      meCalls.push(url);
      if (mePending) {
        // Never resolves: keeps the query in its loading state.
        return await new Promise<Response>(() => {});
      }
      meSettled = true;
      return jsonResponse({
        id: "user-1",
        email: "user@example.com",
        role: meRole,
        created_at: "2025-01-01T00:00:00Z",
      });
    }
    return jsonResponse({});
  });
});

function renderNavbar(auth: AuthContextValue, path = "/") {
  const queryClient = createTestQueryClient();
  return {
    queryClient,
    ...render(
      <QueryClientProvider client={queryClient}>
        <AuthContext.Provider value={auth}>
          <MemoryRouter initialEntries={[path]}>
            <Navbar />
            <Routes>
              <Route path="/ingest" element={<p>Ingest page</p>} />
              <Route path="/api-keys" element={<p>API keys page</p>} />
            </Routes>
          </MemoryRouter>
        </AuthContext.Provider>
      </QueryClientProvider>,
    ),
  };
}

describe("Navbar", () => {
  it("offers public registration when capabilities explicitly enable it", async () => {
    renderNavbar(signedOut);

    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/login");
    expect(await screen.findByRole("link", { name: "Register" })).toHaveAttribute(
      "href",
      "/register",
    );
    expect(screen.queryByRole("link", { name: "API keys" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Sign out" })).not.toBeInTheDocument();
  });

  it("hides registration when capabilities disable it", async () => {
    capabilitiesMode = "closed";
    const { queryClient } = renderNavbar(signedOut);

    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/login");
    await waitFor(() => {
      expect(queryClient.getQueryState(queryKeys.capabilities())?.status).toBe("success");
    });
    expect(screen.queryByRole("link", { name: "Register" })).not.toBeInTheDocument();
  });

  it("hides registration while capabilities are loading", () => {
    capabilitiesMode = "pending";
    const { queryClient } = renderNavbar(signedOut);

    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/login");
    expect(queryClient.getQueryState(queryKeys.capabilities())?.fetchStatus).toBe("fetching");
    expect(screen.queryByRole("link", { name: "Register" })).not.toBeInTheDocument();
  });

  it("hides registration when capabilities fail to load", async () => {
    capabilitiesMode = "error";
    const { queryClient } = renderNavbar(signedOut);

    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/login");
    await waitFor(() => {
      expect(queryClient.getQueryState(queryKeys.capabilities())?.status).toBe("error");
    });
    expect(screen.queryByRole("link", { name: "Register" })).not.toBeInTheDocument();
  });

  it("does not request the account profile for signed-out visitors", async () => {
    const { queryClient } = renderNavbar(signedOut);

    await waitFor(() => {
      expect(queryClient.getQueryState(queryKeys.capabilities())?.status).toBe("success");
    });
    expect(meCalls).toHaveLength(0);
  });

  it("shows account tools, hides Ingest, and invokes logout from the account menu", async () => {
    const logout = vi.fn();
    renderNavbar({ ...signedIn(), logout });

    expect(screen.queryByRole("link", { name: "Ingest" })).not.toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByRole("link", { name: "API keys" })).toHaveAttribute("href", "/api-keys");
    });
    expect(capabilitiesCalls).toHaveLength(0);
    expect(await screen.findByRole("link", { name: "Admin" })).toHaveAttribute("href", "/admin");
    expect(screen.queryByRole("button", { name: "Sign out" })).not.toBeInTheDocument();

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Account menu, user@example.com" }));
    await user.click(await screen.findByRole("menuitem", { name: "Sign out" }));
    expect(logout).toHaveBeenCalledOnce();
  });

  it("operates the account menu from the keyboard", async () => {
    const logout = vi.fn();
    renderNavbar({ ...signedIn(), logout });
    const user = userEvent.setup();

    screen.getByRole("button", { name: "Account menu, user@example.com" }).focus();
    await user.keyboard("{Enter}");
    expect(await screen.findByRole("menuitem", { name: "Profile" })).toBeInTheDocument();
    // Sign out is the last item, so End reaches it however many items sit above it.
    await user.keyboard("{End}{Enter}");
    expect(logout).toHaveBeenCalledOnce();
  });

  it("puts Profile in the account menu for every signed-in person, members included", async () => {
    meRole = "member";
    renderNavbar(signedIn());

    await waitFor(() => expect(meSettled).toBe(true));
    expect(screen.queryByRole("link", { name: "Profile" })).not.toBeInTheDocument();
    await userEvent.setup().click(
      screen.getByRole("button", { name: "Account menu, user@example.com" }),
    );
    expect(await screen.findByRole("menuitem", { name: "Profile" })).toHaveAttribute(
      "href",
      "/profile",
    );
  });

  it("does not offer the account menu to a signed-out visitor", () => {
    renderNavbar(signedOut);
    expect(screen.queryByRole("button", { name: /Account menu/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Profile" })).not.toBeInTheDocument();
  });

  it("shows API keys to members, who manage keys for their own projects", async () => {
    meRole = "member";
    renderNavbar(signedIn());

    await waitFor(() => expect(meSettled).toBe(true));
    expect(screen.getByRole("link", { name: "API keys" })).toHaveAttribute("href", "/api-keys");
    expect(screen.queryByRole("link", { name: "Admin" })).not.toBeInTheDocument();
  });

  it("shows API keys while the profile is still loading", async () => {
    mePending = true;
    renderNavbar(signedIn());

    await waitFor(() => expect(meCalls).toHaveLength(1));
    expect(screen.getByRole("link", { name: "API keys" })).toHaveAttribute("href", "/api-keys");
  });

  it("truncates and titles the email, and keeps the trigger named when the text is hidden", () => {
    renderNavbar(signedIn("a-very-long-address@example.com"));

    const trigger = screen.getByRole("button", {
      name: "Account menu, a-very-long-address@example.com",
    });
    const email = screen.getByText("a-very-long-address@example.com");
    expect(trigger).toContainElement(email);
    expect(email).toHaveAttribute("title", "a-very-long-address@example.com");
    expect(email).toHaveClass("truncate", "max-sm:hidden");
  });

  it("ends the row with the account menu, after Teams, API keys and Admin", async () => {
    renderNavbar(signedIn());
    await screen.findByRole("link", { name: "Admin" });

    const nav = screen.getByRole("navigation", { name: "Main" });
    const names = [...nav.querySelectorAll("a, button")].map((el) =>
      el.getAttribute("aria-label") ?? el.textContent
    );

    expect(names).toEqual([
      "Specht",
      expect.stringMatching(/^Theme/),
      "Open command palette",
      "Projects",
      "Teams",
      "API keys",
      "Admin",
      "Account menu, user@example.com",
    ]);
  });

  it("gives primary links the ghost button look and the current page a fill", async () => {
    renderNavbar(signedIn(), "/teams");

    const teams = screen.getByRole("link", { name: "Teams" });
    expect(teams).toHaveAttribute("aria-current", "page");
    expect(teams).toHaveClass("h-8", "px-2.5", "rounded-lg", "bg-muted", "text-foreground");
    const keys = screen.getByRole("link", { name: "API keys" });
    expect(keys).not.toHaveAttribute("aria-current");
    expect(keys).toHaveClass("hover:bg-muted", "text-muted-foreground");
    expect(keys).not.toHaveClass("bg-muted");
  });

  describe("Projects link", () => {
    const projects = () => screen.getByRole("link", { name: "Projects" });

    it("comes first among the primary links and points home", () => {
      renderNavbar(signedIn());

      expect(projects()).toHaveAttribute("href", "/");
      const links = within(screen.getByRole("navigation", { name: "Main" })).getAllByRole("link");
      expect(links.map((link) => link.textContent).slice(0, 3)).toEqual([
        "Specht",
        "Projects",
        "Teams",
      ]);
    });

    it("is the current page, and the only one, on the project list", () => {
      renderNavbar(signedIn(), "/");

      expect(projects()).toHaveAttribute("aria-current", "page");
      expect(projects()).toHaveClass("bg-muted", "text-foreground");
      const nav = screen.getByRole("navigation", { name: "Main" });
      expect(nav.querySelectorAll("[aria-current]")).toHaveLength(1);
    });

    it.each([
      "/projects/new",
      "/payments/findings",
      "/payments/findings/f1",
      "/payments/settings",
      "/payments/changes/abc1234",
    ])("is filled but not the current page on %s", (path) => {
      renderNavbar(signedIn(), path);

      expect(projects()).toHaveAttribute("aria-current", "true");
      expect(projects()).toHaveClass("bg-muted", "text-foreground");
    });

    it.each(["/teams", "/api-keys", "/admin", "/profile", "/no/such/page"])(
      "is not marked on %s",
      (path) => {
        renderNavbar(signedIn(), path);

        expect(projects()).not.toHaveAttribute("aria-current");
        expect(projects()).not.toHaveClass("bg-muted");
        expect(projects()).toHaveClass("text-muted-foreground");
      },
    );

    it("is left out for a signed-out visitor", () => {
      renderNavbar(signedOut);

      expect(screen.queryByRole("link", { name: "Projects" })).not.toBeInTheDocument();
    });

    it("leaves the brand link plain, so it is never the current page", () => {
      renderNavbar(signedIn(), "/");

      expect(screen.getByRole("link", { name: "Specht" })).not.toHaveAttribute("aria-current");
    });
  });

  it("marks the active link with aria-current", async () => {
    renderNavbar(signedOut, "/register");

    expect(await screen.findByRole("link", { name: "Register" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(screen.getByRole("link", { name: "Sign in" })).not.toHaveAttribute("aria-current");
  });

  it("keeps the brand link named Specht and hides the decorative mark", () => {
    renderNavbar(signedOut);

    const brand = screen.getByRole("link", { name: "Specht" });
    expect(brand).toHaveAttribute("href", "/");
    const mark = brand.querySelector("svg");
    expect(mark).not.toBeNull();
    expect(mark).toHaveAttribute("aria-hidden", "true");
  });

  it("offers the theme toggle both signed out and signed in", async () => {
    const { unmount } = renderNavbar(signedOut);
    expect(screen.getByRole("button", { name: /^Theme: / })).toBeInTheDocument();
    unmount();

    renderNavbar(signedIn());
    expect(screen.getByRole("button", { name: /^Theme: / })).toBeInTheDocument();
    await waitFor(() => expect(meCalls).toHaveLength(1));
  });
});
