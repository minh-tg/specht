import { queryKeys } from "@/api/hooks";
import { AuthContext, type AuthContextValue } from "@/auth/context";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
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

  it("shows account tools, hides Ingest, and invokes logout when signed in", async () => {
    const logout = vi.fn();
    renderNavbar({ ...signedIn(), logout });

    expect(screen.queryByRole("link", { name: "Ingest" })).not.toBeInTheDocument();
    expect(screen.getByText("user@example.com")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByRole("link", { name: "API keys" })).toHaveAttribute("href", "/api-keys");
    });
    expect(capabilitiesCalls).toHaveLength(0);
    expect(await screen.findByRole("link", { name: "Admin" })).toHaveAttribute("href", "/admin");

    const logoutButton = screen.getByRole("button", { name: "Sign out" });
    expect(logoutButton).toHaveAttribute("type", "button");
    await userEvent.setup().click(logoutButton);
    expect(logout).toHaveBeenCalledOnce();
  });

  it("links to the profile page for every signed-in person, members included", async () => {
    meRole = "member";
    renderNavbar(signedIn());

    expect(screen.getByRole("link", { name: "Profile" })).toHaveAttribute("href", "/profile");
    await waitFor(() => expect(meSettled).toBe(true));
    expect(screen.getByRole("link", { name: "Profile" })).toBeInTheDocument();
  });

  it("does not offer the profile page to a signed-out visitor", () => {
    renderNavbar(signedOut);
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

  it("truncates and titles the signed-in email", async () => {
    renderNavbar(signedIn("a-very-long-address@example.com"));

    const email = screen.getByText("a-very-long-address@example.com");
    expect(email).toHaveAttribute("title", "a-very-long-address@example.com");
    expect(email).toHaveClass("truncate", "max-w-[10rem]", "hidden", "sm:inline");
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
