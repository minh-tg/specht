import { AuthContext, type AuthContextValue } from "@/auth/context";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
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
  loading: false,
};

function signedIn(email = "user@example.com"): AuthContextValue {
  return {
    token: "session-token",
    userId: "user-1",
    email,
    login: async () => {},
    logout: () => {},
    loading: false,
  };
}

let meCalls: string[];
let meRole: "admin" | "member";
let meSettled: boolean;
let mePending: boolean;

beforeEach(() => {
  meCalls = [];
  meRole = "admin";
  meSettled = false;
  mePending = false;
  globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/api/v1/me")) {
      meCalls.push(url);
      if (mePending) {
        // Never resolves: keeps the query in its loading state.
        return await new Promise<Response>(() => {});
      }
      return {
        ok: true,
        json: () => {
          meSettled = true;
          return Promise.resolve({
            id: "user-1",
            email: "user@example.com",
            role: meRole,
            created_at: "2025-01-01T00:00:00Z",
          });
        },
      } as Response;
    }
    return { ok: true, json: () => Promise.resolve(undefined) } as Response;
  });
});

function renderNavbar(auth: AuthContextValue, path = "/") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
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
  );
}

describe("Navbar", () => {
  it("offers public sign-in and registration links when signed out", () => {
    renderNavbar(signedOut);

    expect(screen.getByRole("link", { name: "Register" })).toHaveAttribute("href", "/register");
    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/login");
    expect(screen.queryByRole("link", { name: "API Keys" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Logout" })).not.toBeInTheDocument();
  });

  it("does not request the account profile for signed-out visitors", () => {
    renderNavbar(signedOut);

    expect(meCalls).toHaveLength(0);
  });

  it("shows account tools, hides Ingest, and invokes logout when signed in", async () => {
    const logout = vi.fn();
    renderNavbar({ ...signedIn(), logout });

    expect(screen.queryByRole("link", { name: "Ingest" })).not.toBeInTheDocument();
    expect(screen.getByText("user@example.com")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByRole("link", { name: "API Keys" })).toHaveAttribute("href", "/api-keys");
    });

    const logoutButton = screen.getByRole("button", { name: "Logout" });
    expect(logoutButton).toHaveAttribute("type", "button");
    await userEvent.setup().click(logoutButton);
    expect(logout).toHaveBeenCalledOnce();
  });

  it("hides API Keys from members", async () => {
    meRole = "member";
    renderNavbar(signedIn());

    await waitFor(() => expect(meSettled).toBe(true));
    expect(screen.queryByRole("link", { name: "API Keys" })).not.toBeInTheDocument();
  });

  it("hides API Keys while the profile is loading", async () => {
    mePending = true;
    renderNavbar(signedIn());

    await waitFor(() => expect(meCalls).toHaveLength(1));
    expect(screen.queryByRole("link", { name: "API Keys" })).not.toBeInTheDocument();
  });

  it("truncates and titles the signed-in email", async () => {
    renderNavbar(signedIn("a-very-long-address@example.com"));

    const email = screen.getByText("a-very-long-address@example.com");
    expect(email).toHaveAttribute("title", "a-very-long-address@example.com");
    expect(email).toHaveClass("truncate", "max-w-[10rem]", "hidden", "sm:inline");
  });

  it("marks the active link with aria-current", () => {
    renderNavbar(signedOut, "/register");

    expect(screen.getByRole("link", { name: "Register" })).toHaveAttribute(
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
