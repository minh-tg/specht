import { AuthProvider } from "@/auth/AuthContext";
import { AuthContext, type AuthContextValue } from "@/auth/context";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { MemoryRouter, Route, Routes } from "react-router-dom";
import { vi } from "vitest";
import { Login } from "./Login";
import { safeRedirect } from "./safeRedirect";

function renderLogin() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AuthProvider>
          <Login />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

let authState: { token: string | null; login: (email: string, password: string) => Promise<void>; };

function authContext(): AuthContextValue {
  return {
    token: authState.token,
    userId: authState.token ? "u1" : null,
    email: authState.token ? "test@test.com" : null,
    login: authState.login,
    logout: () => {},
    loading: false,
  };
}

function renderLoginWithAuth(initialPath = "/login") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialPath]}>
        <AuthContext.Provider value={authContext()}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/" element={<div>Home page</div>} />
            <Route path="/dashboard" element={<div>Dashboard page</div>} />
          </Routes>
        </AuthContext.Provider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("safeRedirect", () => {
  it("returns internal paths unchanged", () => {
    expect(safeRedirect("/dashboard")).toBe("/dashboard");
    expect(safeRedirect("/reports/42?tab=details")).toBe("/reports/42?tab=details");
  });

  it("falls back to / when no redirect is given", () => {
    expect(safeRedirect(null)).toBe("/");
  });

  it("falls back to / for empty and relative-path redirects", () => {
    expect(safeRedirect("")).toBe("/");
    expect(safeRedirect("dashboard")).toBe("/");
  });

  it("blocks protocol-relative external URLs", () => {
    expect(safeRedirect("//evil.example.com")).toBe("/");
    expect(safeRedirect("///evil.example.com")).toBe("/");
  });

  it("blocks absolute external URLs", () => {
    expect(safeRedirect("https://evil.example.com/phish")).toBe("/");
    expect(safeRedirect("http://evil.example.com")).toBe("/");
  });

  it("blocks backslash and encoded-scheme tricks", () => {
    expect(safeRedirect("\\evil.example.com")).toBe("/");
    expect(safeRedirect("/\\evil.example.com")).toBe("/");
    expect(safeRedirect("https:%2F%2Fevil.example.com")).toBe("/");
  });

  it("blocks javascript: and data: URLs", () => {
    expect(safeRedirect("javascript:alert(1)")).toBe("/");
    expect(safeRedirect("data:text/html,<script>alert(1)</script>")).toBe("/");
  });

  it("falls back to / for control-character prefix tricks", () => {
    expect(safeRedirect("\n//evil.example.com")).toBe("/");
    expect(safeRedirect("\t/\\evil.example.com")).toBe("/");
  });
});

describe("Login", () => {
  beforeEach(() => {
    authState = { token: null, login: async () => {} };
    globalThis.fetch = vi.fn();
  });

  it("renders the login form", () => {
    renderLogin();
    expect(screen.getByLabelText("Email")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });

  it("returns an authenticated user to the home page", async () => {
    authState.token = "session-token";
    renderLoginWithAuth();

    expect(await screen.findByText("Home page")).toBeInTheDocument();
  });

  it("shows error on invalid credentials", async () => {
    const res = new Response(
      JSON.stringify({
        error: { code: "invalid_credentials", message: "Invalid email or password" },
      }),
      {
        status: 401,
        headers: { "Content-Type": "application/json" },
      },
    );
    vi.mocked(globalThis.fetch).mockResolvedValue(res);

    renderLogin();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Email"), "bad@test.com");
    await user.type(screen.getByLabelText("Password"), "wrong");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByText("Invalid email or password")).toBeInTheDocument();
    });
  });

  it("shows generic error on network failure", async () => {
    vi.mocked(globalThis.fetch).mockRejectedValue(new Error("Network error"));

    renderLogin();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Email"), "test@test.com");
    await user.type(screen.getByLabelText("Password"), "test");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByText("Login failed. Please try again.")).toBeInTheDocument();
    });
  });

  it("navigates to an internal redirect after login", async () => {
    authState.login = async () => {};
    renderLoginWithAuth("/login?redirect=%2Fdashboard");
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Email"), "test@test.com");
    await user.type(screen.getByLabelText("Password"), "test");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    expect(await screen.findByText("Dashboard page")).toBeInTheDocument();
  });

  it.each([
    "/login?redirect=https%3A%2F%2Fevil.example.com%2Fphish",
    "/login?redirect=%2F%2Fevil.example.com",
  ])(
    "falls back to home when redirect is external (%s)",
    async (path) => {
      authState.login = async () => {};
      renderLoginWithAuth(path);
      const user = userEvent.setup();
      await user.type(screen.getByLabelText("Email"), "test@test.com");
      await user.type(screen.getByLabelText("Password"), "test");
      await user.click(screen.getByRole("button", { name: /sign in/i }));

      expect(await screen.findByText("Home page")).toBeInTheDocument();
    },
  );

  it("links to the SSO entry point next to the password form", async () => {
    authState.login = async () => {};
    renderLoginWithAuth("/login");

    const link = screen.getByRole("link", { name: /sign in with sso/i });
    expect(link).toHaveAttribute("href", "/api/v1/auth/sso/login");
  });

  it("preserves an internal redirect when starting SSO", async () => {
    authState.login = async () => {};
    renderLoginWithAuth("/login?redirect=%2Fdashboard%3Ftab%3Dfindings");

    const link = screen.getByRole("link", { name: /sign in with sso/i });
    expect(link).toHaveAttribute(
      "href",
      "/api/v1/auth/sso/login?redirect=%2Fdashboard%3Ftab%3Dfindings",
    );
  });
});
