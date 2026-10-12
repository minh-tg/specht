import { AuthContext, type AuthContextValue } from "@/auth/context";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Login } from "./Login";

const base = {
  registration: { enabled: true },
  sso: { enabled: true, login_path: "/api/v1/auth/sso/login" },
  setup: { required: false },
  version: "dev",
  commit: "none",
};

function renderLogin(capabilities: unknown) {
  globalThis.fetch = vi.fn().mockImplementation(async () => jsonResponse(capabilities));
  const auth: AuthContextValue = {
    token: null,
    userId: null,
    email: null,
    login: async () => {},
    logout: () => {},
    adopt: () => {},
    loading: false,
  };
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={["/login"]}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/setup" element={<h1>Set up Specht</h1>} />
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

describe("Login and the server's capabilities", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("offers registration and SSO when the server does", async () => {
    renderLogin(base);

    expect(await screen.findByRole("link", { name: "Create an account" })).toHaveAttribute(
      "href",
      "/register",
    );
    expect(screen.getByRole("link", { name: /sign in with sso/i })).toBeInTheDocument();
    expect(screen.queryByText(/registration is closed/i)).not.toBeInTheDocument();
  });

  it("says registration is closed and offers no register link or SSO when neither is available", async () => {
    renderLogin({ ...base, registration: { enabled: false }, sso: { enabled: false } });

    expect(await screen.findByText(/registration is closed on this server/i)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Create an account" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /sign in with sso/i })).not.toBeInTheDocument();
  });

  it("keeps the extras out until the server has answered", () => {
    globalThis.fetch = vi.fn().mockImplementation(() => new Promise(() => {}));
    const { container } = render(
      <QueryClientProvider client={createTestQueryClient()}>
        <AuthContext.Provider
          value={{
            token: null,
            userId: null,
            email: null,
            login: async () => {},
            logout: () => {},
            adopt: () => {},
            loading: false,
          }}
        >
          <MemoryRouter>
            <Login />
          </MemoryRouter>
        </AuthContext.Provider>
      </QueryClientProvider>,
    );

    expect(screen.getByLabelText("Email")).toBeInTheDocument();
    expect(container.querySelector("a[href=\"/register\"]")).toBeNull();
    expect(screen.queryByRole("link", { name: /sign in with sso/i })).not.toBeInTheDocument();
  });

  it("sends everyone to set the server up while it has no account", async () => {
    renderLogin({ ...base, setup: { required: true } });

    expect(await screen.findByRole("heading", { name: "Set up Specht" })).toBeInTheDocument();
  });
});
