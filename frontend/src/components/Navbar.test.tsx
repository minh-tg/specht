import { AuthContext, type AuthContextValue } from "@/auth/context";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { Navbar } from "./Navbar";

function renderNavbar(auth: AuthContextValue) {
  return render(
    <AuthContext.Provider value={auth}>
      <MemoryRouter>
        <Navbar />
        <Routes>
          <Route path="/ingest" element={<p>Ingest page</p>} />
          <Route path="/api-keys" element={<p>API keys page</p>} />
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

describe("Navbar", () => {
  it("offers public sign-in and registration links when signed out", () => {
    renderNavbar({
      token: null,
      userId: null,
      email: null,
      login: async () => {},
      logout: () => {},
      loading: false,
    });

    expect(screen.getByRole("link", { name: "Register" })).toHaveAttribute("href", "/register");
    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/login");
    expect(screen.queryByRole("link", { name: "API Keys" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Logout" })).not.toBeInTheDocument();
  });

  it("shows account tools and invokes logout when signed in", async () => {
    const logout = vi.fn();
    renderNavbar({
      token: "session-token",
      userId: "user-1",
      email: "user@example.com",
      login: async () => {},
      logout,
      loading: false,
    });

    expect(screen.getByText("user@example.com")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Ingest" })).toHaveAttribute("href", "/ingest");
    expect(screen.getByRole("link", { name: "API Keys" })).toHaveAttribute("href", "/api-keys");
    await userEvent.setup().click(screen.getByRole("button", { name: "Logout" }));
    expect(logout).toHaveBeenCalledOnce();
  });
});
