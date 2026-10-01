import { AuthContext, type AuthContextValue } from "@/auth/context";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Register } from "./Register";

function renderRegister(token: string | null = null) {
  const auth: AuthContextValue = {
    token,
    userId: token ? "user-1" : null,
    email: token ? "user@example.com" : null,
    login: async () => {},
    logout: () => {},
    loading: false,
  };

  return render(
    <AuthContext.Provider value={auth}>
      <MemoryRouter initialEntries={["/register"]}>
        <Routes>
          <Route path="/register" element={<Register />} />
          <Route path="/login" element={<h1>Sign in</h1>} />
          <Route path="/" element={<h1>Projects</h1>} />
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

describe("Register", () => {
  beforeEach(() => {
    globalThis.fetch = vi.fn();
  });

  it("requires a valid email and a password of at least eight characters", async () => {
    renderRegister();
    const user = userEvent.setup();

    await user.type(screen.getByLabelText("Email"), "not-an-email");
    await user.type(screen.getByLabelText("Password"), "1234567");
    await user.click(screen.getByRole("button", { name: "Create account" }));

    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(screen.getByRole("heading", { name: "Create account" })).toBeInTheDocument();
  });

  it("exposes autocomplete hints for new credentials", () => {
    renderRegister();

    expect(screen.getByLabelText("Email")).toHaveAttribute("autocomplete", "email");
    expect(screen.getByLabelText("Password")).toHaveAttribute("autocomplete", "new-password");
  });

  it("creates an account and sends the user to sign in", async () => {
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response("{}", { status: 201, headers: { "Content-Type": "application/json" } }),
    );
    renderRegister();
    const user = userEvent.setup();

    await user.type(screen.getByLabelText("Email"), "new@example.com");
    await user.type(screen.getByLabelText("Password"), "correct-horse-battery");
    await user.click(screen.getByRole("button", { name: "Create account" }));

    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    const [requestURL, request] = vi.mocked(globalThis.fetch).mock.calls[0];
    expect(String(requestURL)).toBe("/api/v1/auth/register");
    expect(request?.method).toBe("POST");
    expect(JSON.parse(String(request?.body))).toEqual({
      email: "new@example.com",
      password: "correct-horse-battery",
    });
  });

  it("shows a useful server error when the email is already registered", async () => {
    vi.mocked(globalThis.fetch).mockResolvedValue(
      new Response(
        JSON.stringify({
          error: { code: "email_taken", message: "An account already uses this email" },
        }),
        { status: 409, headers: { "Content-Type": "application/json" } },
      ),
    );
    renderRegister();
    const user = userEvent.setup();

    await user.type(screen.getByLabelText("Email"), "existing@example.com");
    await user.type(screen.getByLabelText("Password"), "correct-horse-battery");
    await user.click(screen.getByRole("button", { name: "Create account" }));

    expect(await screen.findByText("An account already uses this email")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create account" })).toBeEnabled();
  });

  it("shows a generic error when the registration service is unavailable", async () => {
    vi.mocked(globalThis.fetch).mockRejectedValue(new Error("connection refused"));
    renderRegister();
    const user = userEvent.setup();

    await user.type(screen.getByLabelText("Email"), "new@example.com");
    await user.type(screen.getByLabelText("Password"), "correct-horse-battery");
    await user.click(screen.getByRole("button", { name: "Create account" }));

    expect(await screen.findByText("Registration failed. Please try again.")).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Create account" })).toBeEnabled()
    );
  });

  it("returns an authenticated user to the projects page", async () => {
    renderRegister("session-token");

    expect(await screen.findByRole("heading", { name: "Projects" })).toBeInTheDocument();
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});
