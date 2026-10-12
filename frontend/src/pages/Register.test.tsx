import { AuthContext, type AuthContextValue } from "@/auth/context";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Register } from "./Register";

const open = {
  registration: { enabled: true },
  sso: { enabled: false },
  setup: { required: false },
  version: "dev",
  commit: "none",
};

/** Answers the capabilities call, and the registration call with whatever the test gives. */
function mockServer(
  register: () => Response | Promise<Response> = () => jsonResponse({}, 201),
  capabilities: unknown = open,
) {
  globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
    if (String(input).endsWith("/api/v1/capabilities")) return jsonResponse(capabilities);
    return register();
  });
}

function registrations() {
  return vi.mocked(globalThis.fetch).mock.calls.filter(
    ([url]) => String(url).endsWith("/api/v1/auth/register"),
  );
}

function renderRegister(token: string | null = null) {
  const auth: AuthContextValue = {
    token,
    userId: token ? "user-1" : null,
    email: token ? "user@example.com" : null,
    login: async () => {},
    logout: () => {},
    adopt: () => {},
    loading: false,
  };

  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={["/register"]}>
          <Routes>
            <Route path="/register" element={<Register />} />
            <Route path="/login" element={<h1>Sign in</h1>} />
            <Route path="/setup" element={<h1>Set up Specht</h1>} />
            <Route path="/" element={<h1>Projects</h1>} />
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

describe("Register", () => {
  beforeEach(() => {
    mockServer();
  });

  it("requires a valid email and a password that meets the rules", async () => {
    renderRegister();
    const user = userEvent.setup();

    await user.type(screen.getByLabelText("Email"), "not-an-email");
    await user.type(screen.getByLabelText("Password"), "1234567");
    await user.click(screen.getByRole("button", { name: "Create account" }));
    expect(registrations()).toHaveLength(0);

    await user.clear(screen.getByLabelText("Email"));
    await user.type(screen.getByLabelText("Email"), "new@example.com");
    await user.click(screen.getByRole("button", { name: "Create account" }));

    expect(registrations()).toHaveLength(0);
    expect(await screen.findByText("Choose a password that meets the requirements."))
      .toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Create account" })).toBeInTheDocument();
  });

  it("shows the password rules only once typing starts", async () => {
    renderRegister();
    const user = userEvent.setup();

    expect(screen.queryByRole("list", { name: "Requirements" })).not.toBeInTheDocument();
    await user.type(screen.getByLabelText("Password"), "a");
    expect(screen.getByRole("list", { name: "Requirements" })).toBeInTheDocument();
  });

  it("exposes autocomplete hints for new credentials", () => {
    renderRegister();

    expect(screen.getByLabelText("Email")).toHaveAttribute("autocomplete", "email");
    expect(screen.getByLabelText("Password")).toHaveAttribute("autocomplete", "new-password");
  });

  it("creates an account and sends the user to sign in", async () => {
    renderRegister();
    const user = userEvent.setup();

    await user.type(screen.getByLabelText("Email"), "new@example.com");
    await user.type(screen.getByLabelText("Password"), "correct-horse-battery");
    await user.click(screen.getByRole("button", { name: "Create account" }));

    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    const [requestURL, request] = registrations()[0];
    expect(String(requestURL)).toBe("/api/v1/auth/register");
    expect(request?.method).toBe("POST");
    expect(JSON.parse(String(request?.body))).toEqual({
      email: "new@example.com",
      password: "correct-horse-battery",
    });
  });

  it("shows a useful server error when the email is already registered", async () => {
    mockServer(() =>
      jsonResponse(
        { error: { code: "email_taken", message: "An account already uses this email" } },
        409,
      )
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
    mockServer(() => {
      throw new Error("connection refused");
    });
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
    expect(registrations()).toHaveLength(0);
  });

  it("sends people to sign in when the server has closed registration", async () => {
    mockServer(undefined, { ...open, registration: { enabled: false } });
    renderRegister();

    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });

  it("sends people to set the server up when it has no account yet", async () => {
    mockServer(undefined, { ...open, setup: { required: true } });
    renderRegister();

    expect(await screen.findByRole("heading", { name: "Set up Specht" })).toBeInTheDocument();
  });
});
