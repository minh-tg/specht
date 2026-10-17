import { AuthContext, type AuthContextValue } from "@/auth/context";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Setup } from "./Setup";

const fresh = {
  registration: { enabled: true },
  sso: { enabled: false },
  setup: { required: true },
  version: "dev",
  commit: "none",
};

let adopt: ReturnType<typeof vi.fn>;
let setupAnswer: () => Response;

function setupCalls() {
  return vi.mocked(globalThis.fetch).mock.calls.filter(([url]) => String(url) === "/api/v1/setup");
}

function renderSetup(opts: { capabilities?: unknown; token?: string | null; } = {}) {
  globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
    if (String(input).endsWith("/api/v1/capabilities")) {
      return jsonResponse(opts.capabilities ?? fresh);
    }
    return setupAnswer();
  });
  const auth: AuthContextValue = {
    token: opts.token ?? null,
    userId: null,
    email: null,
    login: async () => {},
    logout: () => {},
    adopt: adopt as unknown as AuthContextValue["adopt"],
    loading: false,
  };
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={["/setup"]}>
          <Routes>
            <Route path="/setup" element={<Setup />} />
            <Route path="/login" element={<h1>Sign in</h1>} />
            <Route path="/" element={<h1>Projects</h1>} />
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

async function fillIn(
  user: ReturnType<typeof userEvent.setup>,
  password = "correct-horse-battery",
) {
  await user.type(await screen.findByLabelText("Setup token"), "  tok-123  ");
  await user.type(screen.getByLabelText("Email"), "ada@acme.example");
  await user.type(screen.getByLabelText(/^Name/), "Ada Okafor");
  await user.type(screen.getByLabelText("Password"), password);
}

describe("Setup", () => {
  beforeEach(() => {
    adopt = vi.fn();
    setupAnswer = () =>
      jsonResponse(
        { token: "t", refresh_token: "r", user_id: "u1", email: "ada@acme.example" },
        201,
      );
  });

  it("sends people to sign in when the server already has an account", async () => {
    renderSetup({ capabilities: { ...fresh, setup: { required: false } } });
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });

  it("sends a signed-in person home", async () => {
    renderSetup({ token: "session" });
    expect(await screen.findByRole("heading", { name: "Projects" })).toBeInTheDocument();
  });

  it("shows no password rules until the first character, then lists the ones not met", async () => {
    renderSetup();
    const user = userEvent.setup();
    const password = await screen.findByLabelText("Password");

    expect(screen.queryByRole("list", { name: "Requirements" })).not.toBeInTheDocument();

    await user.type(password, "abc");
    const rules = screen.getByRole("list", { name: "Requirements" });
    expect(rules).toHaveTextContent("At least 8 characters (not met)");

    await user.type(password, "defgh");
    expect(rules).toHaveTextContent("At least 8 characters (met)");
  });

  it("creates the administrator, signs them in and goes home", async () => {
    renderSetup();
    const user = userEvent.setup();
    await fillIn(user);
    await user.click(screen.getByRole("button", { name: "Create administrator" }));

    expect(await screen.findByRole("heading", { name: "Projects" })).toBeInTheDocument();
    expect(JSON.parse(String(setupCalls()[0][1]?.body))).toEqual({
      token: "tok-123",
      email: "ada@acme.example",
      password: "correct-horse-battery",
      display_name: "Ada Okafor",
    });
    expect(adopt).toHaveBeenCalledWith(
      expect.objectContaining({ token: "t", refresh_token: "r", email: "ada@acme.example" }),
    );
  });

  it("does not send a password that breaks the rules", async () => {
    renderSetup();
    const user = userEvent.setup();
    await fillIn(user, "short");
    await user.click(screen.getByRole("button", { name: "Create administrator" }));

    expect(setupCalls()).toHaveLength(0);
    expect(await screen.findByText("Choose a password that meets the requirements."))
      .toBeInTheDocument();
  });

  it("says when the token is wrong and keeps what was typed", async () => {
    setupAnswer = () =>
      jsonResponse(
        { error: { code: "invalid_setup_token", message: "the setup token is wrong" } },
        403,
      );
    renderSetup();
    const user = userEvent.setup();
    await fillIn(user);
    await user.click(screen.getByRole("button", { name: "Create administrator" }));

    expect(await screen.findByText(/does not match the one this server printed/i))
      .toBeInTheDocument();
    expect(screen.getByLabelText("Setup token")).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByLabelText("Email")).toHaveValue("ada@acme.example");
    expect(adopt).not.toHaveBeenCalled();
  });

  it("sends people to sign in when someone else finished setup first", async () => {
    setupAnswer = () => jsonResponse({ error: { code: "not_found", message: "not found" } }, 404);
    renderSetup();
    const user = userEvent.setup();
    await fillIn(user);
    await user.click(screen.getByRole("button", { name: "Create administrator" }));

    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });

  it.each([
    [
      "password_too_common",
      "This password is on a list of commonly used passwords. Choose another.",
    ],
    ["password_matches_account", "The password must not be your email address or name."],
  ])("shows %s on the password field", async (code, message) => {
    setupAnswer = () => jsonResponse({ error: { code, message } }, 400);
    renderSetup();
    const user = userEvent.setup();
    await fillIn(user);
    await user.click(screen.getByRole("button", { name: "Create administrator" }));

    const password = screen.getByLabelText("Password");
    await waitFor(() => expect(password).toHaveAttribute("aria-invalid", "true"));
    expect(password).toHaveAccessibleDescription(expect.stringContaining(message));
    expect(screen.getByLabelText("Setup token")).not.toHaveAttribute("aria-invalid");
    expect(adopt).not.toHaveBeenCalled();
  });

  it("tells the person to retype an address with hidden characters", async () => {
    setupAnswer = () =>
      jsonResponse(
        { error: { code: "invalid_email_characters", message: "invalid email address" } },
        400,
      );
    renderSetup();
    const user = userEvent.setup();
    await fillIn(user);
    await user.click(screen.getByRole("button", { name: "Create administrator" }));

    expect(
      await screen.findByText("This email has hidden characters. Retype it instead of pasting it."),
    ).toBeInTheDocument();
    expect(adopt).not.toHaveBeenCalled();
  });

  it("shows the server's message for a bad email, and a plain one for anything else", async () => {
    setupAnswer = () =>
      jsonResponse(
        { error: { code: "invalid_credentials", message: "invalid email address" } },
        400,
      );
    renderSetup();
    const user = userEvent.setup();
    await fillIn(user);
    await user.click(screen.getByRole("button", { name: "Create administrator" }));
    expect(await screen.findByText("invalid email address")).toBeInTheDocument();

    setupAnswer = () => jsonResponse({ error: { code: "internal_error", message: "boom" } }, 500);
    await user.click(screen.getByRole("button", { name: "Create administrator" }));
    expect(await screen.findByText("Setup failed. Please try again.")).toBeInTheDocument();
  });
});
