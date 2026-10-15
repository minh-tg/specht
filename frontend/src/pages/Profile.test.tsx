import { AuthContext, type AuthContextValue } from "@/auth/context";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Profile } from "./Profile";

const adopt = vi.fn();
const { check } = vi.hoisted(() => ({
  check: vi.fn(() => ({ score: 3, feedback: { warning: null, suggestions: [] } })),
}));
vi.mock("@/components/PasswordStrengthEngine", () => ({
  loadStrengthEngine: () => Promise.resolve({ check }),
}));

function authValue(): AuthContextValue {
  return {
    token: "test-token",
    userId: "u1",
    email: "ada@acme.corp",
    login: async () => {},
    logout: () => {},
    adopt,
    loading: false,
  };
}

function renderProfile() {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <AuthContext.Provider value={authValue()}>
        <MemoryRouter>
          <Profile />
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

interface Call {
  url: string;
  method: string;
  body?: unknown;
}

describe("Profile", () => {
  let calls: Call[] = [];
  let meFails = false;
  let displayName: string | null = "Ada";
  let passwordReply: () => Response = () =>
    jsonResponse({
      token: "fresh",
      refresh_token: "fresh-refresh",
      user_id: "u1",
      email: "ada@acme.corp",
    });

  beforeEach(() => {
    calls = [];
    meFails = false;
    displayName = "Ada";
    adopt.mockReset();
    check.mockClear();
    passwordReply = () =>
      jsonResponse({
        token: "fresh",
        refresh_token: "fresh-refresh",
        user_id: "u1",
        email: "ada@acme.corp",
      });

    globalThis.fetch = vi.fn().mockImplementation(async (url, opts) => {
      const u = String(url);
      const method = ((opts as RequestInit)?.method ?? "GET").toUpperCase();
      const raw = (opts as RequestInit)?.body as string | undefined;
      calls.push({ url: u, method, body: raw ? JSON.parse(raw) : undefined });

      if (u.endsWith("/api/v1/me/password")) return passwordReply();
      if (u.endsWith("/api/v1/me")) {
        if (method === "PUT") {
          displayName = (JSON.parse(raw ?? "{}") as { display_name: string; }).display_name || null;
        } else if (meFails) {
          return jsonResponse(
            { error: { code: "internal", message: "database unavailable" } },
            500,
          );
        }
        return jsonResponse({
          id: "u1",
          email: "ada@acme.corp",
          display_name: displayName,
          role: "member",
          created_at: "2026-09-01T00:00:00Z",
        });
      }
      return jsonResponse({});
    });
  });

  async function fillPasswords(
    user: ReturnType<typeof userEvent.setup>,
    current: string,
    next: string,
    confirm: string,
  ) {
    await user.type(await screen.findByLabelText("Current password"), current);
    await user.type(screen.getByLabelText("New password"), next);
    await user.type(screen.getByLabelText("Confirm new password"), confirm);
  }

  it("shows who is signed in and keeps the address read-only", async () => {
    renderProfile();

    expect(await screen.findByText("ada@acme.corp")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Your profile" })).toBeInTheDocument();
    expect(screen.getByText("Member")).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: /email/i })).not.toBeInTheDocument();
  });

  it("counts the email, its local part and each word of the name against the new password", async () => {
    displayName = "Ada King Lovelace";
    const user = userEvent.setup();
    renderProfile();

    await user.type(await screen.findByLabelText("New password"), "ada-1815");
    await screen.findByRole("meter");
    expect(check).toHaveBeenLastCalledWith("ada-1815", [
      "ada@acme.corp",
      "ada",
      "Ada",
      "King",
      "Lovelace",
    ]);
  });

  it("saves a new display name and nothing else", async () => {
    const user = userEvent.setup();
    renderProfile();

    const field = await screen.findByLabelText("Display name");
    expect(field).toHaveValue("Ada");
    await user.clear(field);
    await user.type(field, "Ada Okafor");
    await user.click(screen.getByRole("button", { name: "Save name" }));

    await waitFor(() => {
      const put = calls.find((c) => c.url.endsWith("/api/v1/me") && c.method === "PUT");
      expect(put?.body).toEqual({ display_name: "Ada Okafor" });
    });
    expect(calls.some((c) => c.url.endsWith("/api/v1/me/password"))).toBe(false);
  });

  it("does not offer to save a name that has not changed", async () => {
    renderProfile();
    expect(await screen.findByRole("button", { name: "Save name" })).toBeDisabled();
  });

  it("clears the name when the field is emptied", async () => {
    const user = userEvent.setup();
    renderProfile();

    await user.clear(await screen.findByLabelText("Display name"));
    await user.click(screen.getByRole("button", { name: "Save name" }));

    await waitFor(() => {
      const put = calls.find((c) => c.url.endsWith("/api/v1/me") && c.method === "PUT");
      expect(put?.body).toEqual({ display_name: "" });
    });
  });

  it("shows a retry when the profile cannot be loaded", async () => {
    meFails = true;
    const user = userEvent.setup();
    renderProfile();

    expect(await screen.findByText("Could not load your profile.")).toBeInTheDocument();
    meFails = false;
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("heading", { name: "Your profile" })).toBeInTheDocument();
  });

  describe("changing the password", () => {
    const sentPasswords = () => calls.filter((c) => c.url.endsWith("/api/v1/me/password"));

    it("refuses two entries that differ, without asking the server", async () => {
      const user = userEvent.setup();
      renderProfile();

      await fillPasswords(user, "old-password-1", "new-password-1", "new-password-2");
      await user.click(screen.getByRole("button", { name: "Change password" }));

      expect(await screen.findByText("The two passwords do not match.")).toBeInTheDocument();
      expect(sentPasswords()).toHaveLength(0);
    });

    it("refuses a password that breaks the rules", async () => {
      const user = userEvent.setup();
      renderProfile();

      await fillPasswords(user, "old-password-1", "short", "short");
      await user.click(screen.getByRole("button", { name: "Change password" }));

      expect(await screen.findByText("Choose a password that meets the requirements."))
        .toBeInTheDocument();
      expect(sentPasswords()).toHaveLength(0);
    });

    it("refuses the password already in use", async () => {
      const user = userEvent.setup();
      renderProfile();

      await fillPasswords(user, "same-password-1", "same-password-1", "same-password-1");
      await user.click(screen.getByRole("button", { name: "Change password" }));

      expect(await screen.findByText("Choose a password you are not using now."))
        .toBeInTheDocument();
      expect(sentPasswords()).toHaveLength(0);
    });

    it("sends both passwords, keeps the person signed in and clears the form", async () => {
      const user = userEvent.setup();
      renderProfile();

      await fillPasswords(user, "old-password-1", "new-password-1", "new-password-1");
      await user.click(screen.getByRole("button", { name: "Change password" }));

      await waitFor(() => expect(sentPasswords()).toHaveLength(1));
      expect(sentPasswords()[0].method).toBe("PUT");
      expect(sentPasswords()[0].body).toEqual({
        current_password: "old-password-1",
        new_password: "new-password-1",
      });
      await waitFor(() =>
        expect(adopt).toHaveBeenCalledWith({
          token: "fresh",
          refresh_token: "fresh-refresh",
          user_id: "u1",
          email: "ada@acme.corp",
        })
      );
      await waitFor(() =>
        expect(screen.getByRole("status")).toHaveTextContent(
          "Password changed. Your other sessions were signed out.",
        )
      );
      expect(screen.getByLabelText("Current password")).toHaveValue("");
      expect(screen.getByLabelText("New password")).toHaveValue("");
      expect(screen.getByLabelText("Confirm new password")).toHaveValue("");
    });

    it("says so under the field when the current password is wrong", async () => {
      passwordReply = () =>
        jsonResponse({
          error: { code: "wrong_password", message: "the current password is not correct" },
        }, 400);
      const user = userEvent.setup();
      renderProfile();

      await fillPasswords(user, "wrong-password", "new-password-1", "new-password-1");
      await user.click(screen.getByRole("button", { name: "Change password" }));

      expect(await screen.findByText("The current password is not correct.")).toBeInTheDocument();
      expect(adopt).not.toHaveBeenCalled();
      expect(screen.getByLabelText("New password")).toHaveValue("new-password-1");
    });

    it("shows the server's message when it rejects the new password", async () => {
      passwordReply = () =>
        jsonResponse({
          error: {
            code: "invalid_password",
            message:
              "password must be at most 72 bytes; some characters, such as emoji, take more than one",
          },
        }, 400);
      const user = userEvent.setup();
      renderProfile();

      await fillPasswords(user, "old-password-1", "new-password-1", "new-password-1");
      await user.click(screen.getByRole("button", { name: "Change password" }));

      expect(
        await screen.findByText(
          "password must be at most 72 bytes; some characters, such as emoji, take more than one",
        ),
      ).toBeInTheDocument();
    });

    it.each([
      [
        "password_too_common",
        "This password is on a list of commonly used passwords. Choose another.",
      ],
      ["password_matches_account", "The password must not be your email address or name."],
    ])("shows %s on the new password field", async (code, message) => {
      passwordReply = () => jsonResponse({ error: { code, message } }, 400);
      const user = userEvent.setup();
      renderProfile();

      await fillPasswords(user, "old-password-1", "new-password-1", "new-password-1");
      await user.click(screen.getByRole("button", { name: "Change password" }));

      const next = screen.getByLabelText("New password");
      await waitFor(() => expect(next).toHaveAttribute("aria-invalid", "true"));
      expect(next).toHaveAccessibleDescription(expect.stringContaining(message));
      expect(screen.getByLabelText("Current password")).not.toHaveAttribute("aria-invalid");
      expect(adopt).not.toHaveBeenCalled();
    });

    it("explains that an SSO account has no password to change", async () => {
      passwordReply = () =>
        jsonResponse({ error: { code: "no_local_password", message: "no password" } }, 409);
      const user = userEvent.setup();
      renderProfile();

      await fillPasswords(user, "old-password-1", "new-password-1", "new-password-1");
      await user.click(screen.getByRole("button", { name: "Change password" }));

      expect(await screen.findByText(/signs in through your identity provider/))
        .toBeInTheDocument();
      expect(screen.queryByLabelText("Current password")).not.toBeInTheDocument();
    });

    it("asks the person to wait when the sign-in limit is reached", async () => {
      passwordReply = () =>
        jsonResponse({ error: { code: "rate_limited", message: "slow down" } }, 429);
      const user = userEvent.setup();
      renderProfile();

      await fillPasswords(user, "old-password-1", "new-password-1", "new-password-1");
      await user.click(screen.getByRole("button", { name: "Change password" }));

      expect(await screen.findByText("Too many attempts. Wait a minute and try again."))
        .toBeInTheDocument();
    });

    it("shows the rules once the person starts typing a new password", async () => {
      const user = userEvent.setup();
      renderProfile();

      await user.type(await screen.findByLabelText("New password"), "abc");

      expect(screen.getByRole("list", { name: "Requirements" })).toBeInTheDocument();
    });
  });
});
