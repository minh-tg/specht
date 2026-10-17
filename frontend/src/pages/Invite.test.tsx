import { AuthContext, type AuthContextValue } from "@/auth/context";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Invite } from "./Invite";

let adopt: ReturnType<typeof vi.fn>;
let logout: ReturnType<typeof vi.fn>;
let routes: Record<string, () => Response>;

function calls(suffix: string) {
  return vi.mocked(globalThis.fetch).mock.calls.filter(([url]) => String(url).endsWith(suffix));
}

function renderInvite(opts: { signedInAs?: string; } = {}) {
  globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
    const url = String(input);
    for (const [suffix, answer] of Object.entries(routes)) {
      if (url.endsWith(suffix)) return answer();
    }
    throw new Error(`unexpected request ${url}`);
  });
  const auth: AuthContextValue = {
    token: opts.signedInAs ? "session" : null,
    userId: opts.signedInAs ? "u9" : null,
    email: opts.signedInAs ?? null,
    login: async () => {},
    logout: logout as unknown as AuthContextValue["logout"],
    adopt: adopt as unknown as AuthContextValue["adopt"],
    loading: false,
  };
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={["/invite/tok-abc"]}>
          <Routes>
            <Route path="/invite/:token" element={<Invite />} />
            <Route path="/payments" element={<h1>Payments project</h1>} />
            <Route path="/login" element={<h1>Sign in</h1>} />
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

const lookup = (extra: object = {}) => () =>
  jsonResponse({ project_name: "Payments API", role: "manager", ...extra });

const session = {
  token: "t",
  refresh_token: "r",
  user_id: "u1",
  email: "ada@acme.example",
  project_slug: "payments",
  role: "manager",
};

describe("Invite", () => {
  beforeEach(() => {
    adopt = vi.fn();
    logout = vi.fn();
    routes = {
      "/api/v1/invites/tok-abc": lookup(),
      "/api/v1/invites/tok-abc/accept": () => jsonResponse(session, 201),
      "/api/v1/invites/tok-abc/join": () =>
        jsonResponse({ project_slug: "payments", role: "manager" }),
    };
  });

  it("names the project and what the role can do", async () => {
    renderInvite();

    expect(await screen.findByRole("heading", { name: "Join Payments API" })).toBeInTheDocument();
    expect(screen.getByText("manager")).toBeInTheDocument();
    const can = screen.getByRole("list", { name: "What a manager can do" });
    expect(can).toHaveTextContent("Set up CI and API keys");
    expect(can).toHaveTextContent("Invite people up to the same role");
  });

  it("lists less for a member", async () => {
    routes["/api/v1/invites/tok-abc"] = lookup({ role: "member" });
    renderInvite();

    const can = await screen.findByRole("list", { name: "What a member can do" });
    expect(can).toHaveTextContent("Read findings and request waivers");
    expect(can).not.toHaveTextContent("Invite people");
  });

  it("explains a link that does not work, whatever made it dead", async () => {
    routes["/api/v1/invites/tok-abc"] = () =>
      jsonResponse({ error: { code: "not_found", message: "invite not found" } }, 404);
    renderInvite();

    expect(await screen.findByRole("heading", { name: "This invite link does not work" }))
      .toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go to sign in" })).toHaveAttribute("href", "/login");
  });

  it("creates an account, signs it in and opens the project", async () => {
    renderInvite();
    const user = userEvent.setup();

    await user.type(await screen.findByLabelText("Email"), "ada@acme.example");
    await user.type(screen.getByLabelText(/^Name/), "Ada");
    await user.type(screen.getByLabelText("Choose a password"), "correct-horse-battery");
    await user.click(screen.getByRole("button", { name: "Create account and join" }));

    expect(await screen.findByRole("heading", { name: "Payments project" })).toBeInTheDocument();
    expect(JSON.parse(String(calls("/accept")[0][1]?.body))).toEqual({
      email: "ada@acme.example",
      password: "correct-horse-battery",
      display_name: "Ada",
    });
    expect(adopt).toHaveBeenCalledWith(
      expect.objectContaining({ token: "t", project_slug: "payments" }),
    );
  });

  it("shows the password rules once typing starts and refuses a weak password", async () => {
    renderInvite();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Email"), "ada@acme.example");

    expect(screen.queryByRole("list", { name: "Requirements" })).not.toBeInTheDocument();
    await user.type(screen.getByLabelText("Choose a password"), "short");
    expect(screen.getByRole("list", { name: "Requirements" })).toHaveTextContent(
      "(not met)",
    );

    await user.click(screen.getByRole("button", { name: "Create account and join" }));
    expect(calls("/accept")).toHaveLength(0);
    expect(screen.getByText("Choose a password that meets the requirements.")).toBeInTheDocument();
  });

  it("fixes the email when the invite is bound to an address", async () => {
    routes["/api/v1/invites/tok-abc"] = lookup({ email: "lead@acme.example" });
    renderInvite();
    const user = userEvent.setup();

    const email = await screen.findByLabelText("Email");
    expect(email).toHaveValue("lead@acme.example");
    expect(email).toHaveAttribute("readonly");
    expect(screen.getByText(/only join with/i)).toHaveTextContent("lead@acme.example");

    await user.type(screen.getByLabelText("Choose a password"), "correct-horse-battery");
    await user.click(screen.getByRole("button", { name: "Create account and join" }));
    await screen.findByRole("heading", { name: "Payments project" });
    expect(JSON.parse(String(calls("/accept")[0][1]?.body)).email).toBe("lead@acme.example");
  });

  it("offers sign-in-to-join for people who already have an account", async () => {
    renderInvite();

    expect(await screen.findByRole("link", { name: "Sign in to join" })).toHaveAttribute(
      "href",
      "/login?redirect=%2Finvite%2Ftok-abc",
    );
  });

  it("says plainly when the address already has an account", async () => {
    routes["/api/v1/invites/tok-abc/accept"] = () =>
      jsonResponse({ error: { code: "registration_failed", message: "registration failed" } }, 422);
    renderInvite();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Email"), "ada@acme.example");
    await user.type(screen.getByLabelText("Choose a password"), "correct-horse-battery");
    await user.click(screen.getByRole("button", { name: "Create account and join" }));

    expect(await screen.findByText(/already has an account/i)).toBeInTheDocument();
    expect(adopt).not.toHaveBeenCalled();
  });

  it("tells the person to retype an address with hidden characters and keeps the form", async () => {
    routes["/api/v1/invites/tok-abc/accept"] = () =>
      jsonResponse(
        { error: { code: "invalid_email_characters", message: "invalid email address" } },
        400,
      );
    renderInvite();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Email"), "ada@acme.example");
    await user.type(screen.getByLabelText("Choose a password"), "correct-horse-battery");
    await user.click(screen.getByRole("button", { name: "Create account and join" }));

    expect(
      await screen.findByText("This email has hidden characters. Retype it instead of pasting it."),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create account and join" })).toBeEnabled();
    expect(adopt).not.toHaveBeenCalled();
  });

  it.each([
    [
      "password_too_common",
      "This password is on a list of commonly used passwords. Choose another.",
    ],
    ["password_matches_account", "The password must not be your email address or name."],
  ])("shows %s on the password field and keeps the form", async (code, message) => {
    routes["/api/v1/invites/tok-abc/accept"] = () =>
      jsonResponse({ error: { code, message } }, 400);
    renderInvite();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Email"), "ada@acme.example");
    await user.type(screen.getByLabelText("Choose a password"), "correct-horse-battery");
    await user.click(screen.getByRole("button", { name: "Create account and join" }));

    const password = screen.getByLabelText("Choose a password");
    await waitFor(() => expect(password).toHaveAttribute("aria-invalid", "true"));
    expect(password).toHaveAccessibleDescription(expect.stringContaining(message));
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(adopt).not.toHaveBeenCalled();
  });

  it("turns into the dead-link page when the link is used up in between", async () => {
    routes["/api/v1/invites/tok-abc/accept"] = () =>
      jsonResponse({ error: { code: "not_found", message: "invite not found" } }, 404);
    renderInvite();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Email"), "ada@acme.example");
    await user.type(screen.getByLabelText("Choose a password"), "correct-horse-battery");
    await user.click(screen.getByRole("button", { name: "Create account and join" }));

    expect(await screen.findByRole("heading", { name: "This invite link does not work" }))
      .toBeInTheDocument();
  });

  it("lets a signed-in person join with their own account", async () => {
    renderInvite({ signedInAs: "ada@acme.example" });
    const user = userEvent.setup();

    expect(await screen.findByText(/signed in as/i)).toHaveTextContent("ada@acme.example");
    expect(screen.queryByLabelText("Choose a password")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Join Payments API" }));

    expect(await screen.findByRole("heading", { name: "Payments project" })).toBeInTheDocument();
    expect(calls("/join")[0][1]?.method).toBe("POST");
  });

  it("names the right address when a signed-in person has the wrong account", async () => {
    routes["/api/v1/invites/tok-abc"] = lookup({ email: "lead@acme.example" });
    routes["/api/v1/invites/tok-abc/join"] = () =>
      jsonResponse({ error: { code: "invite_email_mismatch", message: "wrong address" } }, 403);
    renderInvite({ signedInAs: "other@acme.example" });
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Join Payments API" }));

    expect(await screen.findByText(/invitation is for lead@acme.example/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Use another account" }));
    expect(logout).toHaveBeenCalled();
  });
});
