import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ResetPassword } from "./ResetPassword";

interface Call {
  url: string;
  body?: unknown;
}

let calls: Call[];
let reply: () => Response;

beforeEach(() => {
  calls = [];
  reply = () => new Response(null, { status: 204 });
  globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
    calls.push({ url: String(url), body: init?.body ? JSON.parse(String(init.body)) : undefined });
    return reply();
  });
});

function renderPage(path = "/reset/tok-123") {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/reset/:token" element={<ResetPassword />} />
          <Route path="/login" element={<p>Sign in page</p>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const GOOD = "a-long-enough-password";

describe("ResetPassword", () => {
  it("sets the password from the link and then offers sign in", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("New password", { exact: true }), GOOD);
    await user.type(screen.getByLabelText("Confirm new password"), GOOD);
    await user.click(screen.getByRole("button", { name: "Set password" }));

    expect(await screen.findByRole("heading", { name: "Password changed" })).toBeInTheDocument();
    expect(calls).toEqual([{
      url: "/api/v1/auth/reset",
      body: { token: "tok-123", password: GOOD },
    }]);
    await user.click(screen.getByRole("link", { name: "Go to sign in" }));
    expect(screen.getByText("Sign in page")).toBeInTheDocument();
  });

  it("does not send a password that fails the rules", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("New password", { exact: true }), "short");
    await user.type(screen.getByLabelText("Confirm new password"), "short");
    await user.click(screen.getByRole("button", { name: "Set password" }));

    expect(await screen.findByText("Choose a password that meets the requirements."))
      .toBeInTheDocument();
    expect(calls).toHaveLength(0);
  });

  it("does not send two passwords that differ", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("New password", { exact: true }), GOOD);
    await user.type(screen.getByLabelText("Confirm new password"), GOOD + "x");
    await user.click(screen.getByRole("button", { name: "Set password" }));

    expect(await screen.findByText("The two passwords do not match.")).toBeInTheDocument();
    expect(calls).toHaveLength(0);
  });

  it("says the link is dead when the server does, and keeps no form", async () => {
    reply = () =>
      jsonResponse(
        {
          error: {
            code: "reset_link_invalid",
            message: "this reset link is not valid or has expired",
          },
        },
        400,
      );
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("New password", { exact: true }), GOOD);
    await user.type(screen.getByLabelText("Confirm new password"), GOOD);
    await user.click(screen.getByRole("button", { name: "Set password" }));

    expect(await screen.findByRole("heading", { name: "This reset link does not work" }))
      .toBeInTheDocument();
    expect(screen.queryByLabelText("Confirm new password")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go to sign in" })).toHaveAttribute("href", "/login");
  });

  it("shows another server refusal in the form and lets the person try again", async () => {
    reply = () =>
      jsonResponse({
        error: {
          code: "invalid_password",
          message:
            "password must be at most 72 bytes; some characters, such as emoji, take more than one",
        },
      }, 400);
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("New password", { exact: true }), GOOD);
    await user.type(screen.getByLabelText("Confirm new password"), GOOD);
    await user.click(screen.getByRole("button", { name: "Set password" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "password must be at most 72 bytes; some characters, such as emoji, take more than one",
    );
    expect(screen.getByRole("button", { name: "Set password" })).toBeEnabled();
  });

  it("shows a generic message when the server fails", async () => {
    reply = () => jsonResponse({ error: { code: "internal_error", message: "boom" } }, 500);
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("New password", { exact: true }), GOOD);
    await user.type(screen.getByLabelText("Confirm new password"), GOOD);
    await user.click(screen.getByRole("button", { name: "Set password" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Could not set the password. Please try again.",
    );
  });
});
