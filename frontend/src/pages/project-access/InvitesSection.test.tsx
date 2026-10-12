import { Toaster } from "@/components/ui/sonner";
import { chooseOption, createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { expiresIn } from "./expiry";
import { InvitesSection } from "./InvitesSection";

const DAY = 24 * 60 * 60 * 1000;

let open: Array<Record<string, unknown>>;
let calls: Array<{ url: string; method: string; body: string; }>;
let createAnswer: () => Response;

function renderSection() {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <InvitesSection slug="payments" />
      <Toaster />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  calls = [];
  open = [
    {
      id: "i1",
      role: "member",
      created_by: "ada@acme.example",
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 6.5 * DAY).toISOString(),
    },
    {
      id: "i2",
      role: "manager",
      email: "jonas@acme.example",
      created_by: "lena@acme.example",
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 2.5 * DAY).toISOString(),
    },
  ];
  createAnswer = () =>
    jsonResponse({
      id: "i3",
      role: "manager",
      email: "new@acme.example",
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 14 * DAY).toISOString(),
      link: "/invite/q3Zk0wY1b8Vn",
    }, 201);
  globalThis.fetch = vi.fn().mockImplementation(
    async (url: RequestInfo | URL, init?: RequestInit) => {
      const method = (init?.method ?? "GET").toUpperCase();
      calls.push({ url: String(url), method, body: String(init?.body ?? "") });
      if (method === "POST") return createAnswer();
      if (method === "DELETE") return jsonResponse(null, 204);
      return jsonResponse(open);
    },
  );
});

describe("expiresIn", () => {
  const now = Date.parse("2026-10-13T12:00:00Z");
  it("uses the largest whole unit", () => {
    expect(expiresIn("2026-10-19T12:00:00Z", now)).toBe("6 days");
    expect(expiresIn("2026-10-14T12:00:00Z", now)).toBe("1 day");
    expect(expiresIn("2026-10-13T20:00:00Z", now)).toBe("8 hours");
    expect(expiresIn("2026-10-13T12:20:00Z", now)).toBe("1 hour");
  });
  it("says so once it has passed", () => {
    expect(expiresIn("2026-10-13T11:59:59Z", now)).toBe("expired");
  });
});

describe("InvitesSection", () => {
  it("lists the open invites without any link", async () => {
    renderSection();

    const list = await screen.findByRole("list", { name: "Pending invites" });
    const rows = within(list).getAllByRole("listitem");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("Anyone with the link");
    expect(rows[0]).toHaveTextContent("Created by ada@acme.example");
    expect(rows[0]).toHaveTextContent("Member · expires in 6 days");
    expect(rows[1]).toHaveTextContent("jonas@acme.example");
    expect(rows[1]).toHaveTextContent("Manager · expires in 2 days");
    expect(list.textContent).not.toContain("/invite/");
  });

  it("says when there are none", async () => {
    open = [];
    renderSection();
    expect(await screen.findByText("No open invites.")).toBeInTheDocument();
  });

  it("creates an invite and shows its link once, with the role and expiry that were chosen", async () => {
    renderSection();
    const user = userEvent.setup();
    await screen.findByRole("list", { name: "Pending invites" });

    await user.click(screen.getByRole("button", { name: "Invite people" }));
    await chooseOption(user, screen.getByRole("combobox", { name: "Role" }), "Manager");
    await user.type(screen.getByLabelText(/^Email/), "new@acme.example");
    await chooseOption(user, screen.getByRole("combobox", { name: "Expires" }), "in 14 days");
    await user.click(screen.getByRole("button", { name: "Create link" }));

    const post = calls.find((c) => c.method === "POST");
    expect(post?.url).toBe("/api/v1/projects/payments/invites");
    expect(JSON.parse(post?.body ?? "{}")).toEqual({
      role: "manager",
      email: "new@acme.example",
      expires_in_days: 14,
    });
    expect(await screen.findByText("Send this link")).toBeInTheDocument();
    expect(screen.getByTestId("invite-link")).toHaveTextContent(
      `${window.location.origin}/invite/q3Zk0wY1b8Vn`,
    );
    expect(screen.getByText(/only time the link is shown/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy invite link" })).toBeInTheDocument();

    // Closing it and opening again starts a fresh form, with no trace of the link.
    await user.click(screen.getByRole("button", { name: "Done" }));
    await user.click(screen.getByRole("button", { name: "Invite people" }));
    expect(screen.queryByTestId("invite-link")).not.toBeInTheDocument();
    expect(screen.getByLabelText(/^Email/)).toHaveValue("");
  });

  it("leaves the email out when it is empty", async () => {
    renderSection();
    const user = userEvent.setup();
    await screen.findByRole("list", { name: "Pending invites" });
    await user.click(screen.getByRole("button", { name: "Invite people" }));
    await user.click(screen.getByRole("button", { name: "Create link" }));

    const post = calls.find((c) => c.method === "POST");
    expect(JSON.parse(post?.body ?? "{}")).toEqual({ role: "member", expires_in_days: 7 });
  });

  it("shows the server's reason when the invite cannot be made", async () => {
    createAnswer = () =>
      jsonResponse(
        { error: { code: "too_many_invites", message: "this project has too many open invites" } },
        409,
      );
    renderSection();
    const user = userEvent.setup();
    await screen.findByRole("list", { name: "Pending invites" });
    await user.click(screen.getByRole("button", { name: "Invite people" }));
    await user.click(screen.getByRole("button", { name: "Create link" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("too many open invites");
    expect(screen.queryByText("Send this link")).not.toBeInTheDocument();
  });

  it("revokes an invite", async () => {
    renderSection();
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole("button", { name: "Revoke the invite for jonas@acme.example" }),
    );

    const del = calls.find((c) => c.method === "DELETE");
    expect(del?.url).toBe("/api/v1/projects/payments/invites/i2");
    expect(await screen.findByText("Invite revoked")).toBeInTheDocument();
  });
});
