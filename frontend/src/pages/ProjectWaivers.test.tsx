import { AuthContext, type AuthContextValue } from "@/auth/context";
import { Toaster } from "@/components/ui/sonner";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import type { Waiver } from "@/types/api";
import { QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ProjectWaivers } from "./ProjectWaivers";

const SOON = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

function waiver(extra: Partial<Waiver>): Waiver {
  return {
    id: "w",
    project_id: "p1",
    name: "Waiver request: openssh-server: security issue",
    description: "",
    enabled: true,
    status: "pending",
    scope_all: false,
    reason: "Not reachable from the public API.",
    requested_by: "u-tomas",
    requested_at: new Date(Date.now() - 2 * 3600 * 1000).toISOString(),
    decision_note: "",
    expires_at: SOON,
    targets: [{ id: "t1", finding_id: "f1" }],
    created_at: "2026-10-01T00:00:00Z",
    updated_at: "2026-10-01T00:00:00Z",
    ...extra,
  };
}

let waivers: Waiver[];
let permissions: { approve_waivers: boolean; manage_waivers: boolean; };
let calls: { url: string; method: string; body?: unknown; }[];
let listFails: boolean;
let updateError: string | null;

function renderPage(userId = "u-ada") {
  const auth: AuthContextValue = {
    token: "t",
    userId,
    email: "ada@acme.example",
    login: async () => {},
    logout: () => {},
    adopt: () => {},
    loading: false,
  };
  function Where() {
    return <output data-testid="where">{useLocation().search}</output>;
  }
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={["/payments/waivers"]}>
          <Routes>
            <Route
              path="/:slug/waivers"
              element={
                <>
                  <ProjectWaivers />
                  <Where />
                </>
              }
            />
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>
      <Toaster />
    </QueryClientProvider>,
  );
}

describe("ProjectWaivers", () => {
  beforeEach(() => {
    listFails = false;
    updateError = null;
    calls = [];
    permissions = { approve_waivers: true, manage_waivers: true };
    waivers = [
      waiver({ id: "w1" }),
      waiver({
        id: "w2",
        name: "Waiver request: Dockerfile and base image (+2 more)",
        reason: "Internal tooling image.",
        targets: [{ id: "t2", finding_id: "f2" }, { id: "t3", finding_id: "f3" }, {
          id: "t4",
          finding_id: "f4",
        }],
      }),
      waiver({
        id: "w3",
        status: "approved",
        decided_by: "u-ada",
        decision_note: "Mitigated by the sandbox.",
        name: "Waiver request: zlib: heap overflow",
      }),
      waiver({
        id: "w4",
        status: "rejected",
        decided_by: "u-ada",
        decision_note: "Encrypt it, it takes one line.",
        name: "Waiver request: S3 bucket without encryption",
      }),
    ];
    globalThis.fetch = vi.fn().mockImplementation(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        const body = init?.body ? JSON.parse(String(init.body)) : undefined;
        calls.push({ url, method, body });
        if (url.endsWith("/api/v1/me")) {
          return jsonResponse({ id: "u-ada", email: "ada@acme.example", role: "user" });
        }
        if (url.endsWith("/projects/payments")) {
          return jsonResponse({ id: "p1", slug: "payments", name: "Payments", permissions });
        }
        if (url.includes("/findings/")) {
          return jsonResponse({ id: "f1", current_severity: "critical", current_title: "x" });
        }
        if (url.endsWith("/waivers") && method === "GET") {
          return listFails
            ? jsonResponse({ error: { code: "internal", message: "down" } }, 500)
            : jsonResponse(waivers);
        }
        if (method === "PUT" && /\/waivers\/[^/]+$/.test(url)) {
          return updateError
            ? jsonResponse({ error: { code: "invalid", message: updateError } }, 400)
            : jsonResponse(waivers[0]);
        }
        if (method === "POST" && /\/waivers\/[^/]+\/(approve|reject|withdraw|toggle)$/.test(url)) {
          return jsonResponse(waivers[0]);
        }
        throw new Error(`unexpected request ${method} ${url}`);
      },
    );
  });

  it("opens on the waiting list and counts every list", async () => {
    renderPage();
    expect(await screen.findByRole("tab", { name: "Waiting 2" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(screen.getByRole("tab", { name: "In force 1" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Closed 1" })).toBeInTheDocument();
    expect(screen.getByText("openssh-server: security issue")).toBeInTheDocument();
    expect(screen.getByText("Dockerfile and base image (+2 more)")).toBeInTheDocument();
    expect(screen.queryByText("zlib: heap overflow")).not.toBeInTheDocument();
    expect(screen.getByText("Not reachable from the public API.")).toBeInTheDocument();
  });

  it("switches list, keeps it in the address, and moves with the arrow keys", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("tab", { name: "In force 1" }));
    expect(screen.getByText("zlib: heap overflow")).toBeInTheDocument();
    expect(screen.getByTestId("where")).toHaveTextContent("?state=in_force");

    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: "Closed 1" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText("S3 bucket without encryption")).toBeInTheDocument();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: "Waiting 2" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("where")).toHaveTextContent("");
  });

  it("lets a manager approve with an optional note", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "Approve openssh-server: security issue" }),
    );
    const dialog = await screen.findByRole("dialog", { name: "Approve this waiver?" });
    await user.type(within(dialog).getByLabelText(/Note/), "Fine until the image bump.");
    await user.click(within(dialog).getByRole("button", { name: "Approve" }));
    await waitFor(() =>
      expect(calls.some((c) => c.url.endsWith("/waivers/w1/approve"))).toBe(true)
    );
    const sent = calls.find((c) => c.url.endsWith("/waivers/w1/approve"))!;
    expect(sent.method).toBe("POST");
    expect(sent.body).toEqual({ note: "Fine until the image bump." });
    expect(await screen.findByText("Waiver approved")).toBeInTheDocument();
  });

  it("will not reject without a note", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "Reject openssh-server: security issue" }),
    );
    const dialog = await screen.findByRole("dialog", { name: "Reject this waiver?" });
    const submit = within(dialog).getByRole("button", { name: "Reject" });
    expect(submit).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/Note/), "Encrypt it.");
    expect(submit).toBeEnabled();
    await user.click(submit);
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/waivers/w1/reject"))).toBe(true));
    expect(calls.find((c) => c.url.endsWith("/waivers/w1/reject"))!.body).toEqual({
      note: "Encrypt it.",
    });
  });

  it("shows a developer their own request with Withdraw and no decision buttons", async () => {
    permissions = { approve_waivers: false, manage_waivers: false };
    waivers = [
      waiver({ id: "w1", requested_by: "u-ada" }),
      waiver({ id: "w2", requested_by: "u-tomas", name: "Waiver request: expat" }),
    ];
    const user = userEvent.setup();
    renderPage("u-ada");
    await screen.findByText("openssh-server: security issue");
    expect(screen.queryByRole("button", { name: /^Approve/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Reject/ })).not.toBeInTheDocument();
    const withdraws = screen.getAllByRole("button", { name: /^Withdraw/ });
    expect(withdraws).toHaveLength(1);
    await user.click(withdraws[0]!);
    await waitFor(() =>
      expect(calls.some((c) => c.url.endsWith("/waivers/w1/withdraw"))).toBe(true)
    );
    expect(await screen.findByText("Request withdrawn")).toBeInTheDocument();
  });

  it("lets a manager revoke a waiver that is in force", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("tab", { name: "In force 1" }));
    await user.click(screen.getByRole("button", { name: "Revoke zlib: heap overflow" }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/waivers/w3/toggle"))).toBe(true));
    expect(await screen.findByText("Waiver revoked")).toBeInTheDocument();
  });

  it("says who decided a closed waiver, and why", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("tab", { name: "Closed 1" }));
    expect(screen.getByText("Rejected by You: Encrypt it, it takes one line.")).toBeInTheDocument();
  });

  it("says so when a list is empty", async () => {
    waivers = [];
    renderPage();
    expect(await screen.findByText("Nothing is waiting for a decision.")).toBeInTheDocument();
  });

  it("offers a retry when the waivers cannot be loaded", async () => {
    listFails = true;
    renderPage();
    expect(await screen.findByText("Could not load waivers.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
  });

  it("hides Edit from people without manage_waivers", async () => {
    permissions = { approve_waivers: true, manage_waivers: false };
    renderPage();
    await screen.findByText("openssh-server: security issue");
    expect(screen.queryByRole("button", { name: /^Edit / })).not.toBeInTheDocument();
  });

  it("sends only the fields that changed when a manager edits a waiver", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "Edit openssh-server: security issue" }),
    );
    const dialog = await screen.findByRole("dialog", { name: "Edit waiver" });
    await user.type(within(dialog).getByLabelText("Description"), "Scoped to the bastion.");
    await user.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    const sent = calls.find((c) => c.method === "PUT")!;
    expect(sent.url).toMatch(/\/waivers\/w1$/);
    expect(sent.body).toEqual({ description: "Scoped to the bastion." });
    expect(await screen.findByText("Waiver saved")).toBeInTheDocument();
  });

  it("sends a new expiry as an RFC 3339 timestamp", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "Edit openssh-server: security issue" }),
    );
    const dialog = await screen.findByRole("dialog", { name: "Edit waiver" });
    fireEvent.change(within(dialog).getByLabelText("Expires"), {
      target: { value: "2027-03-01" },
    });
    await user.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    const body = calls.find((c) => c.method === "PUT")!.body as { expires_at: string; };
    expect(body).toEqual({ expires_at: "2027-03-01T23:59:59.999Z" });
  });

  it("sends an empty expiry when No expiry is ticked", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "Edit openssh-server: security issue" }),
    );
    const dialog = await screen.findByRole("dialog", { name: "Edit waiver" });
    await user.click(within(dialog).getByRole("checkbox", { name: "No expiry" }));
    await user.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    expect(calls.find((c) => c.method === "PUT")!.body).toEqual({ expires_at: "" });
  });

  it("shows a server error inside the edit dialog and keeps it open", async () => {
    updateError = "Expiry must be in the future.";
    const user = userEvent.setup();
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "Edit openssh-server: security issue" }),
    );
    const dialog = await screen.findByRole("dialog", { name: "Edit waiver" });
    await user.type(within(dialog).getByLabelText("Description"), "Scoped.");
    await user.click(within(dialog).getByRole("button", { name: "Save" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Expiry must be in the future.",
    );
    expect(screen.getByRole("dialog", { name: "Edit waiver" })).toBeInTheDocument();
  });
});
