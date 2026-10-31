import { AuthContext, type AuthContextValue } from "@/auth/context";
import { Toaster } from "@/components/ui/sonner";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import type { Waiver, WaiverEvent } from "@/types/api";
import { QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ProjectWaivers } from "./ProjectWaivers";

const playCue = vi.hoisted(() => vi.fn());
vi.mock("@/lib/sound", () => ({ playCue }));

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
let eventsMode: "ok" | "empty" | "fail" | "slow";
let events: WaiverEvent[];
let updateError: string | null;
/** When set, every revoke or restore is refused with this 409 code, as if the server had decided so. */
let switchRefusal: string | null;

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
    playCue.mockClear();
    listFails = false;
    eventsMode = "ok";
    events = [
      {
        id: "e1",
        waiver_id: "w1",
        event_type: "requested",
        actor_id: "u-tomas",
        actor_name: "Tomas Reyes",
        created_at: "2026-10-01T09:00:00Z",
      },
      {
        id: "e2",
        waiver_id: "w1",
        event_type: "approved",
        actor_id: "u-ada",
        created_at: "2026-10-01T10:00:00Z",
      },
      {
        id: "e3",
        waiver_id: "w1",
        event_type: "mystery_step",
        actor_id: null,
        created_at: "2026-10-01T11:00:00Z",
      },
    ];
    updateError = null;
    switchRefusal = null;
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
        if (method === "GET" && url.endsWith("/waivers/w1/events")) {
          if (eventsMode === "fail") {
            return jsonResponse({ error: { code: "internal", message: "down" } }, 500);
          }
          if (eventsMode === "slow") return new Promise(() => {});
          return jsonResponse(eventsMode === "empty" ? [] : events);
        }
        if (method === "DELETE" && /\/waivers\/[^/]+$/.test(url)) {
          return jsonResponse(undefined, 204);
        }
        if (method === "PUT" && /\/waivers\/[^/]+$/.test(url)) {
          return updateError
            ? jsonResponse({ error: { code: "invalid", message: updateError } }, 400)
            : jsonResponse(waivers[0]);
        }
        if (method === "GET" && /\/waivers\/[^/]+$/.test(url)) {
          return jsonResponse(waivers.find((w) => url.endsWith(`/waivers/${w.id}`)));
        }
        const switching = /\/waivers\/([^/]+)\/(revoke|restore)$/.exec(url);
        if (method === "POST" && switching) {
          const target = waivers.find((w) => w.id === switching[1])!;
          const wantOn = switching[2] === "restore";
          const refuse = (code: string) =>
            jsonResponse({ error: { code, message: `refused: ${code}` } }, 409);
          if (switchRefusal) return refuse(switchRefusal);
          // The real server compares the version the caller saw with the stored one.
          if (body?.expected_updated_at && body.expected_updated_at !== target.updated_at) {
            return refuse("waiver_changed");
          }
          if (wantOn && target.expires_at && Date.parse(target.expires_at) <= Date.now()) {
            return refuse("waiver_expired");
          }
          if (target.enabled !== wantOn) {
            target.enabled = wantOn;
            target.updated_at = new Date(Date.parse(target.updated_at) + 1000).toISOString();
          }
          return jsonResponse(target);
        }
        if (method === "POST" && /\/waivers\/[^/]+\/(approve|reject|withdraw)$/.test(url)) {
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

  it("lets a manager revoke a waiver that is in force, sending the version it showed", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("tab", { name: "In force 1" }));
    await user.click(screen.getByRole("button", { name: "Revoke zlib: heap overflow" }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/waivers/w3/revoke"))).toBe(true));
    expect(await screen.findByText("Waiver revoked")).toBeInTheDocument();
    const revoke = calls.find((c) => c.url.endsWith("/waivers/w3/revoke"))!;
    expect(revoke.method).toBe("POST");
    expect(revoke.body).toEqual({ expected_updated_at: "2026-10-01T00:00:00Z" });
    expect(calls.some((c) => c.url.endsWith("/toggle"))).toBe(false);
  });

  it("puts a revoked waiver back in force from the toast, silent on revoke and one cue on Undo", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("tab", { name: "In force 1" }));
    await user.click(screen.getByRole("button", { name: "Revoke zlib: heap overflow" }));
    await user.click(await screen.findByRole("button", { name: "Undo" }));

    expect(await screen.findByText("Waiver back in force")).toBeInTheDocument();
    const restore = calls.filter((c) => c.url.endsWith("/waivers/w3/restore"));
    expect(restore).toHaveLength(1);
    // Undo sends the version the revoke returned, not the one the list had before it.
    expect(restore[0]!.body).toEqual({ expected_updated_at: "2026-10-01T00:00:01.000Z" });
    expect(waivers.find((w) => w.id === "w3")?.enabled).toBe(true);
    // A removal or revocation is silent, so the only cue is the one the successful Undo plays.
    expect(playCue.mock.calls).toEqual([["accepted"]]);
  });

  it("refuses to undo a revoke when the waiver changed meanwhile, and says so", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("tab", { name: "In force 1" }));
    await user.click(screen.getByRole("button", { name: "Revoke zlib: heap overflow" }));
    const undo = await screen.findByRole("button", { name: "Undo" });
    // Another manager restores and revokes it again before Undo is pressed.
    waivers.find((w) => w.id === "w3")!.updated_at = "2026-10-01T00:05:00.000Z";
    await user.click(undo);

    expect(await screen.findByText("The waiver changed in the meantime, so Undo did nothing."))
      .toBeInTheDocument();
    expect(waivers.find((w) => w.id === "w3")?.enabled).toBe(false);
    expect(playCue).toHaveBeenLastCalledWith("error");
  });

  it("refuses to undo a revoke once the waiver has expired", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("tab", { name: "In force 1" }));
    await user.click(screen.getByRole("button", { name: "Revoke zlib: heap overflow" }));
    const undo = await screen.findByRole("button", { name: "Undo" });
    switchRefusal = "waiver_expired";
    await user.click(undo);

    expect(await screen.findByText("The waiver has expired. Extend its expiry first."))
      .toBeInTheDocument();
    expect(playCue).toHaveBeenLastCalledWith("error");
  });

  describe("Restore", () => {
    const revoked = () =>
      waiver({
        id: "w5",
        status: "approved",
        enabled: false,
        name: "Waiver request: log4j: remote code execution",
        updated_at: "2026-10-05T08:00:00.123456Z",
      });
    const expired = () =>
      waiver({
        id: "w6",
        status: "approved",
        enabled: false,
        name: "Waiver request: openssl: timing leak",
        expires_at: "2026-09-30T00:00:00Z",
      });

    it("lets a manager put a revoked waiver back in force, and moves focus to the list", async () => {
      waivers.push(revoked());
      const user = userEvent.setup();
      renderPage();
      await user.click(await screen.findByRole("tab", { name: "Closed 2" }));
      await user.click(
        screen.getByRole("button", { name: "Restore log4j: remote code execution" }),
      );

      expect(await screen.findByText("Waiver restored")).toBeInTheDocument();
      const call = calls.find((c) => c.url.endsWith("/waivers/w5/restore"))!;
      expect(call.method).toBe("POST");
      expect(call.body).toEqual({ expected_updated_at: "2026-10-05T08:00:00.123456Z" });
      expect(waivers.find((w) => w.id === "w5")?.enabled).toBe(true);
      expect(playCue.mock.calls).toEqual([["accepted"]]);
      await waitFor(() =>
        expect(screen.getByRole("tab", { name: "In force 2" })).toBeInTheDocument()
      );
      await waitFor(() => expect(screen.getByRole("tabpanel")).toHaveFocus());
      // The restored waiver left the closed list and is not offered Restore again.
      expect(screen.queryByRole("button", { name: /Restore log4j/ })).not.toBeInTheDocument();
    });

    it("does not offer Restore to a person who cannot manage waivers", async () => {
      permissions = { approve_waivers: true, manage_waivers: false };
      waivers.push(revoked());
      const user = userEvent.setup();
      renderPage();
      await user.click(await screen.findByRole("tab", { name: "Closed 2" }));
      expect(screen.getByText("Revoked")).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: /Restore/ })).not.toBeInTheDocument();
    });

    it("does not offer Restore on rejected or withdrawn requests", async () => {
      waivers.push(waiver({ id: "w7", status: "withdrawn", name: "Waiver request: curl: bug" }));
      const user = userEvent.setup();
      renderPage();
      await user.click(await screen.findByRole("tab", { name: "Closed 2" }));
      expect(screen.queryByRole("button", { name: /Restore/ })).not.toBeInTheDocument();
    });

    it("calls a waiver the sweeper switched off Expired and offers Edit expiry, not Restore", async () => {
      waivers.push(expired());
      const user = userEvent.setup();
      renderPage();
      await user.click(await screen.findByRole("tab", { name: "Closed 2" }));

      expect(screen.getByText(/^Expired/)).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: /Restore/ })).not.toBeInTheDocument();
      await user.click(screen.getByRole("button", { name: "Edit expiry of openssl: timing leak" }));
      expect(await screen.findByRole("heading", { name: "Edit waiver" })).toBeInTheDocument();
      expect(screen.getByLabelText("Expires")).toBeInTheDocument();
    });

    it("says the waiver changed, and refreshes the list, when someone else wrote it first", async () => {
      waivers.push(revoked());
      const user = userEvent.setup();
      renderPage();
      await user.click(await screen.findByRole("tab", { name: "Closed 2" }));
      // Another manager restored it, and revoked it again, after this list loaded.
      waivers.find((w) => w.id === "w5")!.updated_at = "2026-10-05T09:00:00.000000Z";
      await user.click(
        screen.getByRole("button", { name: "Restore log4j: remote code execution" }),
      );

      expect(await screen.findByRole("alert")).toHaveTextContent(
        "The waiver changed since this list loaded, so nothing was done. The list is up to date now.",
      );
      expect(waivers.find((w) => w.id === "w5")?.enabled).toBe(false);
      expect(playCue).toHaveBeenLastCalledWith("error");
      await waitFor(() =>
        expect(calls.filter((c) => c.method === "GET" && c.url.endsWith("/waivers")).length)
          .toBeGreaterThan(1)
      );
    });

    it("says the waiver has expired when the server refuses a restore for that reason", async () => {
      waivers.push(revoked());
      const user = userEvent.setup();
      renderPage();
      await user.click(await screen.findByRole("tab", { name: "Closed 2" }));
      switchRefusal = "waiver_expired";
      await user.click(
        screen.getByRole("button", { name: "Restore log4j: remote code execution" }),
      );

      expect(await screen.findByRole("alert")).toHaveTextContent(
        "The waiver has expired. Extend its expiry first.",
      );
    });
  });

  it("says who decided a closed waiver, and why", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("tab", { name: "Closed 1" }));
    expect(screen.getByText("Rejected by You: Encrypt it, it takes one line.")).toBeInTheDocument();
  });

  it("labels a request the server rejected for lateness as expired, not rejected", async () => {
    waivers.push(waiver({
      id: "w8",
      status: "rejected",
      decision_reason: "expired",
      decision_note: "expired before a decision",
      name: "Waiver request: zlib: overflow",
    }));
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("tab", { name: "Closed 2" }));

    expect(screen.getByText("Expired before a decision")).toBeInTheDocument();
    expect(screen.getByText("Rejected by You: Encrypt it, it takes one line."))
      .toBeInTheDocument();
    expect(screen.queryByText(/Rejected: expired before a decision/)).not.toBeInTheDocument();
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
    expect(body).toEqual({ expires_at: new Date(2027, 2, 1, 23, 59, 59, 999).toISOString() });
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

  it("hides Delete from people without manage_waivers", async () => {
    permissions = { approve_waivers: true, manage_waivers: false };
    renderPage();
    await screen.findByText("openssh-server: security issue");
    expect(screen.queryByRole("button", { name: /^Delete / })).not.toBeInTheDocument();
  });

  it("asks before deleting, and Cancel sends nothing", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "Delete openssh-server: security issue" }),
    );
    const dialog = await screen.findByRole("alertdialog", { name: "Delete this waiver?" });
    expect(
      within(dialog).getByText(
        "Findings it covered start blocking the gate again. The waiver and its history are removed. This cannot be undone.",
      ),
    ).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument());
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
  });

  it("deletes the waiver once confirmed", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "Delete openssh-server: security issue" }),
    );
    const dialog = await screen.findByRole("alertdialog", { name: "Delete this waiver?" });
    await user.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE")).toBe(true));
    expect(calls.find((c) => c.method === "DELETE")!.url).toMatch(/\/waivers\/w1$/);
    expect(await screen.findByText("Waiver deleted")).toBeInTheDocument();
    // Deleting has no inverse, so it keeps its dialog and its toast has no Undo.
    expect(screen.queryByRole("button", { name: "Undo" })).not.toBeInTheDocument();
  });

  it("shows History to people who cannot manage waivers", async () => {
    permissions = { approve_waivers: false, manage_waivers: false };
    renderPage();
    expect(
      await screen.findByRole("button", { name: "History of openssh-server: security issue" }),
    ).toHaveAttribute("aria-expanded", "false");
  });

  it("loads a waiver's history only when it is opened, and labels each step", async () => {
    const user = userEvent.setup();
    renderPage();
    const toggle = await screen.findByRole("button", {
      name: "History of openssh-server: security issue",
    });
    expect(calls.some((c) => c.url.endsWith("/waivers/w1/events"))).toBe(false);

    await user.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(await screen.findByText("Requested")).toBeInTheDocument();
    expect(screen.getByText("Approved")).toBeInTheDocument();
    expect(screen.getByText("mystery_step")).toBeInTheDocument();
    expect(screen.getByText("by Tomas Reyes")).toBeInTheDocument();
    expect(screen.getByText("by You")).toBeInTheDocument();
    expect(screen.getByText("by System")).toBeInTheDocument();
    expect(calls.filter((c) => c.url.endsWith("/waivers/w1/events"))).toHaveLength(1);

    await user.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByText("Requested")).not.toBeInTheDocument();
  });

  it("says so when a waiver has no history", async () => {
    eventsMode = "empty";
    const user = userEvent.setup();
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "History of openssh-server: security issue" }),
    );
    expect(await screen.findByText("No history yet.")).toBeInTheDocument();
  });

  it("shows a loading state while the history is on its way", async () => {
    eventsMode = "slow";
    const user = userEvent.setup();
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "History of openssh-server: security issue" }),
    );
    expect(await screen.findByRole("status", { name: "Loading history" })).toBeInTheDocument();
  });

  it("offers a retry when the history cannot be loaded", async () => {
    eventsMode = "fail";
    const user = userEvent.setup();
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "History of openssh-server: security issue" }),
    );
    expect(await screen.findByText("Could not load history.")).toBeInTheDocument();
    eventsMode = "ok";
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("Requested")).toBeInTheDocument();
  });
});
