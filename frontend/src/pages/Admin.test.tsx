import { Toaster } from "@/components/ui/sonner";
import { formatDate } from "@/lib/format";
import { chooseOption, createTestQueryClient, jsonResponse } from "@/test/utils";
import type { UserProfile, WatcherHealth } from "@/types/api";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Admin } from "./Admin";

const ada: UserProfile = {
  id: "u-ada",
  email: "ada@acme.example",
  display_name: "Ada Okafor",
  role: "admin",
  created_at: "2026-09-01T00:00:00Z",
};
const lena: UserProfile = {
  id: "u-lena",
  email: "lena@acme.example",
  display_name: "Lena Brandt",
  role: "member",
  created_at: "2026-09-02T00:00:00Z",
};
const jonas: UserProfile = {
  id: "u-jonas",
  email: "jonas@acme.example",
  role: "member",
  disabled: true,
  disabled_at: "2026-10-01T00:00:00Z",
  created_at: "2026-09-03T00:00:00Z",
};

const healthy: WatcherHealth = {
  last_successful_poll_at: "2026-10-12T11:50:00Z",
  last_poll_attempt_at: "2026-10-12T11:50:00Z",
  consecutive_failures: 0,
  healthy: true,
  stale: false,
};

let role: "admin" | "member";
let users: UserProfile[];
let health: WatcherHealth;
let staleReports: number;
let calls: { url: string; method: string; body?: unknown; }[];
let writeError: { code: string; message: string; } | null;
let statusFails: boolean;

function renderPage() {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <MemoryRouter>
        <Admin />
      </MemoryRouter>
      <Toaster />
    </QueryClientProvider>,
  );
}

describe("Admin", () => {
  beforeEach(() => {
    role = "admin";
    users = [ada, lena, jonas];
    health = healthy;
    staleReports = 214;
    calls = [];
    writeError = null;
    statusFails = false;
    globalThis.fetch = vi.fn().mockImplementation(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        const body = init?.body ? JSON.parse(String(init.body)) : undefined;
        calls.push({ url, method, body });
        if (url.endsWith("/api/v1/me")) {
          return jsonResponse({ id: "u-ada", email: ada.email, role });
        }
        if (url.endsWith("/api/v1/admin/status")) {
          return statusFails
            ? jsonResponse({ error: { code: "internal", message: "down" } }, 500)
            : jsonResponse({
              projects: 6,
              users: 23,
              open_findings: 214,
              reports: 1382,
              oldest_settled_report_at: "2025-03-04T00:00:00Z",
            });
        }
        if (url.includes("/api/v1/users?")) return jsonResponse(users);
        if (method !== "GET" && url.includes("/api/v1/users/")) {
          if (writeError) {
            return jsonResponse({ error: writeError }, 409);
          }
          return jsonResponse(lena);
        }
        if (url.endsWith("/api/v1/watcher/status")) return jsonResponse(health);
        if (url.includes("/api/v1/admin/retention/preview")) {
          const days = Number(new URL(url, "http://x").searchParams.get("days"));
          return jsonResponse({
            older_than_days: days,
            cutoff: "2025-10-12T00:00:00Z",
            stale_reports: staleReports,
          });
        }
        if (url.endsWith("/api/v1/admin/retention/purge")) {
          return jsonResponse({
            older_than_days: body.older_than_days,
            cutoff: "2025-10-12T00:00:00Z",
            deleted_reports: staleReports,
            truncated: staleReports > 500,
          });
        }
        throw new Error(`unexpected request ${method} ${url}`);
      },
    );
  });

  it("tells someone who is not a global admin the page is not for them, without asking for data", async () => {
    role = "member";
    renderPage();
    expect(await screen.findByText("Only global admins can see this page.")).toBeInTheDocument();
    expect(calls.some((c) => c.url.includes("/admin/status"))).toBe(false);
    expect(calls.some((c) => c.url.includes("/api/v1/users"))).toBe(false);
  });

  it("shows the totals for the whole server", async () => {
    renderPage();
    const read = (label: string) => screen.getByText(label).previousElementSibling;
    await screen.findByText("open findings");
    expect(read("projects")).toHaveTextContent("6");
    expect(read("people")).toHaveTextContent("23");
    expect(read("open findings")).toHaveTextContent("214");
    expect(read("reports")).toHaveTextContent("1,382");
    expect(screen.getByText(`Oldest finished report: ${formatDate("2025-03-04T00:00:00Z")}.`))
      .toBeInTheDocument();
  });

  describe("people", () => {
    it("lists everyone, marks you, and shows who is deactivated", async () => {
      renderPage();
      const list = await screen.findByRole("list", { name: "People" });
      const rows = within(list).getAllByRole("listitem");
      expect(rows).toHaveLength(3);
      expect(rows[0]).toHaveTextContent("Ada Okafor");
      expect(rows[0]).toHaveTextContent("(you)");
      expect(rows[0]).toHaveTextContent("That is you");
      expect(within(rows[0]!).getByRole("combobox", { name: "Role of Ada Okafor" })).toBeDisabled();
      expect(rows[1]).toHaveTextContent("Active");
      expect(rows[2]).toHaveTextContent("Deactivated");
      expect(within(rows[2]!).getByRole("button", { name: "Reactivate jonas@acme.example" }))
        .toBeInTheDocument();
    });

    it("leaves the system account out, since it is not a person", async () => {
      users = [
        ada,
        { ...lena, id: "u-system", email: "system@specht.local", display_name: "Specht system" },
        lena,
      ];
      renderPage();
      const list = await screen.findByRole("list", { name: "People" });
      expect(within(list).getAllByRole("listitem")).toHaveLength(2);
      expect(within(list).queryByText("Specht system")).not.toBeInTheDocument();
    });

    it("changes a role", async () => {
      const user = userEvent.setup();
      renderPage();
      await chooseOption(
        user,
        await screen.findByRole("combobox", { name: "Role of Lena Brandt" }),
        "Admin",
      );
      await waitFor(() =>
        expect(calls.find((c) => c.method === "PUT" && c.url.endsWith("/users/u-lena/role"))?.body)
          .toEqual({ role: "admin" })
      );
      expect(await screen.findByText("Role changed")).toBeInTheDocument();
    });

    it("asks before deactivating, and does nothing when the question is declined", async () => {
      const user = userEvent.setup();
      renderPage();
      await user.click(await screen.findByRole("button", { name: "Deactivate Lena Brandt" }));
      const dialog = await screen.findByRole("alertdialog", { name: "Deactivate Lena Brandt?" });
      await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
      await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument());
      expect(calls.some((c) => c.url.endsWith("/deactivate"))).toBe(false);

      await user.click(screen.getByRole("button", { name: "Deactivate Lena Brandt" }));
      await user.click(
        within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Deactivate" }),
      );
      await waitFor(() =>
        expect(calls.some((c) => c.method === "POST" && c.url.endsWith("/users/u-lena/deactivate")))
          .toBe(true)
      );
      expect(await screen.findByText("Account deactivated")).toBeInTheDocument();
    });

    it("reactivates without asking", async () => {
      const user = userEvent.setup();
      renderPage();
      await user.click(
        await screen.findByRole("button", { name: "Reactivate jonas@acme.example" }),
      );
      await waitFor(() =>
        expect(
          calls.some((c) => c.method === "POST" && c.url.endsWith("/users/u-jonas/reactivate")),
        )
          .toBe(true)
      );
    });

    it("relays the server's refusal, for example for the last admin", async () => {
      writeError = { code: "last_admin", message: "the last active admin cannot be demoted" };
      const user = userEvent.setup();
      renderPage();
      await chooseOption(
        user,
        await screen.findByRole("combobox", { name: "Role of Lena Brandt" }),
        "Admin",
      );
      expect(await screen.findByRole("alert")).toHaveTextContent(
        "the last active admin cannot be demoted",
      );
    });

    it("finds people by email and asks the server, not the page", async () => {
      const user = userEvent.setup();
      renderPage();
      await screen.findByRole("list", { name: "People" });
      users = [lena];
      await user.type(screen.getByRole("searchbox", { name: "Find a person by email" }), "lena");
      await waitFor(() =>
        expect(calls.some((c) => c.url.includes("/api/v1/users?") && c.url.includes("email=lena")))
          .toBe(true)
      );
      await waitFor(() =>
        expect(within(screen.getByRole("list", { name: "People" })).getAllByRole("listitem"))
          .toHaveLength(1)
      );
    });

    it("says when nobody matches", async () => {
      const user = userEvent.setup();
      renderPage();
      await screen.findByRole("list", { name: "People" });
      users = [];
      await user.type(screen.getByRole("searchbox", { name: "Find a person by email" }), "zzz");
      expect(await screen.findByText("Nobody has an email that contains that."))
        .toBeInTheDocument();
    });

    it("offers more when a full page came back", async () => {
      users = Array.from({ length: 50 }, (_, i) => ({
        ...lena,
        id: `u-${i}`,
        email: `p${i}@acme.example`,
        display_name: `Person ${i}`,
      }));
      const user = userEvent.setup();
      renderPage();
      await user.click(await screen.findByRole("button", { name: "Show more" }));
      await waitFor(() => expect(calls.some((c) => c.url.includes("limit=100"))).toBe(true));
    });
  });

  describe("CVE watcher", () => {
    it("is healthy after a good poll", async () => {
      renderPage();
      expect(await screen.findByText("Healthy")).toBeInTheDocument();
      expect(screen.getByText("Failures in a row").nextElementSibling).toHaveTextContent("0");
      expect(screen.queryByText("Last error")).not.toBeInTheDocument();
    });

    it("shows the error when polls fail", async () => {
      health = {
        ...healthy,
        consecutive_failures: 3,
        healthy: false,
        last_error: "nvd: 503 service unavailable",
      };
      renderPage();
      expect(await screen.findByText("Failing")).toBeInTheDocument();
      expect(screen.getByText("nvd: 503 service unavailable")).toBeInTheDocument();
      expect(screen.getByText(/3 polls in a row failed/)).toBeInTheDocument();
    });
  });

  describe("old reports", () => {
    it("counts what the window would remove, and asks before removing it", async () => {
      const user = userEvent.setup();
      renderPage();
      expect(await screen.findByText("214 reports would be removed")).toBeInTheDocument();
      await user.click(screen.getByRole("button", { name: "Remove them…" }));
      const dialog = await screen.findByRole("alertdialog", { name: "Remove 214 reports?" });
      expect(dialog).toHaveTextContent(formatDate("2025-10-12T00:00:00Z"));
      await user.click(within(dialog).getByRole("button", { name: "Remove" }));
      await waitFor(() =>
        expect(calls.find((c) => c.url.endsWith("/retention/purge"))?.body).toEqual({
          older_than_days: 365,
        })
      );
      expect(await screen.findByText("Removed 214 reports")).toBeInTheDocument();
    });

    it("previews again for another window", async () => {
      const user = userEvent.setup();
      renderPage();
      await screen.findByText("214 reports would be removed");
      staleReports = 1;
      await chooseOption(user, screen.getByRole("combobox", { name: "Older than" }), "90 days");
      expect(await screen.findByText("1 report would be removed")).toBeInTheDocument();
      expect(calls.some((c) => c.url.includes("retention/preview?days=90"))).toBe(true);
    });

    it("has nothing to do when no report is old enough", async () => {
      staleReports = 0;
      renderPage();
      expect(await screen.findByText("Nothing to remove")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Remove them…" })).toBeDisabled();
    });

    it("says when one run was not enough", async () => {
      staleReports = 600;
      const user = userEvent.setup();
      renderPage();
      await user.click(await screen.findByRole("button", { name: "Remove them…" }));
      await user.click(
        within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Remove" }),
      );
      expect(await screen.findByText(/Run it again for the rest/)).toBeInTheDocument();
    });
  });

  it("offers a retry when the totals cannot be loaded, and keeps the rest of the page", async () => {
    statusFails = true;
    renderPage();
    expect(await screen.findByText("Could not load the totals.")).toBeInTheDocument();
    expect(await screen.findByRole("list", { name: "People" })).toBeInTheDocument();
  });
});
