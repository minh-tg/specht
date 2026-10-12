import { Toaster } from "@/components/ui/sonner";
import { chooseOption, createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FindingsDashboard } from "./FindingsDashboard";

const finding = (id: string, title: string, extra: object = {}) => ({
  id,
  project_id: "p1",
  current_title: title,
  current_severity: "high",
  triage_status: "untriaged",
  finding_kind: "sca",
  state: "open",
  analysis_state: "unanalyzed",
  gate_effect: "block",
  last_seen_at: "2025-01-01T00:00:00Z",
  first_seen_at: "2025-01-01T00:00:00Z",
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-01T00:00:00Z",
  ...extra,
});

let permissions: Record<string, boolean>;
let calls: Array<{ url: string; method: string; body: string; }>;
let bulkAnswer: () => Response;

function renderList(path = "/payments/findings") {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/:slug/findings" element={<FindingsDashboard />} />
        </Routes>
      </MemoryRouter>
      <Toaster />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  permissions = { triage: true, request_waiver: true };
  calls = [];
  bulkAnswer = () =>
    jsonResponse({
      results: [
        { finding_id: "f1", analysis_state: "exploitable", gate_effect: "block" },
        { finding_id: "f2", analysis_state: "exploitable", gate_effect: "block" },
      ],
    });
  globalThis.fetch = vi.fn().mockImplementation(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), "http://localhost");
      const method = (init?.method ?? "GET").toUpperCase();
      calls.push({ url: url.pathname + url.search, method, body: String(init?.body ?? "") });
      if (url.pathname.endsWith("/bulk-analysis")) return bulkAnswer();
      if (url.pathname.endsWith("/waivers/requests")) {
        return jsonResponse({ id: "w1", status: "pending", targets: [] }, 201);
      }
      if (url.pathname.endsWith("/gate")) return jsonResponse({ blocked_by: [] });
      if (url.pathname.endsWith("/stats")) {
        return jsonResponse({
          total_findings: 3,
          blocking_count: 0,
          waiver_count: 0,
          report_count: 1,
          by_severity: [],
        });
      }
      if (url.pathname === "/api/v1/projects/payments") {
        return jsonResponse({ id: "p1", slug: "payments", name: "payments", permissions });
      }
      if (url.pathname.endsWith("/findings")) {
        return jsonResponse([
          finding("f1", "First finding"),
          finding("f2", "Second finding"),
          finding("f3", "Third finding"),
        ]);
      }
      return jsonResponse({});
    },
  );
});

async function selectTwo(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("checkbox", { name: "Select First finding" }));
  await user.click(screen.getByRole("checkbox", { name: "Select Second finding" }));
}

describe("the findings list's selection and bulk actions", () => {
  it("offers no checkboxes to someone who may neither triage nor request waivers", async () => {
    permissions = { triage: false, request_waiver: false };
    renderList();

    await screen.findByText("First finding");
    expect(screen.queryAllByRole("checkbox")).toHaveLength(0);
  });

  it("offers nothing until the server has said what the person may do", async () => {
    globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const path = new URL(String(input), "http://localhost").pathname;
      if (path === "/api/v1/projects/payments") return new Promise<Response>(() => {});
      if (path.endsWith("/findings")) return jsonResponse([finding("f1", "First finding")]);
      return jsonResponse({});
    });
    renderList();

    await screen.findByText("First finding");
    expect(screen.queryAllByRole("checkbox")).toHaveLength(0);
  });

  it("shows the bulk bar with the count as soon as something is selected", async () => {
    renderList();
    const user = userEvent.setup();
    await screen.findByText("First finding");
    expect(screen.queryByRole("region", { name: "Bulk actions" })).not.toBeInTheDocument();

    await selectTwo(user);

    const bar = screen.getByRole("region", { name: "Bulk actions" });
    expect(bar).toHaveTextContent("2 selected");
    expect(within(bar).getByRole("button", { name: "Triage…" })).toBeInTheDocument();
    expect(within(bar).getByRole("button", { name: "Request waiver" })).toBeInTheDocument();
  });

  it("offers only the actions the person may take", async () => {
    permissions = { triage: false, request_waiver: true };
    renderList();
    const user = userEvent.setup();
    await selectTwo(user);

    const bar = screen.getByRole("region", { name: "Bulk actions" });
    expect(within(bar).queryByRole("button", { name: "Triage…" })).not.toBeInTheDocument();
    expect(within(bar).getByRole("button", { name: "Request waiver" })).toBeInTheDocument();
  });

  it("selects the whole page from the header and clears it from the bar", async () => {
    renderList();
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole("checkbox", { name: "Select all findings on this page" }),
    );

    expect(screen.getByRole("region", { name: "Bulk actions" })).toHaveTextContent("3 selected");

    await user.click(screen.getByRole("button", { name: "Clear" }));
    expect(screen.queryByRole("region", { name: "Bulk actions" })).not.toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: "Select First finding" })).not.toBeChecked();
  });

  it("drops the selection when the list changes, because it is a different list", async () => {
    renderList();
    const user = userEvent.setup();
    await selectTwo(user);

    await user.click(screen.getByRole("button", { name: /^Critical/ }));

    await waitFor(() =>
      expect(screen.queryByRole("region", { name: "Bulk actions" })).not.toBeInTheDocument()
    );
  });

  it("applies one decision to everything selected and clears the selection", async () => {
    renderList();
    const user = userEvent.setup();
    await selectTwo(user);
    await user.click(screen.getByRole("button", { name: "Triage…" }));

    const dialog = await screen.findByRole("dialog", { name: "Triage 2 findings" });
    await chooseOption(
      user,
      within(dialog).getByRole("combobox", { name: "Decision" }),
      "Exploitable",
    );
    await user.click(within(dialog).getByRole("button", { name: "Apply to 2 findings" }));

    const post = calls.find((c) => c.method === "POST" && c.url.endsWith("/bulk-analysis"));
    expect(JSON.parse(post?.body ?? "{}")).toEqual({
      finding_ids: ["f1", "f2"],
      analysis_state: "exploitable",
    });
    expect(await screen.findByText("Triage saved for 2 findings")).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.queryByRole("region", { name: "Bulk actions" })).not.toBeInTheDocument()
    );
  });

  it("asks for a reason and an expiry before accepting a risk", async () => {
    renderList();
    const user = userEvent.setup();
    await selectTwo(user);
    await user.click(screen.getByRole("button", { name: "Triage…" }));
    const dialog = await screen.findByRole("dialog", { name: "Triage 2 findings" });
    const apply = within(dialog).getByRole("button", { name: "Apply to 2 findings" });

    expect(apply).toBeDisabled();
    await chooseOption(
      user,
      within(dialog).getByRole("combobox", { name: "Decision" }),
      "Accepted risk",
    );
    expect(apply).toBeDisabled();

    await user.type(within(dialog).getByLabelText("Reason"), "Behind the VPN until the migration");
    expect(apply).toBeDisabled();
    await user.type(within(dialog).getByLabelText("Review again on"), "2026-12-31");
    expect(apply).toBeEnabled();

    await user.click(apply);
    const post = calls.find((c) => c.url.endsWith("/bulk-analysis"));
    const body = JSON.parse(post?.body ?? "{}");
    expect(body.analysis_state).toBe("accepted_risk");
    expect(body.reason).toBe("Behind the VPN until the migration");
    expect(body.analysis_expires_at).toBe("2026-12-31T23:59:59.999Z");
  });

  it("keeps the selection and says why when the server refuses the whole batch", async () => {
    bulkAnswer = () =>
      jsonResponse({
        error: { code: "invalid_analysis", message: "finding f2 cannot take this decision" },
      }, 422);
    renderList();
    const user = userEvent.setup();
    await selectTwo(user);
    await user.click(screen.getByRole("button", { name: "Triage…" }));
    const dialog = await screen.findByRole("dialog", { name: "Triage 2 findings" });
    await chooseOption(
      user,
      within(dialog).getByRole("combobox", { name: "Decision" }),
      "Exploitable",
    );
    await user.click(within(dialog).getByRole("button", { name: "Apply to 2 findings" }));

    expect(await within(dialog).findByRole("alert")).toHaveTextContent("cannot take this decision");
    expect(screen.getByRole("region", { name: "Bulk actions" })).toHaveTextContent("2 selected");
  });

  it("requests one waiver for everything selected", async () => {
    renderList();
    const user = userEvent.setup();
    await selectTwo(user);
    await user.click(screen.getByRole("button", { name: "Request waiver" }));

    const dialog = await screen.findByRole("dialog", { name: "Request a waiver" });
    expect(dialog).toHaveTextContent("2 findings");
    await user.type(
      within(dialog).getByLabelText("Why is this safe to ship?"),
      "Not reachable from the public API",
    );
    await user.click(within(dialog).getByRole("button", { name: "Send request" }));

    const post = calls.find((c) => c.url.endsWith("/waivers/requests"));
    const body = JSON.parse(post?.body ?? "{}");
    expect(body.target_ids).toEqual(["f1", "f2"]);
    expect(body.reason).toBe("Not reachable from the public API");
    await waitFor(() =>
      expect(screen.queryByRole("region", { name: "Bulk actions" })).not.toBeInTheDocument()
    );
  });
});
