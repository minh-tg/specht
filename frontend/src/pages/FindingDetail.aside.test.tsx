import { Toaster } from "@/components/ui/sonner";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FindingDetail } from "./FindingDetail";

let finding: Record<string, unknown>;
let gate: Record<string, unknown>;
let permissions: Record<string, boolean>;
let pendingWaivers: unknown[];
let calls: Array<{ url: string; method: string; body: string; }>;

beforeEach(() => {
  finding = {
    id: "f1",
    project_id: "p1",
    finding_kind: "sca",
    fingerprint: "fp1",
    current_title: "openssh-server: security issue",
    current_severity: "critical",
    current_score: 9.8,
    state: "open",
    triage_status: "untriaged",
    analysis_state: "unanalyzed",
    gate_effect: "block",
    first_seen_at: "2025-01-01T00:00:00Z",
    last_seen_at: "2025-01-02T00:00:00Z",
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
    remediation: { summary: "Upgrade openssh-server to 9.6p1-3" },
    intel: { cve_id: "CVE-2025-20006", epss: 0.71, kev: true },
  };
  gate = { blocked_by: ["f1"], policy: { severity_floor: "high" } };
  permissions = { request_waiver: true, triage: true };
  pendingWaivers = [];
  calls = [];
  globalThis.fetch = vi.fn().mockImplementation(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), "http://localhost");
      const method = (init?.method ?? "GET").toUpperCase();
      calls.push({ url: url.pathname + url.search, method, body: String(init?.body ?? "") });
      if (url.pathname.endsWith("/waivers/requests")) {
        return jsonResponse({ id: "w1", status: "pending", targets: [] }, 201);
      }
      if (url.pathname.endsWith("/waivers")) return jsonResponse(pendingWaivers);
      if (url.pathname.endsWith("/gate")) return jsonResponse(gate);
      if (url.pathname.endsWith("/events") || url.pathname.endsWith("/reachability")) {
        return jsonResponse([]);
      }
      if (url.pathname === "/api/v1/projects/payments") {
        return jsonResponse({ id: "p1", slug: "payments", name: "payments", permissions });
      }
      if (url.pathname === "/api/v1/findings/f1") return jsonResponse(finding);
      return jsonResponse({});
    },
  );
});

function renderDetail() {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <MemoryRouter initialEntries={["/payments/findings/f1"]}>
        <Routes>
          <Route path="/:slug/findings/:findingId" element={<FindingDetail />} />
        </Routes>
      </MemoryRouter>
      <Toaster />
    </QueryClientProvider>,
  );
}

describe("the finding page's aside and fix", () => {
  it("lists the exploit facts when a feed knows the CVE", async () => {
    renderDetail();

    const aside = await screen.findByRole("complementary", { name: "About this finding" });
    expect(within(aside).getByText("9.8")).toBeInTheDocument();
    expect(within(aside).getByText("71.0%")).toBeInTheDocument();
    expect(within(aside).getByText("Known exploited").nextElementSibling).toHaveTextContent("Yes");
  });

  it("omits the exploit facts when no feed knows the finding, rather than saying No", async () => {
    delete finding.intel;
    renderDetail();

    const aside = await screen.findByRole("complementary", { name: "About this finding" });
    expect(within(aside).queryByText("Known exploited")).not.toBeInTheDocument();
    expect(within(aside).queryByText("EPSS")).not.toBeInTheDocument();
  });

  it("puts the fix in a box with a copy button", async () => {
    renderDetail();

    expect(await screen.findByText("Upgrade openssh-server to 9.6p1-3")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy fix" })).toBeInTheDocument();
  });

  it("offers a waiver request for a blocking finding to someone who may make one", async () => {
    renderDetail();
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: "Request waiver" }));
    const dialog = await screen.findByRole("dialog", { name: "Request a waiver" });
    await user.type(within(dialog).getByLabelText("Why is this safe to ship?"), "Not reachable");
    await user.click(within(dialog).getByRole("button", { name: "Send request" }));

    const post = calls.find((c) => c.url.endsWith("/waivers/requests"));
    expect(JSON.parse(post?.body ?? "{}").target_ids).toEqual(["f1"]);
  });

  it("does not offer a waiver without the permission, or for a finding that does not block", async () => {
    permissions = { request_waiver: false, triage: false };
    const first = renderDetail();
    await screen.findByRole("complementary", { name: "About this finding" });
    expect(screen.queryByRole("button", { name: "Request waiver" })).not.toBeInTheDocument();
    first.unmount();

    permissions = { request_waiver: true, triage: true };
    gate = { blocked_by: [], policy: { severity_floor: "high" } };
    renderDetail();
    await screen.findByRole("complementary", { name: "About this finding" });
    expect(screen.queryByRole("button", { name: "Request waiver" })).not.toBeInTheDocument();
  });

  it("says a request is waiting instead of offering another one", async () => {
    pendingWaivers = [{ id: "w1", status: "pending", targets: [{ id: "t1", finding_id: "f1" }] }];
    renderDetail();

    expect(await screen.findByText(/Waiver requested\. A manager will decide/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Request waiver" })).not.toBeInTheDocument();
  });
});
