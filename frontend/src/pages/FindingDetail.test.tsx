import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FindingDetail } from "./FindingDetail";

interface FindingFixture {
  first_seen_at?: string;
  last_seen_at?: string;
  context?: { source_link?: string; };
}

let findingFixture: FindingFixture;
let triageCalls: Array<{ url: string; body: string; }>;

function makeFinding(overrides: FindingFixture = {}): Record<string, unknown> {
  return {
    id: "f1",
    project_id: "p1",
    finding_kind: "sca",
    fingerprint: "fp1",
    current_title: "Test Vulnerability",
    current_severity: "high",
    current_score: null,
    state: "open",
    triage_status: "untriaged",
    analysis_state: "unanalyzed",
    gate_effect: "block",
    first_seen_at: "2025-01-01T00:00:00Z",
    last_seen_at: "2025-01-02T00:00:00Z",
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
    ...overrides,
  };
}

function renderDetail() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/p1/findings/f1"]}>
        <Routes>
          <Route path="/:slug/findings/:findingId" element={<FindingDetail />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  findingFixture = {};
  triageCalls = [];
  globalThis.fetch = vi.fn().mockImplementation(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.endsWith("/reachability") && method === "GET") {
        return { ok: true, json: () => Promise.resolve([]) } as Response;
      }
      if (url.endsWith("/findings/f1") && method === "PATCH") {
        triageCalls.push({ url, body: String(init?.body ?? "") });
        return {
          ok: true,
          json: () =>
            Promise.resolve({
              finding_id: "f1",
              analysis_state: "accepted_risk",
              gate_effect: "ignore",
            }),
        } as Response;
      }
      return { ok: true, json: () => Promise.resolve(makeFinding(findingFixture)) } as Response;
    },
  );
});

describe("FindingDetail dates", () => {
  it("shows a formatted date when first_seen_at is invalid", async () => {
    findingFixture = { first_seen_at: "not-a-date", last_seen_at: "2025-01-02T00:00:00Z" };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    // The invalid value must never render through toLocaleString() (which
    // throws RangeError on an Invalid Date) — the fallback shows instead.
    expect(screen.getByText("–", { exact: true })).toBeInTheDocument();
  });
});

describe("FindingDetail source link", () => {
  it("renders an https link with its hostname visible", async () => {
    findingFixture = {
      context: { source_link: "https://github.com/acme/widget/blob/abc123/main.go" },
    };
    renderDetail();

    const link = await screen.findByRole("link", { name: /github\.com\/acme\/widget/ });
    expect(link).toHaveAttribute("href", "https://github.com/acme/widget/blob/abc123/main.go");
  });

  it("rejects a javascript: source link and shows no anchor", async () => {
    findingFixture = { context: { source_link: "javascript:alert(1)" } };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    // The Back link remains, but no source anchor with the unsafe href may render.
    expect(
      screen.queryByRole("link", { name: /javascript:|data:/i }),
    ).not.toBeInTheDocument();
    expect(document.querySelector("a[href^=\"javascript:\"]")).toBeNull();
  });

  it("rejects a data: source link", async () => {
    findingFixture = {
      context: { source_link: "data:text/html,<script>alert(1)</script>" },
    };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(document.querySelector("a[href^=\"data:\"]")).toBeNull();
  });
});

describe("FindingDetail triage expiry", () => {
  it("blocks accepted_risk until an expiry date is chosen", async () => {
    const user = userEvent.setup();
    renderDetail();
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    const selects = screen.getAllByRole("combobox");
    expect(selects.length).toBeGreaterThanOrEqual(2);
    const triageSelect = selects[0];
    await user.selectOptions(triageSelect, "accepted_risk");
    const apply = screen.getByRole("button", { name: "Apply" });
    expect(apply).toBeDisabled();

    const dateInput = document.querySelector("input[type=\"date\"]");
    expect(dateInput).not.toBeNull();
    await user.type(dateInput as HTMLInputElement, "2025-06-01");
    expect(apply).toBeEnabled();
    await user.click(apply);

    expect(await screen.findByText(/triage saved/i)).toBeInTheDocument();
    expect(triageCalls).toHaveLength(1);
    expect(JSON.parse(triageCalls[0].body)).toEqual({
      analysis_state: "accepted_risk",
      reason: "",
      analysis_expires_at: "2025-06-01T23:59:59.999Z",
    });
  });
});
