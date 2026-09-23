import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FindingsDashboard } from "./FindingsDashboard";

let findingsFixture: Array<Record<string, unknown>>;

beforeEach(() => {
  findingsFixture = [{
    id: "f1",
    project_id: "p1",
    current_title: "Test Vuln",
    current_severity: "high",
    triage_status: "untriaged",
    finding_kind: "sca",
    state: "open",
    analysis_state: "unanalyzed",
    gate_effect: "block",
    last_seen_at: "2025-01-01T00:00:00Z",
    first_seen_at: "2025-01-01T00:00:00Z",
    current_description: null,
    current_remediation: null,
    current_cvss: null,
    cve_id: null,
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
  }];
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve(findingsFixture),
  } as Response);
});

function renderWithProviders(ui: React.ReactElement, initialPath = "/test-project/findings") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route path="/:slug/findings" element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("FindingsDashboard", () => {
  it("shows loading state initially", () => {
    renderWithProviders(<FindingsDashboard />);
    const skeletons = document.querySelectorAll(".animate-pulse");
    expect(skeletons.length).toBeGreaterThan(0);
  });

  it("renders findings after loading", async () => {
    renderWithProviders(<FindingsDashboard />);
    const title = await screen.findByText("Test Vuln");
    expect(title).toBeInTheDocument();
    expect(screen.getByText("sca")).toBeInTheDocument();
  });

  it("labels analysis_state instead of rendering the raw enum", async () => {
    findingsFixture[0].analysis_state = "accepted_risk";
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    expect(screen.getByText("Accepted Risk")).toBeInTheDocument();
    expect(screen.queryByText("accepted_risk")).not.toBeInTheDocument();
  });

  it("renders a controlled chip when analysis_state is unvalidated", async () => {
    findingsFixture[0].analysis_state = "pending_review";
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    expect(screen.queryByText("pending_review")).not.toBeInTheDocument();
    // "Unknown" also exists as a reachability <option>, so assert the chip's text.
    const chip = [...document.querySelectorAll("span")].find(
      (el) => el.textContent === "Unknown" && el.className.includes("rounded"),
    );
    expect(chip).toBeDefined();
  });

  it("labels technical state instead of rendering the raw enum", async () => {
    findingsFixture[0].state = "reopened";
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    const cell = [...document.querySelectorAll("td")].find((el) => el.textContent === "Reopened");
    expect(cell).toBeDefined();
    expect(screen.queryByText("reopened")).not.toBeInTheDocument();
  });

  it("renders a controlled label when technical state is unvalidated", async () => {
    findingsFixture[0].state = "closed";
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    const cell = [...document.querySelectorAll("td")].find((el) => el.textContent === "Unknown");
    expect(cell).toBeDefined();
    expect(screen.queryByText("closed")).not.toBeInTheDocument();
  });

  it("filters findings and resets pagination after a filter changes", async () => {
    findingsFixture = [
      { ...findingsFixture[0], id: "f1", current_title: "High risk", current_severity: "high" },
      {
        ...findingsFixture[0],
        id: "f2",
        current_title: "Critical risk",
        current_severity: "critical",
      },
    ];
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = new URL(String(input), "http://localhost");
      const results = url.searchParams.get("severity") === "critical"
        ? [findingsFixture[1]]
        : findingsFixture;
      return jsonResponse(results);
    });
    renderWithProviders(<FindingsDashboard />, "/test-project/findings?offset=20");
    const user = userEvent.setup();

    expect(await screen.findByText("High risk")).toBeInTheDocument();
    await user.selectOptions(
      screen.getByRole("combobox", { name: "Filter by severity" }),
      "critical",
    );

    expect(await screen.findByText("Critical risk")).toBeInTheDocument();
    expect(screen.queryByText("High risk")).not.toBeInTheDocument();
    expect(vi.mocked(globalThis.fetch).mock.calls.at(-1)?.[0]).toContain("severity=critical");
    expect(vi.mocked(globalThis.fetch).mock.calls.at(-1)?.[0]).toContain("offset=0");
  });

  it("sorts findings in both directions when the title column is selected", async () => {
    findingsFixture = [
      { ...findingsFixture[0], id: "f1", current_title: "Zebra", current_severity: "critical" },
      { ...findingsFixture[0], id: "f2", current_title: "Alpha", current_severity: "low" },
      { ...findingsFixture[0], id: "f3", current_title: "Mystery", current_severity: "unknown" },
    ];
    renderWithProviders(<FindingsDashboard />);
    const user = userEvent.setup();

    await screen.findByText("Zebra");
    const rows = () => within(screen.getByRole("table")).getAllByRole("row").slice(1);
    expect(rows()[0]).toHaveTextContent("Zebra");
    expect(rows().at(-1)).toHaveTextContent("Mystery");

    const title = screen.getByRole("columnheader", { name: /Title/ });
    await user.click(title);
    expect(rows()[0]).toHaveTextContent("Alpha");
    await user.click(title);
    expect(rows()[0]).toHaveTextContent("Zebra");
  });

  it("moves between pages when the current page is full", async () => {
    const firstPage = Array.from({ length: 20 }, (_, index) => ({
      ...findingsFixture[0],
      id: `f${index}`,
      current_title: `Current finding ${index}`,
    }));
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = new URL(String(input), "http://localhost");
      return jsonResponse(
        url.searchParams.get("offset") === "20"
          ? [{ ...findingsFixture[0], id: "next", current_title: "Next page finding" }]
          : firstPage,
      );
    });
    renderWithProviders(<FindingsDashboard />);
    const user = userEvent.setup();

    expect(await screen.findByText("Current finding 0")).toBeInTheDocument();
    expect(screen.getByText("1–20")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next" }));

    expect(await screen.findByText("Next page finding")).toBeInTheDocument();
    expect(screen.getByText("21–21")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Previous" }));
    expect(await screen.findByText("Current finding 0")).toBeInTheDocument();
  });

  it("allows retrying a failed findings request", async () => {
    vi.mocked(globalThis.fetch)
      .mockRejectedValueOnce(new Error("Findings service unavailable"))
      .mockResolvedValue(jsonResponse([]));
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("Findings service unavailable")).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("No findings found")).toBeInTheDocument();
  });
});

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    headers: { "Content-Type": "application/json" },
  });
}
