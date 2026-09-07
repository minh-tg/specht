import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
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

function renderWithProviders(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/test-project/findings"]}>
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
});
