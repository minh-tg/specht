import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
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
    expect(screen.getByText("Accepted risk")).toBeInTheDocument();
    expect(screen.queryByText("accepted_risk")).not.toBeInTheDocument();
  });

  it("shows Not triaged for a finding with no analysis", async () => {
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    expect(screen.getByText("Not triaged")).toBeInTheDocument();
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
    const titleButton = within(title).getByRole("button", { name: /Title/ });
    await user.click(titleButton);
    expect(rows()[0]).toHaveTextContent("Alpha");
    await user.click(titleButton);
    expect(rows()[0]).toHaveTextContent("Zebra");
  });

  it("exposes the sort direction on every sortable header", async () => {
    renderWithProviders(<FindingsDashboard />);
    await screen.findByText("Test Vuln");
    const user = userEvent.setup();

    const severityHeader = screen.getByRole("columnheader", { name: /Severity/ });
    const titleHeader = screen.getByRole("columnheader", { name: /Title/ });
    const lastSeenHeader = screen.getByRole("columnheader", { name: /Last Seen/ });

    expect(severityHeader).toHaveAttribute("aria-sort", "descending");
    expect(titleHeader).toHaveAttribute("aria-sort", "none");
    expect(lastSeenHeader).toHaveAttribute("aria-sort", "none");
    expect(
      screen.getByText("Sorting applies only to the findings on this page."),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Sorting applies to the 20/)).not.toBeInTheDocument();

    const titleButton = within(titleHeader).getByRole("button", { name: /Title/ });
    await user.click(titleButton);
    expect(titleHeader).toHaveAttribute("aria-sort", "ascending");
    expect(severityHeader).toHaveAttribute("aria-sort", "none");

    await user.click(titleButton);
    expect(titleHeader).toHaveAttribute("aria-sort", "descending");
  });

  it("keeps the filters reachable when they match nothing and clears them on demand", async () => {
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = new URL(String(input), "http://localhost");
      return jsonResponse(
        url.searchParams.get("severity") === "critical" ? [] : findingsFixture,
      );
    });
    renderWithProviders(<FindingsDashboard />);
    const user = userEvent.setup();

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Filter by severity"), "critical");

    expect(await screen.findByText("No findings match these filters.")).toBeInTheDocument();
    expect(screen.getByLabelText("Filter by severity")).toBeInTheDocument();
    expect(screen.getByLabelText("Filter by status")).toBeInTheDocument();
    expect(screen.getByLabelText("Filter by finding type")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Clear filters" }));

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    await waitFor(() => {
      expect(String(vi.mocked(globalThis.fetch).mock.calls.at(-1)?.[0])).not.toContain(
        "severity=critical",
      );
    });
    expect(String(vi.mocked(globalThis.fetch).mock.calls.at(-1)?.[0])).toContain("offset=0");
  });

  it("keeps the filter controls mounted while a filtered refetch is pending", async () => {
    let releaseFiltered: ((response: Response) => void) | undefined;
    vi.mocked(globalThis.fetch).mockImplementation((input) => {
      const url = new URL(String(input), "http://localhost");
      if (url.searchParams.get("severity") === "critical") {
        return new Promise<Response>((resolve) => {
          releaseFiltered = resolve;
        });
      }
      return Promise.resolve(jsonResponse(findingsFixture));
    });
    renderWithProviders(<FindingsDashboard />);
    const user = userEvent.setup();

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Filter by severity"), "critical");

    await waitFor(() => expect(releaseFiltered).toBeDefined());
    expect(screen.getByLabelText("Filter by severity")).toHaveValue("critical");
    const region = document.querySelector("[aria-busy]");
    expect(region).toHaveAttribute("aria-busy", "true");
    expect(region?.className).toContain("opacity-60");
    // Stale rows stay visible instead of collapsing into a skeleton.
    expect(screen.getByText("Test Vuln")).toBeInTheDocument();
    expect(document.querySelectorAll(".animate-pulse")).toHaveLength(0);

    await act(async () => {
      releaseFiltered?.(jsonResponse([]));
    });

    expect(await screen.findByText("No findings match these filters.")).toBeInTheDocument();
    expect(screen.getByLabelText("Filter by severity")).toBeInTheDocument();
  });

  it("does not claim the project is empty when the user paged past the last page", async () => {
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = new URL(String(input), "http://localhost");
      return jsonResponse(url.searchParams.get("offset") === "20" ? [] : findingsFixture);
    });
    renderWithProviders(<FindingsDashboard />, "/test-project/findings?offset=20");

    expect(await screen.findByText("No more results.")).toBeInTheDocument();
    expect(screen.queryByText("No findings found")).not.toBeInTheDocument();
    expect(screen.queryByText("Ingest a scan report to see findings")).not.toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();

    const previous = screen.getByRole("button", { name: "Previous" });
    expect(previous).toBeEnabled();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();

    await userEvent.setup().click(previous);

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    expect(String(vi.mocked(globalThis.fetch).mock.calls.at(-1)?.[0])).toContain("offset=0");
  });

  it("shows the ingest empty copy when the first page of an unfiltered project is empty", async () => {
    vi.mocked(globalThis.fetch).mockResolvedValue(jsonResponse([]));
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("No findings found")).toBeInTheDocument();
    expect(screen.getByText("Ingest a scan report to see findings")).toBeInTheDocument();
    expect(screen.queryByText("No more results.")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Previous" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Clear filters" })).not.toBeInTheDocument();
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
