import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FindingsDashboard } from "./FindingsDashboard";

let findingsFixture: Array<Record<string, unknown>>;
let gateFixture: Record<string, unknown>;

beforeEach(() => {
  gateFixture = { blocked_by: [] };
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
  globalThis.fetch = vi.fn().mockImplementation(async (input) => {
    if (String(input).endsWith("/gate")) {
      return jsonResponse(gateFixture);
    }
    return jsonResponse(findingsFixture);
  });
});

function renderWithProviders(ui: React.ReactElement, initialPath = "/test-project/findings") {
  const qc = createTestQueryClient();
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

  it("offers None as a severity filter and requests severity=none", async () => {
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      if (String(input).endsWith("/gate")) return jsonResponse(gateFixture);
      const url = new URL(String(input), "http://localhost");
      return jsonResponse(url.searchParams.get("severity") === "none" ? [] : findingsFixture);
    });
    renderWithProviders(<FindingsDashboard />);
    const user = userEvent.setup();

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    const severity = screen.getByRole("combobox", { name: "Filter by severity" });
    expect(within(severity).getByRole("option", { name: "None" })).toBeInTheDocument();

    await user.selectOptions(severity, "none");

    expect(await screen.findByText("No findings match these filters.")).toBeInTheDocument();
    expect(String(vi.mocked(globalThis.fetch).mock.calls.at(-1)?.[0])).toContain("severity=none");
  });

  it("offers DAST as a finding kind filter and requests kind=dast", async () => {
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      if (String(input).endsWith("/gate")) return jsonResponse(gateFixture);
      const url = new URL(String(input), "http://localhost");
      return jsonResponse(url.searchParams.get("kind") === "dast" ? [] : findingsFixture);
    });
    renderWithProviders(<FindingsDashboard />);
    const user = userEvent.setup();

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    const kind = screen.getByRole("combobox", { name: "Filter by finding type" });
    expect(within(kind).getByRole("option", { name: "DAST" })).toBeInTheDocument();

    await user.selectOptions(kind, "dast");

    expect(await screen.findByText("No findings match these filters.")).toBeInTheDocument();
    expect(String(vi.mocked(globalThis.fetch).mock.calls.at(-1)?.[0])).toContain("kind=dast");
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

  it("sorts a none-severity finding below low, not with unknown values", async () => {
    findingsFixture = [
      { ...findingsFixture[0], id: "f1", current_title: "No severity", current_severity: "none" },
      { ...findingsFixture[0], id: "f2", current_title: "Low severity", current_severity: "low" },
      {
        ...findingsFixture[0],
        id: "f3",
        current_title: "Unknown severity",
        current_severity: "unknown",
      },
    ];
    renderWithProviders(<FindingsDashboard />);
    const user = userEvent.setup();

    await screen.findByText("No severity");
    const rows = () => within(screen.getByRole("table")).getAllByRole("row").slice(1);
    // Default sort is severity descending: low(1), none(0), unknown(-1).
    expect(rows()[0]).toHaveTextContent("Low severity");
    expect(rows()[1]).toHaveTextContent("No severity");
    expect(rows()[2]).toHaveTextContent("Unknown severity");

    const severity = screen.getByRole("columnheader", { name: /Severity/ });
    await user.click(within(severity).getByRole("button", { name: /Severity/ }));

    expect(rows()[0]).toHaveTextContent("Unknown severity");
    expect(rows()[1]).toHaveTextContent("No severity");
    expect(rows()[2]).toHaveTextContent("Low severity");
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
    expect(screen.queryByText(EMPTY_PROJECT_HINT)).not.toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();

    const previous = screen.getByRole("button", { name: "Previous" });
    expect(previous).toBeEnabled();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();

    await userEvent.setup().click(previous);

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    expect(String(vi.mocked(globalThis.fetch).mock.calls.at(-1)?.[0])).toContain("offset=0");
  });

  it("explains where findings come from when the first page of an unfiltered project is empty", async () => {
    vi.mocked(globalThis.fetch).mockResolvedValue(jsonResponse([]));
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("No findings found")).toBeInTheDocument();
    expect(screen.getByText(EMPTY_PROJECT_HINT)).toBeInTheDocument();
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
    let findingsFailures = 1;
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      if (String(input).endsWith("/gate")) return jsonResponse(gateFixture);
      if (findingsFailures-- > 0) throw new Error("Findings service unavailable");
      return jsonResponse([]);
    });
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("Findings service unavailable")).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("No findings found")).toBeInTheDocument();
  });

  it("marks a gate-blocked finding with a Yes chip", async () => {
    gateFixture = { blocked_by: ["f1"] };
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    const cell = gateCell();
    expect(cell).toHaveTextContent("Yes");
    expect(cell.querySelector("span")).toHaveClass("bg-sev-critical-bg", "text-sev-critical-fg");
  });

  it("explains an ignored and a below-floor finding in the gate column", async () => {
    findingsFixture = [
      { ...findingsFixture[0], id: "f1", current_title: "Ignored finding", gate_effect: "ignore" },
      {
        ...findingsFixture[0],
        id: "f2",
        current_title: "Below floor finding",
        current_severity: "low",
      },
    ];
    gateFixture = { blocked_by: [], policy: { severity_floor: "high" } };
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("Ignored finding")).toBeInTheDocument();
    expect(screen.getByText("No (ignored by triage)")).toBeInTheDocument();
    expect(screen.getByText("No (below the floor)")).toBeInTheDocument();
  });

  it("shows a dash in the gate column while the gate is still loading", async () => {
    vi.mocked(globalThis.fetch).mockImplementation((input) => {
      if (String(input).endsWith("/gate")) return new Promise<Response>(() => {});
      return Promise.resolve(jsonResponse(findingsFixture));
    });
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    expect(gateCell()).toHaveTextContent("–");
  });
});

describe("FindingsDashboard links and table semantics", () => {
  it("renders the finding title as a real link to its detail page", async () => {
    renderWithDetailRoute();

    const link = await screen.findByRole("link", { name: "Test Vuln" });
    expect(link).toHaveAttribute("href", "/test-project/findings/f1");
  });

  it("passes the current list search to the detail page as router state", async () => {
    renderWithDetailRoute("/test-project/findings?severity=high&offset=20");

    await userEvent.setup().click(await screen.findByRole("link", { name: "Test Vuln" }));

    expect(await screen.findByTestId("detail-state")).toHaveTextContent(
      JSON.stringify({ from: "?severity=high&offset=20" }),
    );
  });

  it("passes an empty search string when the list has no filters", async () => {
    renderWithDetailRoute();

    await userEvent.setup().click(await screen.findByRole("link", { name: "Test Vuln" }));

    expect(await screen.findByTestId("detail-state")).toHaveTextContent(
      JSON.stringify({ from: "" }),
    );
  });

  it("opens the finding when the row itself is clicked", async () => {
    renderWithDetailRoute();

    await userEvent.setup().click(
      within(await screen.findByRole("row", { name: /Test Vuln/ })).getByText("Open"),
    );

    expect(await screen.findByTestId("detail-state")).toBeInTheDocument();
  });

  it("opens the finding once, not twice, when the title link is clicked", async () => {
    renderWithDetailRoute();
    const user = userEvent.setup();

    await user.click(await screen.findByRole("link", { name: "Test Vuln" }));

    expect(await screen.findByTestId("detail-state")).toBeInTheDocument();
    expect(screen.getAllByTestId("detail-state")).toHaveLength(1);
  });

  it("leaves modifier clicks to the browser instead of navigating the row", async () => {
    renderWithDetailRoute();
    const user = userEvent.setup();
    const cell = within(await screen.findByRole("row", { name: /Test Vuln/ })).getByText("Open");

    await user.keyboard("{Control>}");
    await user.click(cell);
    await user.keyboard("{/Control}");

    expect(screen.queryByTestId("detail-state")).not.toBeInTheDocument();
  });

  it("does not navigate when the user is selecting text in the row", async () => {
    renderWithDetailRoute();
    const user = userEvent.setup();
    const cell = within(await screen.findByRole("row", { name: /Test Vuln/ })).getByText("Open");
    vi.spyOn(window, "getSelection").mockReturnValue(
      { toString: () => "Open" } as unknown as Selection,
    );

    await user.click(cell);

    expect(screen.queryByTestId("detail-state")).not.toBeInTheDocument();
  });

  it("lets keyboard users reach the title link and open it with Enter", async () => {
    renderWithDetailRoute();
    const user = userEvent.setup();
    const link = await screen.findByRole("link", { name: "Test Vuln" });

    link.focus();
    await user.keyboard("{Enter}");

    expect(await screen.findByTestId("detail-state")).toBeInTheDocument();
  });

  it("gives the table a caption and scoped column headers", async () => {
    renderWithDetailRoute();

    const table = await screen.findByRole("table", { name: "Findings" });
    const headers = within(table).getAllByRole("columnheader");
    expect(headers.length).toBeGreaterThan(0);
    for (const header of headers) expect(header).toHaveAttribute("scope", "col");
  });

  it("shows the kind as a neutral chip rather than a hue that collides with severity", async () => {
    renderWithDetailRoute();

    const chip = await screen.findByText("sca");
    expect(chip.className).toContain("bg-muted");
    expect(chip.className).not.toMatch(/blue|purple|amber|rose/);
  });
});

const EMPTY_PROJECT_HINT = "Findings appear here once a report is uploaded or sent from CI.";

function DetailState() {
  const location = useLocation();
  return <div data-testid="detail-state">{JSON.stringify(location.state)}</div>;
}

function renderWithDetailRoute(initialPath = "/test-project/findings") {
  const qc = createTestQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route path="/:slug/findings" element={<FindingsDashboard />} />
          <Route path="/:slug/findings/:findingId" element={<DetailState />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function gateCell(): HTMLElement {
  const rows = within(screen.getByRole("table")).getAllByRole("row");
  return within(rows[1]).getAllByRole("cell")[5];
}
