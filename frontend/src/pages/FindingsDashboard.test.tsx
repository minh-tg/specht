import { formatDate } from "@/lib/format";
import { chooseOption, createTestQueryClient, jsonResponse, listOptions } from "@/test/utils";
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

/** The calls that asked for findings, as URLs, oldest first. */
function findingsRequests(): URL[] {
  return vi.mocked(globalThis.fetch).mock.calls
    .map(([input]) => new URL(String(input), "http://localhost"))
    .filter((url) => url.pathname.endsWith("/findings"));
}

function lastFindingsRequest(): URL {
  return findingsRequests().at(-1) as URL;
}

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
    const status = screen.getByRole("status", { name: "Loading findings" });
    expect(status).toHaveAttribute("aria-busy", "true");
  });

  it("renders findings after loading", async () => {
    renderWithProviders(<FindingsDashboard />);
    const title = await screen.findByText("Test Vuln");
    expect(title).toBeInTheDocument();
    expect(within(screen.getByRole("grid")).getByText("SCA")).toBeInTheDocument();
  });

  it("labels analysis_state instead of rendering the raw enum", async () => {
    findingsFixture[0].analysis_state = "accepted_risk";
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    expect(screen.getByText("Accepted risk")).toBeInTheDocument();
    expect(screen.queryByText("accepted_risk")).not.toBeInTheDocument();
  });

  it("says Open in the State column for a finding nobody has dealt with", async () => {
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    expect(stateCell()).toHaveTextContent("Open");
    expect(stateCell().querySelector("[data-open]")).toHaveAttribute("data-open", "true");
  });

  it("names the triage decision in the State column once someone has made one", async () => {
    findingsFixture[0].analysis_state = "accepted_risk";
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    expect(stateCell()).toHaveTextContent("Accepted risk");
    expect(stateCell().querySelector("[data-open]")).toHaveAttribute("data-open", "false");
  });

  it("says Waived when the gate says an approved waiver covers the finding", async () => {
    gateFixture = { blocked_by: [], waived_finding_ids: ["f1"] };
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    await waitFor(() => expect(stateCell()).toHaveTextContent("Waived"));
  });

  it("says Fixed for a finding a scan has closed", async () => {
    findingsFixture[0].state = "fixed";
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    expect(stateCell()).toHaveTextContent("Fixed");
  });
  it("renders a controlled label when analysis_state is unvalidated", async () => {
    findingsFixture[0].analysis_state = "pending_review";
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    expect(screen.queryByText("pending_review")).not.toBeInTheDocument();
    expect(stateCell()).toHaveTextContent("Unknown");
  });
  it("labels technical state instead of rendering the raw enum", async () => {
    findingsFixture[0].state = "reopened";
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    // The narrow-screen line repeats the technical state in words.
    expect(screen.getByText(/Reopened/)).toBeInTheDocument();
    expect(screen.queryByText("reopened")).not.toBeInTheDocument();
  });
  it("renders a controlled label when technical state is unvalidated", async () => {
    findingsFixture[0].state = "closed";
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    expect(screen.getByText(/Unknown/)).toBeInTheDocument();
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
    await user.click(screen.getByRole("button", { name: /^Critical/ }));

    expect(await screen.findByText("Critical risk")).toBeInTheDocument();
    expect(screen.queryByText("High risk")).not.toBeInTheDocument();
    expect(lastFindingsRequest().searchParams.get("severity")).toBe("critical");
    expect(lastFindingsRequest().searchParams.get("offset")).toBe("0");
  });

  it.each([
    { name: "Needs triage", analysis: "unanalyzed,in_triage", severity: null },
    { name: "Open critical/high", analysis: null, severity: "critical,high" },
  ])(
    "opens the $name view with one complete request and no old filters or offset",
    async ({ name, analysis, severity }) => {
      renderWithProviders(
        <FindingsDashboard />,
        "/test-project/findings?status=fixed&kind=secret&q=old&analysis_state=accepted_risk&severity=low&offset=40",
      );
      await screen.findByText("Test Vuln");
      const before = findingsRequests().length;
      await userEvent.setup().click(screen.getByRole("link", { name, exact: true }));
      await waitFor(() =>
        expect(lastFindingsRequest().searchParams.get("status")).toBe("open,reopened")
      );
      const query = lastFindingsRequest().searchParams;
      expect(query.get("analysis_state")).toBe(analysis);
      expect(query.get("severity")).toBe(severity);
      expect(query.get("q")).toBeNull();
      expect(query.get("kind")).toBeNull();
      expect(query.get("offset")).toBe("0");
      expect(findingsRequests().length).toBe(before + 1);
      expect(screen.getByRole("combobox", { name: "Filter by status" })).toHaveTextContent(
        "Open or reopened",
      );
    },
  );

  it("combines severity chips into one comma list, in severity order", async () => {
    renderWithProviders(<FindingsDashboard />);
    const user = userEvent.setup();
    await screen.findByText("Test Vuln");

    await user.click(screen.getByRole("button", { name: /^High/ }));
    await user.click(screen.getByRole("button", { name: /^Critical/ }));

    await waitFor(() =>
      expect(lastFindingsRequest().searchParams.get("severity")).toBe("critical,high")
    );
    expect(screen.getByRole("button", { name: /^High/ })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: /^Medium/ })).toHaveAttribute(
      "aria-pressed",
      "false",
    );

    await user.click(screen.getByRole("button", { name: /^High/ }));
    await waitFor(() =>
      expect(lastFindingsRequest().searchParams.get("severity")).toBe("critical")
    );
  });

  it("shows how many open findings each severity holds on its chip", async () => {
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith("/stats")) {
        return jsonResponse({
          total_findings: 14,
          blocking_count: 3,
          waiver_count: 0,
          report_count: 1,
          by_severity: [
            { severity: "critical", count: 2, blocking_count: 2 },
            { severity: "high", count: 5, blocking_count: 1 },
            { severity: "low", count: 7, blocking_count: 0 },
          ],
        });
      }
      if (url.endsWith("/gate")) return jsonResponse(gateFixture);
      return jsonResponse(findingsFixture);
    });
    renderWithProviders(<FindingsDashboard />);

    expect(await screen.findByRole("button", { name: "Critical 2 open" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "High 5 open" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Low 7 open" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Medium" })).toBeInTheDocument();
  });
  it("offers Unrated as a severity filter when something is unrated, and requests severity=unknown", async () => {
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = new URL(String(input), "http://localhost");
      if (url.pathname.endsWith("/gate")) return jsonResponse(gateFixture);
      if (url.pathname.endsWith("/stats")) {
        return jsonResponse({
          total_findings: 1,
          blocking_count: 0,
          waiver_count: 0,
          report_count: 1,
          by_severity: [{ severity: "unknown", count: 1, blocking_count: 0 }],
        });
      }
      return jsonResponse(url.searchParams.get("severity") === "unknown" ? [] : findingsFixture);
    });
    renderWithProviders(<FindingsDashboard />);
    const user = userEvent.setup();

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /None/ })).not.toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: /^Unrated/ }));

    expect(await screen.findByText("No findings match these filters.")).toBeInTheDocument();
    expect(String(vi.mocked(globalThis.fetch).mock.calls.at(-1)?.[0])).toContain(
      "severity=unknown",
    );
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
    expect(await listOptions(user, kind)).toContain("DAST");

    await chooseOption(user, kind, "DAST");

    expect(await screen.findByText("No findings match these filters.")).toBeInTheDocument();
    expect(String(vi.mocked(globalThis.fetch).mock.calls.at(-1)?.[0])).toContain("kind=dast");
  });

  it("asks the server to sort by a column and flips the direction on a second click", async () => {
    renderWithProviders(<FindingsDashboard />);
    const user = userEvent.setup();
    await screen.findByText("Test Vuln");
    expect(lastFindingsRequest().searchParams.get("sort")).toBe("severity");
    expect(lastFindingsRequest().searchParams.get("dir")).toBe("desc");

    const titleButton = within(screen.getByRole("columnheader", { name: /Finding/ })).getByRole(
      "button",
      { name: /Finding/ },
    );
    await user.click(titleButton);
    await waitFor(() => expect(lastFindingsRequest().searchParams.get("sort")).toBe("title"));
    expect(lastFindingsRequest().searchParams.get("dir")).toBe("asc");

    await user.click(titleButton);
    await waitFor(() => expect(lastFindingsRequest().searchParams.get("dir")).toBe("desc"));
  });

  it("starts each column in the direction that answers what to look at first", async () => {
    renderWithProviders(<FindingsDashboard />);
    const user = userEvent.setup();
    await screen.findByText("Test Vuln");

    const sortBy = async (header: RegExp) => {
      await user.click(
        within(screen.getByRole("columnheader", { name: header })).getByRole("button", {
          name: header,
        }),
      );
    };
    await sortBy(/Age/);
    await waitFor(() => expect(lastFindingsRequest().searchParams.get("sort")).toBe("first_seen"));
    expect(lastFindingsRequest().searchParams.get("dir")).toBe("asc");

    // The default view was fetched a moment ago, so it comes from the cache without a request.
    await sortBy(/Severity/);
    await waitFor(() =>
      expect(screen.getByRole("columnheader", { name: /Severity/ })).toHaveAttribute(
        "aria-sort",
        "descending",
      )
    );
  });
  it("shows the rows in the order the server returns them", async () => {
    // The server orders the whole result. The page must not reorder its own twenty rows.
    findingsFixture = [
      { ...findingsFixture[0], id: "f1", current_title: "Zebra", current_severity: "low" },
      { ...findingsFixture[0], id: "f2", current_title: "Alpha", current_severity: "critical" },
      { ...findingsFixture[0], id: "f3", current_title: "Mystery", current_severity: "unknown" },
    ];
    renderWithProviders(<FindingsDashboard />);

    await screen.findByText("Zebra");
    const titles = within(screen.getByRole("grid")).getAllByRole("link").map((l) => l.textContent);
    expect(titles).toEqual(["Zebra", "Alpha", "Mystery"]);
  });
  it("labels an unrecognised kind instead of echoing the wire value", async () => {
    findingsFixture[0].finding_kind = "<img src=x>";
    renderWithProviders(<FindingsDashboard />);

    await screen.findByText("Test Vuln");
    expect(within(screen.getByRole("grid")).getAllByText("Unknown").length).toBeGreaterThan(0);
    expect(screen.queryByText("<img src=x>")).not.toBeInTheDocument();
  });

  it("repeats the narrow-screen columns as one line under the title", async () => {
    findingsFixture[0].analysis_state = "accepted_risk";
    renderWithProviders(<FindingsDashboard />);

    await screen.findByText("Test Vuln");
    const row = within(screen.getByRole("grid")).getAllByRole("row")[1];
    expect(row).toHaveTextContent(
      `SCA · Open · Accepted risk · Last seen ${formatDate("2025-01-01T00:00:00Z")}`,
    );
  });

  it("offers a sort control for narrow screens that covers age and last seen", async () => {
    renderWithProviders(<FindingsDashboard />);
    const user = userEvent.setup();

    await screen.findByText("Test Vuln");
    const sort = screen.getByRole("combobox", { name: "Sort findings" });
    expect(sort).toHaveTextContent("Most severe first");

    await chooseOption(user, sort, "Last seen, newest first");
    await waitFor(() => expect(lastFindingsRequest().searchParams.get("sort")).toBe("last_seen"));
    expect(lastFindingsRequest().searchParams.get("dir")).toBe("desc");

    await chooseOption(user, sort, "Oldest first");
    await waitFor(() => expect(lastFindingsRequest().searchParams.get("sort")).toBe("first_seen"));
    expect(lastFindingsRequest().searchParams.get("dir")).toBe("asc");
    expect(sort).toHaveTextContent("Oldest first");
  });
  it("exposes the sort direction on every sortable header", async () => {
    renderWithProviders(<FindingsDashboard />);
    await screen.findByText("Test Vuln");
    const user = userEvent.setup();

    const severityHeader = screen.getByRole("columnheader", { name: /Severity/ });
    const titleHeader = screen.getByRole("columnheader", { name: /Finding/ });
    const ageHeader = screen.getByRole("columnheader", { name: /Age/ });

    expect(severityHeader).toHaveAttribute("aria-sort", "descending");
    expect(titleHeader).toHaveAttribute("aria-sort", "none");
    expect(ageHeader).toHaveAttribute("aria-sort", "none");
    expect(screen.queryByText(/Sorting applies only/)).not.toBeInTheDocument();

    const titleButton = within(titleHeader).getByRole("button", { name: /Finding/ });
    await user.click(titleButton);
    await waitFor(() => expect(titleHeader).toHaveAttribute("aria-sort", "ascending"));
    expect(severityHeader).toHaveAttribute("aria-sort", "none");

    await user.click(titleButton);
    await waitFor(() => expect(titleHeader).toHaveAttribute("aria-sort", "descending"));
  });

  it("searches on the server once typing pauses, not on every key", async () => {
    renderWithProviders(<FindingsDashboard />);
    const user = userEvent.setup();
    await screen.findByText("Test Vuln");
    const before = findingsRequests().length;

    await user.type(screen.getByRole("searchbox", { name: "Search findings" }), "log4j");

    // Nothing has been asked yet for the keys typed one by one.
    expect(findingsRequests().length).toBe(before);
    await waitFor(() => expect(lastFindingsRequest().searchParams.get("q")).toBe("log4j"), {
      timeout: 2000,
    });
    expect(lastFindingsRequest().searchParams.get("offset")).toBe("0");
    expect(findingsRequests().length).toBe(before + 1);
  });

  it("restores the search from the URL and clears it with the filters", async () => {
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = new URL(String(input), "http://localhost");
      if (url.pathname.endsWith("/gate")) return jsonResponse(gateFixture);
      return jsonResponse(url.searchParams.get("q") ? [] : findingsFixture);
    });
    renderWithProviders(<FindingsDashboard />, "/test-project/findings?q=nothing-like-this");
    const user = userEvent.setup();

    expect(screen.getByRole("searchbox", { name: "Search findings" })).toHaveValue(
      "nothing-like-this",
    );
    expect(await screen.findByText("No findings match these filters.")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    expect(screen.getByRole("searchbox", { name: "Search findings" })).toHaveValue("");
  });

  it("filters by triage state, with a ready-made view of what needs triage", async () => {
    renderWithProviders(<FindingsDashboard />);
    const user = userEvent.setup();
    await screen.findByText("Test Vuln");

    await chooseOption(
      user,
      screen.getByRole("combobox", { name: "Filter by triage state" }),
      "Needs triage",
    );
    await waitFor(() =>
      expect(lastFindingsRequest().searchParams.get("analysis_state")).toBe("unanalyzed,in_triage")
    );

    await chooseOption(
      user,
      screen.getByRole("combobox", { name: "Filter by triage state" }),
      "Exploitable",
    );
    await waitFor(() =>
      expect(lastFindingsRequest().searchParams.get("analysis_state")).toBe("exploitable")
    );
  });

  it("shows how old each finding is", async () => {
    findingsFixture[0].first_seen_at = new Date(Date.now() - 12 * 86_400_000).toISOString();
    renderWithProviders(<FindingsDashboard />);

    await screen.findByText("Test Vuln");
    expect(within(screen.getByRole("grid")).getByText("12d")).toBeInTheDocument();
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
    await user.click(screen.getByRole("button", { name: /^Critical/ }));

    expect(await screen.findByText("No findings match these filters.")).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "Filter by severity" })).toBeInTheDocument();
    expect(screen.getByLabelText("Filter by status")).toBeInTheDocument();
    expect(screen.getByLabelText("Filter by finding type")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Clear filters" }));

    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    // The unfiltered page was fetched a moment ago, so it comes from the cache without a request.
    expect(screen.getByRole("button", { name: /^Critical/ })).toHaveAttribute(
      "aria-pressed",
      "false",
    );
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
    await user.click(screen.getByRole("button", { name: /^Critical/ }));

    await waitFor(() => expect(releaseFiltered).toBeDefined());
    expect(screen.getByRole("button", { name: /^Critical/ })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    const region = document.querySelector("[aria-busy]");
    expect(region).toHaveAttribute("aria-busy", "true");
    // Stale rows stay visible instead of collapsing into a skeleton.
    expect(screen.getByText("Test Vuln")).toBeInTheDocument();
    expect(screen.queryByRole("status", { name: "Loading findings" })).not.toBeInTheDocument();

    await act(async () => {
      releaseFiltered?.(jsonResponse([]));
    });

    expect(await screen.findByText("No findings match these filters.")).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "Filter by severity" })).toBeInTheDocument();
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
    expect(screen.queryByRole("grid")).not.toBeInTheDocument();

    const previous = screen.getByRole("button", { name: "Previous page" });
    expect(previous).toBeEnabled();
    expect(screen.getByRole("button", { name: "Next page" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Back to the first page" })).toBeInTheDocument();

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
    expect(screen.queryByRole("button", { name: "Previous page" })).not.toBeInTheDocument();
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
    await user.click(screen.getByRole("button", { name: "Next page" }));

    expect(await screen.findByText("Next page finding")).toBeInTheDocument();
    expect(screen.getByText("21–21")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Previous page" }));
    expect(await screen.findByText("Current finding 0")).toBeInTheDocument();
  });

  it("counts the filtered set so the pager stops at the real last page", async () => {
    const all = Array.from({ length: 45 }, (_, index) => ({
      ...findingsFixture[0],
      id: `f${index}`,
      current_title: `Finding ${index}`,
    }));
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      if (String(input).endsWith("/gate")) return jsonResponse(gateFixture);
      const url = new URL(String(input), "http://localhost");
      const offset = Number.parseInt(url.searchParams.get("offset") ?? "0", 10);
      return new Response(JSON.stringify(all.slice(offset, offset + 20)), {
        status: 200,
        headers: { "Content-Type": "application/json", "X-Total-Count": String(all.length) },
      });
    });
    renderWithProviders(<FindingsDashboard />, "/test-project/findings?offset=20");
    const user = userEvent.setup();

    expect(await screen.findByText("Finding 20")).toBeInTheDocument();
    expect(screen.getByText("21–40 of 45")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next page" })).toBeEnabled();

    await user.click(screen.getByRole("button", { name: "Next page" }));

    expect(await screen.findByText("Finding 40")).toBeInTheDocument();
    expect(screen.getByText("41–45 of 45")).toBeInTheDocument();
    // The total says the list ends here, so a partial page is the last one.
    expect(screen.getByRole("button", { name: "Next page" })).toBeDisabled();
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

  it("gives the grid an accessible name and scoped column headers", async () => {
    renderWithDetailRoute();

    const table = await screen.findByRole("grid", { name: "Findings" });
    const headers = within(table).getAllByRole("columnheader");
    expect(headers.length).toBeGreaterThan(0);
    for (const header of headers) expect(header).toHaveAttribute("scope", "col");
  });

  it("names the kind under the title in plain ink, with no hue that collides with severity", async () => {
    renderWithDetailRoute();

    await screen.findByText("Test Vuln");
    const kind = within(screen.getByRole("grid")).getByText("SCA");
    expect(kind.className).toContain("text-muted-foreground");
    expect(kind.className).not.toMatch(/blue|purple|amber|rose/);
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

/** The State cell of the first row. */
function stateCell(): HTMLElement {
  const table = screen.getByRole("grid");
  const headers = within(table).getAllByRole("columnheader");
  const index = headers.indexOf(within(table).getByRole("columnheader", { name: "State" }));
  const rows = within(table).getAllByRole("row");
  return within(rows[1]).getAllByRole("gridcell")[index];
}
