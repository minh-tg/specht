import { formatDateTime } from "@/lib/format";
import { createTestQueryClient } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { vi } from "vitest";
import { ReportHistory } from "./ReportHistory";

const REPORTS = [
  {
    id: "r1",
    project_id: "p1",
    tool_name: "trivy",
    tool_version: null,
    scan_type: "filesystem",
    scan_target: "repo/foo",
    status: "completed",
    total_findings: 8,
    branch: "main",
    commit_sha: "abcdef1234567890",
    created_at: "2025-01-01T00:00:00Z",
    completed_at: "2025-01-01T00:01:00Z",
  },
  {
    id: "r2",
    project_id: "p1",
    tool_name: "osv-scanner",
    tool_version: null,
    scan_type: "lockfile",
    scan_target: null,
    status: "pending",
    total_findings: null,
    branch: null,
    commit_sha: null,
    created_at: "2025-01-02T00:00:00Z",
    completed_at: null,
  },
  {
    id: "r3",
    project_id: "p1",
    tool_name: "semgrep",
    tool_version: null,
    scan_type: "filesystem",
    scan_target: null,
    status: "failed",
    total_findings: 1,
    branch: "feature/x",
    commit_sha: "1234567abcdef",
    created_at: "2025-01-03T00:00:00Z",
    completed_at: null,
  },
];

function mockReports(reports: unknown[]) {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve(reports),
  } as Response);
}

function renderWithProviders(ui: React.ReactElement) {
  const qc = createTestQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/test-project/reports"]}>
        <Routes>
          <Route path="/:slug/reports" element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("ReportHistory", () => {
  beforeEach(() => {
    mockReports(REPORTS);
  });

  it("shows loading state initially", () => {
    renderWithProviders(<ReportHistory />);
    const skeletons = document.querySelectorAll(".animate-pulse");
    expect(skeletons.length).toBeGreaterThan(0);
  });

  it("renders statuses, plural labels, dates, branch and commit", async () => {
    renderWithProviders(<ReportHistory />);
    expect(await screen.findByText("trivy")).toBeInTheDocument();
    expect(screen.getByText("osv-scanner")).toBeInTheDocument();
    expect(screen.getByText("semgrep")).toBeInTheDocument();

    // API status enum maps to readable labels; "pending" is "Processing".
    expect(screen.getByText("Completed")).toBeInTheDocument();
    expect(screen.getByText("Processing")).toBeInTheDocument();
    expect(screen.getByText("Failed")).toBeInTheDocument();
    expect(screen.queryByText("processing")).not.toBeInTheDocument();

    // Counts are pluralised: 8 findings, but 1 finding (never "1 findings").
    expect(screen.getByText("8 findings")).toBeInTheDocument();
    expect(screen.getByText("1 finding")).toBeInTheDocument();
    expect(screen.queryByText("1 findings")).not.toBeInTheDocument();

    // Dates go through formatDateTime.
    expect(screen.getByText(formatDateTime("2025-01-01T00:00:00Z"))).toBeInTheDocument();

    // Branch plus the short commit sha, as a muted mono line.
    expect(screen.getByText("main · abcdef1")).toBeInTheDocument();
    expect(screen.getByText("feature/x · 1234567")).toBeInTheDocument();

    // The failed report is visually louder than the others.
    const failedCard = screen.getByText("Failed").closest("div.bg-card");
    expect(failedCard?.className).toContain("border-destructive");
  });

  it("labels a report the server is still processing", async () => {
    // The server stores the unfinished state as `processing`; the API document
    // calls it `pending`. Both read as Processing and neither is echoed raw.
    mockReports([{ ...REPORTS[1], status: "processing" }]);
    renderWithProviders(<ReportHistory />);

    const label = await screen.findByText("Processing");
    expect(label.querySelector(".animate-pulse")).not.toBeNull();
    expect(screen.queryByText("processing")).not.toBeInTheDocument();
  });

  it("does not echo a status outside the vocabulary through the prototype chain", async () => {
    mockReports([{ ...REPORTS[0], status: "constructor" }]);
    renderWithProviders(<ReportHistory />);

    expect(await screen.findByText("constructor")).toBeInTheDocument();
    expect(screen.queryByText("Completed")).not.toBeInTheDocument();
  });

  it("shows an upload report link above the list", async () => {
    renderWithProviders(<ReportHistory />);
    expect(await screen.findByRole("link", { name: "Upload report" })).toHaveAttribute(
      "href",
      "/test-project/reports/upload",
    );
  });

  it("shows an empty state with an upload link", async () => {
    mockReports([]);
    renderWithProviders(<ReportHistory />);

    expect(await screen.findByText("No reports yet.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Upload a report" })).toHaveAttribute(
      "href",
      "/test-project/reports/upload",
    );
  });

  it("shows the error state with a retry", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: () => Promise.resolve({ error: { code: "internal", message: "Boom" } }),
    } as Response);

    renderWithProviders(<ReportHistory />);
    expect(await screen.findByText("Boom")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });
});
