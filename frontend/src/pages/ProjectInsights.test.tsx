import { createTestQueryClient, jsonResponse } from "@/test/utils";
import type { Aging, ProjectStats } from "@/types/api";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ProjectInsights } from "./ProjectInsights";

const baseStats: ProjectStats = {
  total_findings: 14,
  blocking_count: 3,
  waiver_count: 1,
  report_count: 6,
  by_severity: [
    { severity: "critical", count: 2, blocking_count: 2 },
    { severity: "high", count: 5, blocking_count: 1 },
    { severity: "medium", count: 4, blocking_count: 0 },
    { severity: "low", count: 3, blocking_count: 0 },
  ],
  by_analysis_state: [
    { state: "unanalyzed", count: 8 },
    { state: "in_triage", count: 2 },
  ],
};

const baseAging: Aging = {
  buckets: [
    { bucket: "new", count: 3, overdue: 0 },
    { bucket: "aging", count: 4, overdue: 0 },
    { bucket: "stale", count: 5, overdue: 2 },
    { bucket: "debt", count: 2, overdue: 0 },
  ],
  overdue_total: 5,
  overdue: [
    {
      id: "f1",
      title: "openssh-server: security issue",
      severity: "critical",
      age_days: 40,
      sla_days: 7,
      due_date: new Date(Date.now() - 33 * 86_400_000).toISOString(),
      reopened: true,
    },
  ],
  reopened: 1,
  new_per_week: Array.from({ length: 12 }, (_, i) => ({ week: `w${i}`, count: i % 4 })),
  truncated: false,
};

let stats: ProjectStats;
let aging: Aging;
let statsFails: boolean;
let agingFails: boolean;

function renderPage() {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <MemoryRouter initialEntries={["/payments/insights"]}>
        <Routes>
          <Route path="/:slug/insights" element={<ProjectInsights />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("ProjectInsights", () => {
  beforeEach(() => {
    stats = baseStats;
    aging = baseAging;
    statsFails = false;
    agingFails = false;
    globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      const fail = () => jsonResponse({ error: { code: "internal", message: "down" } }, 500);
      if (url.endsWith("/stats")) return statsFails ? fail() : jsonResponse(stats);
      if (url.endsWith("/aging")) return agingFails ? fail() : jsonResponse(aging);
      if (url.endsWith("/environments") || url.endsWith("/targets") || url.endsWith("/artifacts")) {
        return jsonResponse([]);
      }
      throw new Error(`unexpected request ${url}`);
    });
  });

  it("states the headline numbers", async () => {
    renderPage();
    expect(await screen.findByRole("heading", { name: "Insights" })).toBeInTheDocument();
    const read = (label: string) => screen.getByText(label).previousElementSibling;
    expect(await screen.findByText("past their fix date")).toBeInTheDocument();
    expect(read("open findings")).toHaveTextContent("14");
    expect(read("block the gate now")).toHaveTextContent("3");
    expect(read("past their fix date")).toHaveTextContent("5");
    expect(read("waiver in force")).toHaveTextContent("1");
  });

  it("writes each count out and marks the share that blocks the gate", async () => {
    renderPage();
    const severity = await screen.findByRole("list", { name: "Open findings by severity" });
    const rows = within(severity).getAllByRole("listitem");
    expect(rows).toHaveLength(4);
    expect(rows[0]).toHaveTextContent("Critical");
    expect(rows[0]).toHaveTextContent("2, 2 block the gate");
    expect(rows[2]).toHaveTextContent("Medium");
    expect(rows[2]).not.toHaveTextContent("block the gate");
    expect(severity.querySelectorAll("[data-blocking]")).toHaveLength(2);

    const states = screen.getByRole("list", { name: "Open findings by triage state" });
    expect(within(states).getAllByRole("listitem").map((li) => li.textContent)).toEqual([
      "Not triaged8",
      "In triage2",
    ]);
  });

  it("charts age and the weekly trend once the aging numbers arrive", async () => {
    renderPage();
    const ages = await screen.findByRole("list", { name: "Open findings by age" });
    expect(within(ages).getByText("30 to 89 days")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /^New findings per week: 0, 1, 2, 3, 0/ }))
      .toBeInTheDocument();
  });

  it("lists what is past its fix date, with a link to the finding", async () => {
    renderPage();
    const link = await screen.findByRole("link", { name: "Open openssh-server: security issue" });
    expect(link).toHaveAttribute("href", "/payments/findings/f1");
    const item = link.closest("li")!;
    expect(item).toHaveTextContent("40 days old");
    expect(item).toHaveTextContent("fix date was 33 days ago");
    expect(item).toHaveTextContent("reopened");
    expect(screen.getByText("Showing the oldest 1 of 5.")).toBeInTheDocument();
  });

  it("says the age numbers cover only the oldest findings when the server cut them off", async () => {
    aging = { ...baseAging, truncated: true };
    renderPage();
    expect(await screen.findByText(/more open findings than the age numbers cover/))
      .toBeInTheDocument();
  });

  it("keeps the counts on screen when only the ages fail, and offers a retry for them", async () => {
    agingFails = true;
    renderPage();
    expect(await screen.findByText("Could not load ages.")).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Open findings by severity" })).toBeInTheDocument();
    expect(screen.getByText("open findings").previousElementSibling).toHaveTextContent("14");
  });

  it("says there is nothing to chart for a project with no open findings", async () => {
    stats = {
      ...baseStats,
      total_findings: 0,
      blocking_count: 0,
      by_severity: [],
      by_analysis_state: [],
    };
    aging = { ...baseAging, overdue_total: 0, overdue: [] };
    renderPage();
    expect(await screen.findByText("No open findings, so there is nothing to chart."))
      .toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Open findings by severity" })).not
      .toBeInTheDocument();
  });

  it("reads null lists as empty, which is how the server sends them for a quiet project", async () => {
    stats = {
      ...baseStats,
      by_severity: null as unknown as ProjectStats["by_severity"],
      by_analysis_state: null as unknown as ProjectStats["by_analysis_state"],
    };
    aging = {
      buckets: null,
      overdue: null,
      new_per_week: null,
      overdue_total: 0,
      reopened: 0,
      truncated: false,
    } as unknown as Aging;
    renderPage();
    const severity = await screen.findByRole("list", { name: "Open findings by severity" });
    expect(within(severity).getAllByRole("listitem")).toHaveLength(4);
    expect(await screen.findByRole("list", { name: "Open findings by age" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Past their fix date" })).not.toBeInTheDocument();
  });

  it("lists where the project runs after the findings blocks", async () => {
    globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/stats")) return jsonResponse(stats);
      if (url.endsWith("/aging")) return jsonResponse(aging);
      if (url.endsWith("/environments")) {
        return jsonResponse([
          {
            id: "e1",
            project_id: "p1",
            name: "prod-eu",
            tier: "production",
            internet_facing: true,
            data_sensitivity: "confidential",
            created_at: "2026-10-01T00:00:00Z",
          },
        ]);
      }
      if (url.endsWith("/targets") || url.endsWith("/artifacts")) return jsonResponse([]);
      throw new Error(`unexpected request ${url}`);
    });
    renderPage();
    expect(await screen.findByRole("heading", { name: "Where it runs" })).toBeInTheDocument();
    const environments = await screen.findByRole("list", { name: "Environments" });
    expect(within(environments).getByText("prod-eu")).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Open findings by severity" })).toBeInTheDocument();
  });

  it("offers a retry when the counts cannot be loaded", async () => {
    statsFails = true;
    renderPage();
    expect(await screen.findByText("Could not load insights.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
  });
});
