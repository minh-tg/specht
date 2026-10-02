import { formatDateTime } from "@/lib/format";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ChangeView } from "./ChangeView";

const FULL_SHA = "abcdef1234567890abcdef1234567890abcdef12";

let projectStatus: number;
let reports: unknown[];
let reportsStatus: number;
let reportsPending: boolean;
let changeGate: Record<string, unknown> | null;
let changeGateStatus: number;
let projectGate: Record<string, unknown>;
let findings: Record<string, unknown>;
let findingFetches: string[];

function report(overrides: Record<string, unknown> = {}) {
  return {
    id: "r1",
    project_id: "p1",
    tool_name: "trivy",
    tool_version: null,
    scan_type: "filesystem",
    scan_target: null,
    status: "completed",
    total_findings: 2,
    branch: "main",
    commit_sha: FULL_SHA,
    created_at: "2025-01-01T00:00:00Z",
    completed_at: null,
    ...overrides,
  };
}

function finding(id: string) {
  return {
    id,
    project_id: "p1",
    finding_kind: "sca",
    fingerprint: id,
    current_title: `Finding ${id}`,
    current_severity: "high",
    current_score: null,
    state: "open",
    triage_status: "untriaged",
    analysis_state: "unanalyzed",
    gate_effect: "block",
    first_seen_at: "2025-01-01T00:00:00Z",
    last_seen_at: "2025-01-01T00:00:00Z",
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
    location: { file: `src/${id}.ts`, start_line: 1 },
    remediation: { summary: `Fix ${id}` },
  };
}

function gate(overrides: Record<string, unknown>) {
  return { threshold_breached: true, blocking_count: 1, blocked_by: [], ...overrides };
}

beforeEach(() => {
  projectStatus = 200;
  reports = [report()];
  reportsStatus = 200;
  reportsPending = false;
  changeGate = gate({ blocked_by: ["f1", "f2"] });
  changeGateStatus = 200;
  projectGate = { threshold_breached: false, blocking_count: 0, blocked_by: [] };
  findings = { f1: finding("f1"), f2: finding("f2") };
  findingFetches = [];

  globalThis.fetch = vi.fn().mockImplementation((input: RequestInfo | URL) => {
    const url = String(input);
    if (url === "/api/v1/projects/acme") {
      if (projectStatus >= 400) {
        return Promise.resolve(
          jsonResponse({ error: { code: "not_found", message: "project missing" } }, projectStatus),
        );
      }
      return Promise.resolve(
        jsonResponse({
          id: "p1",
          slug: "acme",
          name: "Acme API",
          description: null,
          created_at: "",
          updated_at: "",
        }),
      );
    }
    if (url === "/api/v1/projects/acme/reports") {
      if (reportsPending) return new Promise<Response>(() => {});
      if (reportsStatus >= 400) {
        return Promise.resolve(
          jsonResponse({ error: { code: "forbidden", message: "reports failed" } }, reportsStatus),
        );
      }
      return Promise.resolve(jsonResponse(reports));
    }
    if (url.startsWith("/api/v1/projects/acme/gate?")) {
      if (changeGateStatus >= 400) {
        return Promise.resolve(
          jsonResponse({ error: { code: "boom", message: "gate failed" } }, changeGateStatus),
        );
      }
      return Promise.resolve(jsonResponse(changeGate ?? {}));
    }
    if (url === "/api/v1/projects/acme/gate") {
      return Promise.resolve(jsonResponse(projectGate));
    }
    const match = /^\/api\/v1\/findings\/(.+)$/.exec(url);
    if (match) {
      const id = decodeURIComponent(match[1]);
      findingFetches.push(id);
      const data = findings[id];
      if (data === undefined) {
        return Promise.resolve(
          jsonResponse({ error: { code: "not_found", message: "finding missing" } }, 404),
        );
      }
      return Promise.resolve(jsonResponse(data));
    }
    return Promise.resolve(jsonResponse({}));
  });
});

function renderPage(entry = `/acme/changes/${FULL_SHA}`) {
  const qc = createTestQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[entry]}>
        <Routes>
          <Route path="/:slug/changes/:commit" element={<ChangeView />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("ChangeView", () => {
  it("shows a skeleton header and rows while the reports load", () => {
    reportsPending = true;
    const { container } = renderPage();

    expect(container.querySelectorAll(".animate-pulse").length).toBeGreaterThan(3);
    expect(screen.getByLabelText("Change verdict")).toHaveAttribute("aria-busy", "true");
  });

  it("renders the change header with branch, scan time and scanner", async () => {
    renderPage();

    expect(await screen.findByRole("heading", { name: "Change abcdef1" })).toBeInTheDocument();
    expect(await screen.findByRole("link", { name: "Acme API" })).toHaveAttribute(
      "href",
      "/acme/findings",
    );
    expect(screen.getByTitle(formatDateTime("2025-01-01T00:00:00Z"))).toBeInTheDocument();
    expect(screen.getByText("main")).toBeInTheDocument();
  });

  it("offers a neutral no-report card with the reports and upload links", async () => {
    reports = [];
    renderPage();

    expect(await screen.findByText("No scan found for commit abcdef1")).toBeInTheDocument();
    expect(
      screen.getByText("The pipeline may still be running, or this commit was never scanned."),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Reports" })).toHaveAttribute(
      "href",
      "/acme/reports",
    );
    expect(screen.getByRole("link", { name: "Upload a report" })).toHaveAttribute(
      "href",
      "/acme/reports/upload",
    );
  });

  it("does not claim a verdict while a scan is processing", async () => {
    reports = [report({ status: "processing" })];
    renderPage();

    const banner = await screen.findByRole("status");
    expect(banner).toHaveTextContent("This scan is still processing");
    const heading = screen.getByRole("heading", {
      name: "NO VERDICT — this scan did not complete",
    });
    expect(heading).toBeInTheDocument();
    expect(screen.queryByText(/PASSING/)).not.toBeInTheDocument();
    // Degraded evidence is announced above the verdict, never below it.
    expect(banner.compareDocumentPosition(heading) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("announces a failed scan with an alert", async () => {
    reports = [report({ status: "failed" })];
    renderPage();

    expect(await screen.findByRole("alert")).toHaveTextContent("This scan failed");
    expect(
      screen.getByRole("heading", { name: "NO VERDICT — this scan did not complete" }),
    ).toBeInTheDocument();
  });

  it("shows the blockers a change introduces", async () => {
    renderPage();

    expect(
      await screen.findByRole("heading", { name: "BLOCKED — 2 findings block this change" }),
    ).toBeInTheDocument();
    expect(await screen.findByText("Finding f1")).toBeInTheDocument();
    expect(screen.getByText("Finding f2")).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "Decide" })).toHaveLength(2);
    expect(screen.getByText("src/f1.ts:1")).toBeInTheDocument();
    expect(screen.getByText("Fix f1")).toBeInTheDocument();
  });

  it("reads PASSING when nothing is introduced", async () => {
    changeGate = gate({ threshold_breached: false, blocking_count: 0, blocked_by: [] });
    renderPage();

    expect(
      await screen.findByRole("heading", {
        name: "PASSING — this change introduces no blocking findings",
      }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Introduced by this change" }))
      .not.toBeInTheDocument();
  });

  it("alerts with a back link when the gate request fails", async () => {
    changeGateStatus = 500;
    renderPage();

    expect(await screen.findByRole("alert")).toHaveTextContent("gate failed");
    expect(screen.getByRole("link", { name: "Back to project" })).toHaveAttribute(
      "href",
      "/acme/findings",
    );
  });

  it("alerts when the reports request fails", async () => {
    reportsStatus = 403;
    renderPage();

    expect(await screen.findByRole("alert")).toHaveTextContent("reports failed");
  });

  it("shows the project-not-found treatment for a 404 project", async () => {
    projectStatus = 404;
    renderPage();

    expect(await screen.findByRole("heading", { name: "Project not found" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to projects" })).toHaveAttribute("href", "/");
  });

  it("caps the introduced findings at twenty rows behind Show all", async () => {
    const ids = Array.from({ length: 25 }, (_, index) => `f${index}`);
    changeGate = gate({ blocked_by: ids });
    findings = Object.fromEntries(ids.map((id) => [id, finding(id)]));
    renderPage();

    await screen.findByRole("heading", { name: "BLOCKED — 25 findings block this change" });
    const list = screen.getByRole("list");
    await waitFor(() => expect(within(list).getAllByRole("listitem")).toHaveLength(20));
    // The hidden rows are not fetched until they are revealed.
    expect(findingFetches).toHaveLength(20);

    await userEvent.setup().click(screen.getByRole("button", { name: "Show all 25" }));
    await waitFor(() => expect(within(list).getAllByRole("listitem")).toHaveLength(25));
    expect(findingFetches).toHaveLength(25);
  });

  it("resolves a commit prefix and honours the report override", async () => {
    const otherReport = report({
      id: "r2",
      commit_sha: "1111111111111111111111111111111111111111",
      branch: "release",
    });
    reports = [report({ id: "r1", commit_sha: FULL_SHA, branch: "main" }), otherReport];
    renderPage(`/acme/changes/1111111?report=r2`);

    expect(await screen.findByText("release")).toBeInTheDocument();
  });
});
