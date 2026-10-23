import { formatDateTime } from "@/lib/format";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ChangeView } from "./ChangeView";

const FULL_SHA = "abcdef1234567890abcdef1234567890abcdef12";
const NEWER_SHA = "2222222222222222222222222222222222222222";

let projectStatus: number;
let permissions: Record<string, boolean> | undefined;
let reports: unknown[];
let exactReports: Record<string, unknown>;
let reportsStatus: number;
let reportsPending: boolean;
let signalReports: unknown[];
let changeGate: Record<string, unknown> | null;
let changeGateStatus: number;
let projectGate: Record<string, unknown>;
let findings: Record<string, unknown>;
let findingFetches: string[];
let waivers: unknown[];
let waiverPosts: Array<Record<string, unknown>>;

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

function finding(id: string, severity = "high") {
  return {
    id,
    project_id: "p1",
    finding_kind: "sca",
    fingerprint: id,
    current_title: `Finding ${id}`,
    current_severity: severity,
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
  return {
    threshold_breached: true,
    blocking_count: 1,
    blocked_by: [],
    policy: { severity_floor: "high", severity_source: "default" },
    ...overrides,
  };
}

function pendingWaiver(findingId: string) {
  return {
    id: "w1",
    project_id: "p1",
    name: "Waiver request",
    description: "",
    enabled: true,
    status: "pending",
    scope_all: false,
    reason: "not reachable",
    decision_note: "",
    targets: [{ id: "t1", finding_id: findingId }],
    created_at: "",
    updated_at: "",
  };
}

beforeEach(() => {
  projectStatus = 200;
  permissions = { request_waiver: true };
  reports = [report()];
  exactReports = {};
  reportsStatus = 200;
  reportsPending = false;
  signalReports = [];
  changeGate = gate({ blocked_by: ["f1", "f2"] });
  changeGateStatus = 200;
  projectGate = { threshold_breached: false, blocking_count: 0, blocked_by: [] };
  findings = { f1: finding("f1", "critical"), f2: finding("f2") };
  findingFetches = [];
  waivers = [];
  waiverPosts = [];

  globalThis.fetch = vi.fn().mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
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
          role: "member",
          permissions,
        }),
      );
    }
    if (url.startsWith("/api/v1/reports/")) {
      const id = decodeURIComponent(url.slice("/api/v1/reports/".length));
      const found = exactReports[id] ?? reports.find((r) => (r as { id: string; }).id === id);
      return Promise.resolve(
        found ? jsonResponse(found) : jsonResponse({ error: { code: "not_found" } }, 404),
      );
    }
    if (
      url.startsWith("/api/v1/projects/acme/reports?") && !url.includes("commit=")
      && !url.endsWith("?limit=500")
    ) {
      return Promise.resolve(jsonResponse(signalReports));
    }
    if (
      url === "/api/v1/projects/acme/reports" || url === "/api/v1/projects/acme/reports?limit=500"
      || url.includes("/api/v1/projects/acme/reports?commit=")
    ) {
      if (reportsPending) return new Promise<Response>(() => {});
      if (reportsStatus >= 400) {
        return Promise.resolve(
          jsonResponse({ error: { code: "forbidden", message: "reports failed" } }, reportsStatus),
        );
      }
      return Promise.resolve(jsonResponse(reports));
    }
    if (url === "/api/v1/projects/acme/waivers/requests" && init?.method === "POST") {
      const body = JSON.parse(String(init.body)) as { target_ids: string[]; };
      waiverPosts.push(body);
      const created = pendingWaiver(body.target_ids[0]);
      waivers = [created];
      return Promise.resolve(jsonResponse(created, 201));
    }
    if (url.startsWith("/api/v1/projects/acme/waivers")) {
      return Promise.resolve(jsonResponse(waivers));
    }
    if (url.startsWith("/api/v1/projects/acme/gate?introduced_only=")) {
      if (changeGateStatus >= 400) {
        return Promise.resolve(
          jsonResponse({ error: { code: "boom", message: "gate failed" } }, changeGateStatus),
        );
      }
      return Promise.resolve(jsonResponse(changeGate ?? {}));
    }
    if (url.startsWith("/api/v1/projects/acme/gate")) {
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

afterEach(() => {
  vi.useRealTimers();
});

function Where() {
  return <p data-testid="where">{useLocation().pathname}</p>;
}

function renderPage(entry = `/acme/changes/${FULL_SHA}`) {
  const qc = createTestQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[entry]}>
        <Routes>
          <Route
            path="/:slug/changes/:commit"
            element={
              <>
                <ChangeView />
                <Where />
              </>
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** The summary button of a ledger entry, which carries the finding's title as its name. */
function entryButton(title: string) {
  return screen.getByRole("button", { name: title });
}

/** Waits until both findings have loaded into the ledger. */
async function loadedLedger() {
  await screen.findByRole("button", { name: "Finding f1" });
  await screen.findByRole("button", { name: "Finding f2" });
  return screen.getByRole("list", { name: "Blocking findings" });
}

/** The entry that is open, where the detail and its controls can be reached. */
function openEntry() {
  const entry = document.querySelector("li[data-open='true']");
  if (!entry) throw new Error("no ledger entry is open");
  return within(entry as HTMLElement);
}

describe("ChangeView", () => {
  it("explains the project-wide gate and preserves a tightened severity floor", async () => {
    changeGate = gate({ threshold_breached: false, blocked_by: [] });
    projectGate = gate({
      blocked_by: ["f1"],
      policy: { severity_floor: "medium", severity_source: "override" },
    });
    renderPage(`/acme/changes/${FULL_SHA}?report=r1&scope=project&severity=medium`);
    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent(
      "1 finding blocks this project.",
    );
    expect(globalThis.fetch).toHaveBeenCalledWith(
      "/api/v1/projects/acme/gate?severity=medium",
      expect.anything(),
    );
    expect(screen.queryByText("Nothing in it stops the merge. Only a scan can change that.")).not
      .toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Findings blocking this project" }))
      .toBeInTheDocument();
  });

  it("loads an exact report even when it is outside the report list", async () => {
    reports = [];
    exactReports = { old: report({ id: "old" }) };
    renderPage(`/acme/changes/${FULL_SHA}?report=old`);
    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent(
      "2 findings block this change.",
    );
    expect(globalThis.fetch).toHaveBeenCalledWith("/api/v1/reports/old", expect.anything());
  });

  it("queries the commit on the server instead of walking project history", async () => {
    renderPage();
    await screen.findByRole("heading", { level: 1 });
    expect(globalThis.fetch).toHaveBeenCalledWith(
      `/api/v1/projects/acme/reports?commit=${FULL_SHA}&commit_prefix=true`,
      expect.anything(),
    );
  });

  it("shows a skeleton header while the reports load", () => {
    reportsPending = true;
    const { container } = renderPage();

    expect(container.querySelectorAll(".animate-pulse").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByLabelText("Change verdict")).toHaveAttribute("aria-busy", "true");
  });

  it("renders the change header with branch, scan time and scanner", async () => {
    renderPage();

    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent(
      "2 findings block this change.",
    );
    expect(await screen.findByRole("link", { name: "Acme API" })).toHaveAttribute(
      "href",
      "/acme/findings",
    );
    expect(screen.getByTitle(formatDateTime("2025-01-01T00:00:00Z"))).toBeInTheDocument();
    expect(screen.getByText("abcdef1")).toBeInTheDocument();
    expect(screen.getByText("main")).toBeInTheDocument();
    expect(screen.getByText(/from a trivy report/)).toBeInTheDocument();
  });

  it("offers a neutral no-report page with the reports and upload links", async () => {
    reports = [];
    renderPage();

    expect(await screen.findByText("No scan found for commit abcdef1")).toBeInTheDocument();
    expect(
      screen.getByText("The pipeline may still be running, or this commit was never scanned."),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Reports" })).toHaveAttribute("href", "/acme/reports");
    expect(screen.getByRole("link", { name: "Upload a report" })).toHaveAttribute(
      "href",
      "/acme/reports/upload",
    );
  });

  it("does not claim a verdict while a scan is processing", async () => {
    reports = [report({ status: "processing" })];
    renderPage();

    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent(
      "This scan is still processing.",
    );
    expect(screen.getByText("SCANNING")).toBeInTheDocument();
    expect(screen.queryByText("PASSING")).not.toBeInTheDocument();
    expect(screen.queryByText("BLOCKED")).not.toBeInTheDocument();
    expect(screen.queryByText("What is in the way")).not.toBeInTheDocument();
  });

  it("says a failed scan did not complete, with the reason when the scanner gave one", async () => {
    reports = [
      report({
        status: "failed",
        error_message: "scanner exited with status 2: unsupported lockfile version",
      }),
    ];
    renderPage();

    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent(
      "This scan did not complete.",
    );
    expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
    expect(
      screen.getByText("scanner exited with status 2: unsupported lockfile version"),
    ).toBeInTheDocument();
    expect(screen.queryByText("PASSING")).not.toBeInTheDocument();
  });

  it("shows the blockers a change introduces as a ledger, the first one open", async () => {
    renderPage();

    expect(await screen.findByText("BLOCKED")).toBeInTheDocument();
    const ledger = await loadedLedger();
    expect(within(ledger).getAllByRole("listitem")).toHaveLength(2);
    expect(entryButton("Finding f1")).toHaveAttribute("aria-expanded", "true");
    expect(entryButton("Finding f2")).toHaveAttribute("aria-expanded", "false");
    // The open entry says where, why and what to do.
    const entry = openEntry();
    expect(entry.getByText("src/f1.ts:1")).toBeInTheDocument();
    expect(entry.getByText(/Severity CRITICAL is at or above the project floor \(HIGH\)/))
      .toBeInTheDocument();
    expect(entry.getAllByText("Fix f1").length).toBeGreaterThan(0);
    expect(entry.getByRole("link", { name: "Open the full finding" })).toHaveAttribute(
      "href",
      "/acme/findings/f1",
    );
  });

  it("opens another entry from its summary", async () => {
    renderPage();
    await loadedLedger();
    const user = userEvent.setup();

    await user.click(entryButton("Finding f2"));

    expect(entryButton("Finding f2")).toHaveAttribute("aria-expanded", "true");
    expect(document.querySelectorAll("li[data-open='true']")).toHaveLength(2);
  });

  it("tracks the reader's progress without changing the verdict", async () => {
    renderPage();
    await loadedLedger();
    const user = userEvent.setup();
    expect(screen.getByText("0 of 2 handled")).toBeInTheDocument();

    await user.click(screen.getByRole("checkbox", { name: "I've done this: Finding f1" }));

    expect(screen.getByText("1 of 2 handled")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "1 of 2 handled" })).toBeInTheDocument();
    // Only a scan changes the verdict.
    expect(screen.getByText("BLOCKED")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("2 findings block");
    expect(screen.queryByText("Waiting for the next scan")).not.toBeInTheDocument();
  });

  it("keeps the margin checklist and the ledger in step", async () => {
    renderPage();
    await loadedLedger();
    const user = userEvent.setup();

    await user.click(screen.getByRole("checkbox", { name: "Finding f2" }));

    expect(screen.getByRole("checkbox", { name: "I've done this: Finding f2" })).toBeChecked();
    expect(screen.getByText("1 of 2 handled")).toBeInTheDocument();
  });

  it("reads PASSING and keeps the debt section available", async () => {
    changeGate = gate({ threshold_breached: false, blocking_count: 0, blocked_by: [] });
    projectGate = { threshold_breached: true, blocking_count: 1, blocked_by: ["pre1"] };
    findings = { ...findings, pre1: finding("pre1") };
    renderPage();

    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent(
      "This change introduces no blocking findings.",
    );
    expect(screen.getByText("PASSING")).toBeInTheDocument();
    expect(screen.queryByText("What is in the way")).not.toBeInTheDocument();
    expect(await screen.findByText(/1 other finding/)).toBeInTheDocument();
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

  it("retries the requests behind the error and renders the change once they succeed", async () => {
    changeGateStatus = 500;
    renderPage();

    expect(await screen.findByRole("alert")).toHaveTextContent("gate failed");
    changeGateStatus = 200;
    await userEvent.setup().click(screen.getByRole("button", { name: "Retry" }));

    expect(await loadedLedger()).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
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

  it("caps the introduced findings at twenty entries behind Show all", async () => {
    const ids = Array.from({ length: 25 }, (_, index) => `f${index}`);
    changeGate = gate({ blocked_by: ids });
    findings = Object.fromEntries(ids.map((id) => [id, finding(id)]));
    renderPage();

    const ledger = await screen.findByRole("list", { name: "Blocking findings" });
    await waitFor(() => expect(within(ledger).getAllByRole("listitem")).toHaveLength(20));
    // The hidden entries are not fetched until they are revealed.
    expect(findingFetches).toHaveLength(20);

    await userEvent.setup().click(screen.getByRole("button", { name: "Show all 25" }));
    await waitFor(() => expect(within(ledger).getAllByRole("listitem")).toHaveLength(25));
    expect(findingFetches).toHaveLength(25);
  });

  it("folds only findings the change did not introduce into the debt section", async () => {
    changeGate = gate({ blocked_by: ["f1", "f2"] });
    projectGate = {
      threshold_breached: true,
      blocking_count: 3,
      blocked_by: ["f1", "f2", "pre1"],
    };
    findings = { f1: finding("f1"), f2: finding("f2"), pre1: finding("pre1") };
    renderPage();

    const summary = await screen.findByText(
      "1 other finding blocks this project (not introduced by this change)",
    );
    // The introduced findings were fetched; the debt row was not, until opened.
    expect(findingFetches.sort()).toEqual(["f1", "f2"]);

    await userEvent.setup().click(summary);
    await waitFor(() => expect(screen.getByText("Finding pre1")).toBeInTheDocument());
    const details = summary.closest("details");
    if (!details) throw new Error("debt summary is not inside a details element");
    expect(within(details).queryByText("Finding f1")).not.toBeInTheDocument();
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

describe("ChangeView waivers", () => {
  it("offers a waiver request to a member and sends it for the finding", async () => {
    renderPage();
    await loadedLedger();
    const user = userEvent.setup();

    await user.click(openEntry().getByRole("button", { name: "Request waiver" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/The verdict does not change until they approve it/))
      .toBeInTheDocument();
    const send = within(dialog).getByRole("button", { name: "Send request" });
    expect(send).toBeDisabled();

    await user.type(
      within(dialog).getByLabelText("Why is this safe to ship?"),
      "Not reachable from the API.",
    );
    await user.click(send);

    await waitFor(() => expect(waiverPosts).toHaveLength(1));
    expect(waiverPosts[0]).toMatchObject({
      target_ids: ["f1"],
      reason: "Not reachable from the API.",
    });
    expect(typeof waiverPosts[0].expires_at).toBe("string");
    // The request is waiting: the entry says so and the verdict is unchanged.
    expect(await screen.findByText("Waiting for a manager to decide.")).toBeInTheDocument();
    expect(screen.getByText("Waiver requested")).toBeInTheDocument();
    expect(openEntry().queryByRole("button", { name: "Request waiver" })).not.toBeInTheDocument();
    expect(screen.getByText("BLOCKED")).toBeInTheDocument();
  });

  it("shows a request that is already waiting, on load", async () => {
    waivers = [pendingWaiver("f1")];
    renderPage();

    expect(await screen.findByText("Waiting for a manager to decide.")).toBeInTheDocument();
    expect(screen.getByText("Waiver requested")).toBeInTheDocument();
  });

  it("shows the server's refusal inside the dialog and keeps it open", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = vi.fn().mockImplementation(
      (input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input).endsWith("/waivers/requests") && init?.method === "POST") {
          return Promise.resolve(
            jsonResponse({
              error: {
                code: "waiver_request_exists",
                message: "a pending request already covers this",
              },
            }, 409),
          );
        }
        return (original as typeof fetch)(input, init);
      },
    );
    renderPage();
    await loadedLedger();
    const user = userEvent.setup();

    await user.click(openEntry().getByRole("button", { name: "Request waiver" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Why is this safe to ship?"), "Because.");
    await user.click(within(dialog).getByRole("button", { name: "Send request" }));

    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "a pending request already covers this",
    );
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("hides the request button from someone who may not request waivers", async () => {
    permissions = { request_waiver: false };
    renderPage();

    await loadedLedger();
    expect(screen.queryByRole("button", { name: "Request waiver" })).not.toBeInTheDocument();
  });
});

describe("ChangeView waiting for the next scan", () => {
  it("starts waiting when the reader asks for a new report", async () => {
    renderPage();
    await screen.findByRole("list", { name: "Blocking findings" });

    await userEvent.setup().click(screen.getByRole("button", { name: "Wait for a new report" }));

    expect(await screen.findByText("Waiting for the next scan")).toBeInTheDocument();
    expect(screen.getByText("BLOCKED")).toBeInTheDocument();
  });

  it("starts waiting by itself once every blocker is handled", async () => {
    renderPage();
    await loadedLedger();
    const user = userEvent.setup();

    await user.click(screen.getByRole("checkbox", { name: "I've done this: Finding f1" }));
    expect(screen.queryByText("Waiting for the next scan")).not.toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: "Finding f2" }));

    expect(await screen.findByText("Waiting for the next scan")).toBeInTheDocument();
  });

  it("shows the scanning stamp while a newer scan runs, then moves to the new change", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    renderPage();
    await screen.findByRole("list", { name: "Blocking findings" });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });

    await user.click(screen.getByRole("button", { name: "Wait for a new report" }));
    signalReports = [
      report({
        id: "r2",
        commit_sha: NEWER_SHA,
        status: "processing",
        created_at: "2025-01-02T00:00:00Z",
      }),
    ];
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_100);
    });

    expect(await screen.findByText("SCANNING")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Scanning your push.");
    expect(screen.getByTestId("where")).toHaveTextContent(FULL_SHA);

    signalReports = [
      report({
        id: "r2",
        commit_sha: NEWER_SHA,
        status: "completed",
        created_at: "2025-01-02T00:00:00Z",
      }),
    ];
    reports = [
      report(),
      report({ id: "r2", commit_sha: NEWER_SHA, created_at: "2025-01-02T00:00:00Z" }),
    ];
    changeGate = gate({ threshold_breached: false, blocked_by: [] });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_100);
    });

    await waitFor(() =>
      expect(screen.getByTestId("where")).toHaveTextContent("/acme/changes/2222222")
    );
    expect(await screen.findByText("PASSING")).toBeInTheDocument();
  });

  it("ignores an older report on the branch", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    renderPage();
    await screen.findByRole("list", { name: "Blocking findings" });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });

    await user.click(screen.getByRole("button", { name: "Wait for a new report" }));
    signalReports = [
      report({ id: "r0", commit_sha: NEWER_SHA, created_at: "2024-12-01T00:00:00Z" }),
    ];
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_100);
    });

    expect(screen.getByTestId("where")).toHaveTextContent(FULL_SHA);
    expect(screen.getByText("BLOCKED")).toBeInTheDocument();
  });

  it("gives up after ten minutes and says to check the CI job", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    renderPage();
    await screen.findByRole("list", { name: "Blocking findings" });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });

    await user.click(screen.getByRole("button", { name: "Wait for a new report" }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(600_500);
    });

    expect(
      await screen.findByText(
        "Nothing yet after ten minutes. Check your CI job, watcher or report upload.",
      ),
    )
      .toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check again" })).toBeInTheDocument();
  });
});
