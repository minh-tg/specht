import { formatClockTime, formatDateTime } from "@/lib/format";
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
let changeGateRequestId: string | null;
let projectGate: Record<string, unknown>;
let findings: Record<string, unknown>;
let findingFetches: string[];
let waivers: unknown[];
let waiverPosts: Array<Record<string, unknown>>;
let meId: string;
let withdrawCalls: string[];
let withdrawFailure: { status: number; code: string; } | null;

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
  changeGateRequestId = null;
  projectGate = { threshold_breached: false, blocking_count: 0, blocked_by: [] };
  findings = { f1: finding("f1", "critical"), f2: finding("f2") };
  findingFetches = [];
  waivers = [];
  waiverPosts = [];
  meId = "u-ada";
  withdrawCalls = [];
  withdrawFailure = null;

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
    if (url === "/api/v1/me") {
      return Promise.resolve(jsonResponse({ id: meId, email: "ada@example.com", role: "member" }));
    }
    const withdraw = /^\/api\/v1\/projects\/acme\/waivers\/([^/]+)\/withdraw$/.exec(url);
    if (withdraw && init?.method === "POST") {
      withdrawCalls.push(withdraw[1]);
      if (withdrawFailure) {
        const failure = jsonResponse(
          { error: { code: withdrawFailure.code, message: "refused" } },
          withdrawFailure.status,
        );
        failure.headers.set("X-Request-Id", "req-w1");
        return Promise.resolve(failure);
      }
      waivers = (waivers as Array<Record<string, unknown>>).map((w) =>
        w.id === withdraw[1] ? { ...w, status: "withdrawn" } : w
      );
      return Promise.resolve(jsonResponse({}));
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
        const failure = jsonResponse(
          { error: { code: "boom", message: "gate failed" } },
          changeGateStatus,
        );
        if (changeGateRequestId) failure.headers.set("X-Request-Id", changeGateRequestId);
        return Promise.resolve(failure);
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

/**
 * The name of a ledger entry's summary button. It is the row's visible text: the number, the
 * severity, the title and the fix, so a speech user can say any of what they see.
 */
function entryName(title: string) {
  return new RegExp(`^\\d{2} \\S+ ${title}( |$)`);
}

function entryButton(title: string) {
  return screen.getByRole("button", { name: entryName(title) });
}

/** Waits until both findings have loaded into the ledger. */
async function loadedLedger() {
  await screen.findByRole("button", { name: entryName("Finding f1") });
  await screen.findByRole("button", { name: entryName("Finding f2") });
  return screen.getByRole("list", { name: "Blocking findings" });
}

/** The "· checked just now" part of a watching strip, which is split across elements. */
function checkedLine() {
  return screen.queryByText((_, node) =>
    node?.tagName === "SPAN" && /^· checked just now$/.test(node.textContent ?? "")
  );
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

  it("shows nothing for the first 300 ms of loading, then a skeleton that names the commit", async () => {
    vi.useFakeTimers();
    reportsPending = true;
    const { container } = renderPage();

    expect(screen.queryByLabelText("Change verdict")).not.toBeInTheDocument();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(299);
    });
    expect(screen.queryByLabelText("Change verdict")).not.toBeInTheDocument();
    expect(screen.queryByText(/Loading the verdict/)).not.toBeInTheDocument();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1);
    });
    expect(container.querySelectorAll(".animate-pulse").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByLabelText("Change verdict")).toHaveAttribute("aria-busy", "true");
    expect(screen.getByRole("status")).toHaveTextContent("Loading the verdict for abcdef1…");
  });

  it("never shows the skeleton when the verdict arrives within 300 ms", async () => {
    renderPage();

    expect(await screen.findByRole("heading", { level: 1 })).toBeInTheDocument();
    expect(screen.queryByText(/Loading the verdict/)).not.toBeInTheDocument();
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
    permissions = { request_waiver: true, upload_reports: true };
    renderPage();

    expect(await screen.findByText("No scan found for commit abcdef1")).toBeInTheDocument();
    expect(
      screen.getByText("The pipeline may still be running, or this commit was never scanned."),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Reports" })).toHaveAttribute("href", "/acme/reports");
    expect(await screen.findByRole("link", { name: "Upload a report" })).toHaveAttribute(
      "href",
      "/acme/reports/upload",
    );
  });

  it("leaves the upload link out for someone who may not upload", async () => {
    reports = [];
    permissions = { request_waiver: true, upload_reports: false };
    renderPage();

    expect(await screen.findByText("No scan found for commit abcdef1")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Reports" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Upload a report" })).not.toBeInTheDocument();
  });

  it("does not claim a verdict while a scan is processing, and says the page will update", async () => {
    reports = [report({ status: "processing" })];
    renderPage();

    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent(
      "The scan of abcdef1 is still being processed.",
    );
    expect(
      screen.getByText(
        "There is no verdict until it finishes. This page shows it as soon as it does; you do not need to reload.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("SCANNING")).toBeInTheDocument();
    expect(screen.getByText("Watching")).toBeInTheDocument();
    expect(checkedLine()).toBeInTheDocument();
    expect(screen.queryByText("PASSING")).not.toBeInTheDocument();
    expect(screen.queryByText("BLOCKED")).not.toBeInTheDocument();
    expect(screen.queryByText("What is in the way")).not.toBeInTheDocument();
  });

  it("shows the verdict by itself once the scan it was waiting for finishes", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    reports = [report({ status: "processing" })];
    renderPage();
    await screen.findByText("SCANNING");

    reports = [report({ status: "completed" })];
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_100);
    });

    expect(await screen.findByText("BLOCKED")).toBeInTheDocument();
    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent(
      "2 findings block this change.",
    );
  });

  it("keeps the processing page when one check fails, and says so", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    reports = [report({ status: "processing" })];
    renderPage();
    await screen.findByText("SCANNING");

    reportsStatus = 500;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_100);
    });

    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("still being processed");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(await screen.findByText(/last check failed, trying again/)).toBeInTheDocument();
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
      "/acme/findings/f1?from=change",
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
      "Nothing first seen in this commit blocks this change.",
    );
    expect(
      screen.getByText(
        "The scan of abcdef1 found no new finding at High or above. Nothing to do here.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("PASSING")).toBeInTheDocument();
    expect(screen.queryByText("What is in the way")).not.toBeInTheDocument();
    expect(
      await screen.findByText(
        "1 older finding is open in Acme API. It is not counted for this change.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(/other finding/)).not.toBeInTheDocument();
  });

  it("never says CI is green", async () => {
    changeGate = gate({ threshold_breached: false, blocking_count: 0, blocked_by: [] });
    renderPage();

    await screen.findByText("PASSING");
    expect(document.body).not.toHaveTextContent(/\bgreen\b/i);
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

  it("says the CI verdict stands, and shows the request ID with a copy button", async () => {
    changeGateStatus = 500;
    changeGateRequestId = "7f3a9c2e-41d8-4b1e-9c55-2d0e8b1fa0c2";
    const user = userEvent.setup();
    const writeText = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
    renderPage();

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Specht could not load this change.");
    expect(alert).toHaveTextContent(
      "The verdict on your pull request is still the one CI reported. Nothing here changes it.",
    );
    expect(alert).toHaveTextContent("If it keeps failing, give your admin this request ID:");
    expect(screen.getByText("7f3a9c2e-41d8-4b1e-9c55-2d0e8b1fa0c2")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Copy request ID" }));
    expect(writeText).toHaveBeenCalledWith("7f3a9c2e-41d8-4b1e-9c55-2d0e8b1fa0c2");
  });

  it("leaves the request ID out when the response carried none", async () => {
    changeGateStatus = 500;
    renderPage();

    await screen.findByRole("alert");
    expect(screen.queryByText(/request ID/)).not.toBeInTheDocument();
  });

  it("retries the requests behind the error and renders the change once they succeed", async () => {
    changeGateStatus = 500;
    renderPage();

    expect(await screen.findByRole("alert")).toHaveTextContent("gate failed");
    changeGateStatus = 200;
    await userEvent.setup().click(screen.getByRole("button", { name: "Try again" }));

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
    expect(await screen.findByText("Waiver requested. Waiting for a manager.")).toBeInTheDocument();
    expect(screen.getByText("Waiver requested")).toBeInTheDocument();
    expect(openEntry().queryByRole("button", { name: "Request waiver" })).not.toBeInTheDocument();
    expect(screen.getByText("BLOCKED")).toBeInTheDocument();
  });

  it("shows a request that is already waiting, on load", async () => {
    waivers = [pendingWaiver("f1")];
    renderPage();

    expect(await screen.findByText("Waiver requested. Waiting for a manager.")).toBeInTheDocument();
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
      "A request for one of these findings is already waiting for a manager.",
    );
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("keeps the request button, disabled with a reason, for someone who may not request waivers", async () => {
    permissions = { request_waiver: false };
    renderPage();

    await loadedLedger();
    const entry = openEntry();
    expect(entry.getByRole("button", { name: "Request waiver" })).toBeDisabled();
    expect(entry.getByText("You are not a member of this project.")).toBeInTheDocument();
  });

  it("enables the request button for a member, and shows the pending state instead once sent", async () => {
    permissions = { request_waiver: true };
    renderPage();

    await loadedLedger();
    expect(openEntry().getByRole("button", { name: "Request waiver" })).toBeEnabled();
    expect(openEntry().queryByText("You are not a member of this project."))
      .not.toBeInTheDocument();
  });

  it("shows the pending state, not a disabled button, when a request is already waiting", async () => {
    permissions = { request_waiver: true };
    waivers = [pendingWaiver("f1")];
    renderPage();

    await loadedLedger();
    const entry = openEntry();
    expect(await entry.findByText("Waiver requested. Waiting for a manager.")).toBeInTheDocument();
    expect(entry.queryByRole("button", { name: "Request waiver" })).not.toBeInTheDocument();
  });
});

function waiverRow(extra: Record<string, unknown> = {}) {
  return {
    ...pendingWaiver("f1"),
    requested_by: "u-tomas",
    requested_by_name: "Tomas",
    requested_at: "2026-10-30T10:00:00Z",
    created_at: "2026-10-30T10:00:00Z",
    updated_at: "2026-10-30T10:00:00Z",
    expires_at: "2099-01-01T00:00:00Z",
    ...extra,
  };
}

function waiverBlock() {
  return within(openEntry().getByRole("group", { name: "Waiver for Finding f1" }));
}

describe("ChangeView waiver path", () => {
  it.each([
    [
      "rejected",
      {
        status: "rejected",
        decided_by: "u-kim",
        decided_by_name: "A. Kim",
        decision_note: "Too broad.",
      },
      "Waiver rejected by A. Kim.",
      "Waiver rejected",
    ],
    [
      "expired before a decision",
      {
        status: "rejected",
        decision_reason: "expired",
        decision_note: "expired before a decision",
      },
      "The request expired before anyone decided.",
      "Expired before a decision",
    ],
    ["withdrawn", { status: "withdrawn" }, "Request withdrawn.", "Request withdrawn"],
    ["revoked", { status: "approved", enabled: false }, "Waiver revoked.", "Waiver revoked"],
    [
      "approved but expired",
      { status: "approved", enabled: false, expires_at: "2020-01-01T00:00:00Z" },
      "Waiver expired on",
      "Waiver expired",
    ],
  ])("shows a %s waiver and offers to ask again", async (_name, extra, headline, chip) => {
    waivers = [waiverRow(extra)];
    renderPage();
    await loadedLedger();

    expect(await waiverBlock().findByText(new RegExp(headline.replace(/\./g, "\\."))))
      .toBeInTheDocument();
    expect(screen.getAllByText(chip).length).toBeGreaterThan(0);
    expect(openEntry().getByRole("button", { name: "Request again" })).toBeEnabled();
    expect(screen.getByText("BLOCKED")).toBeInTheDocument();
  });

  it("shows an approved waiver without a request button", async () => {
    waivers = [waiverRow({ status: "approved", decided_by: "u-kim", decided_by_name: "A. Kim" })];
    renderPage();
    await loadedLedger();

    expect(await waiverBlock().findByText("Waiver approved by A. Kim.")).toBeInTheDocument();
    expect(openEntry().queryByRole("button", { name: /Request/ })).not.toBeInTheDocument();
  });

  it("shows who asked and who can act on someone else's pending request", async () => {
    waivers = [waiverRow()];
    renderPage();
    await loadedLedger();

    const block = waiverBlock();
    expect(await block.findByText("Waiver requested. Waiting for a manager.")).toBeInTheDocument();
    expect(block.getByText(/Tomas asked/)).toBeInTheDocument();
    expect(block.getByText(/Only Tomas can withdraw it/)).toBeInTheDocument();
    expect(block.queryByRole("button", { name: /Withdraw/ })).not.toBeInTheDocument();
  });

  it("says a manager cannot approve their own request", async () => {
    meId = "u-tomas";
    permissions = { request_waiver: true, approve_waivers: true };
    waivers = [waiverRow()];
    renderPage();
    await loadedLedger();

    expect(await waiverBlock().findByText(/You cannot approve your own request/))
      .toBeInTheDocument();
  });

  it("keeps the request again button disabled, with the reason, for someone who cannot request", async () => {
    permissions = { request_waiver: false };
    waivers = [waiverRow({ status: "rejected" })];
    renderPage();
    await loadedLedger();

    const entry = openEntry();
    expect(await entry.findByRole("button", { name: "Request again" })).toBeDisabled();
    expect(entry.getByText("You are not a member of this project.")).toBeInTheDocument();
  });

  it("treats a null waiver list as no waivers", async () => {
    waivers = null as unknown as unknown[];
    renderPage();
    await loadedLedger();

    expect(openEntry().getByRole("button", { name: "Request waiver" })).toBeEnabled();
  });

  it("treats a waiver with a null target list as covering nothing", async () => {
    waivers = [waiverRow({ targets: null })];
    renderPage();
    await loadedLedger();

    expect(openEntry().getByRole("button", { name: "Request waiver" })).toBeEnabled();
  });

  describe("withdrawing", () => {
    beforeEach(() => {
      meId = "u-tomas";
      waivers = [waiverRow()];
    });

    it("asks first, withdraws, and puts focus on the waiver block", async () => {
      renderPage();
      await loadedLedger();
      const user = userEvent.setup();

      await user.click(
        await waiverBlock().findByRole("button", { name: "Withdraw request: Finding f1" }),
      );
      const dialog = await screen.findByRole("alertdialog");
      expect(within(dialog).getByText("Withdraw this request?")).toBeInTheDocument();
      expect(withdrawCalls).toEqual([]);
      await user.click(within(dialog).getByRole("button", { name: "Withdraw request" }));

      await waitFor(() => expect(withdrawCalls).toEqual(["w1"]));
      expect(await waiverBlock().findByText("Request withdrawn by you.")).toBeInTheDocument();
      await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument());
      await waitFor(() =>
        expect(screen.getByRole("group", { name: "Waiver for Finding f1" })).toHaveFocus()
      );
      expect(openEntry().getByRole("button", { name: "Request again" })).toBeEnabled();
    });

    it("leaves the request alone when the person keeps it", async () => {
      renderPage();
      await loadedLedger();
      const user = userEvent.setup();

      await user.click(
        await waiverBlock().findByRole("button", { name: "Withdraw request: Finding f1" }),
      );
      await user.click(await screen.findByRole("button", { name: "Keep request" }));

      expect(withdrawCalls).toEqual([]);
      expect(await waiverBlock().findByText("Waiver requested. Waiting for a manager."))
        .toBeInTheDocument();
    });

    it("stays open on a failure, shows the request id and lets the person retry", async () => {
      withdrawFailure = { status: 500, code: "internal_error" };
      renderPage();
      await loadedLedger();
      const user = userEvent.setup();

      await user.click(
        await waiverBlock().findByRole("button", { name: "Withdraw request: Finding f1" }),
      );
      const dialog = await screen.findByRole("alertdialog");
      await user.click(within(dialog).getByRole("button", { name: "Withdraw request" }));

      expect(await within(dialog).findByRole("alert")).toHaveTextContent(
        "Could not withdraw the request.",
      );
      expect(within(dialog).getByText("req-w1")).toBeInTheDocument();

      withdrawFailure = null;
      await user.click(within(dialog).getByRole("button", { name: "Try again" }));
      await waitFor(() => expect(withdrawCalls).toEqual(["w1", "w1"]));
      expect(await waiverBlock().findByText("Request withdrawn by you.")).toBeInTheDocument();
    });

    it("says someone decided first, and shows the current state", async () => {
      withdrawFailure = { status: 409, code: "waiver_not_pending" };
      renderPage();
      await loadedLedger();
      const user = userEvent.setup();

      await user.click(
        await waiverBlock().findByRole("button", { name: "Withdraw request: Finding f1" }),
      );
      // The request is rejected while the dialog is open; the refresh after the 409 shows it.
      waivers = [waiverRow({ status: "rejected", decision_note: "No." })];
      const dialog = await screen.findByRole("alertdialog");
      await user.click(within(dialog).getByRole("button", { name: "Withdraw request" }));

      expect(await within(dialog).findByRole("alert")).toHaveTextContent("already decided");
      await user.click(within(dialog).getByRole("button", { name: "Close" }));
      expect(await waiverBlock().findByText("Waiver rejected.")).toBeInTheDocument();
    });
  });
});

function setOnLine(value: boolean) {
  vi.spyOn(navigator, "onLine", "get").mockReturnValue(value);
  act(() => {
    window.dispatchEvent(new Event(value ? "online" : "offline"));
  });
}

function signalCalls() {
  return vi.mocked(globalThis.fetch).mock.calls.filter(([url]) =>
    String(url).startsWith("/api/v1/projects/acme/reports?limit=1")
  ).length;
}

describe("ChangeView watching for the next scan", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("watches without being asked and has no button to start it", async () => {
    renderPage();
    await screen.findByRole("list", { name: "Blocking findings" });

    expect(screen.queryByRole("button", { name: "Wait for a new report" })).not.toBeInTheDocument();
    expect(await screen.findByText("Watching for the next scan of main")).toBeInTheDocument();
    await waitFor(() => expect(checkedLine()).toBeInTheDocument());
    expect(screen.getByText("BLOCKED")).toBeInTheDocument();
  });

  it("announces the watching once, in a single polite status", async () => {
    renderPage();
    await screen.findByText("Watching for the next scan of main");

    const statuses = screen.getAllByRole("status").filter((node) =>
      node.textContent?.includes("Watching")
    );
    expect(statuses).toHaveLength(1);
    expect(statuses[0]).toHaveTextContent(/^Watching for the next scan of main$/);
  });

  it("keeps Copy all fixes", async () => {
    renderPage();
    await loadedLedger();

    expect(screen.getByRole("button", { name: "Copy all fixes" })).toBeInTheDocument();
  });

  it("watches a passing change too, without showing a strip", async () => {
    changeGate = gate({ threshold_breached: false, blocked_by: [] });
    renderPage();
    await screen.findByText("PASSING");

    await waitFor(() => expect(signalCalls()).toBeGreaterThan(0));
    expect(screen.queryByText(/Watching for the next scan/)).not.toBeInTheDocument();
  });

  it("does not watch a report with no branch", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    reports = [report({ branch: null })];
    renderPage();
    await screen.findByRole("list", { name: "Blocking findings" });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(20_000);
    });

    expect(signalCalls()).toBe(0);
    expect(screen.queryByText(/Watching for the next scan/)).not.toBeInTheDocument();
  });

  it("shows the scanning stamp while a newer scan runs, then moves to the new change", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    renderPage();
    await screen.findByRole("list", { name: "Blocking findings" });

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
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
      "A newer report is processing.",
    );
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

    signalReports = [
      report({ id: "r0", commit_sha: NEWER_SHA, created_at: "2024-12-01T00:00:00Z" }),
    ];
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_100);
    });

    expect(screen.getByTestId("where")).toHaveTextContent(FULL_SHA);
    expect(screen.getByText("BLOCKED")).toBeInTheDocument();
  });

  it("stays on an old change when the branch already has a newer report", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    signalReports = [
      report({ id: "r2", commit_sha: NEWER_SHA, created_at: "2025-01-02T00:00:00Z" }),
    ];
    renderPage();
    await screen.findByRole("list", { name: "Blocking findings" });
    await waitFor(() => expect(signalCalls()).toBe(1));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000);
    });

    expect(screen.getByTestId("where")).toHaveTextContent(FULL_SHA);
    expect(screen.queryByText(/Watching for the next scan/)).not.toBeInTheDocument();
    expect(signalCalls()).toBe(1);
  });

  it("says no new report arrived after ten minutes, and keeps watching", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    renderPage();
    await screen.findByRole("list", { name: "Blocking findings" });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(600_500);
    });

    expect(
      await screen.findByText(`No new report since ${formatClockTime("2025-01-01T00:00:00Z")}`),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        /Check that the CI job ran on your last push and that its scan step uploads to Specht\. Still watching; checked/,
      ),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Check again" })).not.toBeInTheDocument();

    const before = signalCalls();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(31_000);
    });
    expect(signalCalls()).toBeGreaterThan(before);
  });

  it("does not announce the strip a second time once the stalled notice speaks", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    renderPage();
    await screen.findByRole("list", { name: "Blocking findings" });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(600_500);
    });
    await screen.findByText(/No new report since/);

    const strip = screen.getByText("Watching for the next scan of main");
    expect(strip).not.toHaveAttribute("role", "status");
  });

  it("says it is offline while the connection is gone, and clears when it is back", async () => {
    renderPage();
    await screen.findByRole("list", { name: "Blocking findings" });

    setOnLine(false);

    expect(
      await screen.findByText(
        /^You are offline\. This is the verdict from \d{2}:\d{2}; it updates when the connection is back\.$/,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("Paused while you are offline")).toBeInTheDocument();
    expect(screen.queryByText("Watching for the next scan of main")).not.toBeInTheDocument();

    setOnLine(true);

    await waitFor(() => expect(screen.queryByText(/You are offline/)).not.toBeInTheDocument());
    expect(screen.getByText("Watching for the next scan of main")).toBeInTheDocument();
  });

  it("says offline on a passing change as well", async () => {
    changeGate = gate({ threshold_breached: false, blocked_by: [] });
    renderPage();
    await screen.findByText("PASSING");

    setOnLine(false);

    expect(await screen.findByText(/^You are offline\./)).toBeInTheDocument();
  });
});
