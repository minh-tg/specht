import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ChangeView } from "./ChangeView";

const SHA = "2222222222222222222222222222222222222222";
const OLD_SHA = "1111111111111111111111111111111111111111";

let reportsById: Record<string, unknown>;
let gates: Record<string, Record<string, unknown> | number>;
let findings: Record<string, unknown>;
let waivers: unknown[];
let signalReports: unknown[];
let gateUrls: string[];

function report(overrides: Record<string, unknown> = {}) {
  return {
    id: "r2",
    project_id: "p1",
    tool_name: "trivy",
    scan_type: "filesystem",
    status: "completed",
    branch: "main",
    commit_sha: SHA,
    scan_mode: "full",
    created_at: "2025-01-02T00:00:00Z",
    completed_at: "2025-01-02T00:01:00Z",
    raw_data_expired: false,
    ...overrides,
  };
}

function finding(id: string, overrides: Record<string, unknown> = {}) {
  return {
    id,
    project_id: "p1",
    finding_kind: "sca",
    fingerprint: id,
    current_title: `Finding ${id}`,
    current_severity: "high",
    state: "open",
    analysis_state: "unanalyzed",
    gate_effect: "block",
    first_seen_at: "2025-01-01T00:00:00Z",
    last_seen_at: "2025-01-01T00:00:00Z",
    remediation: { summary: `Fix ${id}` },
    ...overrides,
  };
}

function passingGate(overrides: Record<string, unknown> = {}) {
  return {
    threshold_breached: false,
    blocking_count: 0,
    blocked_by: [],
    policy: { severity_floor: "high", severity_source: "default" },
    ...overrides,
  };
}

function waiver(overrides: Record<string, unknown> = {}) {
  return {
    id: "w1",
    project_id: "p1",
    name: "Waiver request: SQL injection in user query",
    description: "",
    enabled: true,
    status: "approved",
    scope_all: false,
    reason: "behind the gateway",
    decided_by: "u2",
    decided_by_name: "A. Kim",
    decision_note: "",
    expires_at: "2099-11-27T00:00:00Z",
    conditions: [],
    contexts: [],
    targets: [{ id: "t1", finding_id: "waived" }],
    created_at: "",
    updated_at: "",
    ...overrides,
  };
}

/** The earlier scan (r1) blocked on these; the scan on screen (r2) passes. */
function previousState(ids: string[]) {
  return { previousBlockers: { slug: "acme", reportId: "r1", ids } };
}

beforeEach(() => {
  reportsById = { r2: report() };
  gates = { r2: passingGate(), r1: passingGate() };
  findings = {};
  waivers = [];
  signalReports = [];
  gateUrls = [];

  globalThis.fetch = vi.fn().mockImplementation((input: RequestInfo | URL) => {
    const url = String(input);
    if (url === "/api/v1/projects/acme") {
      return Promise.resolve(
        jsonResponse({
          id: "p1",
          slug: "acme",
          name: "Acme API",
          description: null,
          created_at: "",
          updated_at: "",
          role: "member",
          permissions: { request_waiver: true },
        }),
      );
    }
    if (url.startsWith("/api/v1/reports/")) {
      const found = reportsById[decodeURIComponent(url.slice("/api/v1/reports/".length))];
      return Promise.resolve(
        found ? jsonResponse(found) : jsonResponse({ error: { code: "not_found" } }, 404),
      );
    }
    if (url.startsWith("/api/v1/projects/acme/reports?")) {
      return Promise.resolve(jsonResponse(signalReports));
    }
    if (url.startsWith("/api/v1/projects/acme/waivers")) {
      return Promise.resolve(jsonResponse(waivers));
    }
    if (url.startsWith("/api/v1/projects/acme/gate?introduced_only=")) {
      gateUrls.push(url);
      const id = new URL(url, "http://x").searchParams.get("report_id") ?? "";
      const entry = gates[id];
      if (typeof entry === "number") {
        return Promise.resolve(
          jsonResponse({ error: { code: "boom", message: "gate failed" } }, entry),
        );
      }
      return Promise.resolve(jsonResponse(entry ?? passingGate()));
    }
    if (url.startsWith("/api/v1/projects/acme/gate")) {
      return Promise.resolve(jsonResponse(passingGate()));
    }
    const match = /^\/api\/v1\/findings\/(.+)$/.exec(url);
    if (match) {
      const data = findings[decodeURIComponent(match[1])];
      return Promise.resolve(
        data === undefined
          ? jsonResponse({ error: { code: "not_found", message: "missing" } }, 404)
          : jsonResponse(data),
      );
    }
    return Promise.resolve(jsonResponse({}));
  });
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

function Where() {
  const location = useLocation();
  return (
    <>
      <p data-testid="where">{location.pathname}</p>
      <p data-testid="carried">{JSON.stringify(location.state)}</p>
    </>
  );
}

function renderPage(state?: unknown, path = `/acme/changes/${SHA}?report=r2&scope=introduced`) {
  const qc = createTestQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter
        initialEntries={[{ pathname: path.split("?")[0], search: `?${path.split("?")[1]}`, state }]}
      >
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

function clearedList() {
  return screen.getByRole("list", { name: /that blocked the earlier scan$/ });
}

describe("ChangeView after a blocked scan", () => {
  it("says Unblocked and names how each earlier blocker cleared", async () => {
    findings = {
      fixed: finding("fixed", { state: "fixed", current_title: "Denial of service in ssh" }),
      waived: finding("waived", { current_title: "SQL injection in user query" }),
      dismissed: finding("dismissed", {
        current_title: "Weak hash",
        analysis_state: "not_affected",
        gate_effect: "ignore",
      }),
      uncounted: finding("uncounted", { current_title: "Old header issue" }),
    };
    gates.r1 = passingGate({ waived_finding_ids: ["waived"], waived_count: 1 });
    waivers = [waiver()];
    renderPage(previousState(["fixed", "waived", "dismissed", "uncounted"]));

    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent(
      "Unblocked. Nothing blocks this change now.",
    );
    expect(screen.getByText("PASSING")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "What cleared it" })).toBeInTheDocument();

    const rows = within(await waitForRows(4));
    expect(rows.getByText("Fixed: a scan that checks for it no longer finds it."))
      .toBeInTheDocument();
    expect(
      rows.getByText(
        /^Waived by “SQL injection in user query”, approved by A\. Kim, until .*2099.*\. It blocks again after that\.$/,
      ),
    ).toBeInTheDocument();
    expect(rows.getByText("Marked not affected. The gate ignores it.")).toBeInTheDocument();
    expect(
      rows.getByText("Still open, but it no longer counts toward the gate."),
    ).toBeInTheDocument();
    expect(rows.getByRole("link", { name: "Denial of service in ssh" })).toHaveAttribute(
      "href",
      "/acme/findings/fixed",
    );
  });

  it("explains a mixed set: fixed, a dismissed finding with an end date, and an archived one", async () => {
    findings = {
      fixed: finding("fixed", { state: "fixed" }),
      risk: finding("risk", {
        analysis_state: "accepted_risk",
        gate_effect: "ignore",
        analysis_expires_at: "2099-03-01T00:00:00Z",
      }),
      gone: finding("gone", { state: "archived" }),
    };
    renderPage(previousState(["fixed", "risk", "gone"]));

    await screen.findByRole("heading", { level: 1, name: /^Unblocked/ });
    const rows = within(await waitForRows(3));
    expect(rows.getByText(/^Fixed:/)).toBeInTheDocument();
    expect(
      rows.getByText(/^Marked accepted risk until .*2099.*\. It blocks again after that\.$/),
    ).toBeInTheDocument();
    expect(
      rows.getByText(
        "Archived: the report that found it was deleted. Nothing confirms it is fixed.",
      ),
    ).toBeInTheDocument();
  });

  it("names a waiver with no end date, and a waiver nothing names", async () => {
    findings = { waived: finding("waived"), other: finding("other") };
    gates.r1 = passingGate({ waived_finding_ids: ["waived", "other"] });
    waivers = [waiver({ expires_at: null })];
    renderPage(previousState(["waived", "other"]));

    await screen.findByRole("heading", { level: 1, name: /^Unblocked/ });
    const rows = within(await waitForRows(2));
    expect(
      rows.getByText(
        "Waived by “SQL injection in user query”, approved by A. Kim, with no end date.",
      ),
    ).toBeInTheDocument();
    expect(rows.getByText("Waived: an approved waiver covers it.")).toBeInTheDocument();
  });

  it("does not say Unblocked while an earlier blocker is open and unexplained", async () => {
    findings = {
      fixed: finding("fixed", { state: "fixed" }),
      stuck: finding("stuck", { current_title: "Hard-coded credential" }),
    };
    gates.r1 = passingGate({ threshold_breached: true, blocked_by: ["stuck"] });
    renderPage(previousState(["fixed", "stuck"]));

    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent(
      "Passed, but 1 earlier blocker is still open.",
    );
    expect(document.body).not.toHaveTextContent(/Unblocked/);
    expect(document.body).not.toHaveTextContent(/Nothing blocks this change now/);
    const open = await screen.findByRole("list", { name: "Findings still open" });
    expect(await within(open).findByText("Hard-coded credential")).toBeInTheDocument();
    expect(screen.getByText(/did not examine this finding/)).toBeInTheDocument();
    expect(screen.getByText(/then send a fresh scanner report/)).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { level: 2, name: "What cleared the rest" }),
    ).toBeInTheDocument();
    expect(await within(await waitForRows(1)).findByText(/^Fixed:/)).toBeInTheDocument();
  });

  it("lists every open blocker when several remain", async () => {
    findings = { a: finding("a"), b: finding("b") };
    gates.r1 = passingGate({ threshold_breached: true, blocked_by: ["a", "b"] });
    renderPage(previousState(["a", "b"]));

    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent(
      "Passed, but 2 earlier blockers are still open.",
    );
    expect(screen.getByText(/did not examine these findings/)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /What cleared/ })).not.toBeInTheDocument();
  });

  it("does not say Unblocked when the earlier scan's gate cannot be read", async () => {
    findings = { fixed: finding("fixed", { state: "fixed" }) };
    gates.r1 = 500;
    const user = userEvent.setup();
    renderPage(previousState(["fixed"]));

    expect(await screen.findByText("Could not check what blocked the earlier scan"))
      .toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(/Unblocked/);
    expect(screen.queryByRole("heading", { name: "What cleared it" })).not.toBeInTheDocument();

    gates.r1 = passingGate();
    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("heading", { level: 1, name: /^Unblocked/ }))
      .toBeInTheDocument();
  });

  it("shows no end state when no earlier blocking scan was carried", async () => {
    renderPage(undefined);

    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent(
      "Nothing first seen in this commit blocks the merge.",
    );
    expect(screen.queryByText(/What cleared/)).not.toBeInTheDocument();
    expect(gateUrls.some((url) => url.includes("report_id=r1"))).toBe(false);
  });

  it("ignores carried state from another project or for the report on screen", async () => {
    renderPage({ previousBlockers: { slug: "other", reportId: "r1", ids: ["x"] } });
    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent(
      "Nothing first seen in this commit",
    );
  });

  it("ignores carried state that is not a list of ids", async () => {
    renderPage({ previousBlockers: { slug: "acme", reportId: "r1", ids: null } });
    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent(
      "Nothing first seen in this commit",
    );
    expect(gateUrls.some((url) => url.includes("report_id=r1"))).toBe(false);
  });

  it("says what a filtered scan covered and never calls it a full scan", async () => {
    reportsById.r2 = report({
      scan_filter: { severities: ["critical", "high"], fixable_only: true },
    });
    findings = { fixed: finding("fixed", { state: "fixed" }) };
    renderPage(previousState(["fixed"]));

    await screen.findByRole("heading", { level: 1, name: /^Unblocked/ });
    expect(
      screen.getByText(
        /Filtered scan: it kept only critical and high findings and only findings with a fix\. Findings outside the filter were not examined/,
      ),
    ).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(/Scanned in full|Full scan/);
  });

  it("describes an incremental scan by the files it checked", async () => {
    reportsById.r2 = report({ scan_mode: "incremental", changed_files: ["a.go", "b.go"] });
    findings = { fixed: finding("fixed", { state: "fixed" }) };
    renderPage(previousState(["fixed"]));

    await screen.findByRole("heading", { level: 1, name: /^Unblocked/ });
    expect(screen.getByText(/Incremental scan of 2 changed files/)).toBeInTheDocument();
  });

  it("calls an unfiltered full scan what it is, without claiming completeness", async () => {
    findings = { fixed: finding("fixed", { state: "fixed" }) };
    renderPage(previousState(["fixed"]));

    await screen.findByRole("heading", { level: 1, name: /^Unblocked/ });
    expect(screen.getByText("Full scan, no filter declared.")).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(/Scanned in full/);
  });

  it("says the verdict is recorded and the PR check reflects it as of upload, never that CI is green", async () => {
    findings = { fixed: finding("fixed", { state: "fixed" }) };
    renderPage(previousState(["fixed"]));

    await screen.findByRole("heading", { level: 1, name: /^Unblocked/ });
    expect(screen.getByText(/recorded this verdict when the scan uploaded/)).toBeInTheDocument();
    expect(screen.getByText(/reflects it as of then/)).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(/\bgreen\b/i);
    expect(document.body).not.toHaveTextContent(/blocks the merge|can merge/i);
  });

  it("copes with null lists from the API", async () => {
    findings = { fixed: finding("fixed", { state: "fixed" }), waived: finding("waived") };
    gates.r2 = {
      threshold_breached: false,
      blocking_count: 0,
      blocked_by: null,
      waived_finding_ids: null,
    };
    gates.r1 = {
      threshold_breached: false,
      blocking_count: 0,
      blocked_by: null,
      waived_finding_ids: ["waived"],
    };
    waivers = [waiver({ targets: null })];
    renderPage(previousState(["fixed", "waived"]));

    await screen.findByRole("heading", { level: 1, name: /^Unblocked/ });
    const rows = within(await waitForRows(2));
    expect(rows.getByText(/^Fixed:/)).toBeInTheDocument();
    expect(rows.getByText("Waived: an approved waiver covers it.")).toBeInTheDocument();
  });

  it("caps the cleared list at twenty rows behind Show all", async () => {
    const ids = Array.from({ length: 22 }, (_, i) => `f${i}`);
    findings = Object.fromEntries(ids.map((id) => [id, finding(id, { state: "fixed" })]));
    const user = userEvent.setup();
    renderPage(previousState(ids));

    await screen.findByRole("heading", { level: 1, name: /^Unblocked/ });
    await waitForRows(20);
    expect(within(clearedList()).getAllByRole("listitem")).toHaveLength(20);
    await user.click(screen.getByRole("button", { name: "Show all 22" }));
    await waitForRows(22);
  });
});

describe("ChangeView carrying a blocked scan to the next page", () => {
  it("passes the blockers it showed to the page of the scan that replaces it", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    reportsById = {
      r1: report({ id: "r1", commit_sha: OLD_SHA, created_at: "2025-01-01T00:00:00Z" }),
    };
    gates = {
      r1: {
        threshold_breached: true,
        blocking_count: 2,
        blocked_by: ["f1", "f2"],
        policy: { severity_floor: "high", severity_source: "default" },
      },
      r2: passingGate(),
    };
    findings = { f1: finding("f1"), f2: finding("f2") };
    renderPage(undefined, `/acme/changes/${OLD_SHA}?report=r1&scope=introduced`);
    await screen.findByRole("list", { name: "Blocking findings" });

    reportsById.r2 = report();
    signalReports = [report()];
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_100);
    });
    // The first answer is the baseline; a newer report must appear after it.
    signalReports = [report({ id: "r3", created_at: "2025-01-03T00:00:00Z" })];
    reportsById.r3 = signalReports[0];
    gates.r3 = passingGate();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_100);
    });

    await waitFor(() =>
      expect(screen.getByTestId("where")).toHaveTextContent("/acme/changes/2222222")
    );
    expect(JSON.parse(screen.getByTestId("carried").textContent ?? "null")).toEqual({
      previousBlockers: { slug: "acme", reportId: "r1", ids: ["f1", "f2"] },
    });
  });
});

/** Waits until this many cleared rows have loaded their finding, then returns the list. */
async function waitForRows(count: number) {
  await waitFor(() => {
    const list = clearedList();
    expect(within(list).getAllByRole("listitem")).toHaveLength(count);
    expect(list.querySelector("[aria-busy='true']")).toBeNull();
  });
  return clearedList();
}
