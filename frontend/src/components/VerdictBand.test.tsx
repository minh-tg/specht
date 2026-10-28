import { queryKeys } from "@/api/hooks";
import { formatDateTime } from "@/lib/format";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { VerdictBand } from "./VerdictBand";

interface Fixtures {
  gate?: unknown;
  stats?: unknown;
  me?: unknown;
  project?: unknown;
}

const PERMISSIONS = {
  request_waiver: true,
  manage_waivers: false,
  approve_waivers: false,
  manage_members: false,
  manage_ci: false,
  triage: false,
  upload_reports: false,
};

/** A project read as the server answers it for the given role. */
function projectAs(role: "admin" | "manager" | "member") {
  const manager = role !== "member";
  return {
    id: "p1",
    slug: "alpha",
    name: "Alpha",
    description: null,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    role,
    permissions: manager
      ? Object.fromEntries(Object.keys(PERMISSIONS).map((k) => [k, true]))
      : PERMISSIONS,
  };
}

/** Routes the three VerdictBand queries by path, like the other page tests. */
function mockApi({ gate = {}, stats = {}, me = { role: "member" }, project }: Fixtures = {}) {
  globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/gate")) return jsonResponse(gate);
    if (url.endsWith("/stats")) return jsonResponse(stats);
    if (url.endsWith("/me")) return jsonResponse(me);
    if (project && url.endsWith("/projects/alpha")) return jsonResponse(project);
    return jsonResponse([]);
  });
}

function renderBandIn(client: QueryClient, slug: string) {
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/${slug}/findings`]}>
        <Routes>
          <Route path="/:slug/findings" element={<VerdictBand slug={slug} />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/**
 * Installs the fetch mock and seeds the same fixtures into the query cache, so
 * the assertions never race the mocked network. `staleTime: Infinity` keeps the
 * seeded data from refetching underneath the assertions.
 */
function renderBand(fixtures: Fixtures = {}, slug = "alpha") {
  mockApi(fixtures);
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  });
  client.setQueryData(queryKeys.gate(slug), fixtures.gate ?? {});
  client.setQueryData(queryKeys.projectStats(slug), fixtures.stats ?? {});
  client.setQueryData(queryKeys.me(), fixtures.me ?? { role: "member" });
  if (fixtures.project) client.setQueryData(queryKeys.project(slug), fixtures.project);
  return renderBandIn(client, slug);
}

/** No seeded data and a fetch that never settles: the skeleton stays up. */
function renderLoadingBand(slug = "alpha") {
  globalThis.fetch = vi.fn().mockImplementation(() => new Promise(() => {}));
  const client = createTestQueryClient();
  return renderBandIn(client, slug);
}

/** No seeded data; the supplied fetch implementation decides success or failure. */
function renderLiveBand(
  fetchImpl: (input: RequestInfo | URL) => Promise<Response>,
  slug = "alpha",
) {
  globalThis.fetch = vi.fn().mockImplementation(fetchImpl);
  const client = createTestQueryClient();
  return renderBandIn(client, slug);
}

describe("VerdictBand", () => {
  it("blocks with the blocker count and the waived suffix", () => {
    renderBand({
      gate: {
        threshold_breached: true,
        blocking_count: 3,
        blocked_by: ["a", "b", "c"],
        waived_count: 2,
      },
      stats: { report_count: 4, total_findings: 3, by_severity: [] },
    });

    expect(screen.getByText("3 findings block this project")).toBeInTheDocument();
    expect(screen.getByText("BLOCKED")).toBeInTheDocument();
    expect(screen.getByText("· 2 waived")).toBeInTheDocument();
  });

  it("uses the singular verb for exactly one blocker", () => {
    renderBand({
      gate: { threshold_breached: true, blocking_count: 1, blocked_by: ["a"] },
      stats: { report_count: 1, total_findings: 1, by_severity: [] },
    });

    expect(screen.getByText("1 finding blocks this project")).toBeInTheDocument();
  });

  it("passes when nothing blocks the gate", () => {
    renderBand({
      gate: { threshold_breached: false, blocking_count: 0, blocked_by: [] },
      stats: { report_count: 2, total_findings: 0, by_severity: [] },
    });

    expect(screen.getByText("Nothing blocks this project")).toBeInTheDocument();
    expect(screen.getByText("PASSING")).toBeInTheDocument();
    expect(screen.queryByText(/waived/)).not.toBeInTheDocument();
  });

  it("announces only the verdict sentence from the loaded band", () => {
    renderBand({
      gate: { threshold_breached: false, blocking_count: 0, blocked_by: [] },
      stats: { report_count: 2, total_findings: 0, by_severity: [] },
    });

    expect(document.querySelector("[aria-live]")).toBeNull();
    expect(screen.getByRole("region", { name: "Gate verdict" })).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Nothing blocks this project");
  });

  it("offers a plain member no upload the server would refuse", () => {
    renderBand({
      gate: { threshold_breached: false, blocking_count: 0, blocked_by: [] },
      stats: { report_count: 0, total_findings: 0, by_severity: [] },
      me: { id: "u1", email: "m@acme.io", role: "member" },
      project: projectAs("member"),
    });

    expect(screen.getByText("No scans yet")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Upload a report" })).not.toBeInTheDocument();
    expect(screen.getByText("A project manager or admin can upload a report or connect CI."))
      .toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Set up CI" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "CI setup" })).not.toBeInTheDocument();
  });

  it("gives a project manager who is not a global admin the upload and CI setup links", () => {
    renderBand({
      gate: { threshold_breached: false, blocking_count: 0, blocked_by: [] },
      stats: { report_count: 0, total_findings: 0, by_severity: [] },
      me: { id: "u1", email: "m@acme.io", role: "member" },
      project: projectAs("manager"),
    });

    expect(screen.getByText("No scans yet")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Upload a report" })).toHaveAttribute(
      "href",
      "/alpha/reports/upload",
    );
    expect(screen.getByRole("link", { name: "Set up CI" })).toHaveAttribute("href", "/alpha/setup");
    expect(screen.getByRole("link", { name: "CI setup" })).toHaveAttribute("href", "/alpha/setup");
  });

  it("adds the setup links for admins", () => {
    renderBand({
      gate: { threshold_breached: false, blocking_count: 0, blocked_by: [] },
      stats: { report_count: 0, total_findings: 0, by_severity: [] },
      me: { id: "u0", email: "root@acme.io", role: "admin" },
      project: projectAs("admin"),
    });

    expect(screen.getByRole("link", { name: "Set up CI" })).toHaveAttribute(
      "href",
      "/alpha/setup",
    );
    expect(screen.getByRole("link", { name: "CI setup" })).toHaveAttribute("href", "/alpha/setup");
  });

  it("warns when the latest scan failed", () => {
    renderBand({
      gate: { threshold_breached: false, blocking_count: 0, blocked_by: [] },
      stats: {
        report_count: 2,
        total_findings: 1,
        by_severity: [],
        latest_report: {
          id: "r1",
          status: "failed",
          created_at: "2025-01-01T00:00:00Z",
          tool_name: "trivy",
        },
      },
    });

    expect(screen.getByRole("alert")).toHaveTextContent(
      "The latest scan failed, so this verdict may be incomplete.",
    );
  });

  it("warns while the server reports the latest scan as processing", () => {
    renderBand({
      gate: { threshold_breached: false, blocking_count: 0, blocked_by: [] },
      stats: {
        report_count: 2,
        total_findings: 1,
        by_severity: [],
        latest_report: {
          id: "r1",
          status: "processing",
          created_at: "2025-01-01T00:00:00Z",
          tool_name: "osv-scanner",
        },
      },
    });

    expect(screen.getByRole("alert")).toHaveTextContent(
      "The latest scan is still processing, so this verdict may change.",
    );
  });

  it("warns while the latest scan is still processing", () => {
    renderBand({
      gate: { threshold_breached: false, blocking_count: 0, blocked_by: [] },
      stats: {
        report_count: 2,
        total_findings: 1,
        by_severity: [],
        latest_report: {
          id: "r1",
          status: "pending",
          created_at: "2025-01-01T00:00:00Z",
          tool_name: "osv-scanner",
        },
      },
    });

    expect(screen.getByRole("alert")).toHaveTextContent(
      "The latest scan is still processing, so this verdict may change.",
    );
  });

  it("links severity chips and hides zero counts", () => {
    renderBand({
      gate: { threshold_breached: true, blocking_count: 2, blocked_by: ["a", "b"] },
      stats: {
        report_count: 3,
        total_findings: 3,
        by_severity: [
          { severity: "critical", count: 2, blocking_count: 2 },
          { severity: "high", count: 0, blocking_count: 0 },
          { severity: "low", count: 1, blocking_count: 0 },
        ],
      },
    });

    const critical = screen.getByRole("link", { name: "Critical 2 findings" });
    expect(critical).toHaveAttribute("href", "/alpha/findings?severity=critical");
    const low = screen.getByRole("link", { name: "Low 1 finding" });
    expect(low).toHaveAttribute("href", "/alpha/findings?severity=low");
    expect(low).toHaveTextContent("Low");
    expect(screen.queryByRole("link", { name: /^High \d/ })).not.toBeInTheDocument();
  });

  it("counts findings the scanner did not rate and links them to the unknown filter", () => {
    // The server stores unrated findings as `unknown`; dropping them made the
    // chips add up to less than the project's findings.
    renderBand({
      gate: { threshold_breached: false, blocking_count: 0, blocked_by: [] },
      stats: {
        report_count: 1,
        total_findings: 3,
        by_severity: [
          { severity: "low", count: 1, blocking_count: 0 },
          { severity: "unknown", count: 2, blocking_count: 0 },
        ],
      },
    });

    const unrated = screen.getByRole("link", { name: "Unrated 2 findings" });
    expect(unrated).toHaveAttribute("href", "/alpha/findings?severity=unknown");
    expect(unrated).toHaveTextContent("Unrated");
  });

  it("shows triage counters only when the breakdown is present", () => {
    renderBand({
      gate: { threshold_breached: false, blocking_count: 0, blocked_by: [] },
      stats: {
        report_count: 2,
        total_findings: 5,
        by_severity: [{ severity: "high", count: 5, blocking_count: 0 }],
        by_analysis_state: [
          { state: "unanalyzed", count: 4 },
          { state: "exploitable", count: 2 },
          { state: "false_positive", count: 1 },
        ],
      },
    });

    expect(screen.getByText("Needs triage 4")).toBeInTheDocument();
    expect(screen.getByText("Exploitable 2")).toBeInTheDocument();
    expect(screen.getByText("Dismissed 1")).toBeInTheDocument();
  });

  it("links the needs-triage count to both analysis states and only open or reopened findings", () => {
    renderBand({
      gate: { threshold_breached: false, blocking_count: 0, blocked_by: [] },
      stats: {
        report_count: 1,
        by_analysis_state: [{ state: "unanalyzed", count: 3 }, { state: "in_triage", count: 2 }, {
          state: "exploitable",
          count: 7,
        }],
      },
    });
    const link = screen.getByRole("link", { name: "Needs triage 5" });
    const target = new URL(link.getAttribute("href")!, "http://localhost");
    expect(target.pathname).toBe("/alpha/findings");
    expect(target.searchParams.get("analysis_state")).toBe("unanalyzed,in_triage");
    expect(target.searchParams.get("status")).toBe("open,reopened");
    expect(target.searchParams.has("severity")).toBe(false);
  });

  it("hides the triage counters when the breakdown is absent", () => {
    renderBand({
      gate: { threshold_breached: false, blocking_count: 0, blocked_by: [] },
      stats: {
        report_count: 2,
        total_findings: 1,
        by_severity: [{ severity: "low", count: 1, blocking_count: 0 }],
      },
    });

    expect(screen.getByText("PASSING")).toBeInTheDocument();
    expect(screen.queryByText(/Needs triage/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Dismissed/)).not.toBeInTheDocument();
  });

  it("shows the policy floor and known report receipt time with an absolute-time tooltip", () => {
    renderBand({
      gate: {
        threshold_breached: false,
        blocking_count: 0,
        blocked_by: [],
        policy: {
          template_name: null,
          template_version: 1,
          severity_floor: "medium",
          severity_source: "default",
          watcher_gate: "block",
          watcher_source: "default",
        },
      },
      stats: {
        report_count: 1,
        total_findings: 0,
        by_severity: [],
        latest_report: {
          id: "r1",
          status: "completed",
          created_at: "2025-01-01T00:00:00Z",
          tool_name: "trivy",
        },
      },
    });

    expect(screen.getByText("Floor: medium (default)")).toBeInTheDocument();
    const scan = screen.getByText(/Latest completed report/);
    expect(scan).toHaveTextContent("trivy");
    const when = within(scan).getByRole("time");
    expect(when).toHaveAttribute("datetime", "2025-01-01T00:00:00Z");
    expect(when).toHaveAttribute("title", formatDateTime("2025-01-01T00:00:00Z"));
  });

  it.each(["failed", "processing"])(
    "keeps old completed evidence separate from a newer %s attempt",
    (status) => {
      renderBand({
        gate: { threshold_breached: false, blocked_by: [] },
        stats: {
          report_count: 2,
          latest_completed_report: {
            id: "old",
            status: "completed",
            tool_name: "trivy",
            created_at: "2025-01-01T00:00:00Z",
            completed_at: "2025-01-01T00:02:00Z",
          },
          latest_report: {
            id: "new",
            status,
            tool_name: "sarif",
            created_at: "2025-02-01T00:00:00Z",
            completed_at: "2025-02-01T00:02:00Z",
          },
        },
      });
      const completed = screen.getByText(/Latest completed report/);
      expect(within(completed).getByRole("time")).toHaveAttribute(
        "datetime",
        "2025-01-01T00:02:00Z",
      );
      expect(completed).toHaveTextContent("trivy");
      const attempt = screen.getByText(/Latest attempt/);
      expect(attempt).toHaveTextContent(status === "failed" ? "Failed" : "Processing");
      expect(within(attempt).getByRole("time")).toHaveAttribute("datetime", "2025-02-01T00:00:00Z");
      expect(screen.getByRole("alert")).toHaveTextContent(
        status === "failed" ? "latest scan failed" : "latest scan is still processing",
      );
    },
  );

  it("does not invent completion time for a legacy completed report", () => {
    renderBand({
      gate: {},
      stats: {
        report_count: 1,
        latest_report: {
          id: "legacy",
          status: "completed",
          tool_name: "trivy",
          created_at: "2025-01-01T00:00:00Z",
        },
      },
    });
    const completed = screen.getByText(/Latest completed report/);
    expect(completed).toHaveTextContent("received");
    expect(completed).toHaveTextContent("completion time unavailable");
    expect(within(completed).getByRole("time")).toHaveAttribute("datetime", "2025-01-01T00:00:00Z");
  });

  it("shows a failed-only history without claiming completed evidence", () => {
    renderBand({
      gate: {},
      stats: {
        report_count: 1,
        latest_report: { id: "failed", status: "failed", created_at: "2025-01-01T00:00:00Z" },
      },
    });
    expect(screen.getByText("No completed report available.")).toBeInTheDocument();
    expect(screen.getByText(/Latest attempt/)).toHaveTextContent("Failed");
  });

  it("warns when a background refresh fails without relabelling old evidence as current", async () => {
    const fixtures = {
      gate: { threshold_breached: false, blocked_by: [] },
      stats: {
        report_count: 1,
        latest_report: {
          id: "old",
          status: "completed",
          tool_name: "trivy",
          created_at: "2025-01-01T00:00:00Z",
        },
      },
    };
    mockApi(fixtures);
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false, staleTime: Infinity } },
    });
    client.setQueryData(queryKeys.gate("alpha"), fixtures.gate);
    client.setQueryData(queryKeys.projectStats("alpha"), fixtures.stats);
    renderBandIn(client, "alpha");
    globalThis.fetch = vi.fn().mockResolvedValue(new Response(null, { status: 500 }));
    await act(async () => {
      await client.refetchQueries({ queryKey: queryKeys.projectStats("alpha") });
    });

    expect(await screen.findByRole("alert")).toHaveTextContent("Showing the last fetched data");
    expect(within(screen.getByText(/Latest completed report/)).getByRole("time")).toHaveAttribute(
      "datetime",
      "2025-01-01T00:00:00Z",
    );
    mockApi(fixtures);
    await userEvent.setup().click(screen.getByRole("button", { name: "Retry project data" }));
    expect(await screen.findByText("Nothing blocks this project")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("reserves height with skeletons while loading", () => {
    renderLoadingBand();

    expect(document.querySelectorAll(".bg-muted.animate-pulse").length).toBeGreaterThan(0);
    expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
    expect(screen.queryByText("Nothing blocks this project")).not.toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Gate verdict" })).toHaveAttribute(
      "aria-busy",
      "true",
    );
    expect(document.querySelector("[aria-live]")).toBeNull();
  });

  it("keeps the skeleton for a slow request instead of showing an error", () => {
    renderLoadingBand();

    expect(document.querySelectorAll(".animate-pulse").length).toBeGreaterThan(0);
    expect(screen.queryByText("Couldn't load the verdict.")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retry" })).not.toBeInTheDocument();
  });

  it("shows an error and a retry when the gate request fails", async () => {
    renderLiveBand(async (input) => {
      const url = String(input);
      if (url.endsWith("/gate")) return new Response(null, { status: 500 });
      if (url.endsWith("/stats")) {
        return jsonResponse({ report_count: 2, total_findings: 0, by_severity: [] });
      }
      if (url.endsWith("/me")) return jsonResponse({ role: "member" });
      return jsonResponse([]);
    });

    expect(
      await screen.findByText("Couldn't load the verdict.", undefined, { timeout: 5000 }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toHaveAttribute("type", "button");
    expect(document.querySelectorAll(".animate-pulse").length).toBe(0);
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(document.querySelector("[aria-live]")).toBeNull();
  }, 20000);

  it("shows an error and a retry when the stats request fails", async () => {
    renderLiveBand(async (input) => {
      const url = String(input);
      if (url.endsWith("/stats")) return new Response(null, { status: 500 });
      if (url.endsWith("/gate")) {
        return jsonResponse({ threshold_breached: false, blocking_count: 0, blocked_by: [] });
      }
      if (url.endsWith("/me")) return jsonResponse({ role: "member" });
      return jsonResponse([]);
    });

    expect(
      await screen.findByText("Couldn't load the verdict.", undefined, { timeout: 5000 }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
    expect(document.querySelectorAll(".animate-pulse").length).toBe(0);
  }, 20000);

  it("re-requests and shows the verdict after Retry succeeds", async () => {
    let gateFails = true;
    renderLiveBand(async (input) => {
      const url = String(input);
      if (url.endsWith("/gate")) {
        return gateFails
          ? new Response(null, { status: 500 })
          : jsonResponse({ threshold_breached: false, blocking_count: 0, blocked_by: [] });
      }
      if (url.endsWith("/stats")) {
        return jsonResponse({ report_count: 2, total_findings: 0, by_severity: [] });
      }
      if (url.endsWith("/me")) return jsonResponse({ role: "member" });
      return jsonResponse([]);
    });

    const retry = await screen.findByRole("button", { name: "Retry" }, { timeout: 5000 });
    gateFails = false;
    await userEvent.setup().click(retry);

    expect(
      await screen.findByText("Nothing blocks this project", undefined, { timeout: 5000 }),
    ).toBeInTheDocument();
    expect(screen.queryByText("Couldn't load the verdict.")).not.toBeInTheDocument();
  }, 20000);
});
