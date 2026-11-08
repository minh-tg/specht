import { queryKeys, useGateStatus, useProjectStats } from "@/api/hooks";
import { formatDateTime } from "@/lib/format";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useParams } from "react-router-dom";
import { vi } from "vitest";
import { ProjectList } from "./ProjectList";

const DEFAULT_GATE = { threshold_breached: false, blocking_count: 0, blocked_by: [] };
const DEFAULT_STATS = {
  total_findings: 0,
  blocking_count: 0,
  waiver_count: 0,
  report_count: 0,
  by_severity: [],
};

type MaybePromise<T> = T | Promise<T>;

interface ApiRoutes {
  readonly projects?: readonly { slug: string; }[];
  readonly me?: unknown;
  /** One project's gate and stats. The summaries answer is built from them. */
  readonly gate?: (slug: string) => unknown;
  readonly stats?: (slug: string) => unknown;
  /** Replaces the whole summaries answer, for a pending, failed or partial batch. */
  readonly summaries?: () => MaybePromise<unknown>;
}

beforeEach(() => {
  globalThis.fetch = vi.fn();
  mockApi({});
});

function mockApi(routes: ApiRoutes): void {
  vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
    const url = String(input);

    if (url.endsWith("/api/v1/me")) {
      return jsonResponse(routes.me ?? { role: "member" });
    }
    if (url.endsWith("/api/v1/projects")) {
      return jsonResponse(routes.projects ?? []);
    }
    if (url.endsWith("/api/v1/project-summaries")) {
      if (routes.summaries) return respond(routes.summaries());
      return jsonResponse((routes.projects ?? []).map(({ slug }) => ({
        slug,
        gate: routes.gate ? routes.gate(slug) : DEFAULT_GATE,
        stats: routes.stats ? routes.stats(slug) : DEFAULT_STATS,
      })));
    }

    // The list must not ask per project. These answer anyway so a regression shows up as a
    // request count, not as a hung row.

    const gateMatch = /\/api\/v1\/projects\/([^/]+)\/gate$/.exec(url);
    if (gateMatch) {
      return respond(routes.gate ? routes.gate(gateMatch[1]) : DEFAULT_GATE);
    }

    const statsMatch = /\/api\/v1\/projects\/([^/]+)\/stats$/.exec(url);
    if (statsMatch) {
      return respond(routes.stats ? routes.stats(statsMatch[1]) : DEFAULT_STATS);
    }

    return jsonResponse({});
  });
}

async function respond(value: MaybePromise<unknown>): Promise<Response> {
  const resolved = await value;
  if (resolved instanceof Error) throw resolved;
  return jsonResponse(resolved);
}

function makeGate(blockedBy: string[]) {
  return {
    threshold_breached: blockedBy.length > 0,
    blocking_count: blockedBy.length,
    blocked_by: blockedBy,
  };
}

function makeStats(
  reportCount: number,
  totalFindings: number,
  createdAt?: string,
  status?: string,
) {
  return {
    total_findings: totalFindings,
    blocking_count: 0,
    waiver_count: 0,
    report_count: reportCount,
    by_severity: [],
    latest_report: createdAt ? { id: "r1", created_at: createdAt, status } : undefined,
  };
}

function recentIso(minutesAgo: number): string {
  return new Date(Date.now() - minutesAgo * 60 * 1000).toISOString();
}

function deferred(): { promise: Promise<unknown>; resolve: (value: unknown) => void; } {
  let resolve: (value: unknown) => void = () => {};
  const promise = new Promise<unknown>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

/** Names of the rendered rows, top to bottom. */
function rowNames(): string[] {
  return within(screen.getByRole("table")).getAllByRole("link").map((link) =>
    link.textContent ?? ""
  );
}

/** The table row that owns the project link with this name. */
function rowFor(name: string): HTMLElement {
  const row = within(screen.getByRole("table")).getByRole("link", { name }).closest("tr");
  if (!row) throw new Error(`no row for project ${name}`);
  return row;
}

/** Every URL the page fetched so far. */
function requestedUrls(): string[] {
  return vi.mocked(globalThis.fetch).mock.calls.map(([input]) => String(input));
}

/** Stands in for a project page: it reads the gate and stats the way the real pages do. */
function ProjectPageProbe() {
  const { slug = "" } = useParams();
  const gate = useGateStatus(slug);
  const stats = useProjectStats(slug);
  return (
    <p>
      Findings page: {gate.data?.blocked_by?.length ?? "?"} blocking of{" "}
      {stats.data?.total_findings ?? "?"}
    </p>
  );
}

function renderProjectRoutes() {
  const qc = createTestQueryClient();
  const view = render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/"]}>
        <Routes>
          <Route path="/" element={<ProjectList />} />
          <Route path="/:slug/findings" element={<ProjectPageProbe />} />
          <Route path="/projects/new" element={<p>New project page</p>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { ...view, qc };
}

describe("ProjectList", () => {
  it("shows a table-shaped loading skeleton first", () => {
    renderProjectRoutes();

    expect(screen.getByRole("table", { name: "Projects" })).toBeInTheDocument();
    expect(document.querySelectorAll(".animate-pulse").length).toBeGreaterThan(0);
  });

  it("shows every column for blocked, passing and never-scanned projects", async () => {
    const scannedAt = recentIso(2);
    mockApi({
      projects: [
        { id: "p1", slug: "alpha", name: "Alpha", description: "Production app" },
        { id: "p2", slug: "beta", name: "Beta", description: null },
        { id: "p3", slug: "gamma", name: "Gamma", description: null },
      ],
      me: { role: "member" },
      gate: (slug) => (slug === "alpha" ? makeGate(["f1", "f2", "f3"]) : makeGate([])),
      stats: (slug) => {
        if (slug === "alpha") return makeStats(2, 12, scannedAt);
        if (slug === "beta") return makeStats(1, 4, scannedAt);
        return makeStats(0, 0);
      },
    });
    renderProjectRoutes();

    await screen.findByRole("link", { name: "Alpha" });
    expect(screen.getByRole("table", { name: "Projects" })).toBeInTheDocument();
    for (const column of ["Project", "Verdict", "Blocking", "Findings", "Report received"]) {
      expect(screen.getByRole("columnheader", { name: column })).toBeInTheDocument();
    }
    await waitFor(() => {
      expect(within(rowFor("Alpha")).getByText("BLOCKED")).toBeInTheDocument();
      expect(within(rowFor("Beta")).getByText("PASSING")).toBeInTheDocument();
      expect(within(rowFor("Gamma")).getByText("NO SCANS")).toBeInTheDocument();
    });

    expect(within(rowFor("Alpha")).getByText("Production app")).toBeInTheDocument();
    expect(within(rowFor("Alpha")).getByText("3")).toBeInTheDocument();
    expect(within(rowFor("Alpha")).getByText("12")).toBeInTheDocument();
    const relative = within(rowFor("Alpha")).getByText("2 min ago");
    expect(relative).toHaveAttribute("title", formatDateTime(scannedAt));

    expect(within(rowFor("Beta")).getByText("None")).toBeInTheDocument();
    expect(within(rowFor("Beta")).getByText("4")).toBeInTheDocument();

    expect(within(rowFor("Gamma")).getByText("Never")).toBeInTheDocument();
    expect(within(rowFor("Gamma")).getByText("0")).toBeInTheDocument();
  });

  it("keeps rows alphabetical until the summaries answer, then orders blocked first", async () => {
    const batch = deferred();
    const scannedAt = recentIso(2);
    mockApi({
      projects: [
        { id: "p2", slug: "zulu", name: "Zulu", description: null },
        { id: "p1", slug: "alpha", name: "Alpha", description: null },
      ],
      me: { role: "member" },
      summaries: () => batch.promise,
    });
    renderProjectRoutes();

    await screen.findByRole("link", { name: "Zulu" });
    expect(rowNames()).toEqual(["Alpha", "Zulu"]);
    expect(within(rowFor("Zulu")).getByText("UNKNOWN")).toBeInTheDocument();

    batch.resolve([
      { slug: "zulu", gate: makeGate(["f1", "f2"]), stats: makeStats(1, 2, scannedAt) },
      { slug: "alpha", gate: makeGate(["f1"]), stats: makeStats(1, 1, scannedAt) },
    ]);
    await waitFor(() => expect(rowNames()).toEqual(["Zulu", "Alpha"]));
  });

  it("asks once for every row, however many projects there are", async () => {
    const projects = Array.from({ length: 8 }, (_, i) => ({
      id: `p${i}`,
      slug: `proj-${i}`,
      name: `Project ${i}`,
      description: null,
    }));
    mockApi({
      projects,
      me: { role: "member" },
      gate: (slug) => (slug === "proj-3" ? makeGate(["f1"]) : makeGate([])),
      stats: () => makeStats(1, 2, recentIso(2)),
    });
    renderProjectRoutes();

    await waitFor(() =>
      expect(within(rowFor("Project 3")).getByText("BLOCKED")).toBeInTheDocument()
    );
    expect(screen.getAllByText("PASSING")).toHaveLength(7);

    const urls = requestedUrls();
    expect(urls.filter((url) => url.endsWith("/api/v1/project-summaries"))).toHaveLength(1);
    expect(urls.filter((url) => /\/(gate|stats)$/.test(url))).toEqual([]);
    expect(urls).toHaveLength(3); // me, projects and the summaries
  });

  it("fills each project's gate and stats so opening the project does not ask again", async () => {
    mockApi({
      projects: [{ id: "p1", slug: "alpha", name: "Alpha", description: null }],
      me: { role: "member" },
      gate: () => makeGate(["f1", "f2"]),
      stats: () => makeStats(1, 9, recentIso(2)),
    });
    const { qc } = renderProjectRoutes();

    await screen.findByText("BLOCKED");
    expect(qc.getQueryData(queryKeys.gate("alpha"))).toMatchObject({ blocked_by: ["f1", "f2"] });
    expect(qc.getQueryData(queryKeys.projectStats("alpha"))).toMatchObject({ total_findings: 9 });

    await userEvent.setup().click(screen.getByRole("link", { name: "Alpha" }));
    expect(await screen.findByText("Findings page: 2 blocking of 9")).toBeInTheDocument();
    expect(requestedUrls().filter((url) => /\/(gate|stats)$/.test(url))).toEqual([]);
  });

  it("turns null lists from the server into empty ones", async () => {
    mockApi({
      projects: [{ id: "p1", slug: "alpha", name: "Alpha", description: null }],
      me: { role: "member" },
      summaries: () => [{
        slug: "alpha",
        gate: {
          threshold_breached: false,
          blocking_count: 0,
          blocked_by: null,
          waived_finding_ids: null,
        },
        stats: { ...makeStats(1, 0, recentIso(2)), by_severity: null, by_analysis_state: null },
      }],
    });
    const { qc } = renderProjectRoutes();

    await waitFor(() => expect(within(rowFor("Alpha")).getByText("PASSING")).toBeInTheDocument());
    expect(qc.getQueryData(queryKeys.gate("alpha"))).toMatchObject({
      blocked_by: [],
      waived_finding_ids: [],
    });
    expect(qc.getQueryData(queryKeys.projectStats("alpha"))).toMatchObject({
      by_severity: [],
      by_analysis_state: [],
    });
  });

  it("treats a null summaries answer as no rows of data", async () => {
    mockApi({
      projects: [{ id: "p1", slug: "alpha", name: "Alpha", description: null }],
      me: { role: "member" },
      summaries: () => null,
    });
    renderProjectRoutes();

    await waitFor(() => expect(within(rowFor("Alpha")).getAllByText("None")).toHaveLength(3));
    expect(within(rowFor("Alpha")).getByText("UNKNOWN")).toBeInTheDocument();
  });

  it("names the project to start with once everything has settled", async () => {
    const scannedAt = recentIso(2);
    mockApi({
      projects: [
        { id: "p1", slug: "alpha", name: "Alpha", description: null },
        { id: "p2", slug: "zulu", name: "Zulu", description: null },
        { id: "p3", slug: "mid", name: "Mid", description: null },
      ],
      me: { role: "member" },
      gate: (slug) =>
        slug === "zulu"
          ? makeGate(["f1", "f2", "f3"])
          : slug === "alpha"
          ? makeGate(["f1"])
          : makeGate([]),
      stats: () => makeStats(1, 3, scannedAt),
    });
    renderProjectRoutes();

    const hero = await screen.findByRole("region", { name: /2 projects are blocked/ });
    expect(hero).toHaveTextContent("Start with Zulu.");
    expect(within(hero).getByText("Do this")).toBeInTheDocument();
    expect(within(hero).getByRole("link", { name: "Open Zulu" })).toHaveAttribute(
      "href",
      "/zulu/findings",
    );
  });

  it("says nothing about where to start while the summaries are still loading", async () => {
    const batch = deferred();
    const stats = makeStats(1, 1, recentIso(2));
    mockApi({
      projects: [
        { id: "p1", slug: "alpha", name: "Alpha", description: null },
        { id: "p2", slug: "beta", name: "Beta", description: null },
      ],
      me: { role: "member" },
      summaries: () => batch.promise,
    });
    renderProjectRoutes();

    await screen.findByRole("link", { name: "Beta" });
    expect(screen.queryByText(/Start with/)).not.toBeInTheDocument();

    batch.resolve([
      { slug: "alpha", gate: makeGate([]), stats },
      { slug: "beta", gate: makeGate(["f1"]), stats },
    ]);
    expect(await screen.findByText(/1 project is blocked/)).toBeInTheDocument();
    expect(screen.getByText("Start with", { exact: false })).toHaveTextContent("Start with Beta.");
  });

  it("does not show the start-here step when no project is blocked", async () => {
    mockApi({
      projects: [{ id: "p1", slug: "alpha", name: "Alpha", description: null }],
      me: { role: "member" },
      gate: () => makeGate([]),
      stats: () => makeStats(1, 1, recentIso(2)),
    });
    renderProjectRoutes();

    await screen.findByText("PASSING");
    expect(screen.queryByText(/Start with/)).not.toBeInTheDocument();
  });

  it("demotes New project to a secondary button while a project needs attention first", async () => {
    mockApi({
      projects: [{ id: "p1", slug: "alpha", name: "Alpha", description: null }],
      me: { role: "admin" },
      gate: () => makeGate(["f1"]),
      stats: () => makeStats(1, 1, recentIso(2)),
    });
    renderProjectRoutes();

    await screen.findByText(/Start with/);
    const newProject = screen.getByRole("link", { name: "New project" });
    expect(newProject).not.toHaveClass("bg-primary");
    expect(screen.getByRole("link", { name: "Open Alpha" })).toHaveClass("bg-primary");
  });

  it("says in the row when the latest scan failed or is still processing", async () => {
    mockApi({
      projects: [
        { id: "p1", slug: "alpha", name: "Alpha", description: null },
        { id: "p2", slug: "beta", name: "Beta", description: null },
        { id: "p3", slug: "gamma", name: "Gamma", description: null },
      ],
      me: { role: "member" },
      gate: () => makeGate([]),
      stats: (slug) =>
        makeStats(
          1,
          0,
          recentIso(2),
          slug === "alpha" ? "failed" : slug === "beta" ? "processing" : "completed",
        ),
    });
    renderProjectRoutes();

    await waitFor(() =>
      expect(within(rowFor("Alpha")).getByText(/latest scan failed/)).toBeInTheDocument()
    );
    expect(within(rowFor("Beta")).getByText(/still processing/)).toBeInTheDocument();
    expect(within(rowFor("Gamma")).queryByText(/latest scan/)).not.toBeInTheDocument();
  });

  it("shows UNKNOWN for a project the summaries left out without breaking other rows", async () => {
    const scannedAt = recentIso(2);
    mockApi({
      projects: [
        { id: "p1", slug: "alpha", name: "Alpha", description: null },
        { id: "p2", slug: "beta", name: "Beta", description: null },
      ],
      me: { role: "member" },
      summaries: () => [{ slug: "beta", gate: makeGate([]), stats: makeStats(1, 5, scannedAt) }],
    });
    renderProjectRoutes();

    await screen.findByText("UNKNOWN");
    const alpha = rowFor("Alpha");
    expect(within(alpha).getByText("UNKNOWN")).toBeInTheDocument();
    expect(within(alpha).getAllByText("None")).toHaveLength(3);

    const beta = rowFor("Beta");
    expect(within(beta).getByText("PASSING")).toBeInTheDocument();
    expect(within(beta).getByText("5")).toBeInTheDocument();
  });

  it("keeps the table with dashes in every row when the summaries request fails", async () => {
    mockApi({
      projects: [
        { id: "p1", slug: "alpha", name: "Alpha", description: null },
        { id: "p2", slug: "beta", name: "Beta", description: null },
      ],
      me: { role: "member" },
      summaries: () => new Error("summaries unavailable"),
    });
    renderProjectRoutes();

    await waitFor(() => expect(screen.getAllByText("UNKNOWN")).toHaveLength(2));
    expect(within(rowFor("Alpha")).getAllByText("None")).toHaveLength(3);
    expect(within(rowFor("Beta")).getAllByText("None")).toHaveLength(3);
    expect(screen.queryByText(/Start with/)).not.toBeInTheDocument();
  });

  it("links a project name to its findings page", async () => {
    const scannedAt = recentIso(2);
    mockApi({
      projects: [{ id: "p1", slug: "alpha", name: "Alpha", description: null }],
      me: { role: "member" },
      gate: () => makeGate([]),
      stats: () => makeStats(1, 3, scannedAt),
    });
    renderProjectRoutes();

    const link = await screen.findByRole("link", { name: "Alpha" });
    expect(link).toHaveAttribute("href", "/alpha/findings");

    await userEvent.setup().click(link);
    expect(await screen.findByText(/Findings page/)).toBeInTheDocument();
  });

  it("warms the project and its first findings page when the mouse rests on a project name", async () => {
    mockApi({
      projects: [{ id: "p1", slug: "alpha", name: "Alpha", description: null }],
      me: { role: "member" },
      gate: () => makeGate([]),
      stats: () => makeStats(1, 3, recentIso(2)),
    });
    renderProjectRoutes();

    fireEvent.pointerEnter(await screen.findByRole("link", { name: "Alpha" }), {
      pointerType: "mouse",
    });

    await waitFor(() => {
      const urls = vi.mocked(globalThis.fetch).mock.calls.map(([input]) => String(input));
      expect(urls).toContain("/api/v1/projects/alpha");
      expect(urls).toContain(
        "/api/v1/projects/alpha/findings?sort=severity&dir=desc&offset=0&limit=20",
      );
    });
  });

  it("scrolls the table inside its own focusable region on a narrow screen", async () => {
    mockApi({
      projects: [{ id: "p1", slug: "alpha", name: "Alpha", description: null }],
      me: { role: "member" },
      gate: () => makeGate([]),
      stats: () => makeStats(1, 3, recentIso(2)),
    });
    renderProjectRoutes();

    const region = await screen.findByRole("region", { name: "Projects table" });
    expect(region).toHaveAttribute("tabindex", "0");
    expect(region).toHaveClass("overflow-x-auto");
    expect(within(region).getByRole("table", { name: "Projects" })).toBeInTheDocument();
    expect(screen.getByText("Swipe the table sideways to see every column.")).toBeInTheDocument();
  });

  it("offers the New project action to admins", async () => {
    const scannedAt = recentIso(2);
    mockApi({
      projects: [{ id: "p1", slug: "alpha", name: "Alpha", description: null }],
      me: { role: "admin" },
      gate: () => makeGate([]),
      stats: () => makeStats(1, 1, scannedAt),
    });
    renderProjectRoutes();

    expect(await screen.findByRole("link", { name: "New project" })).toHaveAttribute(
      "href",
      "/projects/new",
    );
  });

  it("hides the New project action from members", async () => {
    const scannedAt = recentIso(2);
    mockApi({
      projects: [{ id: "p1", slug: "alpha", name: "Alpha", description: null }],
      me: { role: "member" },
      gate: () => makeGate([]),
      stats: () => makeStats(1, 1, scannedAt),
    });
    renderProjectRoutes();

    await screen.findByRole("link", { name: "Alpha" });
    expect(screen.queryByRole("link", { name: "New project" })).not.toBeInTheDocument();
  });

  it("invites an administrator to create the first project", async () => {
    mockApi({ projects: [], me: { role: "admin" } });
    renderProjectRoutes();

    expect(await screen.findByText("No projects yet")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Create your first project" })).toHaveAttribute(
      "href",
      "/projects/new",
    );
  });

  it("tells members to ask an administrator when there are no projects", async () => {
    mockApi({ projects: [], me: { role: "member" } });
    renderProjectRoutes();

    expect(await screen.findByText("No projects yet")).toBeInTheDocument();
    expect(screen.getByText("Ask an administrator to create one.")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Create your first project" }))
      .not.toBeInTheDocument();
  });

  it("lets the user retry after projects fail to load", async () => {
    const scannedAt = recentIso(2);
    let failed = false;
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith("/api/v1/projects")) {
        if (!failed) {
          failed = true;
          throw new Error("Service unavailable");
        }
        return jsonResponse([{ id: "p1", slug: "alpha", name: "Alpha", description: null }]);
      }
      if (url.endsWith("/api/v1/me")) return jsonResponse({ role: "member" });
      if (url.endsWith("/api/v1/project-summaries")) {
        return jsonResponse([{
          slug: "alpha",
          gate: makeGate([]),
          stats: makeStats(1, 1, scannedAt),
        }]);
      }
      return jsonResponse({});
    });
    renderProjectRoutes();

    expect(await screen.findByText("Service unavailable")).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("link", { name: "Alpha" })).toBeInTheDocument();
  });
});
