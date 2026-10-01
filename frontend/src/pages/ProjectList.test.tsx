import { formatDateTime } from "@/lib/format";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
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
  readonly projects?: unknown;
  readonly me?: unknown;
  readonly gate?: (slug: string) => MaybePromise<unknown>;
  readonly stats?: (slug: string) => MaybePromise<unknown>;
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

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    headers: { "Content-Type": "application/json" },
  });
}

function makeGate(blockedBy: string[]) {
  return {
    threshold_breached: blockedBy.length > 0,
    blocking_count: blockedBy.length,
    blocked_by: blockedBy,
  };
}

function makeStats(reportCount: number, totalFindings: number, createdAt?: string) {
  return {
    total_findings: totalFindings,
    blocking_count: 0,
    waiver_count: 0,
    report_count: reportCount,
    by_severity: [],
    latest_report: createdAt ? { id: "r1", created_at: createdAt } : undefined,
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
  return screen.getAllByRole("link").map((link) => link.textContent ?? "");
}

/** The table row that owns the project link with this name. */
function rowFor(name: string): HTMLElement {
  const row = screen.getByRole("link", { name }).closest("tr");
  if (!row) throw new Error(`no row for project ${name}`);
  return row;
}

function renderProjectRoutes() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/"]}>
        <Routes>
          <Route path="/" element={<ProjectList />} />
          <Route path="/:slug/findings" element={<p>Findings page</p>} />
          <Route path="/projects/new" element={<p>New project page</p>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("ProjectList", () => {
  it("shows a table-shaped loading skeleton first", () => {
    renderProjectRoutes();

    expect(screen.getByRole("table")).toBeInTheDocument();
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
    for (const column of ["Project", "Verdict", "Blocking", "Findings", "Last scan"]) {
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

    expect(within(rowFor("Beta")).getByText("–")).toBeInTheDocument();
    expect(within(rowFor("Beta")).getByText("4")).toBeInTheDocument();

    expect(within(rowFor("Gamma")).getByText("Never")).toBeInTheDocument();
    expect(within(rowFor("Gamma")).getByText("0")).toBeInTheDocument();
  });

  it("keeps rows alphabetical until all settle, then orders blocked first", async () => {
    const alphaGate = deferred();
    const scannedAt = recentIso(2);
    mockApi({
      projects: [
        { id: "p2", slug: "zulu", name: "Zulu", description: null },
        { id: "p1", slug: "alpha", name: "Alpha", description: null },
      ],
      me: { role: "member" },
      gate: (slug) => (slug === "alpha" ? alphaGate.promise : makeGate(["f1", "f2"])),
      stats: () => makeStats(1, 1, scannedAt),
    });
    renderProjectRoutes();

    // Zulu is blocked but Alpha is still loading, so no reordering may happen.
    await screen.findByText("BLOCKED");
    expect(within(rowFor("Alpha")).getByText("UNKNOWN")).toBeInTheDocument();
    await waitFor(() => expect(rowNames()).toEqual(["Alpha", "Zulu"]));

    alphaGate.resolve(makeGate(["f1"]));
    await waitFor(() => expect(rowNames()).toEqual(["Zulu", "Alpha"]));
  });

  it("shows UNKNOWN for a failed gate request without breaking other rows", async () => {
    const scannedAt = recentIso(2);
    mockApi({
      projects: [
        { id: "p1", slug: "alpha", name: "Alpha", description: null },
        { id: "p2", slug: "beta", name: "Beta", description: null },
      ],
      me: { role: "member" },
      gate: (slug) => {
        if (slug === "alpha") throw new Error("gate unavailable");
        return makeGate([]);
      },
      stats: () => makeStats(1, 5, scannedAt),
    });
    renderProjectRoutes();

    await screen.findByText("UNKNOWN");
    const alpha = rowFor("Alpha");
    expect(within(alpha).getByText("UNKNOWN")).toBeInTheDocument();
    expect(within(alpha).getAllByText("–")).toHaveLength(3);

    const beta = rowFor("Beta");
    expect(within(beta).getByText("PASSING")).toBeInTheDocument();
    expect(within(beta).getByText("5")).toBeInTheDocument();
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
    expect(await screen.findByText("Findings page")).toBeInTheDocument();
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
      if (url.endsWith("/gate")) return jsonResponse(makeGate([]));
      if (url.endsWith("/stats")) return jsonResponse(makeStats(1, 1, scannedAt));
      return jsonResponse({});
    });
    renderProjectRoutes();

    expect(await screen.findByText("Service unavailable")).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("link", { name: "Alpha" })).toBeInTheDocument();
  });
});
