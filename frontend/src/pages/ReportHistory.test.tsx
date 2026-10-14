import { Toaster } from "@/components/ui/sonner";
import { formatDateTime } from "@/lib/format";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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

  it("encodes the commit and report ids in the change link", async () => {
    mockReports([{ ...REPORTS[0], id: "r 1", commit_sha: "ab/c?d" }]);
    renderWithProviders(<ReportHistory />);
    const link = await screen.findByRole("link", { name: "ab/c?d" });
    expect(link).toHaveAttribute("href", "/test-project/changes/ab%2Fc%3Fd?report=r%201");
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

    // Branch text stays, and the commit sha links to its change view.
    expect(screen.getByText("main")).toBeInTheDocument();
    expect(screen.getByText("feature/x")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "abcdef1" })).toHaveAttribute(
      "href",
      "/test-project/changes/abcdef1234567890?report=r1",
    );
    expect(screen.getByRole("link", { name: "1234567" })).toHaveAttribute(
      "href",
      "/test-project/changes/1234567abcdef?report=r3",
    );

    // The failed report is visually louder than the others.
    const failedCard = screen.getByText("Failed").closest("div.bg-card");
    expect(failedCard?.className).toContain("border-destructive");
  });

  it("shows why a failed report failed under its status", async () => {
    mockReports([
      {
        id: "r1",
        project_id: "p1",
        tool_name: "trivy",
        tool_version: null,
        scan_type: "filesystem",
        scan_target: null,
        status: "failed",
        total_findings: null,
        branch: null,
        commit_sha: null,
        error_message: "scanner exited with status 2: unsupported lockfile version",
        created_at: "2025-01-01T00:00:00Z",
        completed_at: null,
      },
    ]);
    renderWithProviders(<ReportHistory />);

    const reason = await screen.findByText(
      "scanner exited with status 2: unsupported lockfile version",
    );
    expect(reason).toHaveClass("text-muted-foreground", "break-words");
    expect(screen.getByText("Failed")).toBeInTheDocument();
  });

  it("omits the reason line when a failed report has no error message", async () => {
    mockReports([
      {
        id: "r1",
        project_id: "p1",
        tool_name: "trivy",
        tool_version: null,
        scan_type: "filesystem",
        scan_target: null,
        status: "failed",
        total_findings: null,
        branch: null,
        commit_sha: null,
        created_at: "2025-01-01T00:00:00Z",
        completed_at: null,
      },
    ]);
    renderWithProviders(<ReportHistory />);

    expect(await screen.findByText("Failed")).toBeInTheDocument();
    expect(screen.getByText("trivy").closest("div.bg-card")).not.toHaveTextContent("unsupported");
    expect(screen.queryByText(/status 2/)).not.toBeInTheDocument();
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

interface RouteOptions {
  me?: Record<string, unknown>;
  members?: unknown[];
  reports?: unknown[];
  onDelete?: () => Response;
}

let requests: Array<{ path: string; method: string; }>;

function routeFetch(options: RouteOptions = {}) {
  requests = [];
  globalThis.fetch = vi.fn().mockImplementation(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), "http://localhost");
      const method = (init?.method ?? "GET").toUpperCase();
      requests.push({ path: url.pathname, method });
      if (method === "DELETE") {
        return options.onDelete?.() ?? new Response(null, {
          status: 204,
          headers: { "X-Archived-Findings": "3" },
        });
      }
      if (url.pathname === "/api/v1/me") {
        return jsonResponse(options.me ?? { id: "u-mem", email: "m@example.corp", role: "member" });
      }
      if (url.pathname.endsWith("/members")) return jsonResponse(options.members ?? []);
      return jsonResponse(options.reports ?? REPORTS);
    },
  );
}

function renderAsProject() {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <MemoryRouter initialEntries={["/test-project/reports"]}>
        <Routes>
          <Route path="/:slug/reports" element={<ReportHistory />} />
        </Routes>
      </MemoryRouter>
      <Toaster />
    </QueryClientProvider>,
  );
}

const PROJECT_ADMIN = {
  me: { id: "u-adm", email: "a@example.corp", role: "member" },
  members: [{
    project_id: "p1",
    user_id: "u-adm",
    role: "admin",
    created_at: "2026-09-01T00:00:00Z",
  }],
};

function cardFor(toolName: string): HTMLElement {
  const card = screen.getByText(toolName).closest("div.bg-card");
  if (!(card instanceof HTMLElement)) throw new Error(`no card for ${toolName}`);
  return card;
}

describe("ReportHistory delete action", () => {
  it("hides delete from a project member who is not an admin", async () => {
    routeFetch({ members: [{ project_id: "p1", user_id: "u-mem", role: "member" }] });
    renderAsProject();

    await screen.findByText("trivy");
    await waitFor(() => expect(requests.some((r) => r.path === "/api/v1/me")).toBe(true));
    expect(screen.queryByRole("button", { name: /^Delete .+ report from / })).not
      .toBeInTheDocument();
  });

  it("shows delete on settled reports only, for a project admin", async () => {
    routeFetch(PROJECT_ADMIN);
    renderAsProject();

    await screen.findByText("trivy");
    await waitFor(() =>
      expect(within(cardFor("trivy")).getByRole("button", { name: /^Delete .+ report from / }))
        .toBeInTheDocument()
    );
    expect(within(cardFor("semgrep")).getByRole("button", { name: /^Delete .+ report from / }))
      .toBeInTheDocument();
    expect(
      within(cardFor("osv-scanner")).queryByRole("button", { name: /^Delete .+ report from / }),
    ).toBeNull();
  });

  it("shows delete to a global admin who is not a project member", async () => {
    routeFetch({ me: { id: "u-root", email: "root@example.corp", role: "admin" }, members: [] });
    renderAsProject();

    await screen.findByText("trivy");
    await waitFor(() =>
      expect(within(cardFor("trivy")).getByRole("button", { name: /^Delete .+ report from / }))
        .toBeInTheDocument()
    );
  });

  it("asks before sending the delete and sends nothing on Cancel", async () => {
    routeFetch(PROJECT_ADMIN);
    renderAsProject();
    const user = userEvent.setup();

    await user.click(
      await within(await cardForAsync("trivy")).findByRole("button", {
        name: /^Delete .+ report from /,
      }),
    );
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText("Delete this report?")).toBeInTheDocument();
    expect(
      within(dialog).getByText(
        "This removes the report's occurrences and package list. Findings that only this report showed are archived, so they stop blocking the gate. This cannot be undone.",
      ),
    ).toBeInTheDocument();
    expect(requests.some((r) => r.method === "DELETE")).toBe(false);

    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument());
    expect(requests.some((r) => r.method === "DELETE")).toBe(false);
  });

  it("sends the delete after confirmation and toasts the archived count", async () => {
    routeFetch(PROJECT_ADMIN);
    renderAsProject();
    const user = userEvent.setup();

    await user.click(
      await within(await cardForAsync("trivy")).findByRole("button", {
        name: /^Delete .+ report from /,
      }),
    );
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Delete report" }));

    expect(await screen.findByText("Report deleted. 3 findings archived.")).toBeInTheDocument();
    expect(requests).toContainEqual({
      path: "/api/v1/projects/test-project/reports/r1",
      method: "DELETE",
    });
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument());
  });

  it("uses the singular for one archived finding", async () => {
    routeFetch({
      ...PROJECT_ADMIN,
      onDelete: () => new Response(null, { status: 204, headers: { "X-Archived-Findings": "1" } }),
    });
    renderAsProject();
    const user = userEvent.setup();

    await user.click(
      await within(await cardForAsync("trivy")).findByRole("button", {
        name: /^Delete .+ report from /,
      }),
    );
    await user.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Delete report" }),
    );
    expect(await screen.findByText("Report deleted. 1 finding archived.")).toBeInTheDocument();
  });

  it("explains a 409 inside the dialog and keeps it open", async () => {
    routeFetch({
      ...PROJECT_ADMIN,
      onDelete: () => jsonResponse({ error: { code: "report_processing", message: "busy" } }, 409),
    });
    renderAsProject();
    const user = userEvent.setup();

    await user.click(
      await within(await cardForAsync("semgrep")).findByRole("button", {
        name: /^Delete .+ report from /,
      }),
    );
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Delete report" }));

    expect(
      await within(dialog).findByText(
        "This report is still being processed. Try again when it finishes.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
  });

  it("shows the server message for any other error and keeps the dialog open", async () => {
    routeFetch({
      ...PROJECT_ADMIN,
      onDelete: () =>
        jsonResponse({
          error: { code: "forbidden", message: "Only project admins can delete reports." },
        }, 403),
    });
    renderAsProject();
    const user = userEvent.setup();

    await user.click(
      await within(await cardForAsync("semgrep")).findByRole("button", {
        name: /^Delete .+ report from /,
      }),
    );
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Delete report" }));

    expect(await within(dialog).findByText("Only project admins can delete reports."))
      .toBeInTheDocument();
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
  });
});

async function cardForAsync(toolName: string): Promise<HTMLElement> {
  await screen.findByText(toolName);
  return cardFor(toolName);
}
