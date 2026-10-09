import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { type QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ProjectSetup } from "./ProjectSetup";

/** Stand-in for the one-time secret: it must never reach a snippet. */
const RAW_KEY = "sk-live-0123456789abcdef";

let meRole: "admin" | "member" = "admin";
let projectStatus = 200;
let versionStatus = 200;
let versionPending = false;
let versionValue = "0.1.0";
let stats: Record<string, unknown>;
let statsRequests = 0;
let statsFailing = false;
let postCalls: Array<Record<string, unknown>> = [];
let writeText: ReturnType<typeof vi.fn>;
let projectSlug = "acme";
let lastClient: QueryClient;

const VERSION_COMMIT = "4f93c32a1b2c3d4e5f60718293a4b5c6d7e8f901";

beforeEach(() => {
  meRole = "admin";
  projectSlug = "acme";
  statsFailing = false;
  projectStatus = 200;
  versionStatus = 200;
  versionPending = false;
  versionValue = "0.1.0";
  stats = {
    report_count: 0,
    total_findings: 0,
    blocking_count: 0,
    waiver_count: 0,
    by_severity: [],
  };
  statsRequests = 0;
  postCalls = [];
  writeText = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", {
    value: { writeText },
    configurable: true,
  });

  globalThis.fetch = vi.fn().mockImplementation(async (input, init) => {
    const url = String(input);
    const method = ((init as RequestInit | undefined)?.method ?? "GET").toUpperCase();

    if (url === "/api/v1/me") {
      return jsonResponse({ id: "u1", email: "user@example.com", role: meRole, created_at: "" });
    }
    if (url === "/api/v1/projects/acme") {
      if (projectStatus >= 400) {
        return jsonResponse({ error: { message: "not found" } }, projectStatus);
      }
      return jsonResponse({
        id: "p1",
        slug: projectSlug,
        name: "Acme API",
        description: null,
        created_at: "",
        updated_at: "",
      });
    }
    if (url === "/api/v1/version") {
      if (versionPending) return new Promise<Response>(() => {});
      if (versionStatus >= 400) {
        return jsonResponse({ error: { message: "unavailable" } }, versionStatus);
      }
      return jsonResponse({ version: versionValue, commit: VERSION_COMMIT });
    }
    if (url === "/api/v1/projects/acme/stats") {
      statsRequests += 1;
      if (statsFailing) {
        return jsonResponse({ error: { code: "internal", message: "stats unavailable" } }, 500);
      }
      return jsonResponse(stats);
    }
    if (url === "/api/v1/auth/apikeys" && method === "POST") {
      postCalls.push(JSON.parse((init as RequestInit).body as string));
      return jsonResponse({
        id: "k1",
        name: "CI",
        key_prefix: "sk-live",
        raw_key: RAW_KEY,
        created_at: "",
      });
    }
    return jsonResponse({});
  });
});

afterEach(() => {
  vi.useRealTimers();
});

function renderPage() {
  const qc = createTestQueryClient();
  lastClient = qc;
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/acme/setup"]}>
        <Routes>
          <Route path="/:slug/setup" element={<ProjectSetup />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** The step <li> that owns the heading with the given name. */
function step(name: string): HTMLElement {
  const heading = screen.getByRole("heading", { name });
  const item = heading.closest("li");
  if (!item) throw new Error(`no <li> for step "${name}"`);
  return item;
}

describe("ProjectSetup", () => {
  it("tells members that only administrators can create projects", async () => {
    meRole = "member";
    renderPage();

    expect(await screen.findByText("Only administrators can set up CI for a project."))
      .toBeInTheDocument();
    expect(screen.getByRole("link", { name: /back to projects/i })).toHaveAttribute("href", "/");
  });

  it("names the project in the heading", async () => {
    renderPage();
    expect(await screen.findByRole("heading", { name: "Set up CI for Acme API" }))
      .toBeInTheDocument();
  });

  it("reveals the raw key once and copies it to the clipboard", async () => {
    const user = userEvent.setup();
    // user-event installs its own clipboard stub; put ours back on top.
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });
    renderPage();

    expect(screen.queryByText(RAW_KEY)).not.toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: "Create key" }));

    expect(await screen.findByText(RAW_KEY)).toBeInTheDocument();
    expect(postCalls).toEqual([{ project: "acme", name: "CI" }]);
    expect(screen.getByText("Copy it now. It will not be shown again.")).toBeInTheDocument();
    expect(
      screen.getByText(
        "This key can upload reports and read results. It cannot change findings, waivers or policies.",
      ),
    ).toBeInTheDocument();

    await user.click(
      within(step("Create an API key")).getByRole("button", { name: "Copy API key" }),
    );

    expect(writeText).toHaveBeenCalledWith(RAW_KEY);
    expect(within(step("Create an API key")).getByRole("button", { name: "Copied API key" }))
      .toBeInTheDocument();
  });

  it("reports a failed key creation", async () => {
    globalThis.fetch = vi.fn().mockImplementation(async (input, init) => {
      const url = String(input);
      const method = ((init as RequestInit | undefined)?.method ?? "GET").toUpperCase();
      if (url === "/api/v1/me") {
        return jsonResponse({ id: "u1", email: "user@example.com", role: "admin", created_at: "" });
      }
      if (url === "/api/v1/projects/acme") {
        return jsonResponse({
          id: "p1",
          slug: "acme",
          name: "Acme API",
          description: null,
          created_at: "",
          updated_at: "",
        });
      }
      if (url === "/api/v1/projects/acme/stats") return jsonResponse(stats);
      if (method === "POST") {
        return jsonResponse({ error: { code: "internal", message: "key creation failed" } }, 500);
      }
      return jsonResponse({});
    });

    renderPage();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Create key" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("key creation failed");
    expect(screen.queryByText(RAW_KEY)).not.toBeInTheDocument();
  });

  it("renders both pipeline snippets with the slug, API URL and pinned server version but no key", async () => {
    renderPage();
    await screen.findByRole("heading", { name: "Set up CI for Acme API" });
    await waitFor(() => {
      expect(document.body.textContent).toContain("minh-tg/specht@v0.1.0");
    });

    const snippets = [...document.querySelectorAll("pre")].map((pre) => pre.textContent ?? "");
    expect(snippets).toHaveLength(2);
    for (const snippet of snippets) {
      expect(snippet).toContain("acme");
      expect(snippet).toContain(window.location.origin);
      expect(snippet).toContain("v0.1.0");
      expect(snippet).not.toContain("./cmd/adapter");
      expect(snippet).not.toContain("go run");
      expect(snippet).not.toContain("jq");
      expect(snippet).not.toContain("raw_key");
      expect(snippet).not.toContain(RAW_KEY);
    }
    expect(screen.getByText("More examples: examples/ci/ in the repository.")).toBeInTheDocument();
  });

  it("pins the GitHub action and the GitLab adapter image to the release", async () => {
    renderPage();
    await screen.findByRole("heading", { name: "Set up CI for Acme API" });

    await waitFor(() => {
      expect(document.body.textContent).toContain("minh-tg/specht@v0.1.0");
    });
    const snippets = [...document.querySelectorAll("pre")].map((pre) => pre.textContent ?? "");
    expect(snippets[0]).toContain("uses: minh-tg/specht@v0.1.0");
    expect(snippets[1]).toContain("ghcr.io/minh-tg/specht-adapter:v0.1.0");
    expect(screen.queryByText(/development build/)).not.toBeInTheDocument();
  });

  it("shows only the placeholder while the version is loading", async () => {
    versionPending = true;
    renderPage();
    await screen.findByRole("heading", { name: "Set up CI for Acme API" });
    await waitFor(() => {
      expect(document.body.textContent).toContain("minh-tg/specht@vX.Y.Z");
    });

    const snippets = [...document.querySelectorAll("pre")].map((pre) => pre.textContent ?? "");
    expect(snippets).toHaveLength(2);
    for (const snippet of snippets) {
      expect(snippet).toContain("vX.Y.Z");
    }
    expect(screen.queryByText(/development build/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Could not read this server's version/)).not.toBeInTheDocument();
  });

  it("keeps the placeholder and explains a failed version request", async () => {
    versionStatus = 500;
    renderPage();
    await screen.findByRole("heading", { name: "Set up CI for Acme API" });
    await waitFor(() => {
      expect(document.body.textContent).toContain("minh-tg/specht@vX.Y.Z");
    });

    const snippets = [...document.querySelectorAll("pre")].map((pre) => pre.textContent ?? "");
    expect(snippets).toHaveLength(2);
    for (const snippet of snippets) {
      expect(snippet).toContain("vX.Y.Z");
      expect(snippet).not.toContain("./cmd/adapter");
    }
    expect(
      screen.getByText(
        "Could not read this server's version. Replace vX.Y.Z with the Specht version you run.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(/development build/)).not.toBeInTheDocument();
  });

  it("shows the development-build note for a dev build", async () => {
    versionValue = "dev";
    renderPage();
    await screen.findByRole("heading", { name: "Set up CI for Acme API" });

    expect(await screen.findByText(/development build/)).toBeInTheDocument();
    const snippets = [...document.querySelectorAll("pre")].map((pre) => pre.textContent ?? "");
    expect(snippets).toHaveLength(2);
    for (const snippet of snippets) {
      expect(snippet).toContain("vX.Y.Z");
      expect(snippet).not.toContain("v0.1.0");
    }
  });

  it("shows a not-found message and no pipeline when the project does not exist", async () => {
    projectStatus = 404;
    renderPage();

    expect(await screen.findByRole("heading", { name: "Project not found" })).toBeInTheDocument();
    expect(document.querySelectorAll("pre")).toHaveLength(0);
    expect(screen.queryByRole("button", { name: "Create key" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to projects" })).toHaveAttribute("href", "/");
  });

  it("quotes the project slug so it cannot add keys or jobs to the pipeline", async () => {
    projectSlug = "acme\n    evil-job:\n      runs-on: ubuntu-latest";
    renderPage();
    await screen.findByRole("heading", { name: "Set up CI for Acme API" });

    const snippets = [...document.querySelectorAll("pre")].map((pre) => pre.textContent ?? "");
    expect(snippets).toHaveLength(2);
    for (const snippet of snippets) {
      expect(snippet).not.toMatch(/^\s*evil-job:/m);
      expect(snippet).toContain(JSON.stringify(projectSlug));
    }
  });

  it("builds the snippets from the project the server returned, not from the URL", async () => {
    projectSlug = "canonical-slug";
    renderPage();
    await screen.findByRole("heading", { name: "Set up CI for Acme API" });

    const github = document.querySelector("pre")?.textContent ?? "";
    expect(github).toContain("project: \"canonical-slug\"");
    expect(github).not.toContain("project: \"acme\"");
  });

  it("drops the one-time key from the mutation cache once the page is left", async () => {
    const view = renderPage();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Create key" }));
    expect(await screen.findByText(RAW_KEY)).toBeInTheDocument();

    view.unmount();

    await waitFor(() => expect(lastClient.getMutationCache().getAll()).toHaveLength(0));
  });

  it("tells the user when copying fails instead of claiming success", async () => {
    const user = userEvent.setup();
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText: vi.fn().mockRejectedValue(new Error("denied")) },
      configurable: true,
    });
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Create key" }));
    await screen.findByText(RAW_KEY);

    const keyStep = step("Create an API key");
    await user.click(within(keyStep).getByRole("button", { name: "Copy API key" }));

    expect(await within(keyStep).findByText(/copy it manually/)).toBeInTheDocument();
    expect(within(keyStep).getByRole("button", { name: "Copy failed API key" }))
      .toBeInTheDocument();
  });

  it("links to the manual upload and the findings of the project", async () => {
    renderPage();
    expect(await screen.findByRole("link", { name: "Upload a report" }))
      .toHaveAttribute("href", "/acme/reports/upload");
  });

  it("polls until the first report lands and then stops", async () => {
    vi.useFakeTimers();
    renderPage();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(statsRequests).toBe(1);
    expect(screen.getByText("Waiting for the first report...")).toHaveAttribute("role", "status");
    expect(screen.getByRole("heading", { name: "Waiting for the first report" }))
      .toBeInTheDocument();

    stats = { ...stats, report_count: 1, total_findings: 1 };
    await act(async () => {
      // Past the poll interval: the refetch and the re-render it triggers
      // both land inside this step.
      await vi.advanceTimersByTimeAsync(6000);
    });

    // The same live region is updated in place, so the arrival is announced.
    expect(screen.getByText("First report received: 1 finding.")).toHaveAttribute("role", "status");
    expect(screen.getByRole("heading", { name: "First report received" })).toBeInTheDocument();
    expect(statsRequests).toBe(2);
    expect(screen.queryByText("Waiting for the first report...")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View findings" })).toHaveAttribute(
      "href",
      "/acme/findings",
    );
    expect(screen.getByRole("link", { name: "Back to projects" })).toHaveAttribute("href", "/");

    const requestsAfterFirstReport = statsRequests;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15000);
    });
    expect(statsRequests).toBe(requestsAfterFirstReport);
  });

  it("does not say it is waiting when the status poll fails, and retries on demand", async () => {
    const user = userEvent.setup();
    statsFailing = true;
    renderPage();

    expect(await screen.findByText("Could not check for the first report.")).toHaveAttribute(
      "role",
      "alert",
    );
    expect(screen.getByRole("heading", { name: "First report status unavailable" }))
      .toBeInTheDocument();
    expect(screen.queryByText("Waiting for the first report...")).not.toBeInTheDocument();

    statsFailing = false;
    await user.click(screen.getByRole("button", { name: "Retry" }));

    expect(await screen.findByText("Waiting for the first report...")).toHaveAttribute(
      "role",
      "status",
    );
    expect(screen.queryByText("Could not check for the first report.")).not.toBeInTheDocument();
  });

  it("keeps polling while the first report is processing, then reports its findings", async () => {
    vi.useFakeTimers();
    stats = {
      ...stats,
      report_count: 1,
      total_findings: 0,
      latest_report: { id: "r1", status: "processing", created_at: "2025-01-01T00:00:00Z" },
    };
    renderPage();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(screen.getByRole("heading", { name: "Processing the first report" }))
      .toBeInTheDocument();
    expect(screen.getByText(/still being processed/)).toHaveAttribute("role", "status");
    expect(screen.queryByRole("link", { name: "View findings" })).not.toBeInTheDocument();

    stats = {
      ...stats,
      total_findings: 3,
      latest_report: { id: "r1", status: "completed", created_at: "2025-01-01T00:00:00Z" },
    };
    await act(async () => {
      await vi.advanceTimersByTimeAsync(6000);
    });

    expect(screen.getByText("First report received: 3 findings.")).toHaveAttribute(
      "role",
      "status",
    );
    expect(screen.getByRole("link", { name: "View findings" })).toBeInTheDocument();
  });

  it("says when the first report failed, links to the reports and keeps polling", async () => {
    vi.useFakeTimers();
    stats = {
      ...stats,
      report_count: 1,
      total_findings: 0,
      latest_report: { id: "r1", status: "failed", created_at: "2025-01-01T00:00:00Z" },
    };
    renderPage();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(screen.getByRole("heading", { name: "The first report failed" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View reports" })).toHaveAttribute(
      "href",
      "/acme/reports",
    );
    expect(screen.queryByRole("link", { name: "View findings" })).not.toBeInTheDocument();

    const requests = statsRequests;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(6000);
    });
    expect(statsRequests).toBeGreaterThan(requests);
  });
});
