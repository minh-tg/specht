import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
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
let stats: Record<string, unknown>;
let statsRequests = 0;
let postCalls: Array<Record<string, unknown>> = [];
let writeText: ReturnType<typeof vi.fn>;
let projectSlug = "acme";
let lastClient: QueryClient;

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status < 400,
    status,
    json: () => Promise.resolve(body),
  } as Response;
}

const VERSION_COMMIT = "4f93c32a1b2c3d4e5f60718293a4b5c6d7e8f901";

beforeEach(() => {
  meRole = "admin";
  projectSlug = "acme";
  projectStatus = 200;
  versionStatus = 200;
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
      if (versionStatus >= 400) {
        return jsonResponse({ error: { message: "unavailable" } }, versionStatus);
      }
      return jsonResponse({ version: "0.1.0", commit: VERSION_COMMIT });
    }
    if (url === "/api/v1/projects/acme/stats") {
      statsRequests += 1;
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
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
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

  it("renders both pipeline snippets with the slug, API URL and server build but no key", async () => {
    renderPage();
    await screen.findByRole("heading", { name: "Set up CI for Acme API" });
    await waitFor(() => {
      expect(document.body.textContent).toContain(`cmd/adapter@${VERSION_COMMIT}`);
    });

    const snippets = [...document.querySelectorAll("pre")].map((pre) => pre.textContent ?? "");
    expect(snippets).toHaveLength(2);
    for (const snippet of snippets) {
      expect(snippet).toContain("acme");
      expect(snippet).toContain(window.location.origin);
      expect(snippet).toContain(`cmd/adapter@${VERSION_COMMIT}`);
      expect(snippet).not.toContain("./cmd/adapter");
      expect(snippet).not.toContain("raw_key");
      expect(snippet).not.toContain(RAW_KEY);
    }
    expect(screen.getByText("More examples: examples/ci/ in the repository.")).toBeInTheDocument();
  });

  it("falls back to the main branch when the build info is unavailable", async () => {
    versionStatus = 500;
    renderPage();
    await screen.findByRole("heading", { name: "Set up CI for Acme API" });
    await waitFor(() => {
      expect(document.body.textContent).toContain("cmd/adapter@main");
    });

    const snippets = [...document.querySelectorAll("pre")].map((pre) => pre.textContent ?? "");
    expect(snippets).toHaveLength(2);
    for (const snippet of snippets) {
      expect(snippet).toContain("cmd/adapter@main");
      expect(snippet).not.toContain("./cmd/adapter");
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
      expect(snippet).toContain(`SPECHT_PROJECT: ${JSON.stringify(projectSlug)}`);
    }
  });

  it("builds the snippets from the project the server returned, not from the URL", async () => {
    projectSlug = "canonical-slug";
    renderPage();
    await screen.findByRole("heading", { name: "Set up CI for Acme API" });

    const github = document.querySelector("pre")?.textContent ?? "";
    expect(github).toContain("SPECHT_PROJECT: \"canonical-slug\"");
    expect(github).not.toContain("SPECHT_PROJECT: \"acme\"");
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
    expect(screen.getByText("Waiting for the first report...")).toBeInTheDocument();

    stats = { ...stats, report_count: 1, total_findings: 1 };
    await act(async () => {
      // Past the poll interval: the refetch and the re-render it triggers
      // both land inside this step.
      await vi.advanceTimersByTimeAsync(6000);
    });

    expect(screen.getByText("First report received: 1 finding.")).toBeInTheDocument();
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
});
