import { queryKeys } from "@/api/hooks";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { ProjectLayout } from "./ProjectLayout";

const project = {
  id: "p1",
  slug: "alpha",
  name: "Alpha",
  description: null,
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-01T00:00:00Z",
};

function mockApi() {
  globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/alpha/gate")) {
      return jsonResponse({ threshold_breached: false, blocking_count: 0, blocked_by: [] });
    }
    if (url.endsWith("/alpha/stats")) {
      return jsonResponse({ report_count: 2, total_findings: 0, by_severity: [] });
    }
    if (url.endsWith("/me")) {
      return jsonResponse({ id: "u1", email: "a@b.c", role: "member" });
    }
    if (url.endsWith("/projects/alpha")) return jsonResponse(project);
    return jsonResponse([]);
  });
}

function renderLayoutIn(
  client: QueryClient,
  initialEntry: string,
  reportUploadAction?: React.ReactNode,
) {
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <Routes>
          <Route path="/:slug/findings" element={<ProjectLayout />} />
          <Route
            path="/:slug/reports"
            element={<ProjectLayout reportUploadAction={reportUploadAction} />}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/**
 * Installs the fetch mock and seeds the header queries into the cache so the
 * breadcrumb assertion does not race the mocked network.
 */
function renderLayout(initialEntry = "/alpha/findings") {
  mockApi();
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  });
  client.setQueryData(queryKeys.project("alpha"), project);
  client.setQueryData(queryKeys.gate("alpha"), {
    threshold_breached: false,
    blocking_count: 0,
    blocked_by: [],
  });
  client.setQueryData(queryKeys.projectStats("alpha"), {
    report_count: 2,
    total_findings: 0,
    by_severity: [],
  });
  client.setQueryData(queryKeys.me(), { id: "u1", email: "a@b.c", role: "member" });
  return renderLayoutIn(client, initialEntry);
}

/** No seeded project and a fetch that never settles: the slug stays in the h1. */
function renderPendingLayout(initialEntry = "/alpha/findings") {
  globalThis.fetch = vi.fn().mockImplementation(() => new Promise(() => {}));
  const client = createTestQueryClient();
  return renderLayoutIn(client, initialEntry);
}

describe("ProjectLayout", () => {
  it("shows the project breadcrumb with the project name as the h1", () => {
    renderLayout();

    const heading = screen.getByRole("heading", { level: 1, name: "Alpha" });
    expect(heading).toHaveClass("text-2xl", "font-bold");
    expect(screen.getByRole("link", { name: "Projects" })).toHaveAttribute("href", "/");
  });

  it("shows the slug in the h1 while the project is still loading", () => {
    renderPendingLayout();

    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("alpha");
  });

  it("keeps the findings and reports tabs and renders the verdict band", () => {
    renderLayout();

    expect(screen.getByText("Nothing blocks this project")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Findings" })).toHaveAttribute(
      "href",
      "/alpha/findings",
    );
    expect(screen.getByRole("link", { name: "Reports" })).toHaveAttribute("href", "/alpha/reports");
  });

  it("marks the reports tab as current on the reports route", () => {
    renderLayout("/alpha/reports");

    expect(screen.getByRole("link", { name: "Reports" })).toHaveAttribute("aria-current", "page");
  });

  it("passes the supplied upload action to reports", async () => {
    mockApi();
    renderLayoutIn(
      createTestQueryClient(),
      "/alpha/reports",
      <p>Uploads require a local installation.</p>,
    );

    expect(await screen.findByText("Uploads require a local installation.")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /^Upload (a )?report$/ })).not.toBeInTheDocument();
  });

  it("offers the settings tab to a project admin", async () => {
    mockApi();
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false, staleTime: Infinity } },
    });
    client.setQueryData(queryKeys.project("alpha"), project);
    client.setQueryData(queryKeys.me(), { id: "u1", email: "a@b.c", role: "admin" });
    renderLayoutIn(client, "/alpha/findings");

    await userEvent.setup().click(screen.getByRole("button", { name: "Configuration" }));
    expect(await screen.findByRole("menuitem", { name: "Settings" })).toHaveAttribute(
      "href",
      "/alpha/settings",
    );
  });

  it("hides settings from a member without hiding configuration read access", async () => {
    renderLayout();
    await userEvent.setup().click(screen.getByRole("button", { name: "Configuration" }));

    expect(screen.queryByRole("menuitem", { name: "Settings" })).not.toBeInTheDocument();
    expect(await screen.findByRole("menuitem", { name: "Policy" })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Watcher" })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Access & Members" })).toBeInTheDocument();
  });

  it.each([403, 404])(
    "says the project is out of reach, and shows nothing else, on a %i",
    async (status) => {
      globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/me")) return jsonResponse({ id: "u1", email: "a@b.c", role: "member" });
        return jsonResponse(
          {
            error: {
              code: "project_access_denied",
              message: "project not found or you do not have access",
            },
          },
          status,
        );
      });
      renderLayoutIn(createTestQueryClient(), "/alpha/findings");

      expect(await screen.findByRole("heading", { name: "You cannot open this project" }))
        .toBeInTheDocument();
      expect(screen.getByText(/does not exist or you are not a member/)).toBeInTheDocument();
      expect(screen.getByRole("link", { name: "Back to projects" })).toHaveAttribute("href", "/");
      expect(screen.queryByRole("navigation", { name: "Project sections" })).not
        .toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Retry" })).not.toBeInTheDocument();
    },
  );

  it("keeps the layout and offers a retry when the project fails for another reason", async () => {
    globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/me")) return jsonResponse({ id: "u1", email: "a@b.c", role: "member" });
      return jsonResponse({ error: { code: "internal_error", message: "down" } }, 500);
    });
    renderLayoutIn(createTestQueryClient(), "/alpha/findings");

    expect(await screen.findByRole("navigation", { name: "Project sections" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "You cannot open this project" }))
      .not.toBeInTheDocument();
  });
});
