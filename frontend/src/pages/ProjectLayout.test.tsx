import { queryKeys } from "@/api/hooks";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
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

function renderLayoutIn(client: QueryClient, initialEntry: string) {
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <Routes>
          <Route path="/:slug/findings" element={<ProjectLayout />} />
          <Route path="/:slug/reports" element={<ProjectLayout />} />
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
});
