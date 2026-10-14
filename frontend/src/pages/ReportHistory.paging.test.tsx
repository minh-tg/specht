import { createTestQueryClient, jsonResponse } from "@/test/utils";
import type { Report } from "@/types/api";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ReportHistory } from "./ReportHistory";

function report(n: number): Report {
  return {
    id: `r${n}`,
    project_id: "p1",
    tool_name: `scanner-${n}`,
    tool_version: null,
    scan_type: "filesystem",
    scan_target: null,
    status: "completed",
    total_findings: n,
    branch: "main",
    commit_sha: null,
    created_at: "2026-01-01T00:00:00Z",
    completed_at: "2026-01-01T00:01:00Z",
  } as Report;
}

const ALL = Array.from({ length: 45 }, (_, i) => report(i + 1));
let urls: string[];

beforeEach(() => {
  urls = [];
  globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
    const url = new URL(String(input), "http://localhost");
    urls.push(url.pathname + url.search);
    if (url.pathname === "/api/v1/me") {
      return jsonResponse({ id: "u1", email: "a@b.c", role: "member" });
    }
    if (url.pathname.endsWith("/reports")) {
      const limit = Number(url.searchParams.get("limit") ?? 20);
      return jsonResponse(ALL.slice(0, limit));
    }
    return jsonResponse({});
  });
});

function renderPage() {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <MemoryRouter initialEntries={["/test-project/reports"]}>
        <Routes>
          <Route path="/:slug/reports" element={<ReportHistory />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("ReportHistory paging", () => {
  it("offers more when a full page came back, and asks the server for a longer list", async () => {
    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByText("scanner-1")).toBeInTheDocument();
    expect(screen.queryByText("scanner-21")).not.toBeInTheDocument();
    expect(urls.some((u) => u.includes("/reports?limit=20"))).toBe(true);

    await user.click(screen.getByRole("button", { name: "Show more reports" }));
    expect(await screen.findByText("scanner-21")).toBeInTheDocument();
    expect(urls.some((u) => u.includes("/reports?limit=40"))).toBe(true);
  });

  it("stops offering more when the list is shorter than the page asked for", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("scanner-1");

    await user.click(screen.getByRole("button", { name: "Show more reports" }));
    await screen.findByText("scanner-21");
    await user.click(screen.getByRole("button", { name: "Show more reports" }));

    expect(await screen.findByText("scanner-45")).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Show more reports" })).not.toBeInTheDocument()
    );
  });
});
