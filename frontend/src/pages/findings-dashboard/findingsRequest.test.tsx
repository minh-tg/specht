import { findingsQueryOptions } from "@/api/hooks";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { FindingsDashboard } from "../FindingsDashboard";
import { findingsRequest } from "./findingsRequest";

it("asks for the most severe findings first, one page at a time", () => {
  expect(findingsRequest()).toEqual({
    severity: undefined,
    status: undefined,
    kind: undefined,
    analysisState: undefined,
    q: undefined,
    sort: "severity",
    dir: "desc",
    offset: 0,
    limit: 20,
  });
});

it("is the cache entry the dashboard fills when it opens with no filters", async () => {
  globalThis.fetch = vi.fn().mockImplementation(async (input) =>
    jsonResponse(String(input).endsWith("/gate") ? { blocked_by: [] } : [])
  );
  const qc = createTestQueryClient();
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/p/findings"]}>
        <Routes>
          <Route path="/:slug/findings" element={<FindingsDashboard />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByText("No findings found");

  const { queryKey } = findingsQueryOptions("p", findingsRequest());
  expect(qc.getQueryData(queryKey)).toMatchObject({ findings: [] });
});

it("sends the scanner filter from the URL and offers the scanners the server knows", async () => {
  const urls: string[] = [];
  globalThis.fetch = vi.fn().mockImplementation(async (input) => {
    const url = String(input);
    urls.push(url);
    if (url.endsWith("/gate")) return jsonResponse({ blocked_by: [] });
    if (url.endsWith("/api/v1/scanners")) {
      return jsonResponse([{ name: "trivy", display_name: "Trivy" }, {
        name: "semgrep",
        display_name: "Semgrep",
      }]);
    }
    return jsonResponse([]);
  });
  const qc = createTestQueryClient();
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/p/findings?scanner=trivy"]}>
        <Routes>
          <Route path="/:slug/findings" element={<FindingsDashboard />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  // A scanner filter that matches nothing is a filtered page, not an empty project.
  await screen.findByText("No findings match these filters.");

  expect(urls.some((u) => u.includes("/findings?") && u.includes("scanner=trivy"))).toBe(true);
  expect(await screen.findByRole("combobox", { name: "Filter by scanner" })).toHaveTextContent(
    "Trivy",
  );
});

it("sends the gate filter from the URL, shows it, and offers to clear it", async () => {
  const urls: string[] = [];
  globalThis.fetch = vi.fn().mockImplementation(async (input) => {
    const url = String(input);
    urls.push(url);
    return jsonResponse(url.endsWith("/gate") ? { blocked_by: [] } : []);
  });
  render(
    <QueryClientProvider client={createTestQueryClient()}>
      <MemoryRouter initialEntries={["/p/findings?blocks_gate=true"]}>
        <Routes>
          <Route path="/:slug/findings" element={<FindingsDashboard />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByText("No findings match these filters.");

  expect(urls.some((u) => u.includes("/findings?") && u.includes("blocks_gate=true"))).toBe(true);
  expect(screen.getByRole("combobox", { name: "Filter by gate" })).toHaveTextContent(
    "Blocks the gate",
  );
  expect(screen.getByRole("button", { name: "Clear filters" })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Blocks the gate" })).toHaveAttribute(
    "href",
    "/p/findings?blocks_gate=true",
  );
});

it("sends no gate filter for a value other than true", () => {
  expect(findingsRequest({ ...findingsRequestFilters(), blocksGate: "" }).blocksGate)
    .toBeUndefined();
  expect(findingsRequest({ ...findingsRequestFilters(), blocksGate: "true" }).blocksGate).toBe(
    true,
  );
});

function findingsRequestFilters() {
  return {
    severity: "",
    status: "",
    kind: "",
    analysisState: "",
    q: "",
    branchScope: "",
    assignee: "",
    scanner: "",
    blocksGate: "",
  };
}
