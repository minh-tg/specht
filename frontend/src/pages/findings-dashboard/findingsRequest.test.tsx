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
  await screen.findByText("No findings found");

  expect(urls.some((u) => u.includes("/findings?") && u.includes("scanner=trivy"))).toBe(true);
  expect(await screen.findByRole("combobox", { name: "Filter by scanner" })).toHaveTextContent(
    "Trivy",
  );
});
