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
