import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FindingDetail } from "./FindingDetail";

const TITLE = "Prototype pollution in lodash";
const SHA = "0123456789abcdef0123456789abcdef01234567";

let projectGate: Record<string, unknown>;
let changeGate: () => Response;
let gateQueries: string[];

beforeEach(() => {
  // The finding was seen only on the change's branch, so the project gate (default branch) leaves
  // it out, while the change's own gate lists it as blocking.
  projectGate = { blocked_by: [], policy: { severity_floor: "high" } };
  changeGate = () =>
    jsonResponse({
      blocked_by: ["f1"],
      threshold_breached: true,
      policy: { severity_floor: "high" },
    });
  gateQueries = [];
  globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
    const url = new URL(String(input), "http://localhost");
    if (url.pathname.endsWith("/gate")) {
      gateQueries.push(url.search);
      // The page asks the project gate bare; a change gate always carries its scope.
      if (url.search === "") return jsonResponse(projectGate);
      return changeGate();
    }
    if (url.pathname === "/api/v1/me") {
      return jsonResponse({ id: "u-1", email: "u@example.corp", role: "member" });
    }
    if (url.pathname.endsWith("/members")) return jsonResponse([]);
    if (url.pathname.endsWith("/waivers")) return jsonResponse([]);
    if (url.pathname.endsWith("/events")) return jsonResponse([]);
    if (url.pathname.endsWith("/reachability")) return jsonResponse([]);
    if (url.pathname.endsWith("/evidence")) return jsonResponse([]);
    if (url.pathname.endsWith("/signoff")) return new Response(null, { status: 204 });
    if (url.pathname === "/api/v1/projects/p1") {
      return jsonResponse({
        id: "p1",
        slug: "p1",
        name: "p1",
        role: "member",
        permissions: { request_waiver: true, triage: true },
      });
    }
    if (url.pathname === "/api/v1/findings/f1") {
      return jsonResponse({
        id: "f1",
        project_id: "p1",
        finding_kind: "sca",
        fingerprint: "fp1",
        current_title: TITLE,
        current_severity: "high",
        current_score: null,
        state: "open",
        triage_status: "untriaged",
        analysis_state: "unanalyzed",
        gate_effect: "block",
        only_on_branches: ["feat/x"],
        first_seen_at: "2025-01-01T00:00:00Z",
        last_seen_at: "2025-01-02T00:00:00Z",
        created_at: "2025-01-01T00:00:00Z",
        updated_at: "2025-01-01T00:00:00Z",
      });
    }
    return jsonResponse({});
  });
});

function renderDetail(search: string) {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <MemoryRouter initialEntries={[{ pathname: "/p1/findings/f1", search }]}>
        <Routes>
          <Route path="/:slug/findings/:findingId" element={<FindingDetail />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("FindingDetail opened from a change's blocker", () => {
  it("says it blocks and offers the waiver, as the change view did", async () => {
    renderDetail(`?from=change&commit=${SHA}`);
    await screen.findByRole("heading", { name: TITLE });

    expect(await screen.findByText(/Blocks gate/)).toBeInTheDocument();
    expect(screen.queryByText(/only on an unmerged branch/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Request waiver" })).toBeEnabled();
    expect(gateQueries).toContain(`?introduced_only=true&commit=${SHA}`);
  });

  it("asks the project-wide gate of the branch when the link carried that scope", async () => {
    renderDetail(`?from=change&commit=${SHA}&scope=project&severity=critical&branch=feat%2Fx`);
    await screen.findByText(/Blocks gate/);

    expect(gateQueries).toContain("?branch=feat%2Fx&severity=critical");
  });

  it("keeps the project gate for a change link without a commit", async () => {
    renderDetail("?from=change");
    expect(await screen.findByText(/only on an unmerged branch/)).toBeInTheDocument();
    expect(gateQueries.every((query) => !query.includes("commit="))).toBe(true);
  });

  it("falls back to the project gate when the change gate cannot be read", async () => {
    changeGate = () =>
      jsonResponse(
        { error: { code: "no_report_for_commit", message: "no completed report for the commit" } },
        404,
      );
    renderDetail(`?from=change&commit=${SHA}`);
    expect(await screen.findByText(/only on an unmerged branch/)).toBeInTheDocument();
  });

  it("ignores a commit in a link that was not opened from a change", async () => {
    renderDetail(`?commit=${SHA}`);
    expect(await screen.findByText(/only on an unmerged branch/)).toBeInTheDocument();
    expect(gateQueries.every((query) => !query.includes("commit="))).toBe(true);
  });
});
