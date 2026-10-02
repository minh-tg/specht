import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ExistingDebt } from "./ExistingDebt";

let findingFetches: string[];

function finding(id: string) {
  return {
    id,
    project_id: "p1",
    finding_kind: "sca",
    fingerprint: id,
    current_title: `Finding ${id}`,
    current_severity: "high",
    current_score: null,
    state: "open",
    triage_status: "untriaged",
    analysis_state: "unanalyzed",
    gate_effect: "block",
    first_seen_at: "2025-01-01T00:00:00Z",
    last_seen_at: "2025-01-01T00:00:00Z",
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
    location: { file: "src/a.ts", start_line: 1 },
    remediation: { summary: "Fix it" },
  };
}

beforeEach(() => {
  findingFetches = [];
  globalThis.fetch = vi.fn().mockImplementation((input: RequestInfo | URL) => {
    const url = String(input);
    findingFetches.push(url);
    return Promise.resolve(jsonResponse(finding(url.split("/").pop() ?? "unknown")));
  });
});

function renderDebt(ids: string[]) {
  const qc = createTestQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/acme/changes/abcdef1"]}>
        <ExistingDebt slug="acme" ids={ids} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("ExistingDebt", () => {
  it("renders nothing when there is no pre-existing debt", () => {
    const { container } = renderDebt([]);

    expect(container).toBeEmptyDOMElement();
  });

  it("summarises the debt and links to the full findings list", () => {
    renderDebt(["pre1", "pre2"]);

    expect(
      screen.getByText("2 other findings block this project (not introduced by this change)"),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "See all in Findings" }))
      .toHaveAttribute("href", "/acme/findings");
  });

  it("does not fetch findings until the section is opened", async () => {
    renderDebt(["pre1"]);

    await act(async () => {
      await Promise.resolve();
    });
    expect(findingFetches).toEqual([]);

    await userEvent.setup().click(screen.getByText(/1 other finding/));
    await waitFor(() => expect(screen.getByText("Finding pre1")).toBeInTheDocument());
    expect(findingFetches).toEqual(["/api/v1/findings/pre1"]);
  });

  it("lists at most ten findings when opened", async () => {
    const ids = Array.from({ length: 12 }, (_, index) => `pre${index}`);
    renderDebt(ids);

    await userEvent.setup().click(screen.getByText(/12 other findings/));
    const list = await screen.findByRole("list");
    await waitFor(() => expect(within(list).getAllByRole("listitem")).toHaveLength(10));
  });
});
