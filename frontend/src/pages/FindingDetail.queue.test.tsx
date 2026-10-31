import { resetSingleKeyForTests, setSingleKeyEnabled } from "@/lib/singleKeyShortcuts";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FindingDetail } from "./FindingDetail";

const FROM = "?analysis_state=unanalyzed%2Cin_triage";

let list: { ids: string[]; total?: number; } | null;
/** Rows of the page after the first, for a queue that crosses a page boundary. */
let secondPage: string[];
let listRequests: URLSearchParams[];

function finding(id: string) {
  return {
    id,
    project_id: "p1",
    finding_kind: "sast",
    fingerprint: `fp-${id}`,
    current_title: `Title ${id}`,
    current_severity: "high",
    state: "open",
    analysis_state: "unanalyzed",
    gate_effect: "block",
    first_seen_at: "2025-01-01T00:00:00Z",
    last_seen_at: "2025-01-02T00:00:00Z",
  };
}

function listResponse(ids: string[] | null, total?: number): Response {
  return new Response(JSON.stringify(ids === null ? null : ids.map(finding)), {
    headers: {
      "Content-Type": "application/json",
      ...(total === undefined ? {} : { "X-Total-Count": String(total) }),
    },
  });
}

beforeEach(() => {
  window.localStorage.clear();
  resetSingleKeyForTests();
  list = { ids: ["f0", "f1", "f2"] };
  secondPage = [];
  listRequests = [];
  globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
    const url = new URL(String(input), "http://localhost");
    if (url.pathname === "/api/v1/me") {
      return jsonResponse({ id: "u-1", email: "u@example.corp", role: "member" });
    }
    if (url.pathname === "/api/v1/projects/p1") {
      return jsonResponse({
        id: "p1",
        slug: "p1",
        name: "p1",
        role: "manager",
        permissions: { triage: true, request_waiver: true },
      });
    }
    if (url.pathname === "/api/v1/projects/p1/findings") {
      listRequests.push(url.searchParams);
      if (url.searchParams.get("offset") === "20") return listResponse(secondPage, list?.total);
      return listResponse(list ? list.ids : null, list?.total);
    }
    if (url.pathname.endsWith("/gate")) return jsonResponse({ blocked_by: [] });
    const match = /^\/api\/v1\/findings\/([^/]+)$/.exec(url.pathname);
    if (match) return jsonResponse(finding(match[1]!));
    return jsonResponse([]);
  });
});

/** Shows where the router is, so a test can see which finding J or K opened and with what state. */
function Where() {
  const location = useLocation();
  return (
    <output data-testid="where">
      {location.pathname} {JSON.stringify(location.state)}
    </output>
  );
}

function renderDetail(id: string, state?: unknown) {
  render(
    <QueryClientProvider client={createTestQueryClient()}>
      <MemoryRouter initialEntries={[{ pathname: `/p1/findings/${id}`, state }]}>
        <Routes>
          <Route path="/:slug/findings/:findingId" element={<FindingDetail />} />
        </Routes>
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const liveRegion = () => document.querySelector("[role=status][aria-live=polite]")!;
const where = () => screen.getByTestId("where").textContent;

async function inQueue(position: string) {
  await screen.findByRole("heading", { level: 1 });
  await screen.findByText(`Finding ${position} in this list`);
}

describe("the triage queue from the findings list", () => {
  it("walks the filtered list with J and K and says where it is", async () => {
    const user = userEvent.setup();
    renderDetail("f1", { from: FROM });
    await inQueue("2 of 3");
    expect(listRequests[0]?.get("analysis_state")).toBe("unanalyzed,in_triage");

    await user.keyboard("j");
    expect(await screen.findByRole("heading", { level: 1, name: "Title f2" })).toBeInTheDocument();
    expect(where()).toContain("/p1/findings/f2");
    expect(where()).toContain(JSON.stringify({ from: `${FROM}&offset=0` }));
    expect(liveRegion()).toHaveTextContent("Finding 3 of 3: Title f2");

    await inQueue("3 of 3");
    await user.keyboard("k");
    expect(await screen.findByRole("heading", { level: 1, name: "Title f1" })).toBeInTheDocument();
    expect(liveRegion()).toHaveTextContent("Finding 2 of 3: Title f1");
  });

  it("stays put at the end of the list and says so", async () => {
    const user = userEvent.setup();
    renderDetail("f2", { from: FROM });
    await inQueue("3 of 3");

    expect(screen.getByRole("button", { name: /^Next/ })).toBeDisabled();
    await user.keyboard("j");
    expect(liveRegion()).toHaveTextContent("This is the last finding in the list.");
    expect(where()).toContain("/p1/findings/f2");
  });

  it("stays put at the start of the list and says so", async () => {
    const user = userEvent.setup();
    renderDetail("f0", { from: FROM });
    await inQueue("1 of 3");
    expect(screen.getByRole("button", { name: /^Previous/ })).toBeDisabled();
    await user.keyboard("k");
    expect(liveRegion()).toHaveTextContent("This is the first finding in the list.");
  });

  it("sits in the back link's row, so it adds no height above the decision", async () => {
    renderDetail("f1", { from: FROM });
    await inQueue("2 of 3");

    const nav = screen.getByRole("navigation", { name: "Findings in this list" });
    const back = screen.getByRole("link", { name: "← Back to findings" });
    expect(nav.parentElement).toBe(back.parentElement);
    // Nothing sits between that row and the title.
    expect(nav.parentElement!.nextElementSibling)
      .toContainElement(screen.getByRole("heading", { level: 1 }));
  });

  it("moves with the buttons too, which name their keys", async () => {
    const user = userEvent.setup();
    renderDetail("f1", { from: FROM });
    await inQueue("2 of 3");

    const previous = screen.getByRole("button", { name: /^Previous/ });
    expect(previous.querySelector("kbd")).toHaveTextContent("K");
    await user.click(previous);
    expect(await screen.findByRole("heading", { level: 1, name: "Title f0" })).toBeInTheDocument();
  });

  it("crosses into the next page of the list", async () => {
    list = { ids: Array.from({ length: 20 }, (_, i) => `f${i}`), total: 21 };
    secondPage = ["f20"];
    const user = userEvent.setup();
    renderDetail("f19", { from: FROM });
    await inQueue("20 of 21");

    await waitFor(() => expect(screen.getByRole("button", { name: /^Next/ })).toBeEnabled());
    await user.keyboard("j");
    expect(await screen.findByRole("heading", { level: 1, name: "Title f20" })).toBeInTheDocument();
    expect(where()).toContain(JSON.stringify({ from: `${FROM}&offset=20` }));
  });

  it("ignores J, K and 1 to 3 while the person types a reason", async () => {
    const user = userEvent.setup();
    renderDetail("f1", { from: FROM });
    await inQueue("2 of 3");

    await user.keyboard("2");
    expect(screen.getByRole("radio", { name: /^Not a problem/ })).toBeChecked();
    const reason = screen.getByLabelText(/^Reason/);
    await user.type(reason, "j k 1 3");
    expect(reason).toHaveValue("j k 1 3");
    expect(screen.getByRole("radio", { name: /^Not a problem/ })).toBeChecked();
    expect(where()).toContain("/p1/findings/f1");
  });

  it("picks the three answers with 1 to 3, also from a picked radio", async () => {
    const user = userEvent.setup();
    renderDetail("f1", { from: FROM });
    await inQueue("2 of 3");
    expect(screen.getByText("Keys 1 to 3 pick. They pause while you type in a field."))
      .toBeInTheDocument();

    await user.keyboard("3");
    expect(screen.getByRole("radio", { name: /^Accept for now/ })).toBeChecked();
    await user.click(screen.getByRole("radio", { name: /\(90 days\)/ }));
    await user.keyboard("1");
    expect(screen.getByRole("radio", { name: /^Real issue/ })).toBeChecked();
  });

  it("does nothing with the keys when single-key shortcuts are off, and drops the key hints", async () => {
    setSingleKeyEnabled(false);
    const user = userEvent.setup();
    renderDetail("f1", { from: FROM });
    await inQueue("2 of 3");

    expect(screen.getByText("Single-key shortcuts are off. Turn them on in the account menu."))
      .toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Next/ }).querySelector("kbd")).toBeNull();
    await user.keyboard("j1");
    expect(where()).toContain("/p1/findings/f1");
    expect(screen.getByRole("radio", { name: /^Real issue/ })).not.toBeChecked();
  });

  it("forgets nothing when the decision drops the finding out of the filter", async () => {
    const user = userEvent.setup();
    renderDetail("f1", { from: FROM });
    await inQueue("2 of 3");

    // The list refetches without f1, as it would after a decision.
    list = { ids: ["f0", "f2"] };
    await user.keyboard("1");
    await user.click(screen.getByRole("button", { name: "Save decision" }));
    await waitFor(() => expect(listRequests.length).toBeGreaterThan(1));

    await user.keyboard("j");
    expect(await screen.findByRole("heading", { level: 1, name: "Title f2" })).toBeInTheDocument();
  });
});

describe("a finding without list context", () => {
  it("has no queue and no J or K hint, and the keys do nothing", async () => {
    const user = userEvent.setup();
    renderDetail("f1");
    await screen.findByRole("heading", { level: 1, name: "Title f1" });

    expect(screen.queryByRole("navigation", { name: "Findings in this list" })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Next/ })).toBeNull();
    expect(listRequests).toHaveLength(0);
    await user.keyboard("j");
    expect(where()).toContain("/p1/findings/f1");
  });

  it("has no queue from the change view either", async () => {
    render(
      <QueryClientProvider client={createTestQueryClient()}>
        <MemoryRouter
          initialEntries={[{
            pathname: "/p1/findings/f1",
            search: "?from=change",
            state: { from: FROM },
          }]}
        >
          <Routes>
            <Route path="/:slug/findings/:findingId" element={<FindingDetail />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await screen.findByRole("heading", { level: 1, name: "Title f1" });
    expect(screen.queryByRole("navigation", { name: "Findings in this list" })).toBeNull();
  });

  it("treats a null list as empty and says it is still looking", async () => {
    list = null;
    renderDetail("f1", { from: FROM });
    await screen.findByRole("heading", { level: 1, name: "Title f1" });

    expect(await screen.findByText("Finding its place in the list...")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Next/ })).toBeDisabled();
  });
});
