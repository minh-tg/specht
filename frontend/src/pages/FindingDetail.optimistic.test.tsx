import { Toaster } from "@/components/ui/sonner";
import { chooseOption, createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FindingDetail } from "./FindingDetail";

/** A promise a test settles by hand, to hold a request open. */
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

let server: { analysis_state: string; gate_effect: string; blocked: boolean; };
let patch: ReturnType<typeof deferred<Response>> | null;
let gateHold: ReturnType<typeof deferred<void>> | null;

function finding() {
  return {
    id: "f1",
    project_id: "p1",
    finding_kind: "sca",
    fingerprint: "fp1",
    current_title: "Test Vulnerability",
    current_severity: "high",
    current_score: null,
    state: "open",
    triage_status: "untriaged",
    analysis_state: server.analysis_state,
    gate_effect: server.gate_effect,
    first_seen_at: "2025-01-01T00:00:00Z",
    last_seen_at: "2025-01-02T00:00:00Z",
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
  };
}

function renderDetail() {
  const qc = createTestQueryClient();
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/p1/findings/f1"]}>
        <Routes>
          <Route path="/:slug/findings/:findingId" element={<FindingDetail />} />
        </Routes>
      </MemoryRouter>
      <Toaster />
    </QueryClientProvider>,
  );
  return qc;
}

beforeEach(() => {
  server = { analysis_state: "unanalyzed", gate_effect: "block", blocked: true };
  patch = null;
  gateHold = null;
  globalThis.fetch = vi.fn().mockImplementation(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.endsWith("/findings/f1") && method === "PATCH") {
        patch = deferred<Response>();
        return patch.promise;
      }
      if (url.endsWith("/gate")) {
        if (gateHold) await gateHold.promise;
        return jsonResponse({ blocked_by: server.blocked ? ["f1"] : [] });
      }
      if (url.endsWith("/findings/f1")) return jsonResponse(finding());
      return jsonResponse([]);
    },
  );
});

async function applyExploitable() {
  const user = userEvent.setup();
  await screen.findByRole("heading", { name: "Test Vulnerability" });
  await screen.findByText("Why this blocks");
  await chooseOption(user, screen.getAllByRole("combobox")[0]!, "Exploitable");
  await user.click(screen.getByRole("button", { name: "Apply" }));
  await waitFor(() => expect(patch).not.toBeNull());
}

const decide = () => screen.getByRole("heading", { level: 2, name: "Decide" }).parentElement!;

describe("FindingDetail optimistic triage", () => {
  it("shows the chosen state at once and claims nothing about the gate until it has refetched", async () => {
    renderDetail();
    await applyExploitable();

    expect(decide()).toHaveTextContent("Currently: Exploitable");
    expect(decide()).not.toHaveTextContent(/block gate|Blocks gate/i);
    expect(screen.queryByText("Why this blocks")).not.toBeInTheDocument();
    expect(screen.queryByText("Why this does not block")).not.toBeInTheDocument();
    expect(screen.getByText("Triage", { selector: "dt" }).nextElementSibling).toHaveTextContent(
      "Exploitable",
    );

    // The server accepts the change and now says the finding no longer blocks. Its gate answer is
    // held back, so the page must still not show a verdict.
    server = { analysis_state: "exploitable", gate_effect: "ignore", blocked: false };
    gateHold = deferred<void>();
    patch!.resolve(jsonResponse({
      finding_id: "f1",
      analysis_state: "exploitable",
      gate_effect: "ignore",
    }));
    await screen.findByText(/Triage saved/);
    expect(screen.queryByText("Why this blocks")).not.toBeInTheDocument();
    expect(screen.queryByText("Why this does not block")).not.toBeInTheDocument();

    gateHold.resolve();
    expect(await screen.findByText("Why this does not block")).toBeInTheDocument();
    expect(decide()).toHaveTextContent("Currently: Exploitable · Does not block gate");
  });

  it("goes back to the real state, and the old verdict, with an error toast when the server refuses", async () => {
    renderDetail();
    await applyExploitable();
    expect(decide()).toHaveTextContent("Currently: Exploitable");

    patch!.resolve(
      jsonResponse({ error: { code: "forbidden", message: "project access denied" } }, 403),
    );

    expect(await screen.findAllByText("project access denied")).not.toHaveLength(0);
    await waitFor(() => expect(decide()).toHaveTextContent("Currently: Not triaged · Blocks gate"));
    expect(screen.getByText("Why this blocks")).toBeInTheDocument();
    expect(screen.getByText("Triage", { selector: "dt" }).nextElementSibling).toHaveTextContent(
      "Not triaged",
    );
    // One copy is the toast, the other the inline message under the controls.
    expect(document.querySelector("[data-sonner-toast]")).toHaveTextContent(
      "project access denied",
    );
  });

  it("never writes to the findings list cache", async () => {
    const qc = renderDetail();
    const rows = { findings: [{ id: "f1", analysis_state: "unanalyzed" }], total: 1 };
    const key = ["findings", "p1", { triage: "needs_triage" }];
    qc.setQueryData(key, rows);
    await applyExploitable();

    expect(qc.getQueryData(key)).toBe(rows);
    const detail = qc.getQueryData<{ analysis_state: string; }>(["finding", "f1"]);
    expect(detail?.analysis_state).toBe("unanalyzed");
  });
});
