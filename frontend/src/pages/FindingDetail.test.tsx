import { Toaster } from "@/components/ui/sonner";
import { formatDate } from "@/lib/format";
import { GLOSSARY } from "@/lib/glossary";
import { chooseOption, createTestQueryClient, listOptions } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FindingDetail } from "./FindingDetail";

interface FindingFixture {
  finding_kind?: string;
  first_seen_at?: string;
  last_seen_at?: string;
  state?: string;
  analysis_state?: string;
  gate_effect?: string;
  context?: { source_link?: string; };
  remediation?: { summary?: string; url?: string; source?: string; fallback?: boolean; };
  location?: {
    file?: string;
    start_line?: number;
    end_line?: number;
    resource?: string;
    summary?: string;
  };
  suggestion?: {
    action?: string;
    target?: string;
    detail?: string;
    confidence?: string;
    source?: string;
  };
  introduced_by_report_id?: string;
  introduced_commit_sha?: string;
}

let findingFixture: FindingFixture;
let reachabilityFixture: Array<Record<string, unknown>>;
let eventsFixture: Array<Record<string, unknown>>;
let triageCalls: Array<{ url: string; body: string; }>;
let gateFixture: Record<string, unknown>;
let gateFails: boolean;
let findingFails: boolean;
let triageConflict: boolean;

function makeFinding(overrides: FindingFixture = {}): Record<string, unknown> {
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
    analysis_state: "unanalyzed",
    gate_effect: "block",
    first_seen_at: "2025-01-01T00:00:00Z",
    last_seen_at: "2025-01-02T00:00:00Z",
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
    ...overrides,
  };
}

function renderDetail(state?: unknown, search = "") {
  const qc = createTestQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[{ pathname: "/p1/findings/f1", search, state }]}>
        <Routes>
          <Route path="/:slug/findings/:findingId" element={<FindingDetail />} />
        </Routes>
      </MemoryRouter>
      <Toaster />
    </QueryClientProvider>,
  );
}

/** Fix-first mode still uses the select-based triage and reachability forms these tests cover. */
const FIX_FIRST = "?from=change";

async function openDetails() {
  await userEvent.setup().click(screen.getByRole("button", { name: /^Details/ }));
}

beforeEach(() => {
  findingFixture = {};
  reachabilityFixture = [];
  eventsFixture = [];
  triageCalls = [];
  gateFixture = { blocked_by: [] };
  gateFails = false;
  findingFails = false;
  triageConflict = false;
  globalThis.fetch = vi.fn().mockImplementation(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (/\/events(\?|$)/.test(url) && method === "GET") {
        return { ok: true, json: () => Promise.resolve(eventsFixture) } as Response;
      }
      if (url.endsWith("/reachability") && method === "GET") {
        return { ok: true, json: () => Promise.resolve(reachabilityFixture) } as Response;
      }
      if (url.endsWith("/reachability") && method === "POST") {
        return {
          ok: true,
          json: () =>
            Promise.resolve({
              id: "r2",
              finding_id: "f1",
              state: "reachable",
              evidence: "trace confirmed",
              assessed_by: "u1",
              created_at: "2025-01-01T00:00:00Z",
              updated_at: "2025-01-01T00:00:00Z",
            }),
        } as Response;
      }
      if (url.endsWith("/gate") && method === "GET") {
        if (gateFails) {
          return {
            ok: false,
            status: 500,
            json: () => Promise.resolve({ error: { code: "internal", message: "gate failed" } }),
          } as Response;
        }
        return { ok: true, json: () => Promise.resolve(gateFixture) } as Response;
      }
      if (url.endsWith("/findings/f1") && method === "PATCH") {
        triageCalls.push({ url, body: String(init?.body ?? "") });
        if (triageConflict) {
          return {
            ok: false,
            status: 409,
            json: () =>
              Promise.resolve({
                error: {
                  code: "analysis_conflict",
                  message: "The finding was triaged by someone else since you loaded it.",
                },
              }),
          } as Response;
        }
        return {
          ok: true,
          json: () =>
            Promise.resolve({
              finding_id: "f1",
              analysis_state: "accepted_risk",
              gate_effect: "ignore",
            }),
        } as Response;
      }
      if (url.endsWith("/findings/f1") && method === "GET" && findingFails) {
        return {
          ok: false,
          status: 404,
          json: () =>
            Promise.resolve({ error: { code: "not_found", message: "Finding not found" } }),
        } as Response;
      }
      return { ok: true, json: () => Promise.resolve(makeFinding(findingFixture)) } as Response;
    },
  );
});

describe("FindingDetail dates", () => {
  it("leaves out the first seen row when first_seen_at is invalid", async () => {
    findingFixture = { first_seen_at: "not-a-date", last_seen_at: "2025-01-02T00:00:00Z" };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    // The invalid value must never render through toLocaleString() (which
    // throws RangeError on an Invalid Date), and a row without a date is dropped, not "None".
    expect(screen.queryByText("First seen")).not.toBeInTheDocument();
    expect(screen.queryByText("None", { exact: true })).not.toBeInTheDocument();
    expect(screen.getByText("Last seen")).toBeInTheDocument();
  });
});

describe("FindingDetail source link", () => {
  it("renders an https link with its hostname visible", async () => {
    findingFixture = {
      context: { source_link: "https://github.com/acme/widget/blob/abc123/main.go" },
    };
    renderDetail();

    const link = await screen.findByRole("link", { name: /github\.com\/acme\/widget/ });
    expect(link).toHaveAttribute("href", "https://github.com/acme/widget/blob/abc123/main.go");
  });

  it("rejects a javascript: source link and shows no anchor", async () => {
    findingFixture = { context: { source_link: "javascript:alert(1)" } };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    // The Back link remains, but no source anchor with the unsafe href may render.
    expect(
      screen.queryByRole("link", { name: /javascript:|data:/i }),
    ).not.toBeInTheDocument();
    expect(document.querySelector("a[href^=\"javascript:\"]")).toBeNull();
  });

  it("rejects a data: source link", async () => {
    findingFixture = {
      context: { source_link: "data:text/html,<script>alert(1)</script>" },
    };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(document.querySelector("a[href^=\"data:\"]")).toBeNull();
  });
});

describe("FindingDetail triage validation", () => {
  it("blocks accepted_risk until both an expiry date and a reason are provided", async () => {
    const user = userEvent.setup();
    renderDetail(undefined, FIX_FIRST);
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    const triageSelect = screen.getByLabelText("Triage action");
    await chooseOption(user, triageSelect, "Accepted risk");
    const apply = screen.getByRole("button", { name: "Apply" });
    expect(apply).toBeDisabled();

    const dateInput = document.querySelector("input[type=\"date\"]");
    expect(dateInput).not.toBeNull();
    await user.type(dateInput as HTMLInputElement, "2099-06-01");
    // Still disabled because reason is required
    expect(apply).toBeDisabled();

    const reasonInput = screen.getByPlaceholderText("Reason");
    await user.type(reasonInput, "risk accepted for Q3");
    expect(apply).toBeEnabled();

    await user.click(apply);

    expect(await screen.findByText(/triage saved/i)).toBeInTheDocument();
    expect(triageCalls).toHaveLength(1);
    expect(JSON.parse(triageCalls[0].body)).toEqual({
      analysis_state: "accepted_risk",
      reason: "risk accepted for Q3",
      analysis_expires_at: new Date(2099, 5, 1, 23, 59, 59, 999).toISOString(),
      expected_state: "unanalyzed",
    });
  });

  it("refuses to overwrite a decision made since the page loaded and shows the newer one", async () => {
    triageConflict = true;
    const user = userEvent.setup();
    renderDetail(undefined, FIX_FIRST);
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    await chooseOption(user, screen.getAllByRole("combobox")[0], "False positive");
    await user.type(screen.getByPlaceholderText("Reason"), "not reachable");
    const findingLoads = () =>
      vi.mocked(fetch).mock.calls.filter(([input, init]) =>
        String(input).endsWith("/findings/f1") && (init?.method ?? "GET") === "GET"
      ).length;
    const loadsBefore = findingLoads();
    // Another user marks it exploitable while this page still shows "unanalyzed".
    findingFixture = { analysis_state: "exploitable" };
    await user.click(screen.getByRole("button", { name: "Apply" }));

    expect(JSON.parse(triageCalls[0].body).expected_state).toBe("unanalyzed");
    expect(
      await screen.findAllByText("The finding was triaged by someone else since you loaded it."),
    ).not.toHaveLength(0);
    await waitFor(() => expect(findingLoads()).toBeGreaterThan(loadsBefore));
    expect(await screen.findByText(/^Currently: Exploitable/)).toBeInTheDocument();
  });

  it("blocks false_positive until a reason is provided", async () => {
    const user = userEvent.setup();
    renderDetail(undefined, FIX_FIRST);
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    const selects = screen.getAllByRole("combobox");
    const triageSelect = selects[0];
    await chooseOption(user, triageSelect, "False positive");
    const apply = screen.getByRole("button", { name: "Apply" });
    expect(apply).toBeDisabled();

    const reasonInput = screen.getByPlaceholderText("Reason");
    await user.type(reasonInput, "   ");
    expect(apply).toBeDisabled();

    await user.type(reasonInput, "test code only");
    expect(apply).toBeEnabled();
  });
});

describe("FindingDetail triage explanations", () => {
  it("explains the chosen triage action and links the explanation to the select", async () => {
    const user = userEvent.setup();
    renderDetail(undefined, FIX_FIRST);
    await screen.findByRole("heading", { name: "Test Vulnerability" });
    const select = screen.getByLabelText("Triage action");
    expect(select).not.toHaveAttribute("aria-describedby");

    await chooseOption(user, select, "False positive");
    const hint = screen.getByText(GLOSSARY.falsePositive.short);
    expect(select).toHaveAttribute("aria-describedby", hint.id);

    await chooseOption(user, select, "Exploitable");
    expect(screen.queryByText(GLOSSARY.falsePositive.short)).not.toBeInTheDocument();
    expect(screen.getByText(GLOSSARY.exploitable.short)).toBeInTheDocument();

    await chooseOption(user, select, "Select action...");
    expect(select).not.toHaveAttribute("aria-describedby");
  });
});

describe("FindingDetail accessibility", () => {
  it("names each triage and reachability control for assistive technology", async () => {
    const user = userEvent.setup();
    renderDetail(undefined, FIX_FIRST);
    await screen.findByRole("heading", { name: "Test Vulnerability" });
    await openDetails();

    await chooseOption(user, screen.getByLabelText("Triage action"), "Accepted risk");

    expect(screen.getByLabelText("Triage action")).toBeInTheDocument();
    expect(screen.getByLabelText("Reason")).toBeInTheDocument();
    expect(screen.getByLabelText("Expiry date")).toBeInTheDocument();
    expect(screen.getByLabelText("Reachability assessment")).toBeInTheDocument();
    expect(screen.getByLabelText("Evidence")).toBeInTheDocument();
  });

  it("confirms a successful triage in a polite toast, not in the form", async () => {
    const user = userEvent.setup();
    renderDetail(undefined, FIX_FIRST);
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    await chooseOption(user, screen.getByLabelText("Triage action"), "Exploitable");
    await user.click(screen.getByRole("button", { name: "Apply" }));

    const message = await screen.findByText(/Triage saved \(effect:/);
    expect(message.closest("[aria-live=\"polite\"]")).not.toBeNull();
    expect(screen.getByRole("alert", { name: "Triage result error" })).toBeEmptyDOMElement();
  });

  it("exposes a failed triage through an alert", async () => {
    globalThis.fetch = vi.fn().mockImplementation(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        if (/\/events(\?|$)/.test(url) && method === "GET") {
          return { ok: true, json: () => Promise.resolve(eventsFixture) } as Response;
        }
        if (url.endsWith("/reachability") && method === "GET") {
          return { ok: true, json: () => Promise.resolve(reachabilityFixture) } as Response;
        }
        if (url.endsWith("/findings/f1") && method === "PATCH") {
          return {
            ok: false,
            status: 500,
            json: () =>
              Promise.resolve({ error: { code: "internal", message: "triage failed hard" } }),
          } as Response;
        }
        return { ok: true, json: () => Promise.resolve(makeFinding(findingFixture)) } as Response;
      },
    );

    const user = userEvent.setup();
    renderDetail(undefined, FIX_FIRST);
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    await chooseOption(user, screen.getByLabelText("Triage action"), "Exploitable");
    await user.click(screen.getByRole("button", { name: "Apply" }));

    const alert = screen.getByRole("alert", { name: "Triage result error" });
    await waitFor(() => expect(alert).toHaveTextContent("triage failed hard"));
  });
});

describe("FindingDetail decision flow", () => {
  it("leads with the decision: decide, how to fix, where, context, history", async () => {
    findingFixture = { context: { source_link: "https://example.com/repo" } };
    renderDetail();
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    const order = ["Decide", "How to fix", "Where it occurs", "Context", "History"].map((name) =>
      screen.getByRole("heading", { level: 2, name })
    );
    for (let i = 0; i < order.length - 1; i++) {
      expect(
        order[i].compareDocumentPosition(order[i + 1]) & Node.DOCUMENT_POSITION_FOLLOWING,
      ).toBeTruthy();
    }
  });

  it("puts the decision and the reachability answer in one form inside the Decide section", async () => {
    renderDetail();
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    const decide = screen.getByRole("heading", { level: 2, name: "Decide" }).parentElement!;
    const form = within(decide).getByRole("form", { name: "What is this finding?" });
    expect(within(form).getByRole("group", { name: "What is this finding?" })).toBeInTheDocument();
    expect(within(form).getByRole("group", { name: /Can an attacker reach this code/ }))
      .toBeInTheDocument();
    expect(screen.queryByLabelText("Triage action")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Reachability assessment")).not.toBeInTheDocument();
  });

  it("offers the reachability and triage options from the shared vocabularies", async () => {
    renderDetail(undefined, FIX_FIRST);
    await screen.findByRole("heading", { name: "Test Vulnerability" });
    await openDetails();

    const reachability = screen.getByLabelText("Reachability assessment");
    expect(await listOptions(userEvent.setup(), reachability)).toEqual([
      "Select assessment...",
      "Reachable",
      "Not Reachable",
      "Unknown",
      "Not Applicable",
    ]);

    const triage = screen.getByLabelText("Triage action");
    expect(await listOptions(userEvent.setup(), triage)).toEqual([
      "Select action...",
      "Exploitable",
      "False positive",
      "Not affected",
      "Accepted risk",
      "Won't fix",
      "Not triaged",
      "In triage",
    ]);
  });

  it("states the current triage and gate position at the top of the Decide section", async () => {
    findingFixture = { analysis_state: "accepted_risk" };
    gateFixture = { blocked_by: ["f1"] };
    renderDetail();
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    const decide = screen.getByRole("heading", { level: 2, name: "Decide" }).parentElement!;
    await waitFor(() => expect(decide).toHaveTextContent("Currently: Accepted risk · Blocks gate"));
  });

  it("shows the recorded reason and expiry under the current standing", async () => {
    findingFixture = {
      analysis_state: "accepted_risk",
      analysis_reason: "covered by the WAF rule",
      analysis_expires_at: "2031-03-04T05:06:07Z",
    };
    renderDetail();
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    const note = await screen.findByText(/Reason: covered by the WAF rule/);
    expect(note.textContent).toContain(`Expires ${formatDate("2031-03-04T05:06:07Z")}`);
  });

  it("says Not triaged and omits the gate position while the gate is unknown", async () => {
    gateFails = true;
    renderDetail();
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    const current = screen.getByText(/^Currently:/);
    expect(current).toHaveTextContent("Currently: Not triaged");
    expect(current).not.toHaveTextContent("gate");
  });

  it("mounts the error regions before anything happens", async () => {
    renderDetail(undefined, FIX_FIRST);
    await screen.findByRole("heading", { name: "Test Vulnerability" });
    await openDetails();

    expect(screen.getByRole("alert", { name: "Triage result error" })).toBeEmptyDOMElement();
    expect(screen.getByRole("alert", { name: "Reachability result error" }))
      .toBeEmptyDOMElement();
    expect(screen.queryByRole("status", { name: "Triage result" })).not.toBeInTheDocument();
  });

  it("confirms a reachability save in a toast and leaves triage untouched", async () => {
    const user = userEvent.setup();
    renderDetail(undefined, FIX_FIRST);
    await screen.findByRole("heading", { name: "Test Vulnerability" });
    await openDetails();

    await chooseOption(user, screen.getByLabelText("Reachability assessment"), "Reachable");
    await user.click(screen.getByRole("button", { name: "Assess" }));

    expect(await screen.findByText("Reachability saved")).toBeInTheDocument();
    expect(screen.queryByText(/Triage saved/)).not.toBeInTheDocument();
  });

  it("returns to the list with its filters when the user opened the finding from a filtered page", async () => {
    renderDetail({ from: "?severity=high&offset=20" });
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    expect(screen.getByRole("link", { name: "← Back to findings" })).toHaveAttribute(
      "href",
      "/p1/findings?severity=high&offset=20",
    );
  });

  it("returns to the plain list when there is no router state or an unsafe one", async () => {
    const { unmount } = renderDetail();
    await screen.findByRole("heading", { name: "Test Vulnerability" });
    expect(screen.getByRole("link", { name: "← Back to findings" })).toHaveAttribute(
      "href",
      "/p1/findings",
    );
    unmount();

    renderDetail({ from: "http://evil.example/steal" });
    await screen.findByRole("heading", { name: "Test Vulnerability" });
    expect(screen.getByRole("link", { name: "← Back to findings" })).toHaveAttribute(
      "href",
      "/p1/findings",
    );
  });

  it("marks the page as decide-first when opened from the list, with no origin or an unknown one", async () => {
    for (const search of ["", "?from=list", "?from=", "?from=Change"]) {
      const { container, unmount } = renderDetail(undefined, search);
      await screen.findByRole("heading", { name: "Test Vulnerability" });
      expect(container.querySelector("[data-mode]")).toHaveAttribute("data-mode", "triage");
      unmount();
    }
  });

  it("marks the page as fix-first when opened from the change view", async () => {
    const { container } = renderDetail(undefined, "?from=change");
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    expect(container.querySelector("[data-mode]")).toHaveAttribute("data-mode", "unblock");
  });

  it("goes back to the change it was opened from, with that change's own query", async () => {
    renderDetail(
      { changeView: "/p1/changes/abc1234?report=r1&scope=introduced" },
      "?from=change",
    );
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    expect(screen.getByRole("link", { name: "← Back to the change" })).toHaveAttribute(
      "href",
      "/p1/changes/abc1234?report=r1&scope=introduced",
    );
    expect(screen.queryByRole("link", { name: "← Back to findings" })).not.toBeInTheDocument();
  });

  it("goes back to the list when the change is unknown, unsafe or the page was opened from the list", async () => {
    const cases: Array<[unknown, string]> = [
      [undefined, "?from=change"],
      [{ changeView: "http://evil.example/p1/changes/abc" }, "?from=change"],
      [{ changeView: "/other/changes/abc1234" }, "?from=change"],
      [{ changeView: "/p1/changes/abc1234" }, ""],
    ];
    for (const [state, search] of cases) {
      const { unmount } = renderDetail(state, search);
      await screen.findByRole("heading", { name: "Test Vulnerability" });
      expect(screen.getByRole("link", { name: "← Back to findings" })).toHaveAttribute(
        "href",
        "/p1/findings",
      );
      unmount();
    }
  });

  it("shows event comments in the history without exposing user ids", async () => {
    eventsFixture = [{
      id: "e1",
      finding_id: "f1",
      user_id: "11111111-2222-3333-4444-555555555555",
      event_type: "analysis_changed",
      old_value: "unanalyzed",
      new_value: "accepted_risk",
      comment: "Vendor confirmed the code path is unreachable",
      created_at: "2025-01-03T00:00:00Z",
    }];
    renderDetail();

    expect(await screen.findByText(/Vendor confirmed the code path is unreachable/))
      .toBeInTheDocument();
    expect(screen.queryByText(/11111111-2222/)).not.toBeInTheDocument();
  });
});

describe("FindingDetail enum labels", () => {
  it("labels the analysis state instead of rendering the raw enum", async () => {
    findingFixture = { analysis_state: "accepted_risk" };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.getByText("Accepted risk", { selector: "dd" })).toBeInTheDocument();
    expect(screen.queryByText("accepted_risk", { selector: "dd" })).not.toBeInTheDocument();
  });

  it("renders a controlled label when analysis_state is unvalidated", async () => {
    findingFixture = { analysis_state: "pending_review" };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.queryByText("pending_review")).not.toBeInTheDocument();
    expect(screen.getByText("Unknown", { selector: "dd" })).toBeInTheDocument();
  });

  it("no longer shows a Gate Effect field", async () => {
    findingFixture = { gate_effect: "ignore" };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.queryByText("Gate Effect")).not.toBeInTheDocument();
  });

  it("labels the technical state instead of rendering the raw enum", async () => {
    findingFixture = { state: "reopened" };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.getByText("Reopened", { selector: "dd" })).toBeInTheDocument();
  });

  it("renders a controlled label when state is unvalidated", async () => {
    findingFixture = { state: "closed" };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.queryByText("closed")).not.toBeInTheDocument();
    expect(screen.getByText("Unknown", { selector: "dd" })).toBeInTheDocument();
  });
});

describe("FindingDetail kind", () => {
  it("labels the finding kind the same way the list does", async () => {
    findingFixture = { finding_kind: "image_config" };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.getByText("Image config")).toBeInTheDocument();
    expect(screen.queryByText("image_config")).not.toBeInTheDocument();
  });
});

describe("FindingDetail gate status", () => {
  it("says why the finding blocks, in the panel under the title", async () => {
    gateFixture = { blocked_by: ["f1"], policy: { severity_floor: "high" } };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    const panel = await screen.findByRole("region", { name: "Why this blocks" });
    expect(panel).toHaveAttribute("data-blocks", "true");
    expect(panel).toHaveTextContent(
      "Severity HIGH is at or above the project floor (HIGH). The gate stops a change that carries it until it is fixed or waived.",
    );
  });
  it("explains an ignored finding in the panel", async () => {
    findingFixture = { gate_effect: "ignore" };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    const panel = await screen.findByRole("region", { name: "Why this does not block" });
    expect(panel).toHaveTextContent("Triage marked this finding as not blocking the gate");
    expect(panel).toHaveAttribute("data-blocks", "false");
  });
  it("explains a below-floor finding in the panel", async () => {
    findingFixture = { current_severity: "low" };
    gateFixture = { blocked_by: [], policy: { severity_floor: "high" } };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(await screen.findByText(/Severity LOW is below the project floor \(HIGH\)/))
      .toBeInTheDocument();
  });
  it("says an approved waiver lets the finding through", async () => {
    gateFixture = { blocked_by: [], waived_finding_ids: ["f1"] };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(await screen.findByText(/An approved waiver lets this finding through the gate/))
      .toBeInTheDocument();
  });
  it("renders no chip while the gate status is unknown", async () => {
    gateFails = true;
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.queryByText("Blocks gate")).not.toBeInTheDocument();
    expect(screen.queryByText(/^Does not block gate/)).not.toBeInTheDocument();
  });
});

describe("FindingDetail reachability rendering", () => {
  const assessment = (overrides: Record<string, unknown> = {}) => ({
    id: "r1",
    finding_id: "f1",
    state: "not_reachable",
    evidence: "",
    assessed_by: "u1",
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-03T00:00:00Z",
    ...overrides,
  });

  function latestParagraph(): HTMLParagraphElement {
    const p = [...document.querySelectorAll("p")]
      .find((el) => el.textContent?.startsWith("Latest:"));
    expect(p).toBeDefined();
    return p as HTMLParagraphElement;
  }

  it("labels a reachability state instead of rendering the raw enum", async () => {
    reachabilityFixture = [assessment({ state: "not_reachable" })];
    renderDetail(undefined, FIX_FIRST);

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    await openDetails();
    const latest = latestParagraph();
    expect(latest.textContent).toContain("Not Reachable");
    expect(latest.textContent).not.toContain("not_reachable");
  });

  it("renders a controlled label when a reachability state is unvalidated", async () => {
    reachabilityFixture = [assessment({ state: "maybe_reachable", evidence: "trace exists" })];
    renderDetail(undefined, FIX_FIRST);

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    await openDetails();
    const latest = latestParagraph();
    expect(latest.textContent).not.toContain("maybe_reachable");
    expect(latest.textContent).not.toContain("maybe reachable");
    expect(latest.textContent).toContain("Unknown");
  });

  it("truncates long evidence inline and keeps the full text reachable", async () => {
    const fullEvidence = "x".repeat(2000);
    reachabilityFixture = [assessment({ evidence: fullEvidence })];
    renderDetail(undefined, FIX_FIRST);

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    await openDetails();
    const latest = latestParagraph();
    // The 2000-char payload must not land in the layout.
    expect(latest.textContent!.length).toBeLessThan(300);
    expect(latest.textContent).toContain("…");
    // The complete evidence stays available for inspection.
    expect(screen.getByTitle(fullEvidence)).toBeInTheDocument();
  });

  it("keeps short evidence inline untruncated", async () => {
    reachabilityFixture = [assessment({ evidence: "short reason" })];
    renderDetail(undefined, FIX_FIRST);

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    await openDetails();
    const latest = latestParagraph();
    expect(latest.textContent).toContain(". short reason");
    expect(latest.textContent).not.toContain("…");
  });

  it("resets assessment inputs upon successful submission", async () => {
    const user = userEvent.setup();
    renderDetail(undefined, FIX_FIRST);
    await screen.findByRole("heading", { name: "Test Vulnerability" });
    await openDetails();

    const selects = screen.getAllByRole("combobox");
    const reachSelect = selects[1];
    await chooseOption(user, reachSelect, "Reachable");

    const evidenceInput = screen.getByPlaceholderText("Evidence") as HTMLInputElement;
    await user.type(evidenceInput, "trace confirmed");

    const assessBtn = screen.getByRole("button", { name: "Assess" });
    await user.click(assessBtn);

    expect(await screen.findByText("Reachability saved")).toBeInTheDocument();
    expect(reachSelect).toHaveTextContent("Select assessment...");
    expect(evidenceInput.value).toBe("");
  });
});

describe("FindingDetail back link", () => {
  it("links back to findings list using relative path navigation", async () => {
    renderDetail();
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    const backLink = screen.getByRole("link", { name: /back to findings/i });
    expect(backLink).toBeInTheDocument();
    expect(backLink).toHaveAttribute("href", "/p1/findings");
  });
});

describe("FindingDetail load failure", () => {
  it("shows a heading, the error message, and a back link", async () => {
    findingFails = true;
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Couldn't load this finding" }))
      .toBeInTheDocument();
    expect(screen.getByText("Finding not found")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "← Back to findings" })).toHaveAttribute(
      "href",
      "/p1/findings",
    );
  });

  it("keeps the list filters in the back link when the user came from a filtered page", async () => {
    findingFails = true;
    renderDetail({ from: "?severity=high&offset=20" });

    expect(await screen.findByRole("heading", { name: "Couldn't load this finding" }))
      .toBeInTheDocument();
    expect(screen.getByRole("link", { name: "← Back to findings" })).toHaveAttribute(
      "href",
      "/p1/findings?severity=high&offset=20",
    );
  });

  it("refetches the finding when Retry is pressed", async () => {
    const user = userEvent.setup();
    findingFails = true;
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Couldn't load this finding" }))
      .toBeInTheDocument();

    findingFails = false;
    await user.click(screen.getByRole("button", { name: "Retry" }));

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" }))
      .toBeInTheDocument();
  });
});

describe("FindingDetail remediation", () => {
  it("renders the fix summary with its source", async () => {
    findingFixture = {
      remediation: { summary: "Upgrade lodash to 4.17.21 or later", source: "trivy" },
    };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.getByText("Upgrade lodash to 4.17.21 or later")).toBeInTheDocument();
    expect(screen.getByText(/trivy/)).toBeInTheDocument();
  });

  it("labels fallback guidance as general instead of implying certainty", async () => {
    findingFixture = {
      remediation: { summary: "No fixed version reported by the scanner", fallback: true },
    };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.getByText(/general guidance/i)).toBeInTheDocument();
  });

  it("renders the remediation link when the URL is safe", async () => {
    findingFixture = {
      remediation: {
        summary: "See advisory",
        url: "https://example.com/advisory/1",
        source: "trivy",
      },
    };
    renderDetail();

    const link = await screen.findByRole("link", { name: /remediation reference/i });
    expect(link).toHaveAttribute("href", "https://example.com/advisory/1");
  });
});

describe("FindingDetail suggested action", () => {
  it("renders the action, target, confidence, and detail", async () => {
    findingFixture = {
      remediation: { summary: "Upgrade the dependency" },
      suggestion: {
        action: "upgrade",
        target: "lodash@4.17.21",
        confidence: "high",
        detail: "Fixes CVE-2021-23337",
      },
    };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    const suggestion = screen.getByText(/^Suggested:/);
    expect(suggestion).toHaveTextContent(
      "Suggested: upgrade lodash@4.17.21 (confidence High). Fixes CVE-2021-23337",
    );
    expect(suggestion).toHaveTextContent("lodash@4.17.21");
    expect(suggestion).toHaveTextContent("Fixes CVE-2021-23337");
  });

  it("shows Unknown instead of an unvalidated confidence value", async () => {
    findingFixture = {
      remediation: { summary: "Upgrade the dependency" },
      suggestion: { action: "upgrade", target: "lodash@4.17.21", confidence: "moderate" },
    };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    const suggestion = screen.getByText(/^Suggested:/);
    expect(suggestion).toHaveTextContent("(confidence Unknown)");
    expect(suggestion).not.toHaveTextContent("moderate");
  });

  it("does not render a dangling separator when the detail is missing", async () => {
    findingFixture = {
      remediation: { summary: "Upgrade the dependency" },
      suggestion: { action: "upgrade", target: "lodash@4.17.21", confidence: "high" },
    };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    const suggestion = screen.getByText(/^Suggested:/);
    expect(suggestion).toHaveTextContent("Suggested: upgrade lodash@4.17.21 (confidence High)");
    expect(suggestion.textContent).toMatch(/\(confidence High\)$/);
  });
});

describe("FindingDetail location", () => {
  it("renders the file with line range", async () => {
    findingFixture = {
      finding_kind: "sast",
      location: { file: "app/main.go", start_line: 10, end_line: 12 },
    };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.getByText(/app\/main\.go/)).toBeInTheDocument();
    expect(screen.getByText(/10.*12/)).toBeInTheDocument();
  });

  it("states explicitly when no location was reported", async () => {
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.getByText(/no location reported/i)).toBeInTheDocument();
  });
});

describe("FindingDetail provenance", () => {
  it("renders the short introduced commit", async () => {
    findingFixture = { introduced_commit_sha: "abc123def456789" };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.getByText(/abc123def456/)).toBeInTheDocument();
  });

  it("marks unattributed findings explicitly", async () => {
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.getByText(/unattributed/i)).toBeInTheDocument();
  });
});

describe("FindingDetail history", () => {
  it("renders lifecycle events with their transitions", async () => {
    eventsFixture = [
      {
        id: "e1",
        finding_id: "f1",
        event_type: "regression",
        old_value: "fixed",
        new_value: "reopened",
        created_at: "2025-02-01T00:00:00Z",
      },
    ];
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.getByText(/regression/i)).toBeInTheDocument();
    expect(screen.getByText(/Fixed.*Reopened/)).toBeInTheDocument();
  });

  it("states explicitly when no history exists", async () => {
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.getByText(/no history yet/i)).toBeInTheDocument();
  });

  it("renders None for empty transition values", async () => {
    eventsFixture = [
      {
        id: "e1",
        finding_id: "f1",
        event_type: "commented",
        old_value: "",
        new_value: "",
        created_at: "2025-02-01T00:00:00Z",
      },
    ];
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    const entry = screen.getByText(/commented/i).closest("li");
    expect(entry).not.toBeNull();
    expect(entry!.textContent).toContain("None → None");
  });
});
