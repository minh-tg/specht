import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
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

function renderDetail() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/p1/findings/f1"]}>
        <Routes>
          <Route path="/:slug/findings/:findingId" element={<FindingDetail />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  findingFixture = {};
  reachabilityFixture = [];
  eventsFixture = [];
  triageCalls = [];
  globalThis.fetch = vi.fn().mockImplementation(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.endsWith("/events") && method === "GET") {
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
      if (url.endsWith("/findings/f1") && method === "PATCH") {
        triageCalls.push({ url, body: String(init?.body ?? "") });
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
      return { ok: true, json: () => Promise.resolve(makeFinding(findingFixture)) } as Response;
    },
  );
});

describe("FindingDetail dates", () => {
  it("shows a formatted date when first_seen_at is invalid", async () => {
    findingFixture = { first_seen_at: "not-a-date", last_seen_at: "2025-01-02T00:00:00Z" };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    // The invalid value must never render through toLocaleString() (which
    // throws RangeError on an Invalid Date) — the fallback shows instead.
    expect(screen.getByText("–", { exact: true })).toBeInTheDocument();
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
    renderDetail();
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    const selects = screen.getAllByRole("combobox");
    expect(selects.length).toBeGreaterThanOrEqual(2);
    const triageSelect = selects[0];
    await user.selectOptions(triageSelect, "accepted_risk");
    const apply = screen.getByRole("button", { name: "Apply" });
    expect(apply).toBeDisabled();

    const dateInput = document.querySelector("input[type=\"date\"]");
    expect(dateInput).not.toBeNull();
    await user.type(dateInput as HTMLInputElement, "2025-06-01");
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
      analysis_expires_at: "2025-06-01T23:59:59.999Z",
    });
  });

  it("blocks false_positive until a reason is provided", async () => {
    const user = userEvent.setup();
    renderDetail();
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    const selects = screen.getAllByRole("combobox");
    const triageSelect = selects[0];
    await user.selectOptions(triageSelect, "false_positive");
    const apply = screen.getByRole("button", { name: "Apply" });
    expect(apply).toBeDisabled();

    const reasonInput = screen.getByPlaceholderText("Reason");
    await user.type(reasonInput, "   ");
    expect(apply).toBeDisabled();

    await user.type(reasonInput, "test code only");
    expect(apply).toBeEnabled();
  });
});

describe("FindingDetail accessibility", () => {
  it("names each triage and reachability control for assistive technology", async () => {
    const user = userEvent.setup();
    renderDetail();
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    await user.selectOptions(screen.getByLabelText("Triage action"), "accepted_risk");

    expect(screen.getByLabelText("Triage action")).toBeInTheDocument();
    expect(screen.getByLabelText("Reason")).toBeInTheDocument();
    expect(screen.getByLabelText("Expiry date")).toBeInTheDocument();
    expect(screen.getByLabelText("Reachability assessment")).toBeInTheDocument();
    expect(screen.getByLabelText("Evidence")).toBeInTheDocument();
  });

  it("announces a successful triage with the matched success token pair", async () => {
    const user = userEvent.setup();
    renderDetail();
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    await user.selectOptions(screen.getByLabelText("Triage action"), "exploitable");
    await user.click(screen.getByRole("button", { name: "Apply" }));

    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent(/Triage saved \(effect:/);
    expect(status).toHaveClass("bg-sev-success-bg");
    expect(status).toHaveClass("text-sev-success-fg");
    expect(status).not.toHaveClass("text-green-600");
  });

  it("exposes a failed triage through an alert", async () => {
    globalThis.fetch = vi.fn().mockImplementation(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        if (url.endsWith("/events") && method === "GET") {
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
    renderDetail();
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    await user.selectOptions(screen.getByLabelText("Triage action"), "exploitable");
    await user.click(screen.getByRole("button", { name: "Apply" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("triage failed hard");
  });
});

describe("FindingDetail enum labels", () => {
  it("labels the analysis state instead of rendering the raw enum", async () => {
    findingFixture = { analysis_state: "accepted_risk" };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.getByText("Accepted Risk", { selector: "p" })).toBeInTheDocument();
    expect(screen.queryByText("accepted_risk", { selector: "p" })).not.toBeInTheDocument();
  });

  it("renders a controlled label when analysis_state is unvalidated", async () => {
    findingFixture = { analysis_state: "pending_review" };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.queryByText("pending_review")).not.toBeInTheDocument();
    expect(screen.getByText("Unknown", { selector: "p" })).toBeInTheDocument();
  });

  it("labels the gate effect instead of rendering the raw enum", async () => {
    findingFixture = { gate_effect: "ignore" };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.getByText("Ignore", { selector: "p" })).toBeInTheDocument();
    expect(screen.queryByText("ignore", { selector: "p" })).not.toBeInTheDocument();
  });

  it("renders a controlled label when gate_effect is unvalidated", async () => {
    findingFixture = { gate_effect: "defer" };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.queryByText("defer")).not.toBeInTheDocument();
    expect(screen.getByText("Unknown", { selector: "p" })).toBeInTheDocument();
  });

  it("labels the technical state instead of rendering the raw enum", async () => {
    findingFixture = { state: "reopened" };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.getByText("Reopened", { selector: "p" })).toBeInTheDocument();
  });

  it("renders a controlled label when state is unvalidated", async () => {
    findingFixture = { state: "closed" };
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.queryByText("closed")).not.toBeInTheDocument();
    expect(screen.getByText("Unknown", { selector: "p" })).toBeInTheDocument();
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
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    const latest = latestParagraph();
    expect(latest.textContent).toContain("Not Reachable");
    expect(latest.textContent).not.toContain("not_reachable");
  });

  it("renders a controlled label when a reachability state is unvalidated", async () => {
    reachabilityFixture = [assessment({ state: "maybe_reachable", evidence: "trace exists" })];
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    const latest = latestParagraph();
    expect(latest.textContent).not.toContain("maybe_reachable");
    expect(latest.textContent).not.toContain("maybe reachable");
    expect(latest.textContent).toContain("Unknown");
  });

  it("truncates long evidence inline and keeps the full text reachable", async () => {
    const fullEvidence = "x".repeat(2000);
    reachabilityFixture = [assessment({ evidence: fullEvidence })];
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    const latest = latestParagraph();
    // The 2000-char payload must not land in the layout.
    expect(latest.textContent!.length).toBeLessThan(300);
    expect(latest.textContent).toContain("…");
    // The complete evidence stays available for inspection.
    expect(screen.getByTitle(fullEvidence)).toBeInTheDocument();
  });

  it("keeps short evidence inline untruncated", async () => {
    reachabilityFixture = [assessment({ evidence: "short reason" })];
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    const latest = latestParagraph();
    expect(latest.textContent).toContain("— short reason");
    expect(latest.textContent).not.toContain("…");
  });

  it("resets assessment inputs upon successful submission", async () => {
    const user = userEvent.setup();
    renderDetail();
    await screen.findByRole("heading", { name: "Test Vulnerability" });

    const selects = screen.getAllByRole("combobox");
    const reachSelect = selects[1];
    await user.selectOptions(reachSelect, "reachable");

    const evidenceInput = screen.getByPlaceholderText("Evidence") as HTMLInputElement;
    await user.type(evidenceInput, "trace confirmed");

    const assessBtn = screen.getByRole("button", { name: "Assess" });
    await user.click(assessBtn);

    expect(await screen.findByText("Reachability saved")).toBeInTheDocument();
    expect(reachSelect).toHaveValue("");
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
    expect(screen.getByText(/fixed.*reopened/)).toBeInTheDocument();
  });

  it("states explicitly when no history exists", async () => {
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
    expect(screen.getByText(/no history yet/i)).toBeInTheDocument();
  });

  it("renders a dash for empty transition values", async () => {
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
    expect(entry!.textContent).toContain("– → –");
  });
});
