import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { completeReport } from "./finding-detail/cveDetailFixtures";
import { FindingDetail } from "./FindingDetail";

const TITLE = "Test Vulnerability";

let finding: Record<string, unknown>;
let events: unknown;
let reachability: unknown;
let waivers: unknown;
let gate: Record<string, unknown>;
let canRequestWaiver: boolean;
let paths: string[];

function makeFinding(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "f1",
    project_id: "p1",
    finding_kind: "sast",
    fingerprint: "fp1",
    current_title: TITLE,
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

function sca(suggestion: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  return makeFinding({
    finding_kind: "sca",
    location: { summary: "lodash@4.17.20" },
    suggestion: { confidence: "high", source: "trivy", ...suggestion },
    ...extra,
  });
}

beforeEach(() => {
  finding = makeFinding();
  events = [];
  reachability = [];
  waivers = [];
  gate = { blocked_by: ["f1"], policy: { severity_floor: "high" } };
  canRequestWaiver = true;
  paths = [];
  globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
    const url = new URL(String(input), "http://localhost");
    paths.push(url.pathname);
    if (url.pathname === "/api/v1/me") {
      return jsonResponse({ id: "u-1", email: "u@example.corp", role: "member" });
    }
    if (url.pathname.endsWith("/members")) {
      return jsonResponse([{ project_id: "p1", user_id: "u-1", role: "manager" }]);
    }
    if (url.pathname.endsWith("/waivers")) return jsonResponse(waivers);
    if (url.pathname.endsWith("/gate")) return jsonResponse(gate);
    if (url.pathname.endsWith("/events")) return jsonResponse(events);
    if (url.pathname.endsWith("/reachability")) return jsonResponse(reachability);
    if (url.pathname.endsWith("/cve")) {
      return jsonResponse({ error: { code: "not_cve", message: "No CVE." } }, 404);
    }
    if (url.pathname.endsWith("/evidence")) return jsonResponse([]);
    if (url.pathname.endsWith("/signoff")) {
      return jsonResponse({ error: { code: "not_found", message: "none" } }, 404);
    }
    if (url.pathname === "/api/v1/projects/p1") {
      return jsonResponse({
        id: "p1",
        slug: "p1",
        name: "p1",
        role: "manager",
        permissions: { request_waiver: canRequestWaiver },
      });
    }
    if (url.pathname === "/api/v1/findings/f1") return jsonResponse(finding);
    return jsonResponse({});
  });
});

function renderDetail(search = "?from=change") {
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

async function loaded() {
  await screen.findByRole("heading", { name: TITLE });
}

/** The h2 names as a reader hears them: text inside aria-hidden elements is left out. */
function sectionNames(): string[] {
  return screen.getAllByRole("heading", { level: 2 }).map((heading) => {
    const copy = heading.cloneNode(true) as HTMLElement;
    copy.querySelectorAll("[aria-hidden]").forEach((node) => node.remove());
    return copy.textContent ?? "";
  });
}

async function openDetails() {
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: /^Details/ }));
}

describe("FindingDetail fix-first order", () => {
  it("leads with the fix, then where, then the decision, then the folded details", async () => {
    renderDetail();
    await loaded();

    // This is the height check: four sections and the Details button sit above the fold, and
    // every other section mounts only inside the disclosure.
    expect(sectionNames()).toEqual([
      "Why this blocks",
      "How to fix",
      "Where it occurs",
      "Decide",
      "Details",
    ]);
    const details = screen.getByRole("button", { name: /^Details/ });
    expect(details).toHaveAttribute("aria-expanded", "false");
    for (const name of ["Context", "History", "Evidence", "Reviewer sign-off"]) {
      expect(screen.queryByRole("heading", { name })).not.toBeInTheDocument();
    }
  });

  it("offers the waiver and the triage form before the details", async () => {
    renderDetail();
    await loaded();

    const decide = screen.getByRole("heading", { level: 2, name: "Decide" }).parentElement!;
    expect(within(decide).getByRole("button", { name: "Request waiver" })).toBeEnabled();
    expect(within(decide).getByLabelText("Triage action")).toBeInTheDocument();
    expect(within(decide).queryByLabelText("Reachability assessment")).not.toBeInTheDocument();
    expect(screen.queryByRole("complementary")).not.toBeInTheDocument();
  });

  it("keeps the waiver control and says why when it cannot be used", async () => {
    canRequestWaiver = false;
    renderDetail();
    await loaded();

    const decide = screen.getByRole("heading", { level: 2, name: "Decide" }).parentElement!;
    await waitFor(() =>
      expect(within(decide).getByRole("button", { name: "Request waiver" })).toBeDisabled()
    );
    expect(
      within(decide).getByText("You are not a member of this project.", { selector: ".sr-only" }),
    )
      .toBeInTheDocument();
  });

  it("puts the secondary sections behind the Details button", async () => {
    finding = makeFinding({ context: { branch: "main" } });
    renderDetail();
    await loaded();
    await openDetails();

    const details = screen.getByRole("button", { name: /^Details/ });
    expect(details).toHaveAttribute("aria-expanded", "true");
    expect(sectionNames()).toEqual(expect.arrayContaining([
      "Reachability",
      "Context",
      "About this finding",
      "Evidence",
      "Reviewer sign-off",
      "History",
    ].filter((name) => name !== "Reachability")));
    expect(screen.getByRole("heading", { level: 3, name: "Reachability" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check if it is fixed" })).toBeInTheDocument();
  });

  it("keeps a half-typed reachability note when the details are closed and reopened", async () => {
    renderDetail();
    await loaded();
    const user = userEvent.setup();
    await openDetails();
    await user.type(screen.getByLabelText("Evidence"), "traced");
    await openDetails();
    expect(screen.getByLabelText("Evidence")).not.toBeVisible();
    await openDetails();

    expect(screen.getByLabelText("Evidence")).toHaveValue("traced");
  });
});

describe("FindingDetail fix-first fix", () => {
  it("shows the package, both versions and the ecosystem for a dependency fix", async () => {
    finding = sca({
      action: "upgrade",
      target: "lodash@4.17.21",
      fallback: false,
      package: "lodash",
      ecosystem: "npm",
      installed_version: "4.17.20",
      fixed_version: "4.17.21",
    });
    renderDetail();
    await loaded();

    expect(screen.getByText("Upgrade lodash from 4.17.20 to 4.17.21")).toBeInTheDocument();
    expect(screen.getByText("npm · Confidence High · trivy")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy fix" })).toBeInTheDocument();
    expect(screen.queryByText("No known fix.")).not.toBeInTheDocument();
  });

  it("leaves out the installed version when the scanner gave none", async () => {
    finding = sca({
      action: "upgrade",
      fallback: false,
      package: "lodash",
      fixed_version: "4.17.21",
    });
    renderDetail();
    await loaded();

    expect(screen.getByText("Upgrade lodash to 4.17.21")).toBeInTheDocument();
  });

  it("says there is no known fix and where to start when the suggestion is a fallback", async () => {
    finding = makeFinding({
      location: { file: "src/repository.go", start_line: 88 },
      remediation: { summary: "General guidance for SQL injection", fallback: true },
      suggestion: {
        action: "review",
        target: "src/repository.go",
        confidence: "low",
        fallback: true,
      },
    });
    renderDetail();
    await loaded();

    const section = screen.getByRole("heading", { level: 2, name: "How to fix" }).parentElement!;
    expect(section).toHaveTextContent(
      "No known fix. The scanner reported no fix for this finding. Start at src/repository.go:88.",
    );
    expect(within(section).queryByText(/General guidance/)).not.toBeInTheDocument();
    expect(within(section).queryByRole("button", { name: "Copy fix" })).not.toBeInTheDocument();
  });

  it("names the package in the no-fix branch of a dependency finding", async () => {
    finding = sca({
      action: "review",
      fallback: true,
      package: "lodash",
      installed_version: "4.17.20",
    });
    renderDetail();
    await loaded();

    const section = screen.getByRole("heading", { level: 2, name: "How to fix" }).parentElement!;
    expect(section).toHaveTextContent(
      "No known fix. The scanner reported no fixed version for lodash 4.17.20. Start at lodash@4.17.20.",
    );
  });

  it("says so when there is neither a fix nor a location", async () => {
    finding = makeFinding();
    renderDetail();
    await loaded();

    const section = screen.getByRole("heading", { level: 2, name: "How to fix" }).parentElement!;
    expect(section).toHaveTextContent("No known fix.");
    expect(section).toHaveTextContent("gave no location, so start from the rule or advisory");
  });

  it("shows a real fix of another kind as text with its detail", async () => {
    finding = makeFinding({
      suggestion: {
        action: "rotate",
        target: "the exposed token",
        detail: "Revoke it at the provider first.",
        confidence: "medium",
        fallback: false,
      },
    });
    renderDetail();
    await loaded();

    expect(screen.getByText("Rotate the exposed token")).toBeInTheDocument();
    expect(screen.getByText("Revoke it at the provider first.")).toBeInTheDocument();
  });

  it("shows the scanner's own summary and links its reference", async () => {
    finding = makeFinding({
      remediation: {
        summary: "Use a parameterised query",
        url: "https://example.com/rule",
        source: "semgrep",
      },
    });
    renderDetail();
    await loaded();

    expect(screen.getByText("Use a parameterised query")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Remediation reference" })).toHaveAttribute(
      "href",
      "https://example.com/rule",
    );
  });
});

describe("FindingDetail rows without a value", () => {
  it("drops the date rows instead of printing None", async () => {
    finding = makeFinding({ first_seen_at: "not-a-date" });
    renderDetail();
    await loaded();
    await openDetails();

    const about = screen.getByRole("heading", { level: 2, name: "About this finding" })
      .parentElement!;
    expect(within(about).queryByText("First seen")).not.toBeInTheDocument();
    expect(within(about).getByText("Last seen")).toBeInTheDocument();
    expect(within(about).queryByText("None")).not.toBeInTheDocument();
  });

  it("drops them in decide-first mode as well", async () => {
    finding = makeFinding({ first_seen_at: "not-a-date", last_seen_at: "" });
    renderDetail("");
    await loaded();

    const about = screen.getByRole("complementary", { name: "About this finding" });
    expect(within(about).queryByText("First seen")).not.toBeInTheDocument();
    expect(within(about).queryByText("Last seen")).not.toBeInTheDocument();
    expect(within(about).queryByText("None")).not.toBeInTheDocument();
  });

  it("leaves out context rows the scan did not fill", async () => {
    finding = makeFinding({ context: { branch: "main", target_name: "", environment_name: "" } });
    renderDetail("");
    await loaded();

    expect(screen.getByText("Branch")).toBeInTheDocument();
    expect(screen.queryByText("Target")).not.toBeInTheDocument();
    expect(screen.queryByText("Environment")).not.toBeInTheDocument();
  });
});

describe("FindingDetail CVE block", () => {
  const WITHOUT_INTEL = ["sast", "iac", "secret", "dast", "license"];
  const WITH_CVE = ["sca", "image_config", "cve_watcher"];

  it.each(WITH_CVE)("asks for CVE details on a %s finding in decide-first mode", async (kind) => {
    finding = makeFinding({ finding_kind: kind });
    renderDetail("");
    await loaded();

    await waitFor(() => expect(paths).toContain("/api/v1/findings/f1/cve"));
  });

  it.each(WITHOUT_INTEL)("shows no CVE block and asks for none on a %s finding", async (kind) => {
    finding = makeFinding({ finding_kind: kind });
    renderDetail("");
    await loaded();
    // Everything the page asks for on load has been asked by the time the project has answered.
    await screen.findByRole("button", { name: "Request waiver" });

    expect(paths).not.toContain("/api/v1/findings/f1/cve");
    expect(screen.queryByRole("heading", { name: "CVE details" })).not.toBeInTheDocument();
  });

  it("shows the block for any kind once intel data is present", async () => {
    finding = makeFinding({
      finding_kind: "sast",
      intel: {
        cve_id: "CVE-2024-3094",
        epss: 0.5,
        kev: false,
        sources: ["epss"],
        fetched_at: "2026-10-15T00:00:00Z",
      },
    });
    renderDetail("");
    await loaded();

    await waitFor(() => expect(paths).toContain("/api/v1/findings/f1/cve"));
  });

  it("renders the loaded CVE block inside the details in fix-first mode", async () => {
    finding = makeFinding({ finding_kind: "sca" });
    const detail = completeReport();
    const base = globalThis.fetch;
    globalThis.fetch = vi.fn().mockImplementation(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        if (new URL(String(input), "http://localhost").pathname.endsWith("/cve")) {
          return jsonResponse(detail);
        }
        return (base as typeof fetch)(input, init);
      },
    );
    renderDetail();
    await loaded();

    expect(screen.queryByRole("heading", { name: "CVE details" })).not.toBeInTheDocument();
    await openDetails();
    expect(await screen.findByRole("heading", { name: "CVE details" })).toBeInTheDocument();
  });

  it("does not ask for CVE details of a fix-first sast finding even after opening the details", async () => {
    renderDetail();
    await loaded();
    await openDetails();
    await screen.findByRole("heading", { name: "History" });

    expect(paths).not.toContain("/api/v1/findings/f1/cve");
  });
});

describe("FindingDetail decide-first order", () => {
  it("leads with the decision and keeps the sections unfolded", async () => {
    finding = makeFinding({ finding_kind: "sca", context: { branch: "main" } });
    renderDetail("");
    await loaded();
    await screen.findByRole("heading", { name: "History" });

    const names = sectionNames();
    const order = [
      "Why this blocks",
      "Decide",
      "How to fix",
      "Where it occurs",
      "Context",
      "History",
    ];
    expect(names.filter((name) => order.includes(name))).toEqual(order);
    expect(screen.queryByRole("button", { name: /^Details/ })).not.toBeInTheDocument();

    const decide = screen.getByRole("heading", { level: 2, name: "Decide" }).parentElement!;
    expect(within(decide).getByRole("group", { name: /Can an attacker reach this code/ }))
      .toBeInTheDocument();
    expect(within(decide).getByRole("button", { name: "Request waiver" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check if it is fixed" })).toBeInTheDocument();

    const aside = screen.getByRole("complementary", { name: "About this finding" });
    expect(within(aside).getByText("Fingerprint")).toBeInTheDocument();
  });

  it("keeps the generic guidance block of the old How to fix section", async () => {
    finding = makeFinding({
      remediation: { summary: "No fix reported", fallback: true },
    });
    renderDetail("");
    await loaded();

    expect(screen.getByText(/General guidance/)).toBeInTheDocument();
    expect(screen.queryByText("No known fix.")).not.toBeInTheDocument();
  });
});

describe("FindingDetail null lists", () => {
  it("renders fix-first with null history, reachability, waivers and blockers", async () => {
    events = null;
    reachability = null;
    waivers = null;
    gate = { blocked_by: null, policy: { severity_floor: "high" } };
    renderDetail();
    await loaded();
    await openDetails();

    expect(await screen.findByText("No history yet.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Request waiver" })).toBeInTheDocument();
  });

  it("renders decide-first with the same null lists", async () => {
    events = null;
    reachability = null;
    waivers = null;
    gate = { blocked_by: null };
    renderDetail("");
    await loaded();

    expect(await screen.findByText("No history yet.")).toBeInTheDocument();
  });
});
