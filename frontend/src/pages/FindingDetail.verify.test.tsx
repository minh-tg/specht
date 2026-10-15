const playCue = vi.hoisted(() => vi.fn());
vi.mock("@/lib/sound", () => ({ playCue }));

import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FindingDetail } from "./FindingDetail";

const BUTTON = "Check if it is fixed";

type Role = "member" | "manager";

let role: Role;
let finding: Record<string, unknown>;
let verifyBody: Record<string, unknown>;
let verifyGate: Promise<void> | null;
let verifyError: Response | null;
let requests: Array<{ path: string; method: string; }>;

function baseFinding(state: string): Record<string, unknown> {
  return {
    id: "f1",
    project_id: "p1",
    finding_kind: "sca",
    fingerprint: "fp1",
    current_title: "openssh-server: security issue",
    current_severity: "high",
    current_score: 7.5,
    state,
    triage_status: "untriaged",
    analysis_state: "unanalyzed",
    gate_effect: "block",
    first_seen_at: "2025-01-01T00:00:00Z",
    last_seen_at: "2025-01-02T00:00:00Z",
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
  };
}

beforeEach(() => {
  playCue.mockClear();
  role = "manager";
  finding = baseFinding("open");
  verifyBody = { finding_id: "f1", outcome: "still_present", detail: "" };
  verifyGate = null;
  verifyError = null;
  requests = [];
  globalThis.fetch = vi.fn().mockImplementation(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), "http://localhost");
      const method = (init?.method ?? "GET").toUpperCase();
      requests.push({ path: url.pathname, method });
      if (url.pathname === "/api/v1/findings/f1/verify" && method === "POST") {
        if (verifyGate) await verifyGate;
        if (verifyError) return verifyError;
        return jsonResponse(verifyBody);
      }
      if (url.pathname === "/api/v1/me") {
        return jsonResponse({ id: "u-1", email: "u@example.corp", role: "member" });
      }
      if (url.pathname.endsWith("/members")) {
        return jsonResponse([{
          project_id: "p1",
          user_id: "u-1",
          role,
          created_at: "2026-09-01T00:00:00Z",
        }]);
      }
      if (url.pathname.endsWith("/waivers")) return jsonResponse([]);
      if (url.pathname.endsWith("/gate")) {
        return jsonResponse({ blocked_by: [], policy: { severity_floor: "high" } });
      }
      if (url.pathname.endsWith("/events") || url.pathname.endsWith("/reachability")) {
        return jsonResponse([]);
      }
      if (url.pathname === "/api/v1/projects/payments") {
        return jsonResponse({
          id: "p1",
          slug: "payments",
          name: "payments",
          role,
          permissions: {},
        });
      }
      if (url.pathname === "/api/v1/findings/f1") return jsonResponse(finding);
      return jsonResponse({});
    },
  );
});

function renderDetail() {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <MemoryRouter initialEntries={["/payments/findings/f1"]}>
        <Routes>
          <Route path="/:slug/findings/:findingId" element={<FindingDetail />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function clickCheck() {
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: BUTTON }));
}

// The verdict region is the only status without a label; the evidence and sign-off sections
// render labelled loading regions with the same role.
function verdictStatus(): HTMLElement {
  const found = screen.getAllByRole("status").find((el) => !el.hasAttribute("aria-label"));
  if (!found) throw new Error("verdict status region not found");
  return found;
}

async function findVerdictStatus(): Promise<HTMLElement> {
  return await waitFor(() => verdictStatus());
}

describe("the finding page's fix check", () => {
  it("hides the check from a member who may not triage", async () => {
    role = "member";
    renderDetail();

    await screen.findByRole("heading", { name: "Decide" });
    await waitFor(() =>
      expect(requests.some((r) => r.path === "/api/v1/projects/payments")).toBe(true)
    );
    expect(screen.queryByRole("button", { name: BUTTON })).not.toBeInTheDocument();
  });

  it("shows the check to a project manager and keeps an empty status region in place", async () => {
    renderDetail();

    expect(await screen.findByRole("button", { name: BUTTON })).toBeEnabled();
    const status = verdictStatus();
    expect(status).toHaveTextContent("");
    expect(requests.some((r) => r.method === "POST")).toBe(false);
  });

  it("posts the check and shows a spinner state until the verdict arrives", async () => {
    let release!: () => void;
    verifyGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    renderDetail();
    await clickCheck();

    const pending = await screen.findByRole("button", { name: "Checking..." });
    expect(pending).toBeDisabled();
    expect(pending.querySelector(".animate-spin")).not.toBeNull();
    expect(verdictStatus()).toHaveTextContent("");

    release();
    expect(await screen.findByRole("button", { name: BUTTON })).toBeEnabled();
    expect(requests).toContainEqual({ path: "/api/v1/findings/f1/verify", method: "POST" });
  });

  it("reports a finding that is still present in the latest complete scan", async () => {
    verifyBody = { finding_id: "f1", outcome: "still_present", detail: "" };
    renderDetail();
    await clickCheck();

    const status = await findVerdictStatus();
    expect(status).toHaveTextContent("Still present in the latest complete scan.");
  });

  it("reports an inconclusive check with the server detail", async () => {
    verifyBody = {
      finding_id: "f1",
      outcome: "inconclusive",
      detail: "The newest scan of payments-api is partial.",
    };
    renderDetail();
    await clickCheck();

    const status = await findVerdictStatus();
    expect(status).toHaveTextContent(
      "Not conclusive: the newest scan cannot vouch for completeness.",
    );
    expect(within(status).getByText("The newest scan of payments-api is partial."))
      .toBeInTheDocument();
  });

  it("reports an inconclusive check without a detail line when the server sends none", async () => {
    verifyBody = { finding_id: "f1", outcome: "inconclusive", detail: "" };
    renderDetail();
    await clickCheck();

    const status = await findVerdictStatus();
    expect(status).toHaveTextContent(
      "Not conclusive: the newest scan cannot vouch for completeness.",
    );
    expect(status.textContent).toBe(
      "Not conclusive: the newest scan cannot vouch for completeness.",
    );
  });

  it("marks a verified fix and refetches the finding and its events", async () => {
    verifyBody = { finding_id: "f1", outcome: "verified_fixed", detail: "" };
    renderDetail();
    await screen.findByRole("heading", { name: "Decide" });
    const findingGetsBefore = requests.filter((r) => r.path === "/api/v1/findings/f1").length;
    const eventsBefore = requests.filter((r) => r.path.endsWith("/events")).length;

    finding = baseFinding("fixed");
    await clickCheck();

    expect(await findVerdictStatus()).toHaveTextContent(
      "Verified fixed. The finding is now marked fixed.",
    );
    await waitFor(() => {
      expect(requests.filter((r) => r.path === "/api/v1/findings/f1").length)
        .toBeGreaterThan(findingGetsBefore);
      expect(requests.filter((r) => r.path.endsWith("/events")).length).toBeGreaterThan(
        eventsBefore,
      );
    });
  });

  it("plays the pass cue for a verified fix only", async () => {
    verifyBody = { finding_id: "f1", outcome: "verified_fixed", detail: "" };
    renderDetail();
    await clickCheck();
    await findVerdictStatus();
    await waitFor(() => expect(playCue).toHaveBeenCalledExactlyOnceWith("pass"));
  });

  it.each(["still_present", "inconclusive"])("plays nothing for %s", async (outcome) => {
    verifyBody = { finding_id: "f1", outcome, detail: "" };
    renderDetail();
    await clickCheck();
    await waitFor(() => expect(verdictStatus().textContent).not.toBe(""));
    expect(playCue).not.toHaveBeenCalled();
  });

  it("does not refetch the finding after a still present verdict", async () => {
    renderDetail();
    await screen.findByRole("heading", { name: "Decide" });
    const findingGetsBefore = requests.filter((r) => r.path === "/api/v1/findings/f1").length;

    await clickCheck();
    await findVerdictStatus();
    expect(requests.filter((r) => r.path === "/api/v1/findings/f1").length).toBe(findingGetsBefore);
  });

  it("shows a failed check as an alert and re-enables the button", async () => {
    verifyError = jsonResponse(
      { error: { code: "forbidden", message: "Not allowed to verify." } },
      403,
    );
    renderDetail();
    await clickCheck();

    expect(await screen.findByText("Not allowed to verify.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: BUTTON })).toBeEnabled();
  });
});
