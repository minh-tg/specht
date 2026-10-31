import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FindingDetail } from "./FindingDetail";

const TITLE = "Test Vulnerability";

let finding: Record<string, unknown>;
let reachability: unknown;
let events: unknown;
let manager: boolean;
let requestWaiver: boolean;
let triageReply: () => Response;
let reachReply: () => Response;
let patches: Record<string, unknown>[];
let posts: Record<string, unknown>[];
/** Runs when a triage arrives, before its reply: lets a test change what the next read returns. */
let onPatch: () => void;

const failure = (status: number, code: string, message: string) =>
  jsonResponse({ error: { code, message } }, status);

beforeEach(() => {
  finding = {
    id: "f1",
    project_id: "p1",
    finding_kind: "sca",
    fingerprint: "fp1",
    current_title: TITLE,
    current_severity: "high",
    state: "open",
    analysis_state: "unanalyzed",
    gate_effect: "block",
    first_seen_at: "2025-01-01T00:00:00Z",
    last_seen_at: "2025-01-02T00:00:00Z",
  };
  reachability = [];
  events = [];
  manager = true;
  requestWaiver = true;
  patches = [];
  posts = [];
  onPatch = () => {};
  triageReply = () =>
    jsonResponse({ finding_id: "f1", analysis_state: "exploitable", gate_effect: "block" });
  reachReply = () => jsonResponse({ id: "r1", finding_id: "f1", state: "reachable" });
  globalThis.fetch = vi.fn().mockImplementation(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), "http://localhost");
      const method = (init?.method ?? "GET").toUpperCase();
      const body = init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : {};
      if (url.pathname === "/api/v1/me") {
        return jsonResponse({ id: "u-1", email: "u@example.corp", role: "member" });
      }
      if (url.pathname === "/api/v1/projects/p1") {
        return jsonResponse({
          id: "p1",
          slug: "p1",
          name: "p1",
          role: manager ? "manager" : "member",
          permissions: { triage: manager, request_waiver: requestWaiver },
        });
      }
      if (url.pathname.endsWith("/gate")) return jsonResponse({ blocked_by: ["f1"] });
      if (url.pathname.endsWith("/waivers")) return jsonResponse([]);
      if (url.pathname.endsWith("/events")) return jsonResponse(events);
      if (url.pathname.endsWith("/reachability")) {
        if (method === "POST") {
          posts.push(body);
          return reachReply();
        }
        return jsonResponse(reachability);
      }
      if (url.pathname === "/api/v1/findings/f1") {
        if (method === "PATCH") {
          patches.push(body);
          onPatch();
          return triageReply();
        }
        return jsonResponse(finding);
      }
      return jsonResponse([]);
    },
  );
});

function renderDetail() {
  render(
    <QueryClientProvider client={createTestQueryClient()}>
      <MemoryRouter initialEntries={["/p1/findings/f1"]}>
        <Routes>
          <Route path="/:slug/findings/:findingId" element={<FindingDetail />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function ready() {
  await screen.findByRole("heading", { name: TITLE });
  // The form is live once the role has loaded and the saved reachability answer is in.
  await screen.findByText(/Nobody has answered yet|Saved answer/);
}

const radio = (name: RegExp) => screen.getByRole("radio", { name });
const saveButton = () => screen.getByRole("button", { name: "Save decision" });
const liveRegion = () => document.querySelector("[role=status][aria-live=polite]")!;

describe("decide-first form for a project manager", () => {
  it("leads with three answers and keeps Save off until one is picked", async () => {
    renderDetail();
    await ready();

    const group = screen.getByRole("group", { name: "What is this finding?" });
    expect(within(group).getAllByRole("radio").map((r) => r.closest("label")!.textContent))
      .toEqual([
        expect.stringMatching(/^Real issue/),
        expect.stringMatching(/^Not a problem/),
        expect.stringMatching(/^Accept for now/),
      ]);
    expect(saveButton()).toBeDisabled();
    expect(screen.getByText("Pick one of the three first.")).toBeInTheDocument();
  });

  it("records a real issue as exploitable and sends the state it saw", async () => {
    const user = userEvent.setup();
    renderDetail();
    await ready();

    await user.click(radio(/^Real issue/));
    await user.click(saveButton());

    await waitFor(() => expect(patches).toHaveLength(1));
    expect(patches[0]).toMatchObject({
      analysis_state: "exploitable",
      expected_state: "unanalyzed",
    });
    expect(posts).toHaveLength(0);
    await waitFor(() => expect(liveRegion()).toHaveTextContent("Decision saved: Exploitable."));
  });

  it("needs a reason for not a problem and records the chosen kind", async () => {
    const user = userEvent.setup();
    renderDetail();
    await ready();

    await user.click(radio(/^Not a problem/));
    await user.click(radio(/^The code is not affected/));
    expect(saveButton()).toBeDisabled();
    expect(screen.getByText("Add a reason to save.")).toBeInTheDocument();
    await user.type(screen.getByLabelText(/^Reason/), "only used in tests");
    await user.click(saveButton());

    await waitFor(() => expect(patches).toHaveLength(1));
    expect(patches[0]).toMatchObject({
      analysis_state: "not_affected",
      reason: "only used in tests",
    });
  });

  it("accepts for a number of days with an expiry at the end of that local day", async () => {
    const user = userEvent.setup();
    renderDetail();
    await ready();

    await user.click(radio(/^Accept for now/));
    await user.click(radio(/\(1 year\)/));
    await user.type(screen.getByLabelText(/^Reason/), "vendor fix due next year");
    await user.click(saveButton());

    await waitFor(() => expect(patches).toHaveLength(1));
    const expiry = new Date();
    expiry.setDate(expiry.getDate() + 365);
    expiry.setHours(23, 59, 59, 999);
    expect(patches[0]).toMatchObject({
      analysis_state: "wont_fix",
      analysis_expires_at: expiry.toISOString(),
    });
  });

  it("turns off the reachability answers that would stop a real issue from counting", async () => {
    reachability = [{
      id: "r0",
      finding_id: "f1",
      state: "not_reachable",
      updated_at: "2025-01-03T00:00:00Z",
    }];
    const user = userEvent.setup();
    renderDetail();
    await ready();
    expect(radio(/^No$/)).toBeChecked();

    await user.click(radio(/^Real issue/));
    expect(radio(/^No$/)).toBeDisabled();
    expect(radio(/^Does not apply$/)).toBeDisabled();
    expect(radio(/^Not assessed$/)).toBeChecked();
    await user.click(saveButton());

    // Both parts go: the decision, and the answer moved off "No".
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0]).toMatchObject({ state: "unknown" });
    expect(patches).toHaveLength(1);
  });

  it("saves a reachability answer alone, with the reason as its evidence", async () => {
    const user = userEvent.setup();
    renderDetail();
    await ready();

    await user.click(radio(/^Does not apply$/));
    expect(saveButton()).toBeDisabled();
    await user.type(screen.getByLabelText(/^Reason/), "the endpoint is disabled");
    await user.click(saveButton());

    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0]).toEqual({ state: "not_applicable", evidence: "the endpoint is disabled" });
    expect(patches).toHaveLength(0);
  });

  it("moves a finding back to in triage from Other states", async () => {
    const user = userEvent.setup();
    renderDetail();
    await ready();

    await user.click(screen.getByText("Other states"));
    await user.click(screen.getByRole("button", { name: "Mark as in triage" }));
    await waitFor(() => expect(patches).toHaveLength(1));
    expect(patches[0]).toMatchObject({ analysis_state: "in_triage", reason: "" });
  });
});

describe("decide-first form for someone who may not triage", () => {
  /** The visible note above the form; the disabled buttons repeat it for screen readers. */
  const lockedNote = () =>
    screen.findByText(/Only project managers can record a triage decision\./, { selector: "p" });

  it("shows the answers disabled with the reason, and still offers a waiver request", async () => {
    manager = false;
    renderDetail();
    await ready();

    const reason = await lockedNote();
    expect(reason).toHaveTextContent("You can still request a waiver.");
    const group = screen.getByRole("group", { name: "What is this finding?" });
    expect(group).toBeDisabled();
    expect(group).toHaveAccessibleDescription(reason.textContent!);
    for (const answer of within(group).getAllByRole("radio")) expect(answer).toBeDisabled();
    expect(screen.getByRole("group", { name: /Can an attacker reach this code/ })).toBeDisabled();
    expect(saveButton()).toBeDisabled();
    expect(saveButton().parentElement).toHaveTextContent(
      "Only project managers can record a triage decision.",
    );
    expect(screen.getByRole("button", { name: "Request waiver" })).toBeEnabled();
  });

  it("does not promise a waiver request to someone who may not make one", async () => {
    manager = false;
    requestWaiver = false;
    renderDetail();
    await ready();

    expect(await lockedNote()).toHaveTextContent(
      "Only project managers can record a triage decision.",
    );
    expect(screen.queryByText(/You can still request a waiver/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Request waiver" })).toBeDisabled();
  });
});

describe("decide-first form when one of the two saves fails", () => {
  async function pickBoth(user: ReturnType<typeof userEvent.setup>) {
    await user.click(radio(/^Not a problem/));
    await user.click(radio(/^Yes$/));
    await user.type(screen.getByLabelText(/^Reason/), "checked the call graph");
    await user.click(saveButton());
  }

  it("says the decision saved, keeps the reachability input and retries only that part", async () => {
    reachReply = () => failure(500, "internal_error", "could not update reachability state");
    const user = userEvent.setup();
    renderDetail();
    await ready();
    await pickBoth(user);

    const results = await screen.findByRole("list", { name: "Save results" });
    await waitFor(() => expect(results).toHaveTextContent("Decision saved: False positive."));
    expect(results).toHaveTextContent(
      "Reachability not saved: could not update reachability state",
    );
    expect(liveRegion()).toHaveTextContent(
      "Decision saved: False positive. Reachability not saved: could not update reachability state",
    );
    // The saved part is not undone, and the failed part keeps its input.
    expect(radio(/^Not a problem/)).not.toBeChecked();
    expect(radio(/^Yes$/)).toBeChecked();
    expect(screen.getByLabelText(/^Reason/)).toHaveValue("checked the call graph");
    expect(within(results).queryByRole("button", { name: "Retry the decision" }))
      .not.toBeInTheDocument();

    reachReply = () => jsonResponse({ id: "r1", finding_id: "f1", state: "reachable" });
    await user.click(within(results).getByRole("button", { name: "Retry reachability" }));
    await waitFor(() => expect(results).toHaveTextContent("Reachability saved: Yes."));
    expect(results).toHaveTextContent("Decision saved: False positive.");
    expect(patches).toHaveLength(1);
    expect(posts).toHaveLength(2);
    expect(posts[1]).toEqual({ state: "reachable", evidence: "checked the call graph" });
  });

  it("says reachability saved, keeps the decision input and retries only the decision", async () => {
    triageReply = () => failure(500, "triage_failed", "could not update finding analysis state");
    const user = userEvent.setup();
    renderDetail();
    await ready();
    await pickBoth(user);

    const results = await screen.findByRole("list", { name: "Save results" });
    await waitFor(() => expect(results).toHaveTextContent("Reachability saved: Yes."));
    expect(results).toHaveTextContent(
      "Decision not saved: could not update finding analysis state",
    );
    expect(radio(/^Not a problem/)).toBeChecked();
    expect(radio(/^The scanner is wrong/)).toBeChecked();
    expect(screen.getByLabelText(/^Reason/)).toHaveValue("checked the call graph");

    triageReply = () =>
      jsonResponse({ finding_id: "f1", analysis_state: "false_positive", gate_effect: "ignore" });
    await user.click(within(results).getByRole("button", { name: "Retry the decision" }));
    await waitFor(() => expect(results).toHaveTextContent("Decision saved: False positive."));
    expect(patches).toHaveLength(2);
    expect(posts).toHaveLength(1);
    expect(patches[1]).toMatchObject({
      analysis_state: "false_positive",
      reason: "checked the call graph",
    });
  });
});

describe("decide-first form when someone else triaged first", () => {
  it("reloads, shows what changed and who did it, and re-applies on top of the new state", async () => {
    triageReply = () =>
      failure(
        409,
        "analysis_conflict",
        "The finding was triaged by someone else since you loaded it.",
      );
    onPatch = () => {
      finding = { ...finding, analysis_state: "in_triage", analysis_reason: "looking into it" };
      events = [{
        id: "e1",
        finding_id: "f1",
        user_id: "u-2",
        user_name: "Dana",
        event_type: "analysis_changed",
        old_value: "unanalyzed",
        new_value: "in_triage",
        created_at: "2026-10-30T10:00:00Z",
      }];
    };
    const user = userEvent.setup();
    renderDetail();
    await ready();

    await user.click(radio(/^Real issue/));
    await user.click(saveButton());

    expect(await screen.findByText("Someone else triaged this finding since you opened it."))
      .toBeInTheDocument();
    const saw = await screen.findByText("You saw");
    expect(saw.nextElementSibling).toHaveTextContent("Not triaged");
    const now = screen.getByText("Now").nextElementSibling!;
    await waitFor(() => expect(now).toHaveTextContent("In triage"));
    expect(now).toHaveTextContent("looking into it");
    await waitFor(() => expect(now).toHaveTextContent("by Dana"));
    expect(liveRegion()).toHaveTextContent("Decision not saved: someone else triaged");
    // The person's choice is still there.
    expect(radio(/^Real issue/)).toBeChecked();

    onPatch = () => {};
    triageReply = () =>
      jsonResponse({ finding_id: "f1", analysis_state: "exploitable", gate_effect: "block" });
    await user.click(screen.getByRole("button", { name: "Save mine on top" }));

    await waitFor(() => expect(patches).toHaveLength(2));
    expect(patches[0]).toMatchObject({ expected_state: "unanalyzed" });
    expect(patches[1]).toMatchObject({
      analysis_state: "exploitable",
      expected_state: "in_triage",
    });
    await waitFor(() =>
      expect(screen.queryByText("Someone else triaged this finding since you opened it."))
        .not.toBeInTheDocument()
    );
  });

  it("drops the person's choice when they keep the other decision", async () => {
    triageReply = () => failure(409, "analysis_conflict", "changed");
    onPatch = () => {
      finding = { ...finding, analysis_state: "exploitable" };
    };
    const user = userEvent.setup();
    renderDetail();
    await ready();
    await user.click(radio(/^Real issue/));
    await user.click(saveButton());

    await user.click(await screen.findByRole("button", { name: "Keep theirs" }));
    expect(radio(/^Real issue/)).not.toBeChecked();
    expect(screen.queryByText("Someone else triaged this finding since you opened it."))
      .not.toBeInTheDocument();
    expect(patches).toHaveLength(1);
  });
});

describe("decide-first form with null lists", () => {
  it("treats a null reachability list and a null history as empty", async () => {
    reachability = null;
    events = null;
    renderDetail();
    await ready();

    expect(screen.getByText("Nobody has answered yet.")).toBeInTheDocument();
    expect(radio(/^Not assessed$/)).toBeChecked();
    expect(liveRegion()).toBeEmptyDOMElement();
  });
});
