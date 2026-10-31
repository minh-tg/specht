import { Toaster } from "@/components/ui/sonner";
import type { AnalysisState } from "@/lib/enums";
import { chooseOption, createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { TriageSection } from "./TriageSection";

const playCue = vi.hoisted(() => vi.fn());
vi.mock("@/lib/sound", () => ({ playCue }));

function renderTriageSection(projectSlug = "core-api", currentState?: AnalysisState) {
  const qc = createTestQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[`/${projectSlug}/findings/f1`]}>
        <Routes>
          <Route
            path="/:slug/findings/:findingId"
            element={
              <TriageSection
                findingId="f1"
                projectSlug={projectSlug}
                currentState={currentState}
              />
            }
          />
        </Routes>
      </MemoryRouter>
      <Toaster />
    </QueryClientProvider>,
  );
}

interface Call {
  method: string;
  url: string;
  body?: unknown;
}

const UNDO_URL = "/api/v1/findings/f1/analysis/undo";

/**
 * Serves the person, the project with the role the server computed for them, a triage write that
 * names its event, and the undo of that event, which the server may refuse.
 */
function mockApi(
  projectRole: "manager" | "member" | "none",
  undoRefusal?: { code: string; message: string; },
): Call[] {
  const calls: Call[] = [];
  globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
    const u = String(url);
    const method = init?.method ?? "GET";
    calls.push({ method, url: u, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    if (u.endsWith("/api/v1/me")) {
      return jsonResponse({ id: "u-1", email: "person@example.corp", role: "member" });
    }
    if (u.endsWith("/api/v1/projects/core-api")) {
      const manager = projectRole === "manager";
      return jsonResponse({
        id: "p1",
        slug: "core-api",
        name: "core-api",
        role: projectRole,
        permissions: {
          triage: manager,
          manage_members: manager,
          request_waiver: projectRole !== "none",
        },
      });
    }
    if (u.endsWith("/api/v1/findings/f1") && method === "PATCH") {
      return jsonResponse({
        finding_id: "f1",
        analysis_state: "exploitable",
        gate_effect: "block",
        event_id: "e1",
      });
    }
    if (u.endsWith(UNDO_URL) && method === "POST") {
      if (undoRefusal) return jsonResponse({ error: undoRefusal }, 409);
      return jsonResponse({
        finding_id: "f1",
        analysis_state: "in_triage",
        gate_effect: "block",
        event_id: "e2",
      });
    }
    return jsonResponse({});
  });
  return calls;
}

describe("TriageSection RBAC permissions", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("enables triage controls for a project manager, once the role has loaded", async () => {
    const calls = mockApi("manager");

    renderTriageSection();

    await waitFor(() =>
      expect(calls.some((c) => c.url.endsWith("/api/v1/projects/core-api"))).toBe(true)
    );
    await act(async () => {});
    expect(screen.getByLabelText("Triage action")).not.toBeDisabled();
    expect(screen.queryByText(/Only project managers can record a triage decision/))
      .not.toBeInTheDocument();
  });

  it("does not submit a past expiry", async () => {
    const calls = mockApi("manager");
    const user = userEvent.setup();
    renderTriageSection();
    await waitFor(() => expect(screen.getByLabelText("Triage action")).not.toBeDisabled());
    await chooseOption(user, screen.getByLabelText("Triage action"), "Accepted risk");
    await user.type(screen.getByLabelText("Reason"), "Temporary exception");
    const expiry = screen.getByLabelText("Expiry date");
    expect(expiry).toHaveAttribute("min", new Date().toISOString().slice(0, 10));
    fireEvent.change(expiry, { target: { value: "2000-01-01" } });
    expect(screen.getByRole("button", { name: "Apply" })).toBeDisabled();
    expect(calls.some((c) => c.method === "PATCH")).toBe(false);
    fireEvent.change(expiry, { target: { value: "2099-01-01" } });
    expect(screen.getByRole("button", { name: "Apply" })).not.toBeDisabled();
  });

  it("disables triage for a member, says why, and does not call waivers manager-only", async () => {
    mockApi("member");

    renderTriageSection();

    const note = await screen.findByText(/You can still request a waiver\./);
    expect(note).toHaveTextContent(
      "Only project managers can record a triage decision. You can still request a waiver.",
    );
    expect(screen.getByLabelText("Triage action")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Apply" })).toBeDisabled();
    // The reason also sits next to the disabled control for keyboard and screen reader users.
    expect(screen.getByRole("button", { name: "Apply" }).parentElement)
      .toHaveTextContent("Only project managers can record a triage decision.");
    expect(document.body).not.toHaveTextContent(/Project Manager role/);
    expect(document.body).not.toHaveTextContent(/or request waivers/);
  });

  it("does not promise a waiver request to someone who may not make one", async () => {
    mockApi("none");

    renderTriageSection();

    await waitFor(() => expect(screen.getByLabelText("Triage action")).toBeDisabled());
    expect(await screen.findAllByText(/Only project managers can record a triage decision\./))
      .not.toHaveLength(0);
    expect(screen.queryByText(/request a waiver/)).not.toBeInTheDocument();
  });
});

describe("TriageSection undecided states", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it.each([
    ["Not triaged", "unanalyzed"],
    ["In triage", "in_triage"],
  ])(
    "takes a finding back to %s without asking for a reason or an expiry",
    async (label, state) => {
      const calls = mockApi("manager");
      const user = userEvent.setup();
      renderTriageSection();

      await waitFor(() => expect(screen.getByLabelText("Triage action")).not.toBeDisabled());
      await chooseOption(user, screen.getByLabelText("Triage action"), label);
      expect(screen.queryByLabelText("Reason")).not.toBeInTheDocument();
      expect(screen.queryByLabelText("Expiry date")).not.toBeInTheDocument();
      await user.click(screen.getByRole("button", { name: "Apply" }));

      await waitFor(() => {
        const patch = calls.find((c) => c.method === "PATCH");
        expect(patch).toBeDefined();
        expect(patch?.body).toMatchObject({ analysis_state: state });
      });
    },
  );
});

describe("TriageSection undo", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    playCue.mockClear();
  });

  async function triageTo(label: string) {
    const user = userEvent.setup();
    await waitFor(() => expect(screen.getByLabelText("Triage action")).not.toBeDisabled());
    await chooseOption(user, screen.getByLabelText("Triage action"), label);
    await user.click(screen.getByRole("button", { name: "Apply" }));
    return user;
  }

  it("asks the server to undo the triage event, and cues once per success", async () => {
    const calls = mockApi("manager");
    renderTriageSection("core-api", "in_triage");

    const user = await triageTo("Exploitable");
    await user.click(await screen.findByRole("button", { name: "Undo" }));

    expect(await screen.findByText("Triage restored to In triage")).toBeInTheDocument();
    expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(1);
    const undo = calls.filter((c) => c.url.endsWith(UNDO_URL));
    expect(undo).toHaveLength(1);
    expect(undo[0]).toMatchObject({ method: "POST", body: { event_id: "e1" } });
    // One cue for the triage, one for the undo's own confirmation, none for a hidden second toast.
    expect(playCue.mock.calls).toEqual([["accepted"], ["accepted"]]);
  });

  it.each(["unanalyzed", "accepted_risk", "wont_fix", "false_positive"] as const)(
    "offers Undo when the previous state was %s, reason and expiry included",
    async (previous) => {
      mockApi("manager");
      renderTriageSection("core-api", previous);

      await triageTo("Exploitable");

      expect(await screen.findByRole("button", { name: "Undo" })).toBeInTheDocument();
    },
  );

  it("shows the server's message and cues an error when the undo is refused", async () => {
    const message =
      "This is no longer the latest triage change on the finding, so it cannot be undone.";
    const calls = mockApi("manager", { code: "analysis_conflict", message });
    renderTriageSection("core-api", "in_triage");

    const user = await triageTo("Exploitable");
    await user.click(await screen.findByRole("button", { name: "Undo" }));

    expect(await screen.findByText(message)).toBeInTheDocument();
    expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(1);
    expect(playCue).toHaveBeenLastCalledWith("error");
  });
});
