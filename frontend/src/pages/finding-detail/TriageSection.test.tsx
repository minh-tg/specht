import { Toaster } from "@/components/ui/sonner";
import type { AnalysisState } from "@/lib/enums";
import { chooseOption, createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
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

/** Serves the person, the project with the role the server computed for them, and a triage write. */
function mockApi(projectRole: "manager" | "member", serverState = "exploitable"): Call[] {
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
        permissions: { triage: manager, manage_members: manager },
      });
    }
    if (u.endsWith("/api/v1/findings/f1") && method === "GET") {
      return jsonResponse({ id: "f1", analysis_state: serverState });
    }
    if (u.endsWith("/api/v1/findings/f1") && method === "PATCH") {
      return jsonResponse({ id: "f1", analysis_state: "unanalyzed" });
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
    expect(screen.queryByText(/Requires Project Manager role to triage findings/))
      .not.toBeInTheDocument();
  });

  it("disables triage controls and shows notice for project member", async () => {
    mockApi("member");

    renderTriageSection();

    await waitFor(() => {
      const select = screen.getByLabelText("Triage action");
      expect(select).toBeDisabled();
      expect(
        screen.getByText("Requires Project Manager role to triage findings or request waivers."),
      ).toBeInTheDocument();
    });

    const applyBtn = screen.getByRole("button", { name: "Apply" });
    expect(applyBtn).toBeDisabled();
    expect(applyBtn).toHaveAttribute("title", "Requires Project Manager role");
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

  it("puts a reasonless previous state back with a second PATCH, and cues once per success", async () => {
    const calls = mockApi("manager", "exploitable");
    renderTriageSection("core-api", "in_triage");

    const user = await triageTo("Exploitable");
    await user.click(await screen.findByRole("button", { name: "Undo" }));

    expect(await screen.findByText("Triage restored to In triage")).toBeInTheDocument();
    const patches = calls.filter((c) => c.method === "PATCH");
    expect(patches.map((c) => (c.body as { analysis_state: string; }).analysis_state)).toEqual([
      "exploitable",
      "in_triage",
    ]);
    // One cue for the triage, one for the undo's own confirmation, none for a hidden second toast.
    expect(playCue.mock.calls).toEqual([["accepted"], ["accepted"]]);
  });

  it("offers no Undo when the previous state needed a reason", async () => {
    mockApi("manager", "exploitable");
    renderTriageSection("core-api", "accepted_risk");

    await triageTo("Exploitable");

    expect(await screen.findByText(/Triage saved/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Undo" })).not.toBeInTheDocument();
  });

  it("shows an error and changes nothing when the finding moved on", async () => {
    const calls = mockApi("manager", "wont_fix");
    renderTriageSection("core-api", "in_triage");

    const user = await triageTo("Exploitable");
    await user.click(await screen.findByRole("button", { name: "Undo" }));

    expect(
      await screen.findByText(
        "This finding was triaged again in the meantime, so Undo did nothing.",
      ),
    ).toBeInTheDocument();
    expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(1);
    expect(playCue).toHaveBeenLastCalledWith("error");
  });
});
