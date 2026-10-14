import { chooseOption, createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SignoffSection } from "./SignoffSection";

const SIGNOFF = {
  id: "so-1",
  finding_id: "f1",
  status: "rejected",
  reviewed_by: "u-mgr",
  comment: "Needs the upgrade path first",
  created_at: "2026-10-02T10:00:00Z",
  updated_at: "2026-10-02T10:00:00Z",
};

interface MockOptions {
  role?: "manager" | "member";
  /** The sign-off the GET returns, or null for a 404. */
  signoff?: typeof SIGNOFF | null;
}

/**
 * Serves the sign-off endpoints from one mutable record, so a save is visible to
 * the refetch that follows it, as it is on the server.
 */
function mockApi({ role = "manager", signoff = null }: MockOptions = {}) {
  let current = signoff;
  const calls: Array<{ method: string; url: string; body?: unknown; }> = [];
  globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
    const u = String(url);
    const method = init?.method ?? "GET";
    calls.push({
      method,
      url: u,
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    });
    if (u.endsWith("/api/v1/me")) {
      return jsonResponse({ id: "u-mgr", email: "manager@example.corp", role: "member" });
    }
    if (u.includes("/members")) {
      return jsonResponse([
        {
          project_id: "p1",
          user_id: "u-mgr",
          role: role === "manager" ? "manager" : "member",
          created_at: "2026-09-01T00:00:00Z",
        },
      ]);
    }
    if (u.endsWith("/api/v1/findings/f1/signoff") && method === "GET") {
      if (current === null) return jsonResponse({ code: "not_found", message: "no signoff" }, 404);
      return jsonResponse(current);
    }
    if (u.endsWith("/api/v1/findings/f1/signoff") && method === "POST") {
      const body = JSON.parse(String(init?.body));
      current = { ...SIGNOFF, status: body.status, comment: body.comment ?? "" };
      return jsonResponse(current);
    }
    return jsonResponse({});
  });
  return calls;
}

function renderSignoffSection() {
  const qc = createTestQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/core-api/findings/f1"]}>
        <Routes>
          <Route
            path="/:slug/findings/:findingId"
            element={<SignoffSection findingId="f1" projectSlug="core-api" />}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("SignoffSection", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("treats a 404 from the read as no sign-off yet, not as an error", async () => {
    mockApi({ signoff: null });
    renderSignoffSection();

    expect(await screen.findByText("Not signed off yet.")).toBeInTheDocument();
    expect(screen.queryByText(/Could not load/)).not.toBeInTheDocument();
  });

  it("shows the saved decision, its note and who recorded it", async () => {
    mockApi({ signoff: SIGNOFF });
    renderSignoffSection();

    expect(await screen.findByText("Rejected", { selector: "dd" })).toBeInTheDocument();
    expect(screen.getByText("Needs the upgrade path first", { selector: "dd" }))
      .toBeInTheDocument();
    expect(screen.getByText(/by You/)).toBeInTheDocument();
  });

  it("saves the chosen decision and note, then shows the new decision", async () => {
    const calls = mockApi({ signoff: null });
    const user = userEvent.setup();
    renderSignoffSection();
    await screen.findByText("Not signed off yet.");

    await chooseOption(
      user,
      screen.getByRole("combobox", { name: "Sign-off decision" }),
      "Approved",
    );
    await user.type(screen.getByLabelText("Note"), "Verified the upgrade path.");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => {
      const post = calls.find((c) => c.method === "POST");
      expect(post?.url).toMatch(/\/api\/v1\/findings\/f1\/signoff$/);
      expect(post?.body).toEqual({ status: "approved", comment: "Verified the upgrade path." });
    });
    expect(await screen.findByText("Approved", { selector: "dd" })).toBeInTheDocument();
  });

  it("hides the form from people who cannot triage", async () => {
    mockApi({ role: "member", signoff: SIGNOFF });
    renderSignoffSection();

    expect(await screen.findByText("Rejected", { selector: "dd" })).toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: "Sign-off decision" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save" })).not.toBeInTheDocument();
  });
});
