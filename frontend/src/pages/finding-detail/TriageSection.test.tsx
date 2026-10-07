import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { TriageSection } from "./TriageSection";

function renderTriageSection(projectSlug = "core-api") {
  const qc = createTestQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[`/${projectSlug}/findings/f1`]}>
        <Routes>
          <Route
            path="/:slug/findings/:findingId"
            element={<TriageSection findingId="f1" projectSlug={projectSlug} />}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("TriageSection RBAC permissions", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("enables triage controls for project manager", async () => {
    globalThis.fetch = vi.fn().mockImplementation(async (url) => {
      const u = String(url);
      if (u.endsWith("/api/v1/me")) {
        return jsonResponse({
          id: "u-mgr",
          email: "manager@example.corp",
          role: "member",
        });
      }
      if (u.includes("/members")) {
        return jsonResponse([
          {
            project_id: "p1",
            user_id: "u-mgr",
            role: "manager",
            created_at: "2026-09-01T00:00:00Z",
          },
        ]);
      }
      return jsonResponse({});
    });

    renderTriageSection();

    await waitFor(() => {
      const select = screen.getByLabelText("Triage action");
      expect(select).not.toBeDisabled();
      expect(
        screen.queryByText(/Requires Project Manager role to triage findings/),
      ).not.toBeInTheDocument();
    });
  });

  it("disables triage controls and shows notice for project member", async () => {
    globalThis.fetch = vi.fn().mockImplementation(async (url) => {
      const u = String(url);
      if (u.endsWith("/api/v1/me")) {
        return jsonResponse({
          id: "u-mem",
          email: "member@example.corp",
          role: "member",
        });
      }
      if (u.includes("/members")) {
        return jsonResponse([
          {
            project_id: "p1",
            user_id: "u-mem",
            role: "member",
            created_at: "2026-09-01T00:00:00Z",
          },
        ]);
      }
      return jsonResponse({});
    });

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
