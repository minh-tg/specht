import { AuthContext, type AuthContextValue } from "@/auth/context";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { TeamsDirectory } from "./TeamsDirectory";

const authCtx: AuthContextValue = {
  token: "test-token",
  userId: "u1",
  email: "admin@acme.corp",
  login: async () => {},
  logout: () => {},
  loading: false,
};

function renderTeamsDirectory() {
  const qc = createTestQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <AuthContext.Provider value={authCtx}>
        <MemoryRouter>
          <TeamsDirectory />
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

describe("TeamsDirectory", () => {
  let userRole = "admin";
  let mockTeams: {
    id: string;
    name: string;
    description: string | null;
    created_at: string;
    updated_at: string;
  }[] = [];
  let fetchCalls: { url: string; method: string; body?: string; }[] = [];

  beforeEach(() => {
    fetchCalls = [];
    userRole = "admin";
    mockTeams = [
      {
        id: "t1",
        name: "Security Operations",
        description: "AppSec and vulnerability governance",
        created_at: "2026-09-01T00:00:00Z",
        updated_at: "2026-09-01T00:00:00Z",
      },
      {
        id: "t2",
        name: "Backend Platform",
        description: "Core backend engineering",
        created_at: "2026-09-10T00:00:00Z",
        updated_at: "2026-09-10T00:00:00Z",
      },
    ];

    globalThis.fetch = vi.fn().mockImplementation(async (url, opts) => {
      const u = String(url);
      const method = ((opts as RequestInit)?.method ?? "GET").toUpperCase();
      const body = (opts as RequestInit)?.body as string | undefined;
      fetchCalls.push({ url: u, method, body });

      if (u.endsWith("/api/v1/me")) {
        return jsonResponse({ id: "u1", email: "admin@acme.corp", role: userRole });
      }
      if (u.includes("/members") && u.includes("/teams/")) {
        if (method === "POST") return jsonResponse({ ok: true });
        if (method === "DELETE") return jsonResponse(null, 204);
        return jsonResponse([
          { team_id: "t1", user_id: "u1", created_at: "2026-09-01T00:00:00Z" },
        ]);
      }
      if (u.endsWith("/api/v1/teams")) {
        if (method === "POST") {
          const parsed = JSON.parse(body ?? "{}");
          return jsonResponse({
            id: "t-new",
            name: parsed.name,
            description: parsed.description ?? null,
            created_at: "2026-10-07T00:00:00Z",
            updated_at: "2026-10-07T00:00:00Z",
          });
        }
        return jsonResponse(mockTeams);
      }
      if (u.includes("/api/v1/teams/")) {
        if (method === "DELETE") return jsonResponse(null, 204);
      }
      if (u.includes("/api/v1/users")) {
        return jsonResponse([
          {
            id: "u1",
            email: "admin@acme.corp",
            display_name: "Admin User",
            role: "admin",
            created_at: "2026-09-01T00:00:00Z",
          },
        ]);
      }
      return jsonResponse({});
    });
  });

  it("renders teams directory with team cards", async () => {
    renderTeamsDirectory();

    await waitFor(() => {
      expect(screen.getByText("Company Teams")).toBeInTheDocument();
      expect(screen.getByText("Security Operations")).toBeInTheDocument();
      expect(screen.getByText("Backend Platform")).toBeInTheDocument();
    });
  });

  it("allows global admin to create a new company team", async () => {
    const user = userEvent.setup();
    renderTeamsDirectory();

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "+ Create Team" })).toBeInTheDocument();
    });

    await user.click(screen.getByRole("button", { name: "+ Create Team" }));
    expect(screen.getByRole("heading", { name: "Create Company Team" })).toBeInTheDocument();

    await user.type(screen.getByLabelText("Team Name"), "DevOps Champions");
    await user.type(screen.getByLabelText("Description"), "Infrastructure and automation");

    const submitBtn = screen.getByRole("button", { name: "Create Team" });
    await user.click(submitBtn);

    await waitFor(() => {
      const postCall = fetchCalls.find(
        (c) => c.url.endsWith("/api/v1/teams") && c.method === "POST",
      );
      expect(postCall).toBeDefined();
      expect(JSON.parse(postCall!.body!)).toEqual({
        name: "DevOps Champions",
        description: "Infrastructure and automation",
      });
    });
  });

  it("restricts team creation for non-global-admin users", async () => {
    userRole = "member";
    renderTeamsDirectory();

    await waitFor(() => {
      expect(
        screen.getByText("Global Admin required to create teams"),
      ).toBeInTheDocument();
    });

    expect(screen.queryByRole("button", { name: "+ Create Team" })).not.toBeInTheDocument();
  });
});
