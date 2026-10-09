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
  let addMemberError: { status: number; code: string; message: string; } | null = null;

  beforeEach(() => {
    fetchCalls = [];
    userRole = "admin";
    addMemberError = null;
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
        if (method === "POST") {
          return addMemberError
            ? jsonResponse(
              { error: { code: addMemberError.code, message: addMemberError.message } },
              addMemberError.status,
            )
            : jsonResponse({ ok: true }, 201);
        }
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

  it("sends the user and the selected role when adding a roster member", async () => {
    const user = userEvent.setup();
    renderTeamsDirectory();

    await user.click((await screen.findAllByRole("button", { name: "Manage Roster" }))[0]);
    await user.type(
      screen.getByRole("textbox", { name: "User ID" }),
      "3f9c1d2e-6b7a-4c1e-9f0a-2d8e5b6c7a8f",
    );
    await user.selectOptions(screen.getByRole("combobox", { name: "Team role" }), "admin");
    await user.click(screen.getByRole("button", { name: "Add" }));

    await waitFor(() => {
      const postCall = fetchCalls.find(
        (c) => c.url.endsWith("/api/v1/teams/t1/members") && c.method === "POST",
      );
      expect(postCall).toBeDefined();
      expect(JSON.parse(postCall!.body!)).toEqual({
        user_id: "3f9c1d2e-6b7a-4c1e-9f0a-2d8e5b6c7a8f",
        role: "admin",
      });
    });
  });

  it("defaults the roster role to member", async () => {
    const user = userEvent.setup();
    renderTeamsDirectory();

    await user.click((await screen.findAllByRole("button", { name: "Manage Roster" }))[0]);
    expect(screen.getByRole("combobox", { name: "Team role" })).toHaveValue("member");

    await user.type(
      screen.getByRole("textbox", { name: "User ID" }),
      "3f9c1d2e-6b7a-4c1e-9f0a-2d8e5b6c7a8f",
    );
    await user.click(screen.getByRole("button", { name: "Add" }));

    await waitFor(() => {
      const postCall = fetchCalls.find(
        (c) => c.url.endsWith("/api/v1/teams/t1/members") && c.method === "POST",
      );
      expect(JSON.parse(postCall!.body!)).toEqual({
        user_id: "3f9c1d2e-6b7a-4c1e-9f0a-2d8e5b6c7a8f",
        role: "member",
      });
    });
  });

  it("does not submit a user ID that is not a UUID", async () => {
    const user = userEvent.setup();
    renderTeamsDirectory();

    await user.click((await screen.findAllByRole("button", { name: "Manage Roster" }))[0]);
    await user.type(screen.getByRole("textbox", { name: "User ID" }), "alex@acme.corp");
    await user.click(screen.getByRole("button", { name: "Add" }));

    expect(await screen.findByText(/User ID must be a UUID/)).toBeInTheDocument();
    expect(
      fetchCalls.some((c) => c.url.includes("/members") && c.method === "POST"),
    ).toBe(false);
  });

  it("shows the server message when the user does not exist", async () => {
    const user = userEvent.setup();
    addMemberError = { status: 404, code: "user_not_found", message: "user not found" };
    renderTeamsDirectory();

    await user.click((await screen.findAllByRole("button", { name: "Manage Roster" }))[0]);
    await user.type(
      screen.getByRole("textbox", { name: "User ID" }),
      "3f9c1d2e-6b7a-4c1e-9f0a-2d8e5b6c7a8f",
    );
    await user.click(screen.getByRole("button", { name: "Add" }));

    expect(await screen.findByText("user not found")).toBeInTheDocument();
  });
});
