import { AuthContext, type AuthContextValue } from "@/auth/context";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ProjectAccess } from "./ProjectAccess";

const authCtx: AuthContextValue = {
  token: "test-token",
  userId: "u1",
  email: "sarah@acme.corp",
  login: async () => {},
  logout: () => {},
  loading: false,
};

function renderProjectAccess(slug = "core-api") {
  const qc = createTestQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <AuthContext.Provider value={authCtx}>
        <MemoryRouter initialEntries={[`/${slug}/access`]}>
          <Routes>
            <Route path="/:slug/access" element={<ProjectAccess />} />
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

describe("ProjectAccess", () => {
  let mockMembers: { project_id: string; user_id: string; role: string; created_at: string; }[] =
    [];
  let mockTeams: { project_id: string; team_id: string; team_name: string; role: string; }[] = [];
  let userRole = "admin";
  let fetchCalls: { url: string; method: string; body?: string; }[] = [];
  let deleteError: { status: number; code: string; message: string; } | null = null;
  let addMemberError: { status: number; code: string; message: string; } | null = null;
  let membersLoadFailing = false;

  beforeEach(() => {
    fetchCalls = [];
    userRole = "admin";
    deleteError = null;
    addMemberError = null;
    membersLoadFailing = false;
    mockMembers = [
      { project_id: "p1", user_id: "u1", role: "admin", created_at: "2026-09-12T00:00:00Z" },
      { project_id: "p1", user_id: "u2", role: "manager", created_at: "2026-09-18T00:00:00Z" },
      { project_id: "p1", user_id: "u3", role: "member", created_at: "2026-10-02T00:00:00Z" },
    ];
    mockTeams = [
      { project_id: "p1", team_id: "t1", team_name: "Backend Platform", role: "manager" },
      { project_id: "p1", team_id: "t2", team_name: "Security Champions", role: "admin" },
    ];

    globalThis.fetch = vi.fn().mockImplementation(async (url, opts) => {
      const u = String(url);
      const method = ((opts as RequestInit)?.method ?? "GET").toUpperCase();
      const body = (opts as RequestInit)?.body as string | undefined;
      fetchCalls.push({ url: u, method, body });

      if (u.endsWith("/api/v1/me")) {
        return jsonResponse({ id: "u1", email: "sarah@acme.corp", role: userRole });
      }
      if (u.includes("/members")) {
        if (method === "POST") {
          return addMemberError
            ? jsonResponse(
              { error: { code: addMemberError.code, message: addMemberError.message } },
              addMemberError.status,
            )
            : jsonResponse({ ok: true }, 201);
        }
        if (method === "GET" && membersLoadFailing) {
          return jsonResponse(
            { error: { code: "internal", message: "database unavailable" } },
            500,
          );
        }
        if (method === "DELETE") {
          return deleteError
            ? jsonResponse(
              { error: { code: deleteError.code, message: deleteError.message } },
              deleteError.status,
            )
            : jsonResponse(null, 204);
        }
        return jsonResponse(mockMembers);
      }
      if (u.includes("/teams") && u.includes("/projects/")) {
        if (method === "POST") {
          return jsonResponse({ ok: true });
        }
        if (method === "DELETE") {
          return deleteError
            ? jsonResponse(
              { error: { code: deleteError.code, message: deleteError.message } },
              deleteError.status,
            )
            : jsonResponse(null, 204);
        }
        return jsonResponse(mockTeams);
      }
      if (u.endsWith("/api/v1/teams")) {
        return jsonResponse([
          {
            id: "t1",
            name: "Backend Platform",
            description: null,
            created_at: "2026-09-01T00:00:00Z",
            updated_at: "2026-09-01T00:00:00Z",
          },
          {
            id: "t2",
            name: "Security Champions",
            description: null,
            created_at: "2026-09-01T00:00:00Z",
            updated_at: "2026-09-01T00:00:00Z",
          },
          {
            id: "t3",
            name: "Quality Assurance",
            description: null,
            created_at: "2026-09-01T00:00:00Z",
            updated_at: "2026-09-01T00:00:00Z",
          },
        ]);
      }
      if (u.includes("/api/v1/users")) {
        return jsonResponse([
          {
            id: "u1",
            email: "sarah@acme.corp",
            display_name: "Sarah Chen",
            role: "admin",
            created_at: "2026-09-01T00:00:00Z",
          },
          {
            id: "u2",
            email: "alex@acme.corp",
            display_name: "Alex Rivera",
            role: "member",
            created_at: "2026-09-01T00:00:00Z",
          },
          {
            id: "u3",
            email: "jordan@acme.corp",
            display_name: "Jordan Lee",
            role: "member",
            created_at: "2026-09-01T00:00:00Z",
          },
        ]);
      }
      return jsonResponse({});
    });
  });

  it("renders members and teams roster with role badges", async () => {
    renderProjectAccess();

    await waitFor(() => {
      expect(screen.getByText("Direct Members")).toBeInTheDocument();
      expect(screen.getByText("Sarah Chen")).toBeInTheDocument();
      expect(screen.getByText("Alex Rivera")).toBeInTheDocument();
      expect(screen.getByText("Jordan Lee")).toBeInTheDocument();
      expect(screen.getByText("Backend Platform")).toBeInTheDocument();
      expect(screen.getByText("Security Champions")).toBeInTheDocument();
    });
  });

  it("guards the last project admin from deletion", async () => {
    renderProjectAccess();

    await waitFor(() => {
      expect(screen.getByText("Sarah Chen")).toBeInTheDocument();
    });

    const removeButtons = screen.getAllByRole("button", { name: "Remove" });
    // First remove button is for Sarah Chen (the only admin)
    expect(removeButtons[0]).toBeDisabled();
    expect(removeButtons[0]).toHaveAttribute("title", "Cannot remove the last project admin");

    // Second remove button is for Alex Rivera (manager), enabled for Admin
    expect(removeButtons[1]).not.toBeDisabled();
  });

  it("allows admin to add a new member with admin role", async () => {
    const user = userEvent.setup();
    renderProjectAccess();

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "+ Add Member" })).toBeInTheDocument();
    });

    await user.click(screen.getByRole("button", { name: "+ Add Member" }));
    expect(screen.getByRole("heading", { name: "Add Direct Member" })).toBeInTheDocument();

    await user.type(
      screen.getByLabelText("User ID"),
      "3f9c1d2e-6b7a-4c1e-9f0a-2d8e5b6c7a8f",
    );
    await user.selectOptions(screen.getByLabelText("Project Role"), "admin");

    const submitBtn = screen.getByRole("button", { name: "Add Member" });
    await user.click(submitBtn);

    await waitFor(() => {
      const postCall = fetchCalls.find(
        (c) => c.url.includes("/members") && c.method === "POST",
      );
      expect(postCall).toBeDefined();
      expect(JSON.parse(postCall!.body!)).toEqual({
        user_id: "3f9c1d2e-6b7a-4c1e-9f0a-2d8e5b6c7a8f",
        role: "admin",
      });
    });
  });

  it("closes the add-member dialog with Escape and returns focus to the button that opened it", async () => {
    const user = userEvent.setup();
    renderProjectAccess();

    const opener = await screen.findByRole("button", { name: "+ Add Member" });
    await user.click(opener);
    const dialog = await screen.findByRole("dialog", { name: "Add Direct Member" });
    expect(dialog).toContainElement(screen.getByLabelText("User ID"));

    await user.keyboard("{Escape}");
    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Add Direct Member" })).not.toBeInTheDocument();
    });
    expect(opener).toHaveFocus();
  });

  it("does not submit a member user ID that is not a UUID", async () => {
    const user = userEvent.setup();
    renderProjectAccess();

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "+ Add Member" })).toBeInTheDocument();
    });

    await user.click(screen.getByRole("button", { name: "+ Add Member" }));
    await user.type(screen.getByLabelText("User ID"), "newbie@acme.corp");
    await user.click(screen.getByRole("button", { name: "Add Member" }));

    expect(await screen.findByText(/User ID must be a UUID/)).toBeInTheDocument();
    expect(
      fetchCalls.some((c) => c.url.includes("/members") && c.method === "POST"),
    ).toBe(false);
  });

  it("shows the server message when the member user does not exist", async () => {
    const user = userEvent.setup();
    addMemberError = { status: 404, code: "user_not_found", message: "user not found" };
    renderProjectAccess();

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "+ Add Member" })).toBeInTheDocument();
    });

    await user.click(screen.getByRole("button", { name: "+ Add Member" }));
    await user.type(
      screen.getByLabelText("User ID"),
      "3f9c1d2e-6b7a-4c1e-9f0a-2d8e5b6c7a8f",
    );
    await user.click(screen.getByRole("button", { name: "Add Member" }));

    expect(await screen.findByText("user not found")).toBeInTheDocument();
  });

  it("enforces peer protection when actor is project manager", async () => {
    userRole = "member";
    mockMembers = [
      { project_id: "p1", user_id: "u1", role: "manager", created_at: "2026-09-12T00:00:00Z" },
      { project_id: "p1", user_id: "u2", role: "manager", created_at: "2026-09-18T00:00:00Z" },
      { project_id: "p1", user_id: "u3", role: "member", created_at: "2026-10-02T00:00:00Z" },
      { project_id: "p1", user_id: "u4", role: "admin", created_at: "2026-09-01T00:00:00Z" },
    ];

    renderProjectAccess();

    await waitFor(() => {
      expect(screen.getByText("Manager Authority:")).toBeInTheDocument();
    });

    const removeButtons = screen.getAllByRole("button", { name: "Remove" });
    // First button: u1 (fellow manager) -> disabled
    expect(removeButtons[0]).toBeDisabled();
    expect(removeButtons[0]).toHaveAttribute(
      "title",
      "Managers cannot modify fellow Managers or Admins",
    );

    // Second button: u2 (fellow manager) -> disabled
    expect(removeButtons[1]).toBeDisabled();

    // Third button: u3 (member) -> enabled
    expect(removeButtons[2]).not.toBeDisabled();

    // Fourth button: u4 (admin) -> disabled
    expect(removeButtons[3]).toBeDisabled();
  });

  it("says why removing a member failed, and clears the message on a successful retry", async () => {
    const user = userEvent.setup();
    deleteError = {
      status: 403,
      code: "project_access_denied",
      message: "project access denied",
    };
    renderProjectAccess();

    await waitFor(() => {
      expect(screen.getByText("Alex Rivera")).toBeInTheDocument();
    });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    // Second Remove button belongs to Alex Rivera (manager).
    await user.click(screen.getAllByRole("button", { name: "Remove" })[1]);
    expect(await screen.findByRole("alert")).toHaveTextContent("project access denied");

    deleteError = null;
    await user.click(screen.getAllByRole("button", { name: "Remove" })[1]);
    await waitFor(() => {
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    });
  });

  it("says why unlinking a team failed", async () => {
    const user = userEvent.setup();
    deleteError = {
      status: 403,
      code: "project_access_denied",
      message: "project access denied",
    };
    renderProjectAccess();

    await waitFor(() => {
      expect(screen.getByText("Backend Platform")).toBeInTheDocument();
    });

    await user.click(screen.getAllByRole("button", { name: "Unlink" })[0]);
    expect(await screen.findByRole("alert")).toHaveTextContent("project access denied");
  });

  it("hides management controls for member role", async () => {
    userRole = "member";
    mockMembers = [
      { project_id: "p1", user_id: "u1", role: "member", created_at: "2026-09-12T00:00:00Z" },
      { project_id: "p1", user_id: "u2", role: "admin", created_at: "2026-09-01T00:00:00Z" },
    ];

    renderProjectAccess();

    await waitFor(() => {
      expect(screen.getByText("Read-Only Member View:")).toBeInTheDocument();
    });

    expect(screen.queryByRole("button", { name: "+ Add Member" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "+ Link Team" })).not.toBeInTheDocument();
    expect(screen.getAllByText("View only").length).toBeGreaterThan(0);
  });

  it("shows a load error for members with a retry instead of an empty table", async () => {
    const user = userEvent.setup();
    membersLoadFailing = true;
    renderProjectAccess();

    expect(await screen.findByText("Could not load members.")).toBeInTheDocument();
    expect(screen.queryByText("No direct members granted yet.")).not.toBeInTheDocument();

    membersLoadFailing = false;
    await user.click(screen.getByRole("button", { name: "Retry" }));

    expect(await screen.findByText("Sarah Chen")).toBeInTheDocument();
    expect(screen.queryByText("Could not load members.")).not.toBeInTheDocument();
  });
});
