import { AuthContext, type AuthContextValue } from "@/auth/context";
import { Toaster } from "@/components/ui/sonner";
import { chooseOption, createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ProjectAccess } from "./ProjectAccess";

const playCue = vi.hoisted(() => vi.fn());
vi.mock("@/lib/sound", () => ({ playCue }));

const authCtx: AuthContextValue = {
  token: "test-token",
  userId: "u1",
  email: "sarah@acme.corp",
  login: async () => {},
  logout: () => {},
  adopt: () => {},
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
      <Toaster />
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
  // When set, a member DELETE drops the member from the roster and a member POST adds one.
  let rosterFollowsWrites = false;
  // Sign-up closed, so suggestions are live in every test unless one opens it.
  let capabilities: object = {};

  beforeEach(() => {
    capabilities = { registration: { enabled: false } };
    fetchCalls = [];
    userRole = "admin";
    deleteError = null;
    addMemberError = null;
    membersLoadFailing = false;
    rosterFollowsWrites = false;
    playCue.mockClear();
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
      if (/\/api\/v1\/projects\/[^/]+$/.test(u) && method === "GET") {
        const own = mockMembers.find((m) => m.user_id === "u1");
        return jsonResponse({ id: "p1", slug: "my-app", name: "My App", role: own?.role });
      }
      if (u.endsWith("/api/v1/capabilities")) {
        return jsonResponse(capabilities);
      }
      if (u.includes("/member-suggestions")) {
        return jsonResponse([{
          user_id: "u9",
          email: "ada@acme.example",
          display_name: "Ada Lovelace",
        }]);
      }
      if (u.includes("/members")) {
        if (method === "POST") {
          if (!addMemberError && rosterFollowsWrites) {
            const grant = JSON.parse(body ?? "{}") as { user_id: string; role: string; };
            mockMembers.push({
              project_id: "p1",
              user_id: grant.user_id,
              role: grant.role,
              created_at: "2026-10-15T00:00:00Z",
            });
          }
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
          if (!deleteError && rosterFollowsWrites) {
            mockMembers = mockMembers.filter((m) => !u.endsWith(`/members/${m.user_id}`));
          }
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

  it("lists each member and team as a row with the role written out", async () => {
    renderProjectAccess();

    await screen.findByText("Sarah Chen");
    const members = screen.getByRole("list", { name: "Direct members" });
    const rows = within(members).getAllByRole("listitem");
    expect(rows).toHaveLength(3);
    expect(rows[0]).toHaveTextContent("Sarah Chen");
    expect(rows[0]).toHaveTextContent("sarah@acme.corp");
    expect(rows[0]).toHaveTextContent("admin");
    expect(rows[0]).toHaveTextContent(/^Sarah Chensarah@acme\.corpadminAdded /);

    const teams = screen.getByRole("list", { name: "Linked teams" });
    const teamRows = within(teams).getAllByRole("listitem");
    expect(teamRows).toHaveLength(2);
    expect(teamRows[1]).toHaveTextContent("Security Champions");
    expect(teamRows[1]).toHaveTextContent("admin");
  });

  it("names members from the roster, so a manager who cannot read the directory still sees who they are", async () => {
    userRole = "member";
    mockMembers = [
      {
        project_id: "p1",
        user_id: "u9",
        role: "manager",
        created_at: "2026-09-18T00:00:00Z",
        email: "lena@acme.corp",
        display_name: "Lena Brandt",
      },
      {
        project_id: "p1",
        user_id: "u8",
        role: "member",
        created_at: "2026-09-19T00:00:00Z",
        email: "tomas@acme.corp",
      },
      { project_id: "p1", user_id: "u7", role: "member", created_at: "2026-09-20T00:00:00Z" },
    ];
    renderProjectAccess();

    const members = await screen.findByRole("list", { name: "Direct members" });
    const rows = within(members).getAllByRole("listitem");
    expect(rows[0]).toHaveTextContent("Lena Brandt");
    expect(rows[0]).toHaveTextContent("lena@acme.corp");
    expect(rows[1]).toHaveTextContent("tomas@acme.corp");
    expect(rows[2]).toHaveTextContent("A team member");
    expect(members).not.toHaveTextContent("u7");
    expect(members).not.toHaveTextContent("u9");
  });

  it("says so in the list when nobody is granted yet", async () => {
    mockMembers = [];
    mockTeams = [];
    renderProjectAccess();

    expect(await screen.findByText("No direct members granted yet.")).toBeInTheDocument();
    expect(screen.getByText("No company teams linked to this project.")).toBeInTheDocument();
  });

  it("guards the last project admin from deletion", async () => {
    renderProjectAccess();

    await waitFor(() => {
      expect(screen.getByText("Sarah Chen")).toBeInTheDocument();
    });

    const removeButtons = screen.getAllByRole("button", { name: "Remove" });
    // First remove button is for Sarah Chen (the only admin)
    expect(removeButtons[0]).toBeDisabled();
    expect(removeButtons[0].parentElement).toHaveAttribute("tabindex", "0");
    expect(removeButtons[0].parentElement).toHaveTextContent(
      "Cannot remove the last project admin",
    );

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
      screen.getByLabelText("Email address"),
      "ada@acme.example",
    );
    await chooseOption(user, screen.getByLabelText("Project Role"), /^Admin: full project control/);

    const submitBtn = await screen.findByRole("button", { name: "Add Member" });
    await user.click(submitBtn);

    await waitFor(() => {
      const postCall = fetchCalls.find(
        (c) => c.url.includes("/members") && c.method === "POST",
      );
      expect(postCall).toBeDefined();
      expect(JSON.parse(postCall!.body!)).toEqual({
        email: "ada@acme.example",
        role: "admin",
      });
    });
  });

  it("suggests people while typing and adds the chosen person by email", async () => {
    capabilities = { registration: { enabled: false } };
    const user = userEvent.setup();
    renderProjectAccess();

    await user.click(await screen.findByRole("button", { name: "+ Add Member" }));
    await user.type(screen.getByLabelText("Email address"), "lov");
    const option = await screen.findByRole("option", { name: /ada@acme\.example/ });
    expect(option).toHaveTextContent("Ada Lovelace");
    expect(fetchCalls.filter((c) => c.url.includes("/member-suggestions")).map((c) => c.url))
      .toEqual([
        "/api/v1/projects/core-api/member-suggestions?q=lov",
      ]);

    await user.keyboard("{ArrowDown}{Enter}");
    expect(screen.getByLabelText("Email address")).toHaveValue("ada@acme.example");
    await user.click(screen.getByRole("button", { name: "Add Member" }));

    await waitFor(() => {
      const postCall = fetchCalls.find((c) => c.url.includes("/members") && c.method === "POST");
      expect(JSON.parse(postCall!.body!)).toEqual({ email: "ada@acme.example", role: "member" });
    });
  });

  it("asks for no suggestions while sign-up is open", async () => {
    capabilities = { registration: { enabled: true } };
    const user = userEvent.setup();
    renderProjectAccess();

    await user.click(await screen.findByRole("button", { name: "+ Add Member" }));
    await user.type(screen.getByLabelText("Email address"), "ada@acme");
    await new Promise((r) => setTimeout(r, 300));
    expect(fetchCalls.some((c) => c.url.includes("/member-suggestions"))).toBe(false);
    expect(screen.queryByRole("option")).not.toBeInTheDocument();
  });

  it("closes the add-member dialog with Escape and returns focus to the button that opened it", async () => {
    const user = userEvent.setup();
    renderProjectAccess();

    const opener = await screen.findByRole("button", { name: "+ Add Member" });
    await user.click(opener);
    const dialog = await screen.findByRole("dialog", { name: "Add Direct Member" });
    expect(dialog).toContainElement(screen.getByLabelText("Email address"));

    await user.keyboard("{Escape}");
    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Add Direct Member" })).not.toBeInTheDocument();
    });
    expect(opener).toHaveFocus();
  });

  it("confirms an added member with a toast", async () => {
    const user = userEvent.setup();
    renderProjectAccess();

    await user.click(await screen.findByRole("button", { name: "+ Add Member" }));
    await user.type(
      screen.getByLabelText("Email address"),
      "ada@acme.example",
    );
    await user.click(await screen.findByRole("button", { name: "Add Member" }));

    expect(await screen.findByText("Member added")).toBeInTheDocument();
  });

  it("does not submit an address that is not an email", async () => {
    const user = userEvent.setup();
    renderProjectAccess();

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "+ Add Member" })).toBeInTheDocument();
    });

    await user.click(screen.getByRole("button", { name: "+ Add Member" }));
    await user.type(screen.getByLabelText("Email address"), "newbie@acme");
    await user.click(await screen.findByRole("button", { name: "Add Member" }));

    expect(await screen.findByText(/Enter the person's email address/)).toBeInTheDocument();
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
      screen.getByLabelText("Email address"),
      "ada@acme.example",
    );
    await user.click(await screen.findByRole("button", { name: "Add Member" }));

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
    expect(removeButtons[0].parentElement).toHaveTextContent(
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
    await user.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Remove" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent("project access denied");

    deleteError = null;
    await user.click(screen.getAllByRole("button", { name: "Remove" })[1]);
    await user.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Remove" }),
    );
    await waitFor(() => {
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    });
  });

  it("asks before removing a member and sends nothing until the removal is confirmed", async () => {
    const user = userEvent.setup();
    renderProjectAccess();

    await waitFor(() => {
      expect(screen.getByText("Alex Rivera")).toBeInTheDocument();
    });
    const memberDeletes = () =>
      vi.mocked(globalThis.fetch).mock.calls.filter(
        ([url, opts]) => opts?.method === "DELETE" && String(url).includes("/members/"),
      );

    await user.click(screen.getAllByRole("button", { name: "Remove" })[1]);
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByRole("heading", { name: "Remove Alex Rivera?" }))
      .toBeInTheDocument();
    expect(dialog).toHaveTextContent("lose access to this project");
    expect(memberDeletes()).toHaveLength(0);

    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => {
      expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    });
    expect(memberDeletes()).toHaveLength(0);

    await user.click(screen.getAllByRole("button", { name: "Remove" })[1]);
    await user.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Remove" }),
    );
    await waitFor(() => {
      expect(memberDeletes()).toHaveLength(1);
    });
  });

  async function removeAlex(user: ReturnType<typeof userEvent.setup>) {
    await screen.findByText("Alex Rivera");
    await user.click(screen.getAllByRole("button", { name: "Remove" })[1]!);
    await user.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Remove" }),
    );
  }

  const memberWrites = (method: string) =>
    vi.mocked(globalThis.fetch).mock.calls.filter(
      ([url, opts]) => opts?.method === method && String(url).includes("/members"),
    );

  it("restores a removed member with the role they held when Undo is pressed, with one cue on Undo only", async () => {
    rosterFollowsWrites = true;
    const user = userEvent.setup();
    renderProjectAccess();

    await removeAlex(user);
    await waitFor(() => expect(screen.queryByText("Alex Rivera")).not.toBeInTheDocument());
    await user.click(await screen.findByRole("button", { name: "Undo" }));

    expect(await screen.findByText("Member restored")).toBeInTheDocument();
    expect(memberWrites("POST")).toHaveLength(1);
    expect(JSON.parse(String(memberWrites("POST")[0]![1]!.body))).toEqual({
      user_id: "u2",
      role: "manager",
    });
    expect(await screen.findByText("Alex Rivera")).toBeInTheDocument();
    // A removal or revocation is silent, so the only cue is the one the successful Undo plays.
    expect(playCue.mock.calls).toEqual([["accepted"]]);
  });

  it("refuses to restore a member who was added again meanwhile, and grants nothing", async () => {
    rosterFollowsWrites = true;
    const user = userEvent.setup();
    renderProjectAccess();

    await removeAlex(user);
    const undo = await screen.findByRole("button", { name: "Undo" });
    mockMembers.push({
      project_id: "p1",
      user_id: "u2",
      role: "member",
      created_at: "2026-10-15T00:00:00Z",
    });
    await user.click(undo);

    expect(await screen.findByText("They are a member again, so Undo did nothing."))
      .toBeInTheDocument();
    expect(memberWrites("POST")).toHaveLength(0);
    expect(playCue).toHaveBeenLastCalledWith("error");
  });

  it("offers no Undo when the person removed is the one signed in", async () => {
    rosterFollowsWrites = true;
    mockMembers[2]!.role = "admin";
    const user = userEvent.setup();
    renderProjectAccess();

    await screen.findByText("Sarah Chen");
    await user.click(screen.getAllByRole("button", { name: "Remove" })[0]!);
    await user.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Remove" }),
    );

    expect(await screen.findByText("Member removed")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Undo" })).not.toBeInTheDocument();
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

  it("offers invite links to people who may manage members", async () => {
    renderProjectAccess();

    expect(await screen.findByRole("heading", { name: "Invite links" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Invite people" })).toBeInTheDocument();
  });

  it("hides invite links from plain members, and never asks for them", async () => {
    userRole = "member";
    mockMembers = [
      { project_id: "p1", user_id: "u1", role: "member", created_at: "2026-09-12T00:00:00Z" },
      { project_id: "p1", user_id: "u2", role: "admin", created_at: "2026-09-01T00:00:00Z" },
    ];
    renderProjectAccess();

    await screen.findByText("Read-Only Member View:");
    expect(screen.queryByRole("heading", { name: "Invite links" })).not.toBeInTheDocument();
    expect(fetchCalls.some((c) => c.url.endsWith("/invites"))).toBe(false);
  });
});
