import { AuthContext, type AuthContextValue } from "@/auth/context";
import { chooseOption, createTestQueryClient, jsonResponse } from "@/test/utils";
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
  adopt: () => {},
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
  let removeMemberError: { status: number; code: string; message: string; } | null = null;
  let deleteTeamError: { status: number; code: string; message: string; } | null = null;
  let teamsLoadFailing = false;
  let rosterRows: Record<string, unknown>[] = [];
  // When set, the roster request waits for it, so a test can look at the dialog before the members load.
  let rosterGate: Promise<void> | null = null;
  // Sign-up closed, so suggestions are live in every test unless one opens it.
  let capabilities: object = {};
  let directory: Record<string, unknown>[] = [];

  beforeEach(() => {
    capabilities = { registration: { enabled: false } };
    directory = [
      {
        id: "u1",
        email: "admin@acme.corp",
        display_name: "Admin User",
        role: "admin",
        created_at: "2026-09-01T00:00:00Z",
      },
    ];
    rosterRows = [
      {
        team_id: "t1",
        user_id: "u1",
        user_email: "admin@acme.corp",
        display_name: "Admin User",
        role: "admin",
      },
    ];
    fetchCalls = [];
    rosterGate = null;
    userRole = "admin";
    addMemberError = null;
    removeMemberError = null;
    deleteTeamError = null;
    teamsLoadFailing = false;
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
        if (method === "DELETE") {
          return removeMemberError
            ? jsonResponse(
              { error: { code: removeMemberError.code, message: removeMemberError.message } },
              removeMemberError.status,
            )
            : jsonResponse(null, 204);
        }
        await rosterGate;
        return jsonResponse(rosterRows);
      }
      if (u.endsWith("/api/v1/teams")) {
        if (method === "GET" && teamsLoadFailing) {
          return jsonResponse(
            { error: { code: "internal", message: "database unavailable" } },
            500,
          );
        }
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
        if (method === "DELETE") {
          return deleteTeamError
            ? jsonResponse(
              { error: { code: deleteTeamError.code, message: deleteTeamError.message } },
              deleteTeamError.status,
            )
            : jsonResponse(null, 204);
        }
      }
      if (u.endsWith("/api/v1/capabilities")) {
        return jsonResponse(capabilities);
      }
      if (u.includes("/api/v1/users")) {
        return jsonResponse(directory);
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

  it("sends the email address and the selected role when adding a roster member", async () => {
    const user = userEvent.setup();
    renderTeamsDirectory();

    await user.click((await screen.findAllByRole("button", { name: "Manage Roster" }))[0]);
    await user.type(
      screen.getByRole("combobox", { name: "Email address" }),
      "ada@acme.example",
    );
    await chooseOption(user, screen.getByRole("combobox", { name: "Team role" }), "Admin");
    await user.click(await screen.findByRole("button", { name: "Add" }));

    await waitFor(() => {
      const postCall = fetchCalls.find(
        (c) => c.url.endsWith("/api/v1/teams/t1/members") && c.method === "POST",
      );
      expect(postCall).toBeDefined();
      expect(JSON.parse(postCall!.body!)).toEqual({
        email: "ada@acme.example",
        role: "admin",
      });
    });
  });

  it("suggests people from the loaded directory without asking the server per key", async () => {
    capabilities = { registration: { enabled: false } };
    const person = (id: string, email: string, extra: object = {}) => ({
      id,
      email,
      role: "member",
      created_at: "2026-09-01T00:00:00Z",
      ...extra,
    });
    directory = [
      ...directory,
      person("u2", "adam@acme.corp"),
      person("u3", "zed@acme.corp", { display_name: "Adele Admiral" }),
      person("u4", "adrian@acme.corp", { disabled: true, disabled_at: "2026-09-02T00:00:00Z" }),
      person("u5", "system@specht.local", { display_name: "Admin System" }),
    ];
    const user = userEvent.setup();
    renderTeamsDirectory();

    await user.click((await screen.findAllByRole("button", { name: "Manage Roster" }))[0]);
    await user.type(screen.getByRole("combobox", { name: "Email address" }), "adm");

    const options = await screen.findAllByRole("option");
    // admin@acme.corp is already in the team; the disabled and system accounts are never offered.
    expect(options.map((o) => o.firstElementChild?.textContent)).toEqual(["zed@acme.corp"]);
    await user.clear(screen.getByRole("combobox", { name: "Email address" }));
    await user.type(screen.getByRole("combobox", { name: "Email address" }), "ada");
    await user.keyboard("{ArrowDown}{Enter}");
    expect(screen.getByRole("combobox", { name: "Email address" })).toHaveValue("adam@acme.corp");
    expect(fetchCalls.some((c) => c.url.includes("member-suggestions"))).toBe(false);
  });

  it("offers no one until the team's members have loaded", async () => {
    const person = (id: string, email: string) => ({
      id,
      email,
      role: "member",
      created_at: "2026-09-01T00:00:00Z",
    });
    directory = [...directory, person("u2", "adam@acme.corp"), person("u3", "adan@acme.corp")];
    rosterRows = [...rosterRows, {
      team_id: "t1",
      user_id: "u2",
      user_email: "adam@acme.corp",
      display_name: "",
      role: "member",
    }];
    let release: () => void = () => {};
    rosterGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const user = userEvent.setup();
    renderTeamsDirectory();

    await user.click((await screen.findAllByRole("button", { name: "Manage Roster" }))[0]);
    await user.type(screen.getByRole("combobox", { name: "Email address" }), "ada");
    await new Promise((r) => setTimeout(r, 100));
    expect(screen.queryByRole("option")).not.toBeInTheDocument();

    release();
    const options = await screen.findAllByRole("option");
    // adam is already on the team and was never offered, before or after the load.
    expect(options.map((o) => o.firstElementChild?.textContent)).toEqual(["adan@acme.corp"]);
  });

  it("offers no suggestions while sign-up is open", async () => {
    capabilities = { registration: { enabled: true } };
    directory = [...directory, {
      id: "u2",
      email: "adam@acme.corp",
      role: "member",
      created_at: "2026-09-01T00:00:00Z",
    }];
    const user = userEvent.setup();
    renderTeamsDirectory();

    await user.click((await screen.findAllByRole("button", { name: "Manage Roster" }))[0]);
    await user.type(screen.getByRole("combobox", { name: "Email address" }), "ada");
    await new Promise((r) => setTimeout(r, 100));
    expect(screen.queryByRole("option")).not.toBeInTheDocument();
  });

  it("defaults the roster role to member", async () => {
    const user = userEvent.setup();
    renderTeamsDirectory();

    await user.click((await screen.findAllByRole("button", { name: "Manage Roster" }))[0]);
    expect(screen.getByRole("combobox", { name: "Team role" })).toHaveTextContent("Member");

    await user.type(
      screen.getByRole("combobox", { name: "Email address" }),
      "ada@acme.example",
    );
    await user.click(await screen.findByRole("button", { name: "Add" }));

    await waitFor(() => {
      const postCall = fetchCalls.find(
        (c) => c.url.endsWith("/api/v1/teams/t1/members") && c.method === "POST",
      );
      expect(JSON.parse(postCall!.body!)).toEqual({
        email: "ada@acme.example",
        role: "member",
      });
    });
  });

  it("does not submit an address that is not an email", async () => {
    const user = userEvent.setup();
    renderTeamsDirectory();

    await user.click((await screen.findAllByRole("button", { name: "Manage Roster" }))[0]);
    await user.type(screen.getByRole("combobox", { name: "Email address" }), "alex@acme");
    // The partial address matches nobody, so the list is open with its hint; close it first.
    await user.keyboard("{Escape}");
    await user.click(screen.getByRole("button", { name: "Add" }));

    expect(await screen.findByText(/Enter the person's email address/)).toBeInTheDocument();
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
      screen.getByRole("combobox", { name: "Email address" }),
      "ada@acme.example",
    );
    await user.click(await screen.findByRole("button", { name: "Add" }));

    expect(await screen.findByText("user not found")).toBeInTheDocument();
  });

  it("shows a load error for the teams list and retries", async () => {
    const user = userEvent.setup();
    teamsLoadFailing = true;
    renderTeamsDirectory();

    expect(await screen.findByText("Could not load company teams.")).toBeInTheDocument();
    expect(screen.queryByText("No company teams exist yet.")).not.toBeInTheDocument();

    teamsLoadFailing = false;
    await user.click(screen.getByRole("button", { name: "Retry" }));

    expect(await screen.findByText("Security Operations")).toBeInTheDocument();
    expect(screen.queryByText("Could not load company teams.")).not.toBeInTheDocument();
  });

  it("shows names to a signed-in member, with no emails, controls or directory call", async () => {
    const user = userEvent.setup();
    userRole = "member";
    rosterRows = [
      { team_id: "t1", user_id: "u2", display_name: "Ada Okafor", role: "admin" },
      { team_id: "t1", user_id: "u3", role: "member" },
    ];
    renderTeamsDirectory();

    expect(await screen.findAllByText("2 members")).not.toHaveLength(0);
    expect(screen.queryByText("Could not load members")).not.toBeInTheDocument();
    await user.click((await screen.findAllByRole("button", { name: "View Roster" }))[0]);

    expect(await screen.findByText("Ada Okafor")).toBeInTheDocument();
    expect(screen.getByText("Unnamed account")).toBeInTheDocument();
    expect(screen.queryByText(/@/)).not.toBeInTheDocument();
    expect(screen.queryByText("u2")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove" })).not.toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: "Email address" })).not.toBeInTheDocument();
    expect(fetchCalls.some((c) => c.url.includes("/api/v1/users"))).toBe(false);
  });

  it("gives a team admin who is not a global admin the roster controls the server allows", async () => {
    const user = userEvent.setup();
    userRole = "member";
    rosterRows = [
      { team_id: "t1", user_id: "u1", user_email: "admin@acme.corp", role: "admin" },
      { team_id: "t1", user_id: "u2", user_email: "ada@acme.corp", role: "member" },
    ];
    renderTeamsDirectory();

    await user.click((await screen.findAllByRole("button", { name: "Manage Roster" }))[0]);
    expect(screen.queryByRole("button", { name: "Delete" })).not.toBeInTheDocument();
    expect(await screen.findAllByRole("button", { name: "Remove" })).toHaveLength(2);

    await user.type(screen.getByRole("combobox", { name: "Email address" }), "bo@acme.example");
    await user.click(screen.getByRole("button", { name: "Add" }));
    await waitFor(() =>
      expect(
        fetchCalls.some((c) => c.url.endsWith("/api/v1/teams/t1/members") && c.method === "POST"),
      ).toBe(true)
    );
    // A team admin cannot read the user directory, so the page does not ask for it.
    expect(fetchCalls.some((c) => c.url.includes("/api/v1/users"))).toBe(false);
  });

  it("keeps the roster read-only for a plain member of the team", async () => {
    const user = userEvent.setup();
    userRole = "member";
    rosterRows = [
      { team_id: "t1", user_id: "u1", role: "member" },
      { team_id: "t1", user_id: "u2", display_name: "Ada Okafor", role: "admin" },
    ];
    renderTeamsDirectory();

    await user.click((await screen.findAllByRole("button", { name: "View Roster" }))[0]);
    expect(await screen.findByText("Ada Okafor")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove" })).not.toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: "Email address" })).not.toBeInTheDocument();
  });

  it("shows an admin each member's name with the email beneath it", async () => {
    const user = userEvent.setup();
    rosterRows = [
      {
        team_id: "t1",
        user_id: "u2",
        user_email: "ada@acme.corp",
        display_name: "Ada Okafor",
        role: "member",
      },
      { team_id: "t1", user_id: "u3", user_email: "bo@acme.corp", role: "member" },
    ];
    renderTeamsDirectory();

    await user.click((await screen.findAllByRole("button", { name: "Manage Roster" }))[0]);

    expect(await screen.findByText("Ada Okafor")).toBeInTheDocument();
    expect(screen.getByText("ada@acme.corp")).toBeInTheDocument();
    expect(screen.getByText("bo@acme.corp")).toBeInTheDocument();
    expect(screen.queryByText("Unnamed account")).not.toBeInTheDocument();
  });

  it("shows why removing a roster member failed", async () => {
    const user = userEvent.setup();
    removeMemberError = {
      status: 403,
      code: "team_admin_required",
      message: "team admin role required",
    };
    renderTeamsDirectory();

    await user.click((await screen.findAllByRole("button", { name: "Manage Roster" }))[0]);
    await user.click(await screen.findByRole("button", { name: "Remove" }));

    expect(await screen.findByText("team admin role required")).toBeInTheDocument();
  });

  it("shows why deleting a team failed on that team's card", async () => {
    const user = userEvent.setup();
    deleteTeamError = {
      status: 409,
      code: "team_linked",
      message: "team is still linked to a project",
    };
    renderTeamsDirectory();

    await user.click((await screen.findAllByRole("button", { name: "Delete" }))[0]);
    await user.click(await screen.findByRole("button", { name: "Delete team" }));

    const message = await screen.findByText("team is still linked to a project");
    expect(message.closest("div.bg-card")).toHaveTextContent("Security Operations");
    expect(message.closest("div.bg-card")).not.toHaveTextContent("Backend Platform");
  });

  it("asks before deleting a team, names it, and deletes nothing on cancel", async () => {
    const user = userEvent.setup();
    renderTeamsDirectory();

    await user.click((await screen.findAllByRole("button", { name: "Delete" }))[0]);
    const dialog = await screen.findByRole("alertdialog", { name: /^Delete .+\?$/ });
    expect(dialog).toHaveTextContent("This cannot be undone.");

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => {
      expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    });
    expect(fetchCalls.some((c) => c.method === "DELETE")).toBe(false);
  });

  it("closes the roster with Escape and returns focus to the button that opened it", async () => {
    const user = userEvent.setup();
    renderTeamsDirectory();

    const opener = (await screen.findAllByRole("button", { name: "Manage Roster" }))[0];
    await user.click(opener);
    expect(await screen.findByRole("dialog", { name: /members$/ })).toBeInTheDocument();

    await user.keyboard("{Escape}");
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });
    expect(opener).toHaveFocus();
  });
});
