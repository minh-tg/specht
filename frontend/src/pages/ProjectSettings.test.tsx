import { queryKeys } from "@/api/hooks";
import { AuthContext, type AuthContextValue } from "@/auth/context";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import type { Project } from "@/types/api";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ProjectSettings } from "./project-settings/ProjectSettings";

const auth: AuthContextValue = {
  token: "t",
  userId: "u1",
  email: "ada@acme.example",
  login: async () => {},
  logout: () => {},
  adopt: () => {},
  loading: false,
};

const payments: Project = {
  id: "p1",
  slug: "payments",
  name: "Payments API",
  description: "Card and wallet flows",
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-01T00:00:00Z",
};

let project: Project;
let role: "admin" | "member";
let projectRole: "admin" | "member";
let writes: { method: string; body: unknown; }[];
let writeError: string | null;

function renderPage() {
  const client = createTestQueryClient();
  const view = render(
    <QueryClientProvider client={client}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={["/payments/settings"]}>
          <Routes>
            <Route path="/" element={<p>Projects home</p>} />
            <Route path="/:slug/settings" element={<ProjectSettings />} />
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
  return { client, ...view };
}

describe("ProjectSettings", () => {
  beforeEach(() => {
    project = { ...payments };
    role = "admin";
    projectRole = "admin";
    writes = [];
    writeError = null;
    globalThis.fetch = vi.fn().mockImplementation(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        if (url.endsWith("/api/v1/me")) {
          return jsonResponse({ id: "u1", email: "ada@acme.example", role });
        }
        if (url.endsWith("/payments/members")) {
          return jsonResponse([
            {
              project_id: "p1",
              user_id: "u1",
              role: projectRole,
              created_at: "2025-01-01T00:00:00Z",
            },
          ]);
        }
        if (url.endsWith("/api/v1/projects/payments") && method === "GET") {
          return jsonResponse(project);
        }
        if (url.endsWith("/api/v1/projects/payments") && method === "PUT") {
          const body = JSON.parse(String(init?.body));
          writes.push({ method, body });
          if (writeError) {
            return jsonResponse({ error: { code: "invalid_name", message: writeError } }, 400);
          }
          project = { ...project, ...body, updated_at: "2025-02-01T00:00:00Z" };
          return jsonResponse(project);
        }
        throw new Error(`unexpected request ${method} ${url}`);
      },
    );
  });

  it("shows the slug read-only with the name and description filled in", async () => {
    renderPage();
    expect(await screen.findByLabelText("Name")).toHaveValue("Payments API");
    expect(screen.getByLabelText("Description")).toHaveValue("Card and wallet flows");
    expect(screen.getByLabelText("Slug")).toHaveValue("payments");
    expect(screen.getByLabelText("Slug")).toHaveAttribute("readonly");
  });

  it("keeps Save disabled until a field changes, then sends only the changed fields", async () => {
    const user = userEvent.setup();
    renderPage();
    const save = await screen.findByRole("button", { name: "Save" });
    expect(save).toBeDisabled();

    await user.type(screen.getByLabelText("Name"), "  ");
    expect(save).toBeDisabled();

    await user.clear(screen.getByLabelText("Name"));
    await user.type(screen.getByLabelText("Name"), "Payments");
    expect(save).toBeEnabled();
    await user.click(save);

    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]).toEqual({ method: "PUT", body: { name: "Payments" } });
  });

  it("sends the description alone when only the description changed", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.type(await screen.findByLabelText("Description"), " for cards");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0].body).toEqual({ description: "Card and wallet flows for cards" });
  });

  it("refuses a blank name and keeps Save disabled", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.clear(await screen.findByLabelText("Name"));
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    expect(screen.getByText("Enter a name.")).toBeInTheDocument();
  });

  it("shows a server error under the form and keeps the typed values", async () => {
    writeError = "name is taken";
    const user = userEvent.setup();
    renderPage();
    await user.type(await screen.findByLabelText("Name"), "!");
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("name is taken");
    expect(screen.getByLabelText("Name")).toHaveValue("Payments API!");
  });

  it("refreshes the project and the project list after a save", async () => {
    const user = userEvent.setup();
    const { client } = renderPage();
    client.setQueryData(queryKeys.projects(), [project]);
    await user.type(await screen.findByLabelText("Name"), "!");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(client.getQueryData<Project>(queryKeys.project("payments"))?.name).toBe(
        "Payments API!",
      )
    );
    expect(client.getQueryState(queryKeys.projects())?.isInvalidated).toBe(true);
  });

  it("tells a person without the admin role why the page is closed to them", async () => {
    role = "member";
    projectRole = "member";
    renderPage();

    expect(await screen.findByText("Only project admins can change these settings."))
      .toBeInTheDocument();
    expect(screen.queryByLabelText("Name")).not.toBeInTheDocument();
  });

  it("lets a global admin in without a project membership", async () => {
    projectRole = "member";
    renderPage();
    expect(await screen.findByLabelText("Name")).toBeInTheDocument();
  });
});
