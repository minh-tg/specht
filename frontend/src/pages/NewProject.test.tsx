import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useParams } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { NewProject } from "./NewProject";

let meRole: "admin" | "member" = "admin";
let createStatus = 201;
let createMessage = "slug already exists";
let createDelayMs = 0;
let meDelayMs = 0;
let postCalls: Array<Record<string, unknown>> = [];

const PROJECT = {
  id: "p1",
  slug: "acme-api",
  name: "Acme API",
  description: null,
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-01T00:00:00Z",
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status < 400,
    status,
    json: () => Promise.resolve(body),
  } as Response;
}

function SetupRoute() {
  const { slug } = useParams<{ slug: string; }>();
  return <div>Setup page for {slug}</div>;
}

beforeEach(() => {
  meRole = "admin";
  createStatus = 201;
  createMessage = "slug already exists";
  createDelayMs = 0;
  meDelayMs = 0;
  postCalls = [];
  globalThis.fetch = vi.fn().mockImplementation(async (input, init) => {
    const url = String(input);
    const method = ((init as RequestInit | undefined)?.method ?? "GET").toUpperCase();

    if (url === "/api/v1/me") {
      if (meDelayMs) await sleep(meDelayMs);
      return jsonResponse({ id: "u1", email: "user@example.com", role: meRole, created_at: "" });
    }
    if (url === "/api/v1/projects" && method === "POST") {
      postCalls.push(JSON.parse((init as RequestInit).body as string));
      if (createDelayMs) await sleep(createDelayMs);
      if (createStatus >= 400) {
        return jsonResponse({
          error: { code: "conflict", message: createMessage },
        }, createStatus);
      }
      return jsonResponse(PROJECT, 201);
    }
    return jsonResponse({});
  });
});

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/projects/new"]}>
        <Routes>
          <Route path="/projects/new" element={<NewProject />} />
          <Route path="/:slug/setup" element={<SetupRoute />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("NewProject", () => {
  it("shows a skeleton while the profile loads", () => {
    meDelayMs = 50;
    renderPage();
    expect(document.querySelectorAll(".animate-pulse").length).toBeGreaterThan(0);
    expect(screen.queryByLabelText("Name")).not.toBeInTheDocument();
  });

  it("tells members that only administrators can create projects", async () => {
    meRole = "member";
    renderPage();

    expect(await screen.findByText("Only administrators can create projects.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /back to projects/i })).toHaveAttribute("href", "/");
    expect(screen.queryByLabelText("Name")).not.toBeInTheDocument();
  });

  it("fills the slug from the name until the slug is edited by hand", async () => {
    renderPage();
    const user = userEvent.setup();

    const name = await screen.findByLabelText("Name");
    await user.type(name, "Acme API v2");
    expect(screen.getByLabelText("Slug")).toHaveValue("acme-api-v2");

    const slug = screen.getByLabelText("Slug");
    await user.clear(slug);
    await user.type(slug, "custom-slug");
    await user.type(name, " Extra");
    expect(slug).toHaveValue("custom-slug");
  });

  it("validates the name and the slug before submitting", async () => {
    renderPage();
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: /create project/i }));
    expect(screen.getByText("Name is required")).toBeInTheDocument();
    expect(screen.getByLabelText("Name")).toHaveAttribute(
      "aria-describedby",
      "new-project-name-error",
    );
    expect(postCalls).toHaveLength(0);

    await user.type(screen.getByLabelText("Name"), "Acme API");
    const slug = screen.getByLabelText("Slug");
    await user.clear(slug);
    await user.type(slug, "ab");
    await user.click(screen.getByRole("button", { name: /create project/i }));

    expect(screen.getByText(/use 3-48 lowercase letters/i)).toBeInTheDocument();
    expect(screen.getByLabelText("Slug")).toHaveAttribute(
      "aria-describedby",
      expect.stringContaining("new-project-slug-error"),
    );
    expect(postCalls).toHaveLength(0);
  });

  it("creates the project and moves on to the setup page", async () => {
    renderPage();
    const user = userEvent.setup();

    await user.type(await screen.findByLabelText("Name"), "Acme API");
    await user.type(screen.getByLabelText("Description"), "Security scans");
    await user.click(screen.getByRole("button", { name: /create project/i }));

    expect(await screen.findByText("Setup page for acme-api")).toBeInTheDocument();
    expect(postCalls).toEqual([{
      name: "Acme API",
      slug: "acme-api",
      description: "Security scans",
    }]);
  });

  it("disables the submit button while the project is being created", async () => {
    createDelayMs = 50;
    renderPage();
    const user = userEvent.setup();

    await user.type(await screen.findByLabelText("Name"), "Acme API");
    await user.click(screen.getByRole("button", { name: /create project/i }));

    expect(await screen.findByRole("button", { name: "Creating..." })).toBeDisabled();
    await waitFor(() => {
      expect(screen.getByText("Setup page for acme-api")).toBeInTheDocument();
    });
  });

  it("shows a rejected slug under the slug field", async () => {
    createStatus = 409;
    renderPage();
    const user = userEvent.setup();

    await user.type(await screen.findByLabelText("Name"), "Acme API");
    await user.click(screen.getByRole("button", { name: /create project/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("slug already exists");
    expect(alert).toHaveAttribute("id", "new-project-slug-error");
    expect(screen.getByLabelText("Slug")).toHaveAttribute(
      "aria-describedby",
      expect.stringContaining("new-project-slug-error"),
    );
  });

  it("shows other server errors at form level", async () => {
    createStatus = 500;
    createMessage = "internal error";
    renderPage();
    const user = userEvent.setup();

    await user.type(await screen.findByLabelText("Name"), "Acme API");
    await user.click(screen.getByRole("button", { name: /create project/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("internal error");
    expect(alert).not.toHaveAttribute("id", "new-project-slug-error");
  });
});
