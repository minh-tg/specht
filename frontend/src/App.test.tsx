import { AuthContext, type AuthContextValue } from "@/auth/context";
import { createTestQueryClient } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { AppRoutes } from "./App";

const auth: AuthContextValue = {
  token: "test-token",
  userId: "u1",
  email: "test@test.com",
  login: async () => {},
  logout: () => {},
  loading: false,
};

beforeEach(() => {
  document.title = "";
  const finding = {
    id: "f1",
    project_id: "p1",
    finding_kind: "sca",
    fingerprint: "fp1",
    current_title: "Test Vulnerability",
    current_severity: "high",
    current_score: null,
    state: "open",
    triage_status: "untriaged",
    analysis_state: "unanalyzed",
    gate_effect: "block",
    first_seen_at: "2025-01-01T00:00:00Z",
    last_seen_at: "2025-01-01T00:00:00Z",
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
  };
  globalThis.fetch = vi.fn().mockImplementation((input: RequestInfo | URL) => {
    const path = String(input).split("?")[0];
    let data: unknown = {};
    if (path.endsWith("/reachability") || path.endsWith("/projects") || path.endsWith("/reports")) {
      data = [];
    } else if (path.endsWith("/scanners")) {
      data = [];
    } else if (/\/projects\/[^/]+$/.test(path)) {
      data = {
        id: "p1",
        slug: "test-project",
        name: "Test Project",
        description: null,
        created_at: "2025-01-01T00:00:00Z",
        updated_at: "2025-01-01T00:00:00Z",
      };
    } else if (path.endsWith("/findings")) {
      data = [];
    } else if (path.includes("/findings/")) {
      data = finding;
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve(data) } as Response);
  });
});

function renderRoutes(initialPath: string, token: string | null = auth.token) {
  const queryClient = createTestQueryClient();
  const value: AuthContextValue = {
    ...auth,
    token,
    userId: token ? auth.userId : null,
    email: token ? auth.email : null,
  };

  return render(
    <QueryClientProvider client={queryClient}>
      <AuthContext.Provider value={value}>
        <MemoryRouter initialEntries={[initialPath]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

it("renders the finding detail route", async () => {
  const queryClient = createTestQueryClient();

  render(
    <QueryClientProvider client={queryClient}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={["/test-project/findings/f1"]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );

  expect(await screen.findByRole("heading", { name: "Test Vulnerability" })).toBeInTheDocument();
  expect(screen.getByText("Reachability")).toBeInTheDocument();
});

it("sends anonymous visitors from a protected project page to sign in", async () => {
  renderRoutes("/test-project/findings", null);

  expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  expect(screen.getByLabelText("Email")).toBeInTheDocument();
});

it("keeps project navigation in sync with the selected tab", async () => {
  renderRoutes("/test-project/findings");

  expect(await screen.findByText("No findings found")).toBeInTheDocument();
  await userEvent.setup().click(screen.getByRole("link", { name: "Reports" }));
  expect(await screen.findByText("No reports yet.")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Findings" })).toHaveAttribute(
    "href",
    "/test-project/findings",
  );
});

it("shows a not-found page for unknown routes", async () => {
  renderRoutes("/unknown/deeper/path");

  expect(await screen.findByRole("heading", { name: "Page not found" })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Back to projects" })).toHaveAttribute("href", "/");
  expect(document.title).toBe("Not found · Specht");
});

it("opens a project's findings from its bare URL", async () => {
  renderRoutes("/test-project");

  expect(await screen.findByText("No findings found")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Findings" })).toHaveAttribute("aria-current", "page");
});

it("does not treat the bare-project route as a not-found page for signed-out visitors", async () => {
  renderRoutes("/test-project", null);

  expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
});

it("sets the document title for the sign-in route", async () => {
  renderRoutes("/login", null);

  expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  expect(document.title).toBe("Sign in · Specht");
});

it("sets the document title for the projects route", async () => {
  renderRoutes("/");

  expect(await screen.findByRole("heading", { name: "Projects" })).toBeInTheDocument();
  expect(document.title).toBe("Projects · Specht");
});

it("marks the active project tab with aria-current", async () => {
  renderRoutes("/test-project/findings");

  expect(await screen.findByText("No findings found")).toBeInTheDocument();
  expect(screen.getByRole("navigation", { name: "Project sections" })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Findings" })).toHaveAttribute("aria-current", "page");
  expect(screen.getByRole("link", { name: "Reports" })).not.toHaveAttribute("aria-current");
});

it("moves aria-current to the reports tab when it is selected", async () => {
  renderRoutes("/test-project/reports");

  expect(await screen.findByText("No reports yet.")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Reports" })).toHaveAttribute("aria-current", "page");
  expect(screen.getByRole("link", { name: "Findings" })).not.toHaveAttribute("aria-current");
});

it("renders the new project route", async () => {
  renderRoutes("/projects/new");

  expect(await screen.findByRole("heading", { name: "New project" })).toBeInTheDocument();
  expect(document.title).toBe("New project · Specht");
});

it("renders the CI setup route", async () => {
  renderRoutes("/test-project/setup");

  expect(await screen.findByRole("heading", { name: "CI setup" })).toBeInTheDocument();
  expect(document.title).toBe("CI setup · Specht");
});

it("renders the upload report route", async () => {
  renderRoutes("/test-project/reports/upload");

  expect(await screen.findByRole("heading", { name: "Upload a report" })).toBeInTheDocument();
  expect(document.title).toBe("Upload report · Specht");
});

it("redirects the legacy ingest route to the projects page", async () => {
  renderRoutes("/ingest");

  expect(await screen.findByRole("heading", { name: "Projects" })).toBeInTheDocument();
});
