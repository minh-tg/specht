import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { vi } from "vitest";
import { ProjectList } from "./ProjectList";

beforeEach(() => {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve([]),
  } as Response);
});

function renderWithProviders(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("ProjectList", () => {
  it("shows loading state initially", () => {
    renderWithProviders(<ProjectList />);
    const skeletons = document.querySelectorAll(".animate-pulse");
    expect(skeletons.length).toBeGreaterThan(0);
  });

  it("shows empty state when no projects", async () => {
    renderWithProviders(<ProjectList />);
    const empty = await screen.findByText("No projects yet");
    expect(empty).toBeInTheDocument();
  });

  it("shows gate state and opens a project when selected", async () => {
    const projects = [
      { id: "p1", slug: "alpha", name: "Alpha", description: "Production app" },
      { id: "p2", slug: "beta", name: "Beta", description: null },
    ];
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith("/alpha/gate")) {
        return jsonResponse({ threshold_breached: true, blocking_count: 4 });
      }
      if (url.endsWith("/beta/gate")) {
        return jsonResponse({ threshold_breached: false, blocking_count: 3 });
      }
      return jsonResponse(projects);
    });
    renderProjectRoutes();

    const alpha = await screen.findByRole("button", { name: /Alpha/ });
    expect(await screen.findByText("BLOCKING")).toBeInTheDocument();
    expect(await screen.findByText("3 blocking")).toBeInTheDocument();

    await userEvent.setup().click(alpha);
    expect(await screen.findByText("Findings page")).toBeInTheDocument();
  });

  it("styles the blocking badge with verdict tokens", async () => {
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith("/alpha/gate")) {
        return jsonResponse({ threshold_breached: true, blocking_count: 4 });
      }
      return jsonResponse([
        { id: "p1", slug: "alpha", name: "Alpha", description: null },
      ]);
    });
    renderProjectRoutes();

    const badge = await screen.findByText("BLOCKING");
    expect(badge).toHaveClass("bg-verdict-block", "text-verdict-block-fg");
    expect(badge).not.toHaveClass("text-destructive-foreground");
  });

  it("lets the user retry after projects fail to load", async () => {
    vi.mocked(globalThis.fetch)
      .mockRejectedValueOnce(new Error("Service unavailable"))
      .mockResolvedValue(jsonResponse([
        { id: "p1", slug: "alpha", name: "Alpha", description: null },
      ]));
    renderProjectRoutes();

    expect(await screen.findByText("Service unavailable")).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("button", { name: /Alpha/ })).toBeInTheDocument();
  });
});

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    headers: { "Content-Type": "application/json" },
  });
}

function renderProjectRoutes() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/"]}>
        <Routes>
          <Route path="/" element={<ProjectList />} />
          <Route path="/:slug/findings" element={<p>Findings page</p>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
