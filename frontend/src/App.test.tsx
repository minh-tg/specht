import { AuthContext, type AuthContextValue } from "@/auth/AuthContext";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
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
  globalThis.fetch = vi.fn().mockImplementation((input: RequestInfo | URL) => {
    const url = String(input);
    const data = url.endsWith("/reachability")
      ? []
      : {
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
    return Promise.resolve({ ok: true, json: () => Promise.resolve(data) } as Response);
  });
});

it("renders the finding detail route", async () => {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });

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
