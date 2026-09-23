import { AuthContext, type AuthContextValue } from "@/auth/context";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { ApiKeys } from "./ApiKeys";

const authCtx: AuthContextValue = {
  token: "test-token",
  userId: "u1",
  email: "test@test.com",
  login: async () => {},
  logout: () => {},
  loading: false,
};

function renderApiKeys() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <AuthContext.Provider value={authCtx}>
        <MemoryRouter>
          <ApiKeys />
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

let fetchCalls: { url: string; method: string; body?: string; }[] = [];

describe("ApiKeys", () => {
  beforeEach(() => {
    fetchCalls = [];
    globalThis.fetch = vi.fn().mockImplementation(async (url, opts) => {
      const u = String(url);
      const method = ((opts as RequestInit)?.method ?? "GET").toUpperCase();
      fetchCalls.push({ url: u, method, body: (opts as RequestInit)?.body as string | undefined });
      if (u.includes("/apikeys") && method === "POST") {
        return {
          ok: true,
          json: () => Promise.resolve({ key: "sk-foo-bar-baz" }),
        } as Response;
      }
      if (u.includes("/apikeys") && method === "GET") {
        return {
          ok: true,
          json: () =>
            Promise.resolve([{
              id: "k1",
              name: "My Key",
              key_prefix: "sk-foo",
              project_id: "p1",
              created_at: "2025-01-01T00:00:00Z",
            }]),
        } as Response;
      }
      return {
        ok: true,
        json: () =>
          Promise.resolve([
            {
              id: "p1",
              slug: "test-project",
              name: "Test Project",
              description: null,
              created_at: "",
              updated_at: "",
            },
          ]),
      } as Response;
    });
  });

  it("shows heading and project selector", () => {
    renderApiKeys();
    expect(screen.getByText("API Keys")).toBeInTheDocument();
    expect(screen.getByText("Select a project")).toBeInTheDocument();
  });

  it("shows created key in one-time display modal", async () => {
    renderApiKeys();
    const user = userEvent.setup();

    await waitFor(() => {
      expect(screen.getByText("Test Project")).toBeInTheDocument();
    });

    await user.selectOptions(screen.getByRole("combobox", { name: /project/i }), "test-project");
    await user.type(screen.getByPlaceholderText("Key name"), "My Key");
    await user.click(screen.getByRole("button", { name: /create/i }));

    await waitFor(() => {
      expect(screen.getByText("This key will not be shown again")).toBeInTheDocument();
      expect(screen.getByText("sk-foo-bar-baz")).toBeInTheDocument();
    });

    const postCall = fetchCalls.find((c) => c.method === "POST");
    expect(postCall).toBeDefined();
    expect(JSON.parse(postCall!.body!)).toEqual({ project: "test-project", name: "My Key" });
  });

  it("shows confirm dialog before revoking", async () => {
    renderApiKeys();
    const user = userEvent.setup();

    await waitFor(() => {
      expect(screen.getByText("Test Project")).toBeInTheDocument();
    });

    await user.selectOptions(screen.getByRole("combobox", { name: /project/i }), "test-project");

    await waitFor(() => {
      expect(screen.getByText("My Key")).toBeInTheDocument();
    });

    await user.click(screen.getByRole("button", { name: /revoke/i }));

    expect(screen.getByText("Confirm")).toBeInTheDocument();
    expect(screen.getByText("Cancel")).toBeInTheDocument();
  });

  it("clears displayed keys when project selection is reset", async () => {
    renderApiKeys();
    const user = userEvent.setup();

    await waitFor(() => {
      expect(screen.getByText("Test Project")).toBeInTheDocument();
    });

    const select = screen.getByRole("combobox", { name: /project/i });
    await user.selectOptions(select, "test-project");

    await waitFor(() => {
      expect(screen.getByText("My Key")).toBeInTheDocument();
    });

    await user.selectOptions(select, "");

    await waitFor(() => {
      expect(screen.queryByText("My Key")).not.toBeInTheDocument();
    });
  });
});
