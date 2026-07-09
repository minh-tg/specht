import { AuthProvider } from "@/auth/AuthContext";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { Login } from "./Login";

function renderLogin() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AuthProvider>
          <Login />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Login", () => {
  beforeEach(() => {
    globalThis.fetch = vi.fn();
  });

  it("renders the login form", () => {
    renderLogin();
    expect(screen.getByLabelText("Email")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });

  it("shows error on invalid credentials", async () => {
    const res = new Response(
      JSON.stringify({
        error: { code: "invalid_credentials", message: "Invalid email or password" },
      }),
      {
        status: 401,
        headers: { "Content-Type": "application/json" },
      },
    );
    vi.mocked(globalThis.fetch).mockResolvedValue(res);

    renderLogin();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Email"), "bad@test.com");
    await user.type(screen.getByLabelText("Password"), "wrong");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByText("Invalid email or password")).toBeInTheDocument();
    });
  });

  it("shows generic error on network failure", async () => {
    vi.mocked(globalThis.fetch).mockRejectedValue(new Error("Network error"));

    renderLogin();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Email"), "test@test.com");
    await user.type(screen.getByLabelText("Password"), "test");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByText("Login failed. Please try again.")).toBeInTheDocument();
    });
  });
});
