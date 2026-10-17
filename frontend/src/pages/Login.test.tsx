import { AuthProvider } from "@/auth/AuthContext";
import { AuthContext, type AuthContextValue } from "@/auth/context";
import { hasPendingSsoAttempt } from "@/auth/sso";
import { createTestQueryClient } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { vi } from "vitest";
const playCue = vi.hoisted(() => vi.fn());
vi.mock("@/lib/sound", () => ({ playCue }));

import { Login } from "./Login";
import { safeRedirect } from "./safeRedirect";

function renderLogin() {
  const qc = createTestQueryClient();
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

let authState: {
  token: string | null;
  login: (email: string, password: string) => Promise<void>;
  ssoBrowserMismatch?: boolean;
};

function authContext(): AuthContextValue {
  return {
    token: authState.token,
    userId: authState.token ? "u1" : null,
    email: authState.token ? "test@test.com" : null,
    login: authState.login,
    logout: () => {},
    adopt: () => {},
    loading: false,
    ssoBrowserMismatch: authState.ssoBrowserMismatch ?? false,
  };
}

function FindingsPage() {
  const location = useLocation();
  return <p>Findings page {location.search}</p>;
}

function renderLoginWithAuth(initialPath = "/login") {
  const qc = createTestQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialPath]}>
        <AuthContext.Provider value={authContext()}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/" element={<div>Home page</div>} />
            <Route path="/dashboard" element={<div>Dashboard page</div>} />
            <Route path="/my-app/findings" element={<FindingsPage />} />
          </Routes>
        </AuthContext.Provider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("safeRedirect", () => {
  it("returns internal paths unchanged", () => {
    expect(safeRedirect("/dashboard")).toBe("/dashboard");
    expect(safeRedirect("/reports/42?tab=details")).toBe("/reports/42?tab=details");
  });

  it("falls back to / when no redirect is given", () => {
    expect(safeRedirect(null)).toBe("/");
  });

  it("falls back to / for empty and relative-path redirects", () => {
    expect(safeRedirect("")).toBe("/");
    expect(safeRedirect("dashboard")).toBe("/");
  });

  it("blocks protocol-relative external URLs", () => {
    expect(safeRedirect("//evil.example.com")).toBe("/");
    expect(safeRedirect("///evil.example.com")).toBe("/");
  });

  it("blocks absolute external URLs", () => {
    expect(safeRedirect("https://evil.example.com/phish")).toBe("/");
    expect(safeRedirect("http://evil.example.com")).toBe("/");
  });

  it("blocks backslash and encoded-scheme tricks", () => {
    expect(safeRedirect("\\evil.example.com")).toBe("/");
    expect(safeRedirect("/\\evil.example.com")).toBe("/");
    expect(safeRedirect("https:%2F%2Fevil.example.com")).toBe("/");
  });

  it("blocks javascript: and data: URLs", () => {
    expect(safeRedirect("javascript:alert(1)")).toBe("/");
    expect(safeRedirect("data:text/html,<script>alert(1)</script>")).toBe("/");
  });

  it("falls back to / for control-character prefix tricks", () => {
    expect(safeRedirect("\n//evil.example.com")).toBe("/");
    expect(safeRedirect("\t/\\evil.example.com")).toBe("/");
  });
});

describe("Login", () => {
  beforeEach(() => {
    authState = { token: null, login: async () => {}, ssoBrowserMismatch: false };
    globalThis.fetch = vi.fn();
    playCue.mockClear();
  });

  it("renders the login form", () => {
    renderLogin();
    expect(screen.getByLabelText("Email")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });

  it("tells the user why they were signed out after a reused refresh token", () => {
    renderLoginWithAuth("/login?redirect=%2Fdashboard&reason=session_reused");

    expect(screen.getByRole("status")).toHaveTextContent(/signed out/i);
  });

  it("shows no sign-out notice on a plain visit", () => {
    renderLoginWithAuth("/login");

    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("exposes autocomplete hints so password managers can fill the form", () => {
    renderLogin();

    expect(screen.getByLabelText("Email")).toHaveAttribute("autocomplete", "email");
    expect(screen.getByLabelText("Password")).toHaveAttribute(
      "autocomplete",
      "current-password",
    );
  });

  it("returns an authenticated user to the home page", async () => {
    authState.token = "session-token";
    renderLoginWithAuth();

    expect(await screen.findByText("Home page")).toBeInTheDocument();
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
    expect(playCue).toHaveBeenCalledExactlyOnceWith("error");
  });

  it("shows generic error on network failure", async () => {
    vi.mocked(globalThis.fetch).mockRejectedValue(new Error("Network error"));

    renderLogin();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Email"), "test@test.com");
    await user.type(screen.getByLabelText("Password"), "test");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByText("Sign in failed. Please try again.")).toBeInTheDocument();
    });
    expect(playCue).toHaveBeenCalledExactlyOnceWith("error");
  });

  describe("while the server asks for a wait", () => {
    /** A 429 for a locked account, with the wait in its `Retry-After` header when given. */
    function tooManyAttempts(retryAfter?: string): Response {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (retryAfter !== undefined) headers["Retry-After"] = retryAfter;
      return new Response(
        JSON.stringify({
          error: {
            code: "too_many_attempts",
            message: "too many failed sign-in attempts, retry later",
          },
        }),
        { status: 429, headers },
      );
    }

    /** Answers the sign-in call with a fresh `loginResponse` each time. The page's capabilities
     * query shares `fetch`, so it gets a 404 instead of a body the sign-in call already read. */
    function mockSignIn(loginResponse: () => Response) {
      vi.mocked(globalThis.fetch).mockImplementation(async (input) =>
        String(input).endsWith("/api/v1/auth/login")
          ? loginResponse()
          : new Response("{}", { status: 404 })
      );
    }

    function signInCalls(): number {
      return vi.mocked(globalThis.fetch).mock.calls
        .filter(([input]) => String(input).endsWith("/api/v1/auth/login")).length;
    }

    async function submitOnce(user: ReturnType<typeof userEvent.setup>) {
      await user.type(screen.getByLabelText("Email"), "test@test.com");
      await user.type(screen.getByLabelText("Password"), "test");
      await user.click(screen.getByRole("button", { name: /sign in/i }));
    }

    it("shows the seconds from Retry-After and disables the button", async () => {
      mockSignIn(() => tooManyAttempts("45"));

      renderLogin();
      const user = userEvent.setup();
      await submitOnce(user);

      expect(await screen.findByText("Too many attempts. Try again in 45 seconds."))
        .toBeInTheDocument();
      expect(screen.getByRole("button", { name: /sign in/i })).toBeDisabled();
    });

    it("shows whole minutes from 60 seconds up", async () => {
      mockSignIn(() => tooManyAttempts("120"));

      renderLogin();
      const user = userEvent.setup();
      await submitOnce(user);

      expect(await screen.findByText("Too many attempts. Try again in 2 minutes."))
        .toBeInTheDocument();
    });

    it("keeps the generic message when the response has no Retry-After", async () => {
      mockSignIn(() => tooManyAttempts());

      renderLogin();
      const user = userEvent.setup();
      await submitOnce(user);

      expect(await screen.findByText("Sign in failed. Please try again.")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /sign in/i })).toBeEnabled();
    });

    it("re-enables the button at zero without sending the request again", async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });
      try {
        mockSignIn(() => tooManyAttempts("45"));

        renderLogin();
        const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
        await submitOnce(user);
        expect(await screen.findByText("Too many attempts. Try again in 45 seconds."))
          .toBeInTheDocument();

        act(() => {
          vi.advanceTimersByTime(45_000);
        });

        expect(screen.getByRole("button", { name: /sign in/i })).toBeEnabled();
        expect(screen.queryByText("Too many attempts. Try again in 45 seconds.")).not
          .toBeInTheDocument();
        expect(signInCalls()).toBe(1);
      } finally {
        vi.useRealTimers();
      }
    });
  });

  it("navigates to an internal redirect after login", async () => {
    authState.login = async () => {};
    renderLoginWithAuth("/login?redirect=%2Fdashboard");
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Email"), "test@test.com");
    await user.type(screen.getByLabelText("Password"), "test");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    expect(await screen.findByText("Dashboard page")).toBeInTheDocument();
  });

  it("returns to the full path and query after login", async () => {
    authState.login = async () => {};
    renderLoginWithAuth("/login?redirect=%2Fmy-app%2Ffindings%3Fseverity%3Dhigh%26tab%3Dopen");
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Email"), "test@test.com");
    await user.type(screen.getByLabelText("Password"), "test");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    expect(await screen.findByText(/Findings page/)).toHaveTextContent("?severity=high&tab=open");
  });

  it.each([
    "/login?redirect=https%3A%2F%2Fevil.example.com%2Fphish",
    "/login?redirect=%2F%2Fevil.example.com",
  ])(
    "falls back to home when redirect is external (%s)",
    async (path) => {
      authState.login = async () => {};
      renderLoginWithAuth(path);
      const user = userEvent.setup();
      await user.type(screen.getByLabelText("Email"), "test@test.com");
      await user.type(screen.getByLabelText("Password"), "test");
      await user.click(screen.getByRole("button", { name: /sign in/i }));

      expect(await screen.findByText("Home page")).toBeInTheDocument();
    },
  );

  it("links to the SSO entry point next to the password form", async () => {
    authState.login = async () => {};
    renderLoginWithAuth("/login");

    const link = await screen.findByRole("link", { name: /sign in with sso/i });
    expect(link).toHaveAttribute("href", "/api/v1/auth/sso/login");
  });

  it("preserves an internal redirect when starting SSO", async () => {
    authState.login = async () => {};
    renderLoginWithAuth("/login?redirect=%2Fdashboard%3Ftab%3Dfindings");

    const link = await screen.findByRole("link", { name: /sign in with sso/i });
    expect(link).toHaveAttribute(
      "href",
      "/api/v1/auth/sso/login?redirect=%2Fdashboard%3Ftab%3Dfindings",
    );
  });
  it("asks for a fresh sign-in from this browser after a browser mismatch, with one SSO button", async () => {
    authState.ssoBrowserMismatch = true;
    renderLoginWithAuth("/login?redirect=%2Fdashboard");

    expect(await screen.findByText("Start sign-in again from this browser.")).toBeInTheDocument();
    const links = screen.getAllByRole("link", { name: /sign in with sso/i });
    expect(links).toHaveLength(1);
    expect(links[0]).toHaveAttribute("href", "/api/v1/auth/sso/login?redirect=%2Fdashboard");
  });

  it("restarts the login from the mismatch notice and records the attempt", async () => {
    localStorage.clear();
    authState.ssoBrowserMismatch = true;
    authState.login = async () => {};
    renderLoginWithAuth("/login");

    const restart = await screen.findByRole("link", { name: /sign in with sso/i });
    restart.addEventListener("click", (event) => event.preventDefault());
    expect(hasPendingSsoAttempt()).toBe(false);

    await userEvent.setup().click(restart);

    expect(hasPendingSsoAttempt()).toBe(true);
  });

  it("shows no mismatch notice for other reasons", async () => {
    authState.login = async () => {};
    renderLoginWithAuth("/login");

    await screen.findByRole("link", { name: /sign in with sso/i });
    expect(screen.queryByText("Start sign-in again from this browser.")).not.toBeInTheDocument();
  });

  it("records the SSO attempt when the SSO link is used, so the return can be accepted", async () => {
    localStorage.clear();
    authState.login = async () => {};
    renderLoginWithAuth("/login");

    const link = await screen.findByRole("link", { name: /sign in with sso/i });
    // jsdom cannot navigate; the click handler is what is under test.
    link.addEventListener("click", (event) => event.preventDefault());
    expect(hasPendingSsoAttempt()).toBe(false);

    await userEvent.setup().click(link);

    expect(hasPendingSsoAttempt()).toBe(true);
  });
});
