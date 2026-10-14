import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { AuthContext, type AuthContextValue } from "./context";
import { ProtectedRoute } from "./ProtectedRoute";

function LoginLocation() {
  const location = useLocation();
  return (
    <>
      <p>Login page</p>
      <p data-testid="login-search">{location.search}</p>
    </>
  );
}

function renderProtected(token: string | null, loading = false, url = "/protected") {
  const auth: AuthContextValue = {
    token,
    userId: token ? "u1" : null,
    email: token ? "test@test.com" : null,
    login: async () => {},
    logout: () => {},
    adopt: () => {},
    loading,
  };

  return render(
    <MemoryRouter initialEntries={[url]}>
      <AuthContext.Provider value={auth}>
        <Routes>
          <Route
            path="/protected"
            element={
              <ProtectedRoute>
                <p>Protected content</p>
              </ProtectedRoute>
            }
          />
          <Route path="/login" element={<LoginLocation />} />
          <Route
            path="/my-app/findings"
            element={
              <ProtectedRoute>
                <p>Protected content</p>
              </ProtectedRoute>
            }
          />
        </Routes>
      </AuthContext.Provider>
    </MemoryRouter>,
  );
}

describe("ProtectedRoute", () => {
  it("renders children when authenticated", () => {
    renderProtected("valid-token");
    expect(screen.getByText("Protected content")).toBeInTheDocument();
  });

  it("redirects to login when not authenticated", () => {
    renderProtected(null);
    expect(screen.getByText("Login page")).toBeInTheDocument();
    expect(screen.queryByText("Protected content")).not.toBeInTheDocument();
  });

  it("keeps the query string and hash in the redirect target", () => {
    renderProtected(null, false, "/my-app/findings?severity=high&tab=open#row-3");
    const params = new URLSearchParams(screen.getByTestId("login-search").textContent ?? "");
    expect(params.get("redirect")).toBe("/my-app/findings?severity=high&tab=open#row-3");
  });

  it("shows a loading placeholder, not a blank page, while the session is restored", () => {
    renderProtected(null, true);
    expect(screen.getByRole("status", { name: "Loading" })).toBeInTheDocument();
    expect(screen.queryByText("Protected content")).not.toBeInTheDocument();
    expect(screen.queryByText("Login page")).not.toBeInTheDocument();
  });
});
