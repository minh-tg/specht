import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { AuthContext, type AuthContextValue } from "./context";
import { ProtectedRoute } from "./ProtectedRoute";

function renderProtected(token: string | null, loading = false) {
  const auth: AuthContextValue = {
    token,
    userId: token ? "u1" : null,
    email: token ? "test@test.com" : null,
    login: async () => {},
    logout: () => {},
    loading,
  };

  return render(
    <MemoryRouter initialEntries={["/protected"]}>
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
          <Route path="/login" element={<p>Login page</p>} />
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

  it("shows a loading placeholder, not a blank page, while the session is restored", () => {
    renderProtected(null, true);
    expect(screen.getByRole("status", { name: "Loading" })).toBeInTheDocument();
    expect(screen.queryByText("Protected content")).not.toBeInTheDocument();
    expect(screen.queryByText("Login page")).not.toBeInTheDocument();
  });
});
