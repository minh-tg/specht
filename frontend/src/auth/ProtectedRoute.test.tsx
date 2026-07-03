import { render, screen } from "@testing-library/react"
import { MemoryRouter, Routes, Route } from "react-router-dom"
import { AuthContext, type AuthContextValue } from "./AuthContext"
import { ProtectedRoute } from "./ProtectedRoute"

function renderProtected(token: string | null) {
  const auth: AuthContextValue = {
    token,
    userId: token ? "u1" : null,
    email: token ? "test@test.com" : null,
    login: async () => {},
    logout: () => {},
    loading: false,
  }

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
  )
}

describe("ProtectedRoute", () => {
  it("renders children when authenticated", () => {
    renderProtected("valid-token")
    expect(screen.getByText("Protected content")).toBeInTheDocument()
  })

  it("redirects to login when not authenticated", () => {
    renderProtected(null)
    expect(screen.getByText("Login page")).toBeInTheDocument()
    expect(screen.queryByText("Protected content")).not.toBeInTheDocument()
  })
})
