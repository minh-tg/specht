import { BrowserRouter, Routes, Route, Navigate, Link, useParams, useLocation } from "react-router-dom"
import { AuthProvider } from "@/auth/AuthContext"
import { ProtectedRoute } from "@/auth/ProtectedRoute"
import { Navbar } from "@/components/Navbar"
import { ProjectList } from "@/pages/ProjectList"
import { FindingsDashboard } from "@/pages/FindingsDashboard"
import { ReportHistory } from "@/pages/ReportHistory"
import { Login } from "@/pages/Login"
import { Ingest } from "@/pages/Ingest"
import { ApiKeys } from "@/pages/ApiKeys"

function ProjectLayout() {
  const { slug } = useParams<{ slug: string }>()
  const location = useLocation()
  const currentTab = location.pathname.endsWith("/reports") ? "reports" : "findings"

  return (
    <div className="mx-auto max-w-5xl px-4 py-8">
      <Link to="/" className="text-muted-foreground hover:text-foreground mb-6 inline-block text-sm">
        &larr; Projects
      </Link>
      <div className="mb-6 flex gap-4 border-b">
        <Link
          to={`/${slug}/findings`}
          className={`pb-2 text-sm font-medium ${currentTab === "findings" ? "border-primary text-foreground border-b-2" : "text-muted-foreground hover:text-foreground"}`}
        >
          Findings
        </Link>
        <Link
          to={`/${slug}/reports`}
          className={`pb-2 text-sm font-medium ${currentTab === "reports" ? "border-primary text-foreground border-b-2" : "text-muted-foreground hover:text-foreground"}`}
        >
          Reports
        </Link>
      </div>
      {currentTab === "findings" ? <FindingsDashboard /> : <ReportHistory />}
    </div>
  )
}

function HomePage() {
  return (
    <div className="mx-auto max-w-5xl px-4 py-8">
      <h1 className="mb-6 text-2xl font-bold">Projects</h1>
      <ProjectList />
    </div>
  )
}

function AppLayout() {
  return (
    <AuthProvider>
      <Navbar />
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <HomePage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/:slug/findings"
          element={
            <ProtectedRoute>
              <ProjectLayout />
            </ProtectedRoute>
          }
        />
        <Route
          path="/:slug/reports"
          element={
            <ProtectedRoute>
              <ProjectLayout />
            </ProtectedRoute>
          }
        />
        <Route
          path="/ingest"
          element={
            <ProtectedRoute>
              <Ingest />
            </ProtectedRoute>
          }
        />
        <Route
          path="/api-keys"
          element={
            <ProtectedRoute>
              <ApiKeys />
            </ProtectedRoute>
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AppLayout />
    </BrowserRouter>
  )
}
