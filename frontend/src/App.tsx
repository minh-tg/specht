import { AuthProvider } from "@/auth/AuthContext";
import { ProtectedRoute } from "@/auth/ProtectedRoute";
import { Navbar } from "@/components/Navbar";
import { useDocumentTitle } from "@/lib/useDocumentTitle";
import { ApiKeys } from "@/pages/ApiKeys";
import { FindingDetail } from "@/pages/FindingDetail";
import { FindingsDashboard } from "@/pages/FindingsDashboard";
import { Ingest } from "@/pages/Ingest";
import { Login } from "@/pages/Login";
import { ProjectList } from "@/pages/ProjectList";
import { Register } from "@/pages/Register";
import { ReportHistory } from "@/pages/ReportHistory";
import { type ReactNode } from "react";
import {
  BrowserRouter,
  Link,
  Navigate,
  Route,
  Routes,
  useLocation,
  useParams,
} from "react-router-dom";

function ProjectLayout() {
  const { slug } = useParams<{ slug: string; }>();
  const location = useLocation();
  const path = location.pathname;
  const currentTab = path.endsWith("/reports") ? "reports" : "findings";
  useDocumentTitle(currentTab === "reports" ? `${slug} · Reports` : `${slug} · Findings`);

  return (
    <div className="mx-auto max-w-5xl px-4 py-8">
      <Link
        to="/"
        className="text-muted-foreground hover:text-foreground mb-6 inline-block text-sm"
      >
        &larr; Projects
      </Link>
      <nav aria-label="Project sections" className="mb-6 flex gap-4 border-b">
        <Link
          to={`/${slug}/findings`}
          aria-current={currentTab === "findings" ? "page" : undefined}
          className={`pb-2 text-sm font-medium ${
            currentTab === "findings"
              ? "border-primary text-foreground border-b-2"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Findings
        </Link>
        <Link
          to={`/${slug}/reports`}
          aria-current={currentTab === "reports" ? "page" : undefined}
          className={`pb-2 text-sm font-medium ${
            currentTab === "reports"
              ? "border-primary text-foreground border-b-2"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Reports
        </Link>
      </nav>
      {currentTab === "findings" ? <FindingsDashboard /> : <ReportHistory />}
    </div>
  );
}

function HomePage() {
  useDocumentTitle("Projects");

  return (
    <div className="mx-auto max-w-5xl px-4 py-8">
      <h1 className="mb-6 text-2xl font-bold">Projects</h1>
      <ProjectList />
    </div>
  );
}

function Titled({ title, children }: { title: string; children: ReactNode; }) {
  useDocumentTitle(title);
  return children;
}

export function AppRoutes() {
  return (
    <Routes>
      <Route
        path="/login"
        element={
          <Titled title="Sign in">
            <Login />
          </Titled>
        }
      />
      <Route
        path="/register"
        element={
          <Titled title="Register">
            <Register />
          </Titled>
        }
      />
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
        path="/:slug/findings/:findingId"
        element={
          <ProtectedRoute>
            <Titled title="Finding">
              <FindingDetail />
            </Titled>
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
            <Titled title="Ingest report">
              <Ingest />
            </Titled>
          </ProtectedRoute>
        }
      />
      <Route
        path="/api-keys"
        element={
          <ProtectedRoute>
            <Titled title="API keys">
              <ApiKeys />
            </Titled>
          </ProtectedRoute>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

function AppLayout() {
  return (
    <AuthProvider>
      <Navbar />
      <AppRoutes />
    </AuthProvider>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppLayout />
    </BrowserRouter>
  );
}
