import { AuthProvider } from "@/auth/AuthContext";
import { ProtectedRoute } from "@/auth/ProtectedRoute";
import { SessionCacheGuard } from "@/auth/SessionCacheGuard";
import { AppShell } from "@/components/AppShell";
import { Navbar } from "@/components/Navbar";
import { useDocumentTitle } from "@/lib/useDocumentTitle";
import { Admin } from "@/pages/Admin";
import { ApiKeys } from "@/pages/ApiKeys";
import { ChangeView } from "@/pages/ChangeView";
import { FindingDetail } from "@/pages/FindingDetail";
import { Invite } from "@/pages/Invite";
import { Login } from "@/pages/Login";
import { NewProject } from "@/pages/NewProject";
import { NotFound } from "@/pages/NotFound";
import { Profile } from "@/pages/Profile";
import { ProjectLayout } from "@/pages/ProjectLayout";
import { ProjectList } from "@/pages/ProjectList";
import { ProjectSetup } from "@/pages/ProjectSetup";
import { Register } from "@/pages/Register";
import { ResetPassword } from "@/pages/ResetPassword";
import { Setup } from "@/pages/Setup";
import { TeamsDirectory } from "@/pages/TeamsDirectory";
import { UploadReport } from "@/pages/UploadReport";
import { type ReactNode } from "react";
import { BrowserRouter, Navigate, Route, Routes, useParams } from "react-router-dom";

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

/** A bare project URL opens the project's findings, its default view. */
function ProjectIndexRedirect() {
  const { slug } = useParams<{ slug: string; }>();
  return <Navigate to={`/${slug}/findings`} replace />;
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
        path="/setup"
        element={
          <Titled title="Set up Specht">
            <Setup />
          </Titled>
        }
      />
      <Route
        path="/invite/:token"
        element={
          <Titled title="Invitation">
            <Invite />
          </Titled>
        }
      />
      <Route
        path="/reset/:token"
        element={
          <Titled title="Reset password">
            <ResetPassword />
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
        path="/projects/new"
        element={
          <ProtectedRoute>
            <Titled title="New project">
              <NewProject />
            </Titled>
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
        path="/:slug/access"
        element={
          <ProtectedRoute>
            <ProjectLayout />
          </ProtectedRoute>
        }
      />
      <Route
        path="/:slug/policy"
        element={
          <ProtectedRoute>
            <ProjectLayout />
          </ProtectedRoute>
        }
      />
      <Route
        path="/:slug/waivers"
        element={
          <ProtectedRoute>
            <ProjectLayout />
          </ProtectedRoute>
        }
      />
      <Route
        path="/:slug/insights"
        element={
          <ProtectedRoute>
            <ProjectLayout />
          </ProtectedRoute>
        }
      />
      <Route
        path="/:slug/watcher"
        element={
          <ProtectedRoute>
            <ProjectLayout />
          </ProtectedRoute>
        }
      />
      <Route
        path="/:slug/settings"
        element={
          <ProtectedRoute>
            <ProjectLayout />
          </ProtectedRoute>
        }
      />
      <Route
        path="/admin"
        element={
          <ProtectedRoute>
            <Titled title="Admin">
              <Admin />
            </Titled>
          </ProtectedRoute>
        }
      />
      <Route
        path="/profile"
        element={
          <ProtectedRoute>
            <Titled title="Your profile">
              <Profile />
            </Titled>
          </ProtectedRoute>
        }
      />
      <Route
        path="/teams"
        element={
          <ProtectedRoute>
            <Titled title="Teams">
              <TeamsDirectory />
            </Titled>
          </ProtectedRoute>
        }
      />
      <Route
        path="/:slug/changes/:commit"
        element={
          <ProtectedRoute>
            <ChangeView />
          </ProtectedRoute>
        }
      />
      <Route
        path="/:slug/setup"
        element={
          <ProtectedRoute>
            <Titled title="CI setup">
              <ProjectSetup />
            </Titled>
          </ProtectedRoute>
        }
      />
      <Route
        path="/:slug/reports/upload"
        element={
          <ProtectedRoute>
            <Titled title="Upload report">
              <UploadReport />
            </Titled>
          </ProtectedRoute>
        }
      />
      <Route path="/ingest" element={<Navigate to="/" replace />} />
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
      <Route
        path="/:slug"
        element={
          <ProtectedRoute>
            <ProjectIndexRedirect />
          </ProtectedRoute>
        }
      />
      <Route
        path="*"
        element={
          <Titled title="Not found">
            <NotFound />
          </Titled>
        }
      />
    </Routes>
  );
}

function AppLayout() {
  return (
    <AuthProvider>
      <SessionCacheGuard />
      <AppShell header={<Navbar />}>
        <AppRoutes />
      </AppShell>
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
