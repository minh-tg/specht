import { AuthProvider } from "@/auth/AuthContext";
import { ProtectedRoute } from "@/auth/ProtectedRoute";
import { Navbar } from "@/components/Navbar";
import { useDocumentTitle } from "@/lib/useDocumentTitle";
import { ApiKeys } from "@/pages/ApiKeys";
import { FindingDetail } from "@/pages/FindingDetail";
import { Ingest } from "@/pages/Ingest";
import { Login } from "@/pages/Login";
import { NewProject } from "@/pages/NewProject";
import { ProjectLayout } from "@/pages/ProjectLayout";
import { ProjectList } from "@/pages/ProjectList";
import { ProjectSetup } from "@/pages/ProjectSetup";
import { Register } from "@/pages/Register";
import { UploadReport } from "@/pages/UploadReport";
import { type ReactNode } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";

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
