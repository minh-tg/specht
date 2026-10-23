import { queryKeys } from "@/api/hooks";
import { createQueryClient } from "@/api/queryClient";
import { AuthContext, type AuthContextValue } from "@/auth/context";
import { AppShell } from "@/components/AppShell";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ChangeView } from "@/pages/ChangeView";
import { FindingDetail } from "@/pages/FindingDetail";
import { ProjectLayout } from "@/pages/ProjectLayout";
import { QueryClientProvider } from "@tanstack/react-query";
import { StrictMode, useState } from "react";
import { createRoot } from "react-dom/client";
import { HashRouter, Link, Navigate, Route, Routes } from "react-router-dom";
import { APIError } from "./client";
import snapshot from "./snapshot.json";
import "./demo.css";

const findings = `/${snapshot.slug}/findings`;
const me = snapshot.fixtures["/api/v1/me"].data;
const readOnly = (): never => {
  throw new APIError(403, "demo_read_only", "This demo is read-only. No changes were made.");
};
const observer: AuthContextValue = {
  token: null,
  refreshToken: null,
  userId: me.id,
  email: me.email,
  loading: false,
  ssoBrowserMismatch: false,
  login: async () => readOnly(),
  logout: readOnly,
  adopt: readOnly,
};

export function Unavailable() {
  return (
    <div className="mx-auto max-w-5xl px-4 py-8">
      <h1 className="text-2xl font-bold">Not included in this demo</h1>
      <p className="text-muted-foreground mt-3 max-w-[60ch]">
        Explore findings, reports, a blocked change and waiver history. Uploads, configuration and
        account actions are unavailable. No server is connected.
      </p>
      <Link className="mt-4 inline-block underline underline-offset-4" to={findings}>
        Back to sample findings
      </Link>
    </div>
  );
}
export function Demo() {
  const [dark, setDark] = useState(true);
  const [notice, setNotice] = useState("");
  const header = (
    <header className="border-border border-b px-4 py-4">
      <div className="mx-auto flex max-w-5xl flex-wrap items-center gap-3">
        <a href="../" className="text-lg font-semibold">Specht</a>
        <span className="bg-muted rounded px-2 py-1 text-sm">Read-only demo · Sample data</span>
        <button
          className="border-input ml-auto min-h-11 rounded border px-3 text-sm"
          aria-pressed={dark}
          onClick={() => {
            document.documentElement.classList.toggle("dark", !dark);
            document.documentElement.style.colorScheme = dark ? "light" : "dark";
            setDark(!dark);
          }}
        >
          Dark theme
        </button>
      </div>
      <p className="text-muted-foreground mx-auto mt-3 max-w-5xl text-sm">
        Real interface, fixed synthetic reports. No server, uploads, credentials or saved changes.
      </p>
      <nav
        aria-label="Demo navigation"
        className="mx-auto mt-3 flex max-w-5xl flex-wrap gap-x-5 gap-y-2 text-sm"
      >
        <Link className="demo-nav" to={findings}>Findings</Link>
        <Link className="demo-nav" to={`/${snapshot.slug}/reports`}>Reports</Link>
        <Link className="demo-nav" to={`/${snapshot.slug}/changes/${snapshot.commit}`}>
          Blocked change
        </Link>
        <Link className="demo-nav" to={`/${snapshot.slug}/waivers`}>Waiver history</Link>
        <a className="demo-nav" href="../">Back to product</a>
        <a className="demo-nav" href={__DEMO_SOURCE_URL__}>Source</a>
      </nav>
    </header>
  );
  return (
    <div
      onClickCapture={(event) => {
        const button = (event.target as Element).closest("button");
        if (
          button
          && ["Wait for a new report", "Check again"].includes(button.textContent?.trim() ?? "")
        ) {
          event.preventDefault();
          event.stopPropagation();
          setNotice("Live report monitoring is unavailable in this fixed sample.");
          return;
        }
        const anchor = (event.target as Element).closest<HTMLAnchorElement>("a[href]");
        if (anchor && new URL(anchor.href).pathname.startsWith("/api/")) {
          event.preventDefault();
          setNotice("Downloads and live API links are unavailable in this read-only demo.");
        }
      }}
    >
      <AppShell header={header}>
        {notice && (
          <p role="status" className="bg-muted mx-auto mt-4 max-w-5xl rounded p-3 text-sm">
            {notice}
          </p>
        )}
        <Routes>
          <Route path="/" element={<Navigate to={findings} replace />} />
          <Route path="/:slug/findings" element={<ProjectLayout />} />
          <Route path="/:slug/findings/:findingId" element={<FindingDetail />} />
          <Route path="/:slug/reports" element={<ProjectLayout />} />
          <Route path="/:slug/waivers" element={<ProjectLayout />} />
          <Route path="/:slug/changes/:commit" element={<ChangeView />} />
          <Route path="*" element={<Unavailable />} />
        </Routes>
      </AppShell>
    </div>
  );
}

const queryClient = createQueryClient(false);
queryClient.setQueryData(queryKeys.me(), structuredClone(me));
queryClient.setQueryData(
  queryKeys.project(snapshot.slug),
  structuredClone(snapshot.fixtures["/api/v1/projects/checkout-api"].data),
);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthContext.Provider value={observer}>
        <TooltipProvider delay={300}>
          <HashRouter>
            <Demo />
          </HashRouter>
        </TooltipProvider>
        <Toaster />
      </AuthContext.Provider>
    </QueryClientProvider>
  </StrictMode>,
);
