import { APIError } from "@/api/client";
import { useProject, useProjectRole } from "@/api/hooks";
import { INLINE_LINK } from "@/components/inlineLink";
import { ProjectNavigation } from "@/components/ProjectNavigation";
import { VerdictBand } from "@/components/VerdictBand";
import { useDocumentTitle } from "@/lib/useDocumentTitle";
import { FindingsDashboard } from "@/pages/FindingsDashboard";
import { ProjectSettings } from "@/pages/project-settings/ProjectSettings";
import { ProjectAccess } from "@/pages/ProjectAccess";
import { ProjectInsights } from "@/pages/ProjectInsights";
import { ProjectPolicy } from "@/pages/ProjectPolicy";
import { ProjectWaivers } from "@/pages/ProjectWaivers";
import { ProjectWatcher } from "@/pages/ProjectWatcher";
import { ReportHistory } from "@/pages/ReportHistory";
import type { ReactNode } from "react";
import { Link, useLocation, useParams } from "react-router-dom";

export function ProjectLayout(
  { reportUploadAction }: { readonly reportUploadAction?: ReactNode; } = {},
) {
  const { slug } = useParams<{ slug: string; }>();
  const location = useLocation();
  const path = location.pathname;
  const currentTab = path.endsWith("/reports")
    ? "reports"
    : path.endsWith("/access")
    ? "access"
    : path.endsWith("/policy")
    ? "policy"
    : path.endsWith("/waivers")
    ? "waivers"
    : path.endsWith("/insights")
    ? "insights"
    : path.endsWith("/watcher")
    ? "watcher"
    : path.endsWith("/settings")
    ? "settings"
    : "findings";

  useDocumentTitle(
    currentTab === "reports"
      ? `${slug} · Reports`
      : currentTab === "access"
      ? `${slug} · Access & Members`
      : currentTab === "policy"
      ? `${slug} · Policy`
      : currentTab === "waivers"
      ? `${slug} · Waivers`
      : currentTab === "insights"
      ? `${slug} · Insights`
      : currentTab === "watcher"
      ? `${slug} · Watcher`
      : currentTab === "settings"
      ? `${slug} · Settings`
      : `${slug} · Findings`,
  );

  const { data: project, error: projectError } = useProject(slug ?? "");
  const { isAdmin } = useProjectRole(slug ?? "");

  // The server answers 403 for a project the person cannot see and for one that does not exist, so
  // the page says both at once and offers no tabs that would each fail the same way.
  if (
    projectError instanceof APIError && (projectError.status === 403 || projectError.status === 404)
  ) {
    return (
      <div className="mx-auto max-w-5xl px-4 py-8">
        <h1 className="text-title font-bold">You cannot open this project</h1>
        <p className="text-muted-foreground mt-2 max-w-[60ch]">
          The project does not exist or you are not a member. Ask a project admin to add you.
        </p>
        <Link
          to="/"
          className={`${INLINE_LINK} mt-4 inline-block text-body`}
        >
          Back to projects
        </Link>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-5xl px-4 py-8">
      <nav aria-label="Breadcrumb" className="mb-4 flex items-center gap-2">
        <Link to="/" className="text-muted-foreground hover:text-foreground text-body">
          Projects
        </Link>
        <span aria-hidden="true" className="text-muted-foreground">
          ›
        </span>
        <h1 className="text-title font-bold">{project?.name ?? slug}</h1>
      </nav>

      <div className="mb-6">
        <VerdictBand slug={slug ?? ""} />
      </div>

      <ProjectNavigation slug={slug ?? ""} currentTab={currentTab} isAdmin={isAdmin} />
      {currentTab === "findings"
        ? <FindingsDashboard />
        : currentTab === "reports"
        ? <ReportHistory uploadAction={reportUploadAction} />
        : currentTab === "policy"
        ? <ProjectPolicy />
        : currentTab === "waivers"
        ? <ProjectWaivers />
        : currentTab === "insights"
        ? <ProjectInsights />
        : currentTab === "watcher"
        ? <ProjectWatcher />
        : currentTab === "settings"
        ? <ProjectSettings />
        : <ProjectAccess />}
    </div>
  );
}
