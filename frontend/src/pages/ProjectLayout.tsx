import { APIError } from "@/api/client";
import { useProject, useProjectRole } from "@/api/hooks";
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
import { Link, useLocation, useParams } from "react-router-dom";

export function ProjectLayout() {
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
        <h1 className="text-2xl font-bold">You cannot open this project</h1>
        <p className="text-muted-foreground mt-2 max-w-[60ch]">
          The project does not exist or you are not a member. Ask a project admin to add you.
        </p>
        <Link
          to="/"
          className="text-action mt-4 inline-block text-sm underline underline-offset-4"
        >
          Back to projects
        </Link>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-5xl px-4 py-8">
      <nav aria-label="Breadcrumb" className="mb-4 flex items-center gap-2">
        <Link to="/" className="text-muted-foreground hover:text-foreground text-sm">
          Projects
        </Link>
        <span aria-hidden="true" className="text-muted-foreground">
          ›
        </span>
        <h1 className="text-2xl font-bold">{project?.name ?? slug}</h1>
      </nav>

      <div className="mb-6">
        <VerdictBand slug={slug ?? ""} />
      </div>

      <nav
        aria-label="Project sections"
        className="mb-6 flex gap-4 overflow-x-auto border-b whitespace-nowrap"
      >
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
        <Link
          to={`/${slug}/access`}
          aria-current={currentTab === "access" ? "page" : undefined}
          className={`pb-2 text-sm font-medium ${
            currentTab === "access"
              ? "border-primary text-foreground border-b-2"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Access & Members
        </Link>
        <Link
          to={`/${slug}/policy`}
          aria-current={currentTab === "policy" ? "page" : undefined}
          className={`pb-2 text-sm font-medium ${
            currentTab === "policy"
              ? "border-primary text-foreground border-b-2"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Policy
        </Link>
        <Link
          to={`/${slug}/waivers`}
          aria-current={currentTab === "waivers" ? "page" : undefined}
          className={`pb-2 text-sm font-medium ${
            currentTab === "waivers"
              ? "border-primary text-foreground border-b-2"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Waivers
        </Link>
        <Link
          to={`/${slug}/insights`}
          aria-current={currentTab === "insights" ? "page" : undefined}
          className={`pb-2 text-sm font-medium ${
            currentTab === "insights"
              ? "border-primary text-foreground border-b-2"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Insights
        </Link>
        <Link
          to={`/${slug}/watcher`}
          aria-current={currentTab === "watcher" ? "page" : undefined}
          className={`pb-2 text-sm font-medium ${
            currentTab === "watcher"
              ? "border-primary text-foreground border-b-2"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Watcher
        </Link>
        {isAdmin && (
          <Link
            to={`/${slug}/settings`}
            aria-current={currentTab === "settings" ? "page" : undefined}
            className={`pb-2 text-sm font-medium ${
              currentTab === "settings"
                ? "border-primary text-foreground border-b-2"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            Settings
          </Link>
        )}
      </nav>
      {currentTab === "findings"
        ? <FindingsDashboard />
        : currentTab === "reports"
        ? <ReportHistory />
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
