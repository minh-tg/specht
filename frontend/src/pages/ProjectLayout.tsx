import { useProject } from "@/api/hooks";
import { VerdictBand } from "@/components/VerdictBand";
import { useDocumentTitle } from "@/lib/useDocumentTitle";
import { FindingsDashboard } from "@/pages/FindingsDashboard";
import { ProjectAccess } from "@/pages/ProjectAccess";
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
    : "findings";

  useDocumentTitle(
    currentTab === "reports"
      ? `${slug} · Reports`
      : currentTab === "access"
      ? `${slug} · Access & Members`
      : `${slug} · Findings`,
  );

  const { data: project } = useProject(slug ?? "");

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
      </nav>
      {currentTab === "findings"
        ? <FindingsDashboard />
        : currentTab === "reports"
        ? <ReportHistory />
        : <ProjectAccess />}
    </div>
  );
}
