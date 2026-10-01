import { useDocumentTitle } from "@/lib/useDocumentTitle";
import { FindingsDashboard } from "@/pages/FindingsDashboard";
import { ReportHistory } from "@/pages/ReportHistory";
import { Link, useLocation, useParams } from "react-router-dom";

export function ProjectLayout() {
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
