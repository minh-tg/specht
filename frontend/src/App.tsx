import { BrowserRouter, Routes, Route, Navigate, Link, useParams, useLocation } from "react-router-dom"
import { ProjectList } from "@/pages/ProjectList"
import { FindingsDashboard } from "@/pages/FindingsDashboard"
import { ReportHistory } from "@/pages/ReportHistory"

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

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/:slug/findings" element={<ProjectLayout />} />
        <Route path="/:slug/reports" element={<ProjectLayout />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
