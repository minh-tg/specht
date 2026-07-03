import { useNavigate } from "react-router-dom"
import { useProjects } from "@/api/hooks"

export function ProjectList() {
  const { data: projects, isLoading, isError, error, refetch } = useProjects()
  const navigate = useNavigate()

  if (isLoading) {
    return (
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="bg-muted h-32 animate-pulse rounded-lg" />
        ))}
      </div>
    )
  }

  if (isError) {
    return (
      <div className="flex flex-col items-center gap-2 py-16">
        <p className="text-destructive text-sm">{error?.message ?? "Failed to load projects"}</p>
        <button
          className="text-primary text-sm underline hover:no-underline"
          onClick={() => refetch()}
        >
          Retry
        </button>
      </div>
    )
  }

  if (!projects?.length) {
    return (
      <div className="flex flex-col items-center gap-2 py-16">
        <p className="text-muted-foreground text-sm">No projects yet</p>
        <p className="text-muted-foreground text-xs">
          Ingest a scan report or create a project via the API
        </p>
      </div>
    )
  }

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {projects.map((p) => (
        <button
          key={p.id}
          onClick={() => navigate(`/${p.slug}/findings`)}
          className="bg-card hover:bg-muted/50 dark:bg-muted/10 cursor-pointer rounded-lg border p-4 text-left transition-colors"
        >
          <h3 className="font-medium">{p.name}</h3>
          {p.description && (
            <p className="text-muted-foreground mt-1 text-xs">{p.description}</p>
          )}
        </button>
      ))}
    </div>
  )
}
