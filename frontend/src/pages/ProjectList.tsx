import { useGateStatus, useProjects } from "@/api/hooks";
import { useNavigate } from "react-router-dom";

export function ProjectList() {
  const { data: projects, isLoading, isError, error, refetch } = useProjects();

  if (isLoading) {
    return (
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="bg-muted h-32 animate-pulse rounded-lg" />
        ))}
      </div>
    );
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
    );
  }

  if (!projects?.length) {
    return (
      <div className="flex flex-col items-center gap-2 py-16">
        <p className="text-muted-foreground text-sm">No projects yet</p>
        <p className="text-muted-foreground text-xs">
          Ingest a scan report or create a project via the API
        </p>
      </div>
    );
  }

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {projects.map((p) => (
        <ProjectCard key={p.id} slug={p.slug} name={p.name} description={p.description} />
      ))}
    </div>
  );
}

function ProjectCard(
  { slug, name, description }: { slug: string; name: string; description: string | null; },
) {
  const navigate = useNavigate();
  const { data: gate } = useGateStatus(slug);

  return (
    <button
      onClick={() => navigate(`/${slug}/findings`)}
      className="bg-card hover:bg-muted/50 dark:bg-muted/10 relative cursor-pointer rounded-lg border p-4 text-left transition-colors"
    >
      {gate && gate.threshold_breached && (
        <span className="bg-destructive text-destructive-foreground absolute right-2 top-2 rounded px-1.5 py-0.5 text-[10px] font-medium">
          BLOCKING
        </span>
      )}
      {gate && !gate.threshold_breached && gate.blocking_count > 0 && (
        <span className="bg-muted-foreground/20 text-muted-foreground absolute right-2 top-2 rounded px-1.5 py-0.5 text-[10px] font-medium">
          {gate.blocking_count} blocking
        </span>
      )}
      <h3 className="font-medium">{name}</h3>
      {description && <p className="text-muted-foreground mt-1 text-xs">{description}</p>}
    </button>
  );
}
