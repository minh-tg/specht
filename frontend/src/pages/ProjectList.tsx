import { apiFetch } from "@/api/client";
import { queryKeys, useMe, useProjects } from "@/api/hooks";
import { buttonVariants } from "@/components/ui/button-variants";
import { Skeleton } from "@/components/ui/skeleton";
import { VerdictBadge } from "@/components/VerdictBadge";
import { formatDateTime, formatRelativeTime } from "@/lib/format";
import { blockerCount, degradedMessage, projectVerdict, type Verdict } from "@/lib/verdict";
import type { GateStatus, Project, ProjectStats } from "@/types/api";
import { useQueries } from "@tanstack/react-query";
import { type ReactNode } from "react";
import { Link } from "react-router-dom";

/** Em dash shown wherever a project has no value to report. */
const EMPTY = "–";

const COLUMNS = ["Project", "Verdict", "Blocking", "Findings", "Last scan"] as const;
const SKELETON_ROW_COUNT = 3;

const VERDICT_PRIORITY: Record<Verdict, number> = {
  blocked: 0,
  no_scans: 1,
  passing: 2,
  unknown: 3,
};

/**
 * A project plus the two per-project queries the row needs. `settled` gates
 * sorting so rows never reorder while their data is still in flight, and
 * `failed` lets a broken row degrade to dashes instead of half-truths.
 */
interface ProjectRowData {
  project: Project;
  gate: GateStatus | undefined;
  stats: ProjectStats | undefined;
  settled: boolean;
  failed: boolean;
}

export function ProjectList() {
  const { data: projects, isLoading, isError, error, refetch } = useProjects();
  const { data: me } = useMe();
  const isAdmin = me?.role === "admin";
  const projectList = projects ?? [];

  const gateQueries = useQueries({
    queries: projectList.map((project) => ({
      queryKey: queryKeys.gate(project.slug),
      queryFn: () => apiFetch<GateStatus>(`/api/v1/projects/${project.slug}/gate`),
    })),
  });

  const statsQueries = useQueries({
    queries: projectList.map((project) => ({
      queryKey: queryKeys.projectStats(project.slug),
      queryFn: () => apiFetch<ProjectStats>(`/api/v1/projects/${project.slug}/stats`),
    })),
  });

  if (isLoading) {
    return <ProjectTableSkeleton />;
  }

  if (isError) {
    return (
      <div className="flex flex-col items-center gap-2 py-16">
        <p className="text-destructive text-sm">{error?.message ?? "Failed to load projects"}</p>
        <button
          className="text-action text-sm underline hover:no-underline"
          onClick={() => refetch()}
        >
          Retry
        </button>
      </div>
    );
  }

  if (projectList.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-16">
        <p className="text-muted-foreground text-sm">No projects yet</p>
        {isAdmin
          ? (
            <Link
              to="/projects/new"
              className="text-action text-sm underline hover:no-underline"
            >
              Create your first project
            </Link>
          )
          : (
            <p className="text-muted-foreground text-xs">
              Ask an administrator to create one.
            </p>
          )}
      </div>
    );
  }

  const rows: ProjectRowData[] = projectList.map((project, index) => {
    const gate = gateQueries[index];
    const stats = statsQueries[index];
    return {
      project,
      gate: gate?.data,
      stats: stats?.data,
      settled: gate !== undefined && stats !== undefined && !gate.isPending && !stats.isPending,
      failed: gate?.isError === true || stats?.isError === true,
    };
  });

  // Alphabetical until every row has settled, then blocked first. Sorting on
  // partial data would make rows jump around as their queries land.
  const allSettled = rows.every((row) => row.settled);
  const ordered = [...rows].sort(allSettled ? compareRows : compareByName);

  // Once everything has settled, name the project to start with: the sort put the one with the
  // most blockers first, so it is the first blocked row.
  const blockedRows = allSettled
    ? ordered.filter((row) => !row.failed && projectVerdict(row) === "blocked")
    : [];
  const startWith = blockedRows[0]?.project;

  return (
    <div className="space-y-4">
      {startWith && (
        <section aria-labelledby="start-here" className="space-y-2">
          <p id="start-here" className="text-lg">
            {blockedRows.length === 1
              ? "1 project is blocked."
              : `${blockedRows.length} projects are blocked.`} Start with{" "}
            <span className="font-semibold">{startWith.name}</span>.
          </p>
          <p className="text-muted-foreground text-xs font-semibold tracking-wide uppercase">
            Do this
          </p>
          <Link to={`/${startWith.slug}/findings`} className={buttonVariants()}>
            Open {startWith.name}
          </Link>
        </section>
      )}
      {isAdmin && (
        <div className="flex justify-end">
          <Link
            to="/projects/new"
            className={buttonVariants({ variant: startWith ? "outline" : "default" })}
          >
            New project
          </Link>
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <caption className="sr-only">Projects</caption>
          <ProjectTableHead />
          <tbody>
            {ordered.map((row) => <ProjectTableRow key={row.project.id} row={row} />)}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function compareByName(a: ProjectRowData, b: ProjectRowData): number {
  return a.project.name.localeCompare(b.project.name);
}

function compareRows(a: ProjectRowData, b: ProjectRowData): number {
  const verdictA = projectVerdict({ gate: a.gate, stats: a.stats });
  const verdictB = projectVerdict({ gate: b.gate, stats: b.stats });

  if (verdictA !== verdictB) {
    return VERDICT_PRIORITY[verdictA] - VERDICT_PRIORITY[verdictB];
  }
  if (verdictA === "blocked") {
    const blockers = blockerCount(b.gate) - blockerCount(a.gate);
    if (blockers !== 0) return blockers;
  }
  return compareByName(a, b);
}

function ProjectTableHead() {
  return (
    <thead>
      <tr className="border-border text-muted-foreground border-b text-left">
        {COLUMNS.map((column) => (
          <th key={column} scope="col" className="px-3 py-2 font-medium">
            {column}
          </th>
        ))}
      </tr>
    </thead>
  );
}

function ProjectTableSkeleton() {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <caption className="sr-only">Projects</caption>
        <ProjectTableHead />
        <tbody>
          {Array.from({ length: SKELETON_ROW_COUNT }).map((_, rowIndex) => (
            <tr key={rowIndex} className="border-border border-b">
              {COLUMNS.map((column) => (
                <td key={column} className="px-3 py-2">
                  <Skeleton className="h-4 rounded" />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ProjectTableRow({ row }: { readonly row: ProjectRowData; }) {
  const { project, gate, stats, failed } = row;
  const verdict = projectVerdict({ gate, stats });

  const degraded = failed ? null : degradedMessage(stats);
  const blocking = !failed && verdict === "blocked" ? String(blockerCount(gate)) : EMPTY;
  const findings = !failed && stats ? stats.total_findings : EMPTY;

  let lastScan: ReactNode = EMPTY;
  if (!failed && stats) {
    if (stats.report_count === 0) {
      lastScan = "Never";
    } else {
      const createdAt = stats.latest_report?.created_at;
      lastScan = <span title={formatDateTime(createdAt)}>{formatRelativeTime(createdAt)}</span>;
    }
  }

  return (
    <tr className="border-border border-b">
      <td className="px-3 py-2">
        <Link
          to={`/${project.slug}/findings`}
          className="text-action font-medium hover:underline"
        >
          {project.name}
        </Link>
        {project.description && (
          <p className="text-muted-foreground text-xs">{project.description}</p>
        )}
        {degraded && (
          <p className="bg-sev-high-bg text-sev-high-fg mt-1 inline-block rounded px-2 py-0.5 text-xs">
            {degraded}
          </p>
        )}
      </td>
      <td className="px-3 py-2">
        <VerdictBadge verdict={verdict} />
      </td>
      <td className="px-3 py-2">{blocking}</td>
      <td className="px-3 py-2">{findings}</td>
      <td className="text-muted-foreground px-3 py-2">{lastScan}</td>
    </tr>
  );
}
