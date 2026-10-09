import { APIError } from "@/api/client";
import {
  findingQueryOptions,
  useChangeGate,
  useGateStatus,
  useProject,
  useReports,
} from "@/api/hooks";
import { formatDateTime, formatRelativeTime } from "@/lib/format";
import { useDocumentTitle } from "@/lib/useDocumentTitle";
import { blockerCount, isReportInProgress } from "@/lib/verdict";
import { BlockerRowView } from "@/pages/change-view/BlockerRow";
import { ChangeVerdict } from "@/pages/change-view/ChangeVerdict";
import { ExistingDebt } from "@/pages/change-view/ExistingDebt";
import { existingBlockers, resolveReport, shortCommit } from "@/pages/change-view/resolve";
import type { Report } from "@/types/api";
import { useQueries } from "@tanstack/react-query";
import { type ReactNode, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";

/** Rows rendered before the "Show all" control reveals the rest. */
export const MAX_BLOCKER_ROWS = 20;

const LINK_CLASS = "text-action underline underline-offset-2 hover:no-underline";

function Page({ children }: { children: ReactNode; }) {
  return <div className="mx-auto max-w-3xl px-4 py-8">{children}</div>;
}

function ProjectNotFound() {
  return (
    <div className="mx-auto max-w-3xl px-4 py-8">
      <h1 className="text-2xl font-bold">Project not found</h1>
      <p className="text-muted-foreground mt-2 text-sm">
        There is no project with this address, or you don&apos;t have access to it.
      </p>
      <Link to="/" className={`${LINK_CLASS} mt-4 inline-block text-sm`}>
        Back to projects
      </Link>
    </div>
  );
}

interface ChangeHeaderProps {
  slug: string;
  commit: string;
  projectName: string;
  report: Report | null;
}

function ChangeHeader({ slug, commit, projectName, report }: ChangeHeaderProps) {
  const short = shortCommit(commit);

  return (
    <>
      <nav aria-label="Breadcrumb" className="mb-4 flex flex-wrap items-center gap-2">
        <Link to="/" className="text-muted-foreground hover:text-foreground text-sm">
          Projects
        </Link>
        <span aria-hidden="true" className="text-muted-foreground">
          ›
        </span>
        <Link
          to={`/${slug}/findings`}
          className="text-muted-foreground hover:text-foreground text-sm"
        >
          {projectName}
        </Link>
        <span aria-hidden="true" className="text-muted-foreground">
          ›
        </span>
        <span className="text-muted-foreground text-sm">Change {short}</span>
      </nav>
      <h1 className="text-2xl font-bold">Change {short}</h1>
      {report && (
        <p className="text-muted-foreground mt-1 text-sm">
          {report.branch && <span>{report.branch}</span>}
          {report.branch && " · "}
          <span title={formatDateTime(report.created_at)}>
            scanned {formatRelativeTime(report.created_at)}
          </span>
          {report.tool_name ? ` · ${report.tool_name}` : ""}
        </p>
      )}
    </>
  );
}

/** The verdict block reserve while the page or the gate is loading. */
function ChangeLoading() {
  return (
    <div className="mt-6 space-y-3">
      <ChangeVerdict kind="no_verdict" blockers={0} waived={0} loading />
      {Array.from({ length: 3 }).map((_, index) => (
        <div key={index} className="bg-muted h-16 animate-pulse rounded" />
      ))}
    </div>
  );
}

function BlockerList({ slug, ids }: { slug: string; ids: string[]; }) {
  const [showAll, setShowAll] = useState(false);
  const shown = showAll ? ids : ids.slice(0, MAX_BLOCKER_ROWS);
  const results = useQueries({ queries: shown.map((id) => findingQueryOptions(id)) });

  if (ids.length === 0) return null;

  return (
    <section aria-label="Findings introduced by this change" className="mt-6">
      <h2 className="mb-2 text-sm font-semibold">Introduced by this change</h2>
      <ul className="bg-card rounded-lg border">
        {shown.map((id, index) => {
          const query = results[index];
          return (
            <BlockerRowView
              key={id}
              slug={slug}
              findingId={id}
              finding={query.data}
              isLoading={query.isPending}
              isError={query.isError}
              onRetry={() => void query.refetch()}
            />
          );
        })}
      </ul>
      {shown.length < ids.length && (
        <button
          type="button"
          className={`${LINK_CLASS} mt-2 text-sm`}
          onClick={() => setShowAll(true)}
        >
          Show all {ids.length}
        </button>
      )}
    </section>
  );
}

function NoReport({ slug, commit }: { slug: string; commit: string; }) {
  return (
    <div className="bg-card mt-6 rounded-lg border p-4">
      <p className="font-medium">No scan found for commit {shortCommit(commit)}</p>
      <p className="text-muted-foreground mt-1 text-sm">
        The pipeline may still be running, or this commit was never scanned.
      </p>
      <div className="mt-3 flex flex-wrap gap-4 text-sm">
        <Link to={`/${slug}/reports`} className={LINK_CLASS}>
          Reports
        </Link>
        <Link to={`/${slug}/reports/upload`} className={LINK_CLASS}>
          Upload a report
        </Link>
      </div>
    </div>
  );
}

function DegradedBanner({ failed, reason }: { failed: boolean; reason?: string; }) {
  if (failed) {
    return (
      <div
        role="alert"
        className="border-destructive text-destructive mb-3 rounded border px-3 py-2 text-sm"
      >
        <p>This scan failed</p>
        {reason && <p className="mt-1 text-xs break-words">{reason}</p>}
      </div>
    );
  }
  return (
    <p role="status" className="bg-muted text-muted-foreground mb-3 rounded px-3 py-2 text-sm">
      This scan is still processing
    </p>
  );
}

/**
 * The page a developer lands on from a failing check: what this change
 * introduced, and what to do about the findings that block it. Pre-existing
 * debt is folded away below the verdict.
 */
export function ChangeView() {
  const { slug = "", commit = "" } = useParams<{ slug: string; commit: string; }>();
  const [searchParams] = useSearchParams();
  const reportParam = searchParams.get("report");
  const short = shortCommit(commit);

  useDocumentTitle(`${slug} · Change ${short}`);

  const projectQuery = useProject(slug);
  const reportsQuery = useReports(slug);
  const report = resolveReport(reportsQuery.data, commit, reportParam);
  const degraded = report !== null
    && (isReportInProgress(report.status) || report.status === "failed");
  // A scan without a verdict must not be scoped through the gate.
  const changeGateQuery = useChangeGate(slug, degraded ? undefined : report?.id);
  const projectGateQuery = useGateStatus(slug);

  if (
    projectQuery.isError && projectQuery.error instanceof APIError
    && projectQuery.error.status === 404
  ) {
    return <ProjectNotFound />;
  }

  const header = (
    <ChangeHeader
      slug={slug}
      commit={commit}
      projectName={projectQuery.data?.name ?? slug}
      report={report}
    />
  );

  if (reportsQuery.isPending) {
    return (
      <Page>
        {header}
        <ChangeLoading />
      </Page>
    );
  }

  const requestError = reportsQuery.error ?? projectQuery.error ?? changeGateQuery.error;
  if (reportsQuery.isError || projectQuery.isError || changeGateQuery.isError) {
    return (
      <Page>
        {header}
        <div
          role="alert"
          className="border-destructive text-destructive mt-6 rounded border px-3 py-2 text-sm"
        >
          {requestError instanceof Error ? requestError.message : "Could not load this change"}
        </div>
        <Link to={`/${slug}/findings`} className={`${LINK_CLASS} mt-4 inline-block text-sm`}>
          Back to project
        </Link>
      </Page>
    );
  }

  if (!report) {
    return (
      <Page>
        {header}
        <NoReport slug={slug} commit={commit} />
      </Page>
    );
  }

  if (degraded) {
    return (
      <Page>
        {header}
        <div className="mt-6">
          <DegradedBanner failed={report.status === "failed"} reason={report.error_message} />
          <ChangeVerdict kind="no_verdict" blockers={0} waived={0} />
        </div>
      </Page>
    );
  }

  if (changeGateQuery.isPending || !changeGateQuery.data) {
    return (
      <Page>
        {header}
        <ChangeLoading />
      </Page>
    );
  }

  const gate = changeGateQuery.data;
  const blockedBy = gate.blocked_by ?? [];
  const kind = gate.threshold_breached ? "blocked" : "passing";
  const existing = existingBlockers(projectGateQuery.data?.blocked_by, blockedBy);

  return (
    <Page>
      {header}
      <div className="mt-6">
        <ChangeVerdict
          kind={kind}
          blockers={blockerCount(gate)}
          waived={gate.waived_count ?? 0}
          policy={gate.policy}
        />
      </div>
      <BlockerList slug={slug} ids={blockedBy} />
      <ExistingDebt slug={slug} ids={existing} />
    </Page>
  );
}
