import { APIError } from "@/api/client";
import {
  queryKeys,
  useChangeGate,
  useChangeReports,
  useGateStatus,
  useProject,
  useScanSignal,
} from "@/api/hooks";
import { ErrorState } from "@/components/ErrorState";
import { INLINE_LINK } from "@/components/inlineLink";
import { formatRelativeTime } from "@/lib/format";
import { useDocumentTitle } from "@/lib/useDocumentTitle";
import { useOnline } from "@/lib/useOnline";
import { blockerCount, isReportInProgress } from "@/lib/verdict";
import { BlockerSection, MAX_BLOCKER_ROWS } from "@/pages/change-view/BlockerSection";
import { ChangeHero, ChangeHeroSkeleton, type ChangeState } from "@/pages/change-view/ChangeHero";
import { ExistingDebt } from "@/pages/change-view/ExistingDebt";
import { existingBlockers, resolveReport, shortCommit } from "@/pages/change-view/resolve";
import { WatchStrip } from "@/pages/change-view/WatchStrip";
import { useQueryClient } from "@tanstack/react-query";
import { type ReactNode, useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";

export { MAX_BLOCKER_ROWS };

function Page({ children }: { children: ReactNode; }) {
  return <div className="mx-auto max-w-5xl px-4 py-8">{children}</div>;
}

function ProjectNotFound() {
  return (
    <Page>
      <h1 className="text-title font-bold">Project not found</h1>
      <p className="text-muted-foreground mt-2 text-body">
        There is no project with this address, or you don&apos;t have access to it.
      </p>
      <Link to="/" className={`${INLINE_LINK} mt-4 inline-block text-body`}>
        Back to projects
      </Link>
    </Page>
  );
}

function Crumbs(
  { slug, commit, projectName }: { slug: string; commit: string; projectName: string; },
) {
  return (
    <nav
      aria-label="Breadcrumb"
      className="text-muted-foreground mb-5 flex flex-wrap items-center gap-2 text-meta"
    >
      <Link to="/" className="text-muted-foreground hover:text-foreground">Projects</Link>
      <span aria-hidden="true">/</span>
      <Link to={`/${slug}/findings`} className="text-muted-foreground hover:text-foreground">
        {projectName}
      </Link>
      <span aria-hidden="true">/</span>
      <span>Change {shortCommit(commit)}</span>
    </nav>
  );
}

function NoReport(
  { slug, commit, canUpload }: { slug: string; commit: string; canUpload: boolean; },
) {
  return (
    <div className="mt-8">
      <h1 className="text-title leading-tight font-bold">
        No scan found for commit {shortCommit(commit)}
      </h1>
      <p className="mt-2 max-w-[58ch] text-section font-normal leading-snug">
        The pipeline may still be running, or this commit was never scanned.
      </p>
      <div className="mt-4 flex flex-wrap gap-4 text-body">
        <Link to={`/${slug}/reports`} className={INLINE_LINK}>Reports</Link>
        {canUpload && (
          <Link to={`/${slug}/reports/upload`} className={INLINE_LINK}>Upload a report</Link>
        )}
      </div>
    </div>
  );
}

/**
 * The page a developer lands on from a failing check: what this change introduced and what to do
 * about the findings that block it. Pre-existing debt is folded away below.
 */
export function ChangeView() {
  const { slug = "", commit = "" } = useParams<{ slug: string; commit: string; }>();
  const [searchParams] = useSearchParams();
  const reportParam = searchParams.get("report");
  const projectWide = searchParams.get("scope") === "project";
  const severity = searchParams.get("severity") || undefined;
  const short = shortCommit(commit);
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  useDocumentTitle(`${slug} · Change ${short}`);

  const online = useOnline();
  const projectQuery = useProject(slug);
  const reportsQuery = useChangeReports(slug, commit, reportParam);
  const report = resolveReport(reportsQuery.data, commit, reportParam);
  const degraded = report !== null
    && (isReportInProgress(report.status) || report.status === "failed");
  // A scan without a verdict must not be scoped through the gate.
  const changeGateQuery = useChangeGate(
    slug,
    degraded ? undefined : report?.id,
    projectWide,
    severity,
  );
  const projectGateQuery = useGateStatus(slug, severity);
  // Refetches every query the page reads. The change gate stays out while it is disabled
  // (no report, or a scan still running), since refetching it would request a gate for nothing.
  const retryLoad = () => {
    const pending = [
      projectQuery.refetch(),
      reportsQuery.refetch(),
      projectGateQuery.refetch(),
    ];
    if (!degraded && report) pending.push(changeGateQuery.refetch());
    return Promise.all(pending);
  };

  // Waiting for the next scan: begins when the reader says they pushed, or has handled every
  // blocker. It ends when a newer report on this branch is final, and the page moves to its change.
  const [waitingFor, setWaitingFor] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const waiting = report !== null && waitingFor === report.id;
  const reportId = report?.id ?? null;
  const startWaiting = useCallback(() => setWaitingFor(reportId), [reportId]);
  const checkAgain = useCallback(() => setAttempt((count) => count + 1), []);
  const signal = useScanSignal(slug, {
    branch: report?.branch,
    enabled: waiting && report !== null,
    attempt,
  });
  const newer = signal.newest && report && signal.newest.id !== report.id
      && signal.newest.created_at > report.created_at
    ? signal.newest
    : null;
  const scanningNewer = newer !== null && isReportInProgress(newer.status);
  const landed = newer !== null && !scanningNewer ? newer : null;

  useEffect(() => {
    if (!landed) return;
    void queryClient.invalidateQueries({ queryKey: queryKeys.reports(slug) });
    void queryClient.invalidateQueries({ queryKey: queryKeys.gate() });
    if (landed.commit_sha) {
      const query = new URLSearchParams({
        report: landed.id,
        scope: projectWide ? "project" : "introduced",
      });
      if (severity) query.set("severity", severity);
      navigate(`/${slug}/changes/${shortCommit(landed.commit_sha)}?${query}`, { replace: true });
    }
  }, [landed, navigate, queryClient, slug, projectWide, severity]);

  if (
    projectQuery.isError && projectQuery.error instanceof APIError
    && projectQuery.error.status === 404
  ) {
    return <ProjectNotFound />;
  }

  const crumbs = (
    <Crumbs slug={slug} commit={commit} projectName={projectQuery.data?.name ?? slug} />
  );

  if (reportsQuery.isPending) {
    return (
      <Page>
        {crumbs}
        <ChangeHeroSkeleton commit={commit} />
      </Page>
    );
  }

  // A failed check while a scan is processing leaves the page it has; only a page with nothing to
  // show turns into an error.
  const requestError = reportsQuery.error ?? projectQuery.error ?? changeGateQuery.error;
  if (
    (reportsQuery.isError && reportsQuery.data === undefined) || projectQuery.isError
    || changeGateQuery.isError
  ) {
    return (
      <Page>
        {crumbs}
        <ErrorState
          title="Specht could not load this change."
          detail={
            <>
              <p>
                The verdict on your pull request is still the one CI reported. Nothing here changes
                it.
              </p>
              {requestError instanceof Error && <p>The server said: {requestError.message}</p>}
            </>
          }
          requestId={requestError instanceof APIError ? requestError.requestId : undefined}
          retryLabel="Try again"
          onRetry={() => void retryLoad()}
        />
        <Link to={`/${slug}/findings`} className={`${INLINE_LINK} mt-4 inline-block text-body`}>
          Back to project
        </Link>
      </Page>
    );
  }

  if (!report) {
    return (
      <Page>
        {crumbs}
        <NoReport
          slug={slug}
          commit={commit}
          canUpload={projectQuery.data?.permissions?.upload_reports === true}
        />
      </Page>
    );
  }

  if (degraded) {
    const state: ChangeState = report.status === "failed" ? "failed" : "processing";
    return (
      <Page>
        {crumbs}
        <ChangeHero
          commit={commit}
          report={report}
          state={state}
          blockers={0}
          existing={0}
          waived={0}
          watch={state === "processing"
            ? (
              <WatchStrip
                label="Watching"
                announce={false}
                watch={{
                  online,
                  stalled: false,
                  checkedAt: reportsQuery.dataUpdatedAt,
                  failing: reportsQuery.isRefetchError,
                }}
              />
            )
            : undefined}
        />
      </Page>
    );
  }

  if (changeGateQuery.isPending || !changeGateQuery.data) {
    return (
      <Page>
        {crumbs}
        <ChangeHeroSkeleton commit={commit} />
      </Page>
    );
  }

  const gate = changeGateQuery.data;
  const blockedBy = gate.blocked_by ?? [];
  const existing = existingBlockers(projectGateQuery.data?.blocked_by, blockedBy);
  const state: ChangeState = scanningNewer
    ? "scanning"
    : gate.threshold_breached
    ? "blocked"
    : "passing";

  return (
    <Page>
      {crumbs}
      <ChangeHero
        commit={commit}
        report={report}
        state={state}
        blockers={blockerCount(gate)}
        existing={existing.length}
        waived={gate.waived_count ?? 0}
        policy={gate.policy}
        projectWide={projectWide}
      />
      {gate.threshold_breached && (
        <BlockerSection
          key={report.id}
          slug={slug}
          ids={blockedBy}
          floor={gate.policy?.severity_floor}
          canRequestWaiver={projectQuery.data?.permissions?.request_waiver ?? false}
          projectWide={projectWide}
          waiting={waiting}
          stalled={signal.stalled}
          onStartWaiting={startWaiting}
          onCheckAgain={checkAgain}
        />
      )}
      <ExistingDebt
        slug={slug}
        ids={existing}
        passing={state === "passing" && !projectWide}
        projectName={projectQuery.data?.name}
      />
      <p className="sr-only" role="status">
        {scanningNewer && newer
          ? `A new scan started ${formatRelativeTime(newer.created_at)}.`
          : ""}
      </p>
    </Page>
  );
}
