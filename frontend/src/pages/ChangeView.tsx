import { APIError } from "@/api/client";
import {
  queryKeys,
  useBranchReports,
  useChangeGate,
  useChangeReports,
  useGateStatus,
  useProject,
  useScanSignal,
} from "@/api/hooks";
import { ErrorState } from "@/components/ErrorState";
import { INLINE_LINK, TOUCH_TARGET } from "@/components/inlineLink";
import { codeSource } from "@/lib/codeLinks";
import { scannedCommit } from "@/lib/commit";
import { formatRelativeTime } from "@/lib/format";
import { useDocumentTitle } from "@/lib/useDocumentTitle";
import { useOnline } from "@/lib/useOnline";
import { blockerCount, isReportInProgress } from "@/lib/verdict";
import { BlockerSection, MAX_BLOCKER_ROWS } from "@/pages/change-view/BlockerSection";
import { ChangeHero, ChangeHeroSkeleton, type ChangeState } from "@/pages/change-view/ChangeHero";
import {
  NewerChangeNotice,
  OfflineNotice,
  StalledNotice,
  UncheckedNotice,
} from "@/pages/change-view/ChangeNotice";
import { ChangeScopeContext } from "@/pages/change-view/changeScope";
import { carryPrevious, judgeCleared, readPrevious } from "@/pages/change-view/cleared";
import { ClearedEnd } from "@/pages/change-view/ClearedEnd";
import { ExistingDebt } from "@/pages/change-view/ExistingDebt";
import {
  commitScans,
  existingBlockers,
  missingScanners,
  shortCommit,
} from "@/pages/change-view/resolve";
import { useEarlierGate } from "@/pages/change-view/useEarlierGate";
import { type WatchState, WatchStrip } from "@/pages/change-view/WatchStrip";
import { useQueryClient } from "@tanstack/react-query";
import { type ReactNode, useEffect } from "react";
import { Link, useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";

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
      <Link to="/" className={`text-muted-foreground hover:text-foreground ${TOUCH_TARGET}`}>
        Projects
      </Link>
      <span aria-hidden="true">/</span>
      <Link
        to={`/${slug}/findings`}
        className={`text-muted-foreground hover:text-foreground ${TOUCH_TARGET}`}
      >
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
  const location = useLocation();
  const queryClient = useQueryClient();

  useDocumentTitle(`${slug} · Change ${short}`);

  const projectQuery = useProject(slug);
  const reportsQuery = useChangeReports(slug, commit);
  // Every scanner's reports of the commit count together, as in the pull-request check. A `report`
  // in the link only picks the report the header links from.
  const scans = commitScans(reportsQuery.data, commit, reportParam);
  const report = scans?.focus ?? null;
  const sha = scans?.sha;
  const degraded = scans !== null && !scans.judged;
  const scanned = scans?.latest.filter((scan) => scan.status === "completed") ?? [];
  // A commit without a completed scan has no verdict, so it must not be scoped through the gate.
  // The project gate is the one of the commit's branch, the same one the CI run checked.
  const changeGateQuery = useChangeGate(
    slug,
    degraded ? undefined : sha,
    projectWide,
    severity,
    report?.branch,
  );
  const projectGateQuery = useGateStatus(slug, severity);

  // After a blocked scan, the findings that blocked it ride along in the location state. When this
  // scan passes, the gate of that earlier scan says which of them are still open.
  const previous = projectWide ? null : readPrevious(location.state, slug, sha);
  const passedNow = !degraded && changeGateQuery.data?.threshold_breached === false;
  const earlierGateQuery = useEarlierGate(
    slug,
    previous && passedNow ? previous.commit : undefined,
    severity,
  );
  const cleared = previous && passedNow
    ? judgeCleared(previous, earlierGateQuery.data, earlierGateQuery.status)
    : null;
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

  // Watching for the next scan runs for as long as the page shows a judged commit on a branch. A
  // newer report of this commit is another scanner's and joins the page. A newer report of another
  // commit ends the watch once it is final, and the page moves to its change.
  const online = useOnline();
  const newestHere = scans?.reports[0];
  const watching = scans !== null && scans.judged && !!report?.branch;
  const signal = useScanSignal(slug, {
    branch: report?.branch,
    enabled: watching,
    current: newestHere ? { id: newestHere.id, createdAt: newestHere.created_at } : undefined,
    commit: sha,
  });
  // A page showing an older commit expects nothing more: those scanners moved on.
  const branchReportsQuery = useBranchReports(slug, report?.branch, watching && !signal.superseded);
  const missing = scans && !signal.superseded
    ? missingScanners(branchReportsQuery.data, scans)
    : [];
  const newer = signal.newer;
  const joined = newer !== null && !!sha && scannedCommit(newer, sha) ? newer : null;
  const elsewhere = newer !== null && !joined ? newer : null;
  const scanningNewer = elsewhere !== null && isReportInProgress(elsewhere.status);
  const landed = elsewhere !== null && !scanningNewer ? elsewhere : null;
  const watch: WatchState | undefined = signal.watching
    ? {
      online,
      stalled: signal.stalled,
      checkedAt: signal.dataUpdatedAt,
      failing: signal.isError,
    }
    : undefined;

  // What the next page needs to know about this one: the blockers it showed, or the earlier ones
  // that are still open. Keyed by value so the landing effect below runs once per landing.
  const carryCommit = changeGateQuery.data?.threshold_breached
    ? sha
    : cleared?.kind === "open"
    ? previous?.commit
    : undefined;
  const carryIds = changeGateQuery.data?.threshold_breached
    ? (changeGateQuery.data.blocked_by ?? []).join(",")
    : cleared?.kind === "open"
    ? cleared.ids.join(",")
    : "";

  // Another scanner reported on this commit: read the commit's reports and its verdict again.
  const joinedId = joined?.id;
  useEffect(() => {
    if (!joinedId) return;
    void queryClient.invalidateQueries({ queryKey: queryKeys.reports(slug) });
    void queryClient.invalidateQueries({ queryKey: queryKeys.gate(slug) });
  }, [joinedId, queryClient, slug]);

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
      const carry = carryCommit && carryIds && !projectWide
        ? carryPrevious({ slug, commit: carryCommit, ids: carryIds.split(",") })
        : undefined;
      navigate(`/${slug}/changes/${shortCommit(landed.commit_sha)}?${query}`, {
        replace: true,
        state: carry,
      });
    }
  }, [landed, navigate, queryClient, slug, projectWide, severity, carryCommit, carryIds]);

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

  if (!scans || !report) {
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
    const state: ChangeState = scans.running.length > 0 ? "processing" : "failed";
    return (
      <Page>
        {crumbs}
        <ChangeHero
          commit={commit}
          report={state === "failed"
            ? scans.latest.find((scan) => scan.status === "failed") ?? report
            : report}
          outstanding={state === "failed"
            ? { running: [], failed: scans.failed.length > 1 ? scans.failed : [] }
            : { running: [], failed: scans.failed }}
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
  const passing = !scanningNewer && !gate.threshold_breached;
  const outstanding = { running: scans.running, failed: scans.failed, missing };
  const complete = outstanding.running.length === 0 && outstanding.failed.length === 0
    && missing.length === 0;
  // A passing scan after a blocked one is judged before it is named: the page waits for the earlier
  // scan's gate, and says "Unblocked" only when no earlier blocker is still open.
  if (passing && cleared?.kind === "checking") {
    return (
      <Page>
        {crumbs}
        <ChangeHeroSkeleton commit={commit} />
      </Page>
    );
  }
  const state: ChangeState = scanningNewer
    ? "scanning"
    : gate.threshold_breached
    ? "blocked"
    : !complete
    ? "incomplete"
    : passing && cleared?.kind === "unblocked"
    ? "unblocked"
    : passing && cleared?.kind === "open"
    ? "unconfirmed"
    : "passing";
  const reportAt = newestHere?.completed_at ?? newestHere?.created_at ?? report.created_at;
  const latestElsewhere = signal.latest?.commit_sha ? signal.latest : null;
  const notice = !online
    ? <OfflineNotice verdictAt={new Date(changeGateQuery.dataUpdatedAt).toISOString()} />
    : state === "blocked" && watch?.stalled
    ? <StalledNotice reportAt={reportAt} checkedAt={signal.dataUpdatedAt} />
    : passing && cleared?.kind === "unchecked"
    ? <UncheckedNotice onRetry={() => void earlierGateQuery.refetch()} />
    : latestElsewhere?.commit_sha && !projectWide
    ? (
      <NewerChangeNotice
        branch={report.branch ?? ""}
        commit={shortCommit(latestElsewhere.commit_sha)}
        href={`/${slug}/changes/${shortCommit(latestElsewhere.commit_sha)}?${new URLSearchParams({
          report: latestElsewhere.id,
          scope: "introduced",
          ...(severity ? { severity } : {}),
        })}`}
      />
    )
    : undefined;
  // The project gate is always evaluated now. Beside a report that is no longer the newest on its
  // branch, the page says so with the time, so nobody reads it as the state at this commit.
  const older = signal.superseded;
  const debt = (
    <ExistingDebt
      slug={slug}
      ids={existing}
      passing={passing && !projectWide}
      projectName={projectQuery.data?.name}
      asOf={older && projectGateQuery.dataUpdatedAt
        ? new Date(projectGateQuery.dataUpdatedAt).toISOString()
        : undefined}
    />
  );

  return (
    <Page>
      {crumbs}
      <ChangeHero
        commit={commit}
        report={report}
        scans={scanned}
        outstanding={outstanding}
        state={state}
        blockers={blockerCount(gate)}
        existing={existing.length}
        waived={gate.waived_count ?? 0}
        earlierOpen={cleared?.kind === "open" ? cleared.ids.length : 0}
        policy={gate.policy}
        projectWide={projectWide}
        reportOnly={gate.report_only === true}
        notice={notice}
        gateAsOf={older && changeGateQuery.dataUpdatedAt
          ? new Date(changeGateQuery.dataUpdatedAt).toISOString()
          : undefined}
      />
      {gate.threshold_breached && (
        // A blocker opened from here is judged with this page's gate, not the project's.
        <ChangeScopeContext.Provider
          value={{ commit: scans.sha, projectWide, severity, branch: report.branch ?? undefined }}
        >
          <BlockerSection
            key={scans.sha}
            slug={slug}
            commit={scans.sha}
            ids={blockedBy}
            floor={gate.policy?.severity_floor}
            permissions={projectQuery.data?.permissions}
            permissionsLoading={projectQuery.isPending}
            projectWide={projectWide}
            branch={report.branch}
            source={codeSource(report)}
            watch={watch}
          />
        </ChangeScopeContext.Provider>
      )}
      {previous && earlierGateQuery.data && (state === "unblocked" || state === "unconfirmed")
        ? (
          <ClearedEnd
            slug={slug}
            projectName={projectQuery.data?.name}
            reports={scanned}
            gate={gate}
            earlierGate={earlierGateQuery.data}
            previous={previous}
            openIds={cleared?.kind === "open" ? cleared.ids : []}
          >
            {debt}
          </ClearedEnd>
        )
        : debt}
      <p className="sr-only" role="status">
        {scanningNewer && newer
          ? `A new scan started ${formatRelativeTime(newer.created_at)}.`
          : ""}
      </p>
    </Page>
  );
}
