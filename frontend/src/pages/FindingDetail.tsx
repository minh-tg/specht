import {
  POLL_MS,
  useFinding,
  useFindingEvents,
  useGateStatus,
  useProject,
  useReachability,
  useWaivers,
} from "@/api/hooks";
import { usePendingTriage } from "@/api/pendingTriage";
import { ErrorState } from "@/components/ErrorState";
import { Section } from "@/components/Section";
import { Skeleton } from "@/components/ui/skeleton";
import { UpdatedHint } from "@/components/UpdatedHint";
import { changeViewBackPath, entryModeFromSearch } from "@/lib/entryMode";
import { analysisStateLabel, isReachabilityState } from "@/lib/enums";
import { blocksGate, blocksGateSentence } from "@/lib/gate";
import { waiverAction } from "@/lib/waiverRequest";
import { useState } from "react";
import { Link, useLocation, useParams } from "react-router-dom";
import { WaiverRequestDialog } from "./change-view/WaiverRequestDialog";
import { AnalysisNote } from "./finding-detail/AnalysisNote";
import { AutoCloseNote } from "./finding-detail/AutoCloseNote";
import { ContextGrid } from "./finding-detail/ContextGrid";
import { showsCveBlock } from "./finding-detail/cveBlock";
import { CveDetails } from "./finding-detail/CveDetails";
import { DecisionForm, type ReachabilityInput } from "./finding-detail/DecisionForm";
import { DetailsDisclosure } from "./finding-detail/DetailsDisclosure";
import { EvidenceSection } from "./finding-detail/EvidenceSection";
import { FindingHeader } from "./finding-detail/FindingHeader";
import { FixFirst } from "./finding-detail/FixFirst";
import { HistorySection } from "./finding-detail/HistorySection";
import { HowToFix } from "./finding-detail/HowToFix";
import { MetadataGrid } from "./finding-detail/MetadataGrid";
import { ReachabilitySection } from "./finding-detail/ReachabilitySection";
import { SignoffSection } from "./finding-detail/SignoffSection";
import { TriageSection } from "./finding-detail/TriageSection";
import { VerifyFixSection } from "./finding-detail/VerifyFixSection";
import { WaiverControl } from "./finding-detail/WaiverControl";
import { WhereItOccurs } from "./finding-detail/WhereItOccurs";

/** Where "Back to findings" goes: the list page the user came from, if known. */
function backToFindingsPath(slug: string, state: unknown): string {
  const from = (state as { from?: unknown; } | null)?.from;
  const search = typeof from === "string" && (from === "" || from.startsWith("?")) ? from : "";
  return `/${slug}/findings${search}`;
}

export function FindingDetail() {
  const { slug, findingId } = useParams<{ slug: string; findingId: string; }>();
  const location = useLocation();
  // The finding and its history ask again every 30 s while the tab is visible.
  const poll = { refetchInterval: POLL_MS };
  const {
    data: finding,
    dataUpdatedAt: findingUpdatedAt,
    isFetching: findingFetching,
    isLoading,
    isError,
    error,
    refetch,
  } = useFinding(findingId ?? "", poll);
  const { data: gate } = useGateStatus(slug ?? "");
  const { data: project, isLoading: projectLoading } = useProject(slug ?? "");
  const pendingWaivers = useWaivers(slug ?? "", ["pending"]);
  const pendingTriage = usePendingTriage(findingId ?? "");
  const [waiverOpen, setWaiverOpen] = useState(false);
  // The page's one polite live region: save results and queue moves are spoken here.
  const [announcement, setAnnouncement] = useState("");
  const {
    data: reachability,
    isLoading: reachabilityLoading,
    isError: reachabilityIsError,
    error: reachabilityError,
    isSuccess: reachabilityLoaded,
  } = useReachability(findingId ?? "");
  const {
    data: events,
    dataUpdatedAt: eventsUpdatedAt,
    isFetching: eventsFetching,
    isLoading: eventsLoading,
    isError: eventsIsError,
    refetch: refetchEvents,
  } = useFindingEvents(findingId ?? "", poll);

  if (isLoading) {
    return (
      <div className="mx-auto max-w-3xl space-y-4 px-4 py-8">
        <Skeleton className="h-6 w-48 rounded" />
        <Skeleton className="h-4 w-96 rounded" />
        <Skeleton className="h-32 rounded" />
      </div>
    );
  }

  if (isError || !finding) {
    return (
      <div className="mx-auto max-w-3xl px-4 py-8">
        <Link
          to={backToFindingsPath(slug ?? "", location.state)}
          className="text-muted-foreground hover:text-foreground mb-6 inline-block text-body"
        >
          &larr; Back to findings
        </Link>
        <h1 className="text-title font-bold">Couldn't load this finding</h1>
        <ErrorState
          className="mt-4"
          title={error?.message ?? "Finding not found"}
          onRetry={() => refetch()}
        />
      </div>
    );
  }

  // The state the person just chose shows at once. The gate verdict, the waiver button and the
  // "why" panel are computed by the server from the old state, so until the gate has refetched the
  // page claims nothing about blocking instead of showing a verdict it knows may be wrong.
  const shown = pendingTriage
    ? { ...finding, analysis_state: pendingTriage.analysisState }
    : finding;
  const gateResult = blocksGate(finding, pendingTriage ? undefined : gate);
  const currentGate = blocksGateSentence(gateResult);
  const waiverPending = (Array.isArray(pendingWaivers.data) ? pendingWaivers.data : []).some((
    waiver,
  ) => waiver.targets?.some((target) => target.finding_id === finding.id));
  const waiver = waiverAction({
    permissions: project?.permissions?.request_waiver,
    loading: projectLoading,
    pending: waiverPending,
    blocking: gateResult,
    gateRechecking: pendingTriage !== undefined,
  });

  const mode = entryModeFromSearch(location.search);
  // Arriving from a change, the way back is the change view itself. A link pasted without the
  // router state has no change to return to, so it falls back to the findings list.
  const changeBack = mode === "unblock" ? changeViewBackPath(slug ?? "", location.state) : null;

  const unblock = mode === "unblock";
  const reachabilitySection = (
    <ReachabilitySection
      findingId={finding.id}
      reachability={reachability}
      isLoading={reachabilityLoading}
      isError={reachabilityIsError}
      error={reachabilityError}
      isSuccess={reachabilityLoaded}
    />
  );
  const cveBlock = showsCveBlock(finding) ? <CveDetails findingId={finding.id} /> : null;
  const latestReach = (Array.isArray(reachability) ? reachability : [])[0];
  const reachInput: ReachabilityInput = {
    status: reachabilityIsError ? "error" : reachabilityLoaded ? "ready" : "loading",
    latest: latestReach && isReachabilityState(latestReach.state) ? latestReach.state : null,
    updatedAt: latestReach?.updated_at,
    evidence: latestReach?.evidence,
  };
  // Fix-first keeps the waiver and the triage form next to the fix and moves the reachability form
  // and the fix check below the fold. Decide-first leads with one form for the decision and the
  // reachability answer, with the waiver request under it.
  const decideSection = (
    <Section
      title="Decide"
      description={
        <>
          Currently: {analysisStateLabel(shown.analysis_state) ?? "Not triaged"}
          {currentGate && <>{" · "}{currentGate}</>}
        </>
      }
    >
      {unblock && (
        <div className="mb-4">
          <WaiverControl waiver={waiver} onRequest={() => setWaiverOpen(true)} />
        </div>
      )}
      {!pendingTriage && (
        <AnalysisNote
          reason={finding.analysis_reason}
          expiresAt={finding.analysis_expires_at}
        />
      )}
      {unblock
        ? (
          <TriageSection
            findingId={finding.id}
            projectSlug={slug}
            currentState={finding.analysis_state}
          />
        )
        : (
          <DecisionForm
            finding={finding}
            slug={slug ?? ""}
            reachability={reachInput}
            events={events}
            waiver={waiver}
            onRequestWaiver={() => setWaiverOpen(true)}
            announce={setAnnouncement}
          />
        )}
      <AutoCloseNote finding={finding} />
    </Section>
  );

  return (
    <div data-mode={mode} className="mx-auto max-w-5xl px-4 py-8">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
        <Link
          to={changeBack ?? backToFindingsPath(slug ?? "", location.state)}
          className="text-muted-foreground hover:text-foreground inline-block text-body"
        >
          {changeBack ? <>&larr; Back to the change</> : <>&larr; Back to findings</>}
        </Link>
        <UpdatedHint
          updatedAt={Math.min(findingUpdatedAt, eventsUpdatedAt || findingUpdatedAt)}
          watch={[finding, events]}
          isFetching={findingFetching || eventsFetching}
          onRefresh={() => {
            void refetch();
            void refetchEvents();
          }}
        />
      </div>

      <FindingHeader
        finding={finding}
        gateResult={gateResult}
        floor={gate?.policy?.severity_floor}
      />

      {mode === "unblock"
        ? (
          <div className="mt-2 max-w-3xl">
            <FixFirst finding={finding} />

            <WhereItOccurs finding={finding} />

            {decideSection}

            <DetailsDisclosure summary="reachability, context, evidence, history">
              {reachabilitySection}
              <VerifyFixSection findingId={finding.id} projectSlug={slug} />
              <ContextGrid context={finding.context} />
              <Section title="About this finding">
                <MetadataGrid finding={shown} />
              </Section>
              {cveBlock}
              <EvidenceSection findingId={finding.id} projectSlug={slug} />
              <SignoffSection findingId={finding.id} projectSlug={slug} />
              <HistorySection
                events={events}
                isLoading={eventsLoading}
                isError={eventsIsError}
              />
            </DetailsDisclosure>
          </div>
        )
        : (
          <div className="mt-2 grid gap-x-10 lg:grid-cols-[minmax(0,1fr)_17rem]">
            <div className="min-w-0">
              {decideSection}

              <HowToFix finding={finding} />

              <WhereItOccurs finding={finding} />

              <VerifyFixSection findingId={finding.id} projectSlug={slug} />

              <ContextGrid context={finding.context} />

              {cveBlock}

              <EvidenceSection findingId={finding.id} projectSlug={slug} />

              <SignoffSection findingId={finding.id} projectSlug={slug} />

              <HistorySection
                events={events}
                isLoading={eventsLoading}
                isError={eventsIsError}
              />
            </div>

            <aside aria-label="About this finding" className="mt-8 grid content-start gap-5">
              <MetadataGrid finding={shown} />
            </aside>
            <p role="status" aria-live="polite" className="sr-only">{announcement}</p>
          </div>
        )}

      <WaiverRequestDialog
        slug={slug ?? ""}
        findingIds={[finding.id]}
        subject={finding.current_title}
        open={waiverOpen}
        onOpenChange={setWaiverOpen}
        onRequested={() => void pendingWaivers.refetch()}
      />
    </div>
  );
}
