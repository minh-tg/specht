import {
  useFinding,
  useFindingEvents,
  useGateStatus,
  useProject,
  useReachability,
  useWaivers,
} from "@/api/hooks";
import { ErrorState } from "@/components/ErrorState";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { analysisStateLabel } from "@/lib/enums";
import { blocksGate, blocksGateSentence } from "@/lib/gate";
import { useState } from "react";
import { Link, useLocation, useParams } from "react-router-dom";
import { WaiverRequestDialog } from "./change-view/WaiverRequestDialog";
import { ContextGrid } from "./finding-detail/ContextGrid";
import { EvidenceSection } from "./finding-detail/EvidenceSection";
import { FindingHeader } from "./finding-detail/FindingHeader";
import { HistorySection } from "./finding-detail/HistorySection";
import { HowToFix } from "./finding-detail/HowToFix";
import { MetadataGrid } from "./finding-detail/MetadataGrid";
import { ReachabilitySection } from "./finding-detail/ReachabilitySection";
import { SignoffSection } from "./finding-detail/SignoffSection";
import { TriageSection } from "./finding-detail/TriageSection";
import { VerifyFixSection } from "./finding-detail/VerifyFixSection";
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
  const { data: finding, isLoading, isError, error, refetch } = useFinding(findingId ?? "");
  const { data: gate } = useGateStatus(slug ?? "");
  const { data: project } = useProject(slug ?? "");
  const pendingWaivers = useWaivers(slug ?? "", ["pending"]);
  const [waiverOpen, setWaiverOpen] = useState(false);
  const {
    data: reachability,
    isLoading: reachabilityLoading,
    isError: reachabilityIsError,
    error: reachabilityError,
    isSuccess: reachabilityLoaded,
  } = useReachability(findingId ?? "");
  const { data: events, isLoading: eventsLoading, isError: eventsIsError } = useFindingEvents(
    findingId ?? "",
  );

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
          className="text-muted-foreground hover:text-foreground mb-6 inline-block text-sm"
        >
          &larr; Back to findings
        </Link>
        <h1 className="text-2xl font-bold">Couldn't load this finding</h1>
        <ErrorState
          className="mt-4"
          title={error?.message ?? "Finding not found"}
          onRetry={() => refetch()}
        />
      </div>
    );
  }

  const gateResult = blocksGate(finding, gate);
  const currentGate = blocksGateSentence(gateResult);
  const canRequestWaiver = project?.permissions?.request_waiver === true
    && gateResult?.blocks === true;
  const waiverPending = (Array.isArray(pendingWaivers.data) ? pendingWaivers.data : []).some((
    waiver,
  ) => waiver.targets?.some((target) => target.finding_id === finding.id));

  return (
    <div className="mx-auto max-w-5xl px-4 py-8">
      <Link
        to={backToFindingsPath(slug ?? "", location.state)}
        className="text-muted-foreground hover:text-foreground mb-6 inline-block text-sm"
      >
        &larr; Back to findings
      </Link>

      <FindingHeader
        finding={finding}
        gateResult={gateResult}
        floor={gate?.policy?.severity_floor}
      />

      <div className="mt-2 grid gap-x-10 lg:grid-cols-[minmax(0,1fr)_17rem]">
        <div className="min-w-0">
          <HowToFix finding={finding} />

          <WhereItOccurs finding={finding} />

          <div className="border-border mt-8 border-t pt-5">
            <h2 className="mb-1 text-lg font-semibold">Decide</h2>
            <p className="text-muted-foreground mb-4 text-xs">
              Currently: {analysisStateLabel(finding.analysis_state) ?? "Not triaged"}
              {currentGate && <>{" · "}{currentGate}</>}
            </p>
            <TriageSection findingId={finding.id} projectSlug={slug} />
            <VerifyFixSection findingId={finding.id} projectSlug={slug} />
            <ReachabilitySection
              findingId={finding.id}
              reachability={reachability}
              isLoading={reachabilityLoading}
              isError={reachabilityIsError}
              error={reachabilityError}
              isSuccess={reachabilityLoaded}
            />
          </div>

          <ContextGrid context={finding.context} />

          <EvidenceSection findingId={finding.id} projectSlug={slug} />

          <SignoffSection findingId={finding.id} projectSlug={slug} />

          <HistorySection
            events={events}
            isLoading={eventsLoading}
            isError={eventsIsError}
          />
        </div>

        <aside aria-label="About this finding" className="mt-8 grid content-start gap-5">
          {canRequestWaiver && (
            waiverPending
              ? (
                <p className="bg-muted text-muted-foreground rounded-md px-3.5 py-3 text-[0.8125rem]">
                  Waiver requested. A manager will decide. The verdict does not change until they
                  approve it.
                </p>
              )
              : (
                <Button variant="outline" onClick={() => setWaiverOpen(true)}>
                  Request waiver
                </Button>
              )
          )}
          <MetadataGrid finding={finding} />
        </aside>
      </div>

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
