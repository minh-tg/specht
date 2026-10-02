import { useFinding, useFindingEvents, useGateStatus, useReachability } from "@/api/hooks";
import { analysisStateLabel } from "@/lib/enums";
import { blocksGate, blocksGateSentence } from "@/lib/gate";
import { Link, useLocation, useParams } from "react-router-dom";
import { FindingHeader } from "./finding-detail/FindingHeader";
import { locationLineRange, locationSubjectLabel, parseSourceLink } from "./finding-detail/format";
import { HistorySection } from "./finding-detail/HistorySection";
import { HowToFix } from "./finding-detail/HowToFix";
import { MetadataGrid } from "./finding-detail/MetadataGrid";
import { ReachabilitySection } from "./finding-detail/ReachabilitySection";
import { TriageSection } from "./finding-detail/TriageSection";

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
        <div className="bg-muted h-6 w-48 animate-pulse rounded" />
        <div className="bg-muted h-4 w-96 animate-pulse rounded" />
        <div className="bg-muted h-32 animate-pulse rounded" />
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
        <p className="text-destructive mt-2 text-sm">{error?.message ?? "Finding not found"}</p>
        <button
          type="button"
          className="text-primary text-sm underline hover:no-underline"
          onClick={() => refetch()}
        >
          Retry
        </button>
      </div>
    );
  }

  const gateResult = blocksGate(finding, gate);

  const currentGate = blocksGateSentence(gateResult);

  return (
    <div className="mx-auto max-w-3xl px-4 py-8">
      <Link
        to={backToFindingsPath(slug ?? "", location.state)}
        className="text-muted-foreground hover:text-foreground mb-6 inline-block text-sm"
      >
        &larr; Back to findings
      </Link>

      <FindingHeader finding={finding} gateResult={gateResult} />

      <MetadataGrid finding={finding} />

      <HowToFix finding={finding} />

      <div className="mt-8 rounded-lg border p-4">
        <h2 className="mb-3 text-sm font-semibold">Where it occurs</h2>
        {finding.location
            && (finding.location.file || finding.location.resource || finding.location.summary)
          ? (
            <div className="grid grid-cols-1 gap-4 text-sm sm:grid-cols-2">
              <div>
                <span className="text-muted-foreground">
                  {locationSubjectLabel(finding.finding_kind)}
                </span>
                <p className="font-mono text-xs break-all select-all">
                  {finding.location.file ?? finding.location.resource ?? finding.location.summary}
                  {locationLineRange(finding.location)}
                </p>
              </div>
              {finding.location.summary && (finding.location.file || finding.location.resource) && (
                <div>
                  <span className="text-muted-foreground">Detail</span>
                  <p className="font-medium">{finding.location.summary}</p>
                </div>
              )}
            </div>
          )
          : (
            <p className="text-muted-foreground text-sm">
              No location reported — the scanner gave no file, resource, or URL.
            </p>
          )}
      </div>

      <div className="mt-8 rounded-lg border p-4">
        <h2 className="mb-1 text-sm font-semibold">Decide</h2>
        <p className="text-muted-foreground mb-4 text-xs">
          Currently: {analysisStateLabel(finding.analysis_state) ?? "Not triaged"}
          {currentGate && <>{" · "}{currentGate}</>}
        </p>
        <TriageSection findingId={finding.id} />
        <ReachabilitySection
          findingId={finding.id}
          reachability={reachability}
          isLoading={reachabilityLoading}
          isError={reachabilityIsError}
          error={reachabilityError}
          isSuccess={reachabilityLoaded}
        />
      </div>

      {finding.context && (
        <div className="mt-8 rounded-lg border p-4">
          <h2 className="mb-3 text-sm font-semibold">Context</h2>
          <div className="grid grid-cols-1 gap-4 text-sm sm:grid-cols-2">
            <div>
              <span className="text-muted-foreground">Target</span>
              <p className="font-medium">
                {[finding.context.target_name, finding.context.target_kind]
                  .filter(Boolean)
                  .join(" · ") || "–"}
              </p>
            </div>
            <div>
              <span className="text-muted-foreground">Environment</span>
              <p className="font-medium">{finding.context.environment_name || "–"}</p>
            </div>
            <div>
              <span className="text-muted-foreground">Branch</span>
              <p className="font-mono text-xs">{finding.context.branch || "–"}</p>
            </div>
            <div>
              <span className="text-muted-foreground">Commit</span>
              <p className="font-mono text-xs">
                {finding.context.commit_sha
                  ? finding.context.commit_sha.slice(0, 12)
                  : "–"}
              </p>
            </div>
            {parseSourceLink(finding.context.source_link) && (
              <div className="sm:col-span-2">
                <span className="text-muted-foreground">Source</span>
                <p className="font-medium">
                  <a
                    href={finding.context.source_link}
                    target="_blank"
                    rel="noreferrer"
                    className="text-primary hover:text-primary/80 text-sm underline underline-offset-4"
                  >
                    {parseSourceLink(finding.context.source_link)!.hostname}
                    {parseSourceLink(finding.context.source_link)!.pathname}
                  </a>
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      <HistorySection
        events={events}
        isLoading={eventsLoading}
        isError={eventsIsError}
      />
    </div>
  );
}
