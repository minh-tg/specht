import {
  useFinding,
  useFindingEvents,
  useGateStatus,
  useReachability,
  useTriageFinding,
  useUpsertReachability,
} from "@/api/hooks";
import { SeverityBadge } from "@/components/ui/severity-badge";
import {
  type AnalysisState,
  analysisStateLabel,
  findingKindLabel,
  gateEffectLabel,
  isAnalysisState,
  isReachabilityState,
  type ReachabilityState,
  reachabilityStateLabel,
  technicalStateLabel,
} from "@/lib/enums";
import { formatDateTime } from "@/lib/format";
import { blocksGate, blocksGateSentence } from "@/lib/gate";
import { truncateText } from "@/lib/utils";
import type { ReachabilityAssessment } from "@/types/api";
import { type ReactNode, useState } from "react";
import { Link, useLocation, useParams } from "react-router-dom";
import {
  confidenceLabel,
  locationLineRange,
  locationSubjectLabel,
  parseSourceLink,
  toExpiryTimestamp,
} from "./finding-detail/format";
import { HistorySection } from "./finding-detail/HistorySection";
import {
  MAX_EVIDENCE_LENGTH,
  REACHABILITY_OPTIONS,
  TRIAGE_OPTIONS,
} from "./finding-detail/options";

/** Triage controls and status feedback for one finding. */
function TriageSection({ findingId }: { readonly findingId: string; }) {
  const triageMutation = useTriageFinding();
  const [selectedState, setSelectedState] = useState<AnalysisState | "">("");
  const [reason, setReason] = useState("");
  const [expiresAt, setExpiresAt] = useState("");

  const selectedOption = TRIAGE_OPTIONS.find((o) => o.value === selectedState);

  async function handleTriage() {
    if (!selectedState) return;
    try {
      await triageMutation.mutateAsync({
        findingId,
        analysisState: selectedState,
        reason: selectedOption?.requiresReason ? reason : undefined,
        analysisExpiresAt: selectedOption?.requiresExpiry
          ? toExpiryTimestamp(expiresAt)
          : undefined,
      });
      setSelectedState("");
      setReason("");
      setExpiresAt("");
    } catch {}
  }

  const triageReady = selectedState !== ""
    && (!selectedOption?.requiresExpiry || expiresAt !== "")
    && (!selectedOption?.requiresReason || reason.trim() !== "");

  return (
    <section aria-labelledby="triage-heading">
      <h3 id="triage-heading" className="mb-3 text-sm font-medium">Triage</h3>
      <div className="flex flex-wrap gap-2">
        <select
          aria-label="Triage action"
          className="border-input bg-background rounded-md border px-3 py-1.5 text-sm"
          value={selectedState}
          onChange={(e) => {
            const value = e.target.value;
            setSelectedState(isAnalysisState(value) ? value : "");
            setReason("");
            setExpiresAt("");
          }}
        >
          <option value="">Select action...</option>
          {TRIAGE_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        {selectedOption?.requiresReason && (
          <input
            className="border-input bg-background min-w-[200px] rounded-md border px-3 py-1.5 text-sm"
            aria-label="Reason"
            placeholder="Reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        )}
        {selectedOption?.requiresExpiry && (
          <input
            aria-label="Expiry date"
            type="date"
            className="border-input bg-background rounded-md border px-3 py-1.5 text-sm"
            value={expiresAt}
            onChange={(e) => setExpiresAt(e.target.value)}
          />
        )}
        <button
          onClick={handleTriage}
          disabled={!triageReady || triageMutation.isPending}
          className="bg-primary text-primary-foreground hover:bg-primary/90 rounded-md px-4 py-1.5 text-sm font-medium disabled:opacity-50"
        >
          {triageMutation.isPending ? "Saving..." : "Apply"}
        </button>
      </div>
      <OutcomeRegions
        label="Triage result"
        error={triageMutation.isError ? triageMutation.error.message : null}
        success={triageMutation.isSuccess
          ? `Triage saved (effect: ${
            gateEffectLabel(triageMutation.data.gate_effect) ?? "Unknown"
          })`
          : null}
      />
    </section>
  );
}

/**
 * Persistent live regions for a form's outcome. They are always mounted and
 * only their text changes: a live region that appears together with its text
 * is announced unreliably by screen readers.
 */
function OutcomeRegions({ label, error, success }: {
  readonly label: string;
  readonly error: string | null;
  readonly success: string | null;
}) {
  return (
    <>
      <div role="status" aria-live="polite" aria-label={label} className="text-xs">
        {success && (
          <span className="bg-sev-success-bg text-sev-success-fg mt-2 inline-block rounded-sm px-2 py-1">
            {success}
          </span>
        )}
      </div>
      <div role="alert" aria-label={`${label} error`} className="text-destructive text-xs">
        {error && <p className="mt-2">{error}</p>}
      </div>
    </>
  );
}

/** The latest assessment line, with truncated inline evidence. */
function latestAssessmentLine(latest: ReachabilityAssessment | null): ReactNode {
  if (!latest) {
    return (
      <>
        Latest: <span className="font-medium">Unknown</span>{" "}
        — no assessment yet; an unassessed finding still blocks the gate until marked not reachable
        or not applicable.
      </>
    );
  }
  const evidence = latest.evidence?.trim();
  return (
    <>
      Latest:{" "}
      <span className="font-medium">
        {reachabilityStateLabel(latest.state) ?? "Unknown"}
      </span>
      {evidence && (
        <span title={evidence}>{" — "}{truncateText(evidence, MAX_EVIDENCE_LENGTH)}</span>
      )} ({formatDateTime(latest.updated_at)})
    </>
  );
}

/** Reachability assessment controls and latest status for one finding. */
function ReachabilitySection({
  findingId,
  reachability,
  isLoading,
  isError,
  error,
  isSuccess,
}: {
  readonly findingId: string;
  readonly reachability?: ReachabilityAssessment[];
  readonly isLoading: boolean;
  readonly isError: boolean;
  readonly error: Error | null;
  readonly isSuccess: boolean;
}) {
  const mutation = useUpsertReachability();
  const [reachState, setReachState] = useState<ReachabilityState | "">("");
  const [reachEvidence, setReachEvidence] = useState("");

  // The list is capped to the latest assessment for inline display; older
  // history is not rendered in this view.
  const latest = reachability?.[0] ?? null;

  let body: ReactNode;
  if (isLoading) {
    body = <p className="text-muted-foreground mb-3 text-xs">Latest: Loading...</p>;
  } else if (isError) {
    body = (
      <p className="text-destructive mb-3 text-xs">
        Unable to load reachability: {error?.message ?? "request failed"}
      </p>
    );
  } else if (!isSuccess) {
    body = <p className="text-muted-foreground mb-3 text-xs">Latest: Loading...</p>;
  } else {
    body = <p className="text-muted-foreground mb-3 text-xs">{latestAssessmentLine(latest)}</p>;
  }

  return (
    <section aria-labelledby="reachability-heading" className="mt-6 border-t pt-4">
      <h3 id="reachability-heading" className="mb-3 text-sm font-medium">Reachability</h3>
      {body}
      <div className="flex flex-wrap gap-2">
        <select
          aria-label="Reachability assessment"
          className="border-input bg-background rounded-md border px-3 py-1.5 text-sm"
          value={reachState}
          onChange={(e) => {
            const value = e.target.value;
            setReachState(isReachabilityState(value) ? value : "");
          }}
        >
          <option value="">Select assessment...</option>
          {REACHABILITY_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        <input
          className="border-input bg-background min-w-[200px] rounded-md border px-3 py-1.5 text-sm"
          aria-label="Evidence"
          placeholder="Evidence"
          value={reachEvidence}
          onChange={(e) => setReachEvidence(e.target.value)}
        />
        <button
          onClick={() => {
            if (!reachState) return;
            mutation.mutate(
              { findingId, state: reachState, evidence: reachEvidence },
              {
                onSuccess: () => {
                  setReachState("");
                  setReachEvidence("");
                },
              },
            );
          }}
          disabled={!reachState || mutation.isPending}
          className="bg-primary text-primary-foreground hover:bg-primary/90 rounded-md px-4 py-1.5 text-sm font-medium disabled:opacity-50"
        >
          {mutation.isPending ? "Saving..." : "Assess"}
        </button>
      </div>
      <OutcomeRegions
        label="Reachability result"
        error={mutation.isError ? mutation.error.message : null}
        success={mutation.isSuccess ? "Reachability saved" : null}
      />
    </section>
  );
}

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

  let gateChip: ReactNode = null;
  if (gateResult?.blocks) {
    gateChip = (
      <span className="bg-sev-critical-bg text-sev-critical-fg rounded-sm px-1.5 py-0.5 text-xs font-medium">
        {blocksGateSentence(gateResult)}
      </span>
    );
  } else if (gateResult) {
    gateChip = (
      <span className="inline-flex items-center rounded-sm border px-1.5 py-0.5 text-xs font-medium text-muted-foreground">
        {blocksGateSentence(gateResult)}
      </span>
    );
  }

  return (
    <div className="mx-auto max-w-3xl px-4 py-8">
      <Link
        to={backToFindingsPath(slug ?? "", location.state)}
        className="text-muted-foreground hover:text-foreground mb-6 inline-block text-sm"
      >
        &larr; Back to findings
      </Link>

      <div className="mb-6">
        <div className="mb-2 flex items-center gap-3">
          <SeverityBadge severity={finding.current_severity} />
          <span className="text-muted-foreground text-xs">
            {findingKindLabel(finding.finding_kind) ?? "–"}
          </span>
          {gateChip}
        </div>
        <h1 className="text-2xl font-bold break-words">{finding.current_title}</h1>
      </div>

      <div className="grid grid-cols-1 gap-4 text-sm sm:grid-cols-2">
        <div>
          <span className="text-muted-foreground">Status</span>
          <p className="font-medium">{technicalStateLabel(finding.state) ?? "–"}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Triage</span>
          <p className="font-medium">
            {analysisStateLabel(finding.analysis_state) ?? "Not triaged"}
          </p>
        </div>
        <div>
          <span className="text-muted-foreground">First Seen</span>
          <p className="font-medium">{formatDateTime(finding.first_seen_at)}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Last Seen</span>
          <p className="font-medium">{formatDateTime(finding.last_seen_at)}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Introduced</span>
          <p className="font-mono text-xs">
            {finding.introduced_commit_sha
              ? finding.introduced_commit_sha.slice(0, 12)
              : "Unattributed"}
          </p>
        </div>
        <div className="sm:col-span-2">
          <span className="text-muted-foreground">Fingerprint</span>
          <p className="font-mono text-xs break-all">{finding.fingerprint}</p>
        </div>
      </div>

      <div className="mt-8 rounded-lg border p-4">
        <h2 className="mb-3 text-sm font-semibold">How to fix</h2>
        {finding.remediation?.summary
          ? (
            <div className="space-y-2 text-sm">
              <p className="font-medium">{finding.remediation.summary}</p>
              {finding.remediation.fallback && (
                <p className="text-muted-foreground text-xs">
                  General guidance — the scanner reported no specific fix.
                </p>
              )}
              {finding.remediation.url && parseSourceLink(finding.remediation.url) && (
                <p>
                  <a
                    href={finding.remediation.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-primary hover:text-primary/80 text-sm underline underline-offset-4"
                  >
                    Remediation reference
                  </a>
                </p>
              )}
              {finding.remediation.source && (
                <p className="text-muted-foreground text-xs">
                  Source: {finding.remediation.source}
                </p>
              )}
              {finding.suggestion && (
                <p className="text-muted-foreground text-xs">
                  Suggested: {finding.suggestion.action}
                  {finding.suggestion.target ? ` ${finding.suggestion.target}` : ""} (confidence
                  {" "}
                  {confidenceLabel(finding.suggestion.confidence)})
                  {finding.suggestion.detail ? ` — ${finding.suggestion.detail}` : ""}
                </p>
              )}
            </div>
          )
          : (
            <p className="text-muted-foreground text-sm">
              No remediation reported for this finding.
            </p>
          )}
      </div>

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
