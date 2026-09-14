import {
  useFinding,
  useFindingEvents,
  useReachability,
  useTriageFinding,
  useUpsertReachability,
} from "@/api/hooks";
import { SeverityBadge } from "@/components/ui/severity-badge";
import {
  type AnalysisState,
  analysisStateLabel,
  gateEffectLabel,
  isAnalysisState,
  isReachabilityState,
  type ReachabilityState,
  reachabilityStateLabel,
  technicalStateLabel,
} from "@/lib/enums";
import { truncateText } from "@/lib/utils";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";

/** Inline evidence is capped so an oversized payload cannot blow up layout. */
const MAX_EVIDENCE_LENGTH = 240;

const REACHABILITY_OPTIONS: Array<{ value: ReachabilityState; label: string; }> = [
  { value: "reachable", label: "Reachable" },
  { value: "not_reachable", label: "Not Reachable" },
  { value: "unknown", label: "Unknown" },
  { value: "not_applicable", label: "Not Applicable" },
];

const TRIAGE_OPTIONS: Array<
  {
    value: AnalysisState;
    label: string;
    requiresReason: boolean;
    requiresExpiry: boolean;
  }
> = [
  { value: "exploitable", label: "Confirmed", requiresReason: false, requiresExpiry: false },
  { value: "false_positive", label: "False Positive", requiresReason: true, requiresExpiry: false },
  { value: "not_affected", label: "Not Affected", requiresReason: true, requiresExpiry: false },
  { value: "accepted_risk", label: "Accepted Risk", requiresReason: true, requiresExpiry: true },
  { value: "wont_fix", label: "Won't Fix", requiresReason: true, requiresExpiry: true },
];

const SOURCE_LINK_SCHEMES = new Set(["http:", "https:"]);

/** Formats an API timestamp for display; a dash when absent or unparseable. */
function formatTimestamp(value: string | undefined): string {
  if (!value) return "–";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "–" : date.toLocaleString();
}

/** Parses a source link only when its scheme is http/https; otherwise null. */
function parseSourceLink(value: string | undefined): URL | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return SOURCE_LINK_SCHEMES.has(url.protocol) ? url : null;
  } catch {
    return null;
  }
}

/** Subject label per finding kind for the location section. */
function locationSubjectLabel(kind: string | undefined): string {
  switch (kind) {
    case "sca":
      return "Package";
    case "sast":
      return "File";
    case "iac":
      return "Resource";
    case "secret":
      return "File";
    case "dast":
      return "URL";
    default:
      return "Subject";
  }
}

/** Humanizes a confidence value; unknown stays visible but unlabeled. */
function confidenceLabel(value: string | undefined): string {
  switch (value) {
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
    default:
      return "Unknown";
  }
}

/** Humanizes a lifecycle event type for the history list. */
function eventTypeLabel(value: string | undefined): string {
  if (!value) return "Unknown";
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}
/** Normalizes a date-input value to a server-accepted RFC3339 expiry. */
function toExpiryTimestamp(value: string): string | undefined {
  if (!value) return undefined;
  const iso = /^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value}T23:59:59.999Z` : value;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

export function FindingDetail() {
  const { findingId } = useParams<{ findingId: string; }>();
  const { data: finding, isLoading, isError, error, refetch } = useFinding(findingId ?? "");
  const triageMutation = useTriageFinding();
  const {
    data: reachability,
    isLoading: reachabilityLoading,
    isError: reachabilityIsError,
    error: reachabilityError,
    isSuccess: reachabilityLoaded,
  } = useReachability(findingId ?? "");
  const reachabilityMutation = useUpsertReachability();
  const {
    data: events,
    isLoading: eventsLoading,
    isError: eventsIsError,
  } = useFindingEvents(findingId ?? "");

  const [selectedState, setSelectedState] = useState<AnalysisState | "">("");
  const [reason, setReason] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [reachState, setReachState] = useState<ReachabilityState | "">("");
  const [reachEvidence, setReachEvidence] = useState("");

  // The list is capped to the latest assessment for inline display; older
  // history is not rendered in this view.
  const latestReachability = reachability?.[0] ?? null;

  const selectedOption = TRIAGE_OPTIONS.find((o) => o.value === selectedState);

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
      <div className="flex flex-col items-center gap-2 py-16">
        <p className="text-destructive text-sm">{error?.message ?? "Finding not found"}</p>
        <button
          className="text-primary text-sm underline hover:no-underline"
          onClick={() => refetch()}
        >
          Retry
        </button>
      </div>
    );
  }

  async function handleTriage() {
    if (!selectedState || !finding) return;
    try {
      await triageMutation.mutateAsync({
        findingId: finding.id,
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
    <div className="mx-auto max-w-3xl px-4 py-8">
      <Link
        to=".."
        relative="path"
        className="text-muted-foreground hover:text-foreground mb-6 inline-block text-sm"
      >
        &larr; Back to findings
      </Link>

      <div className="mb-6">
        <div className="mb-2 flex items-center gap-3">
          <SeverityBadge severity={finding.current_severity} />
          <span className="text-muted-foreground text-xs">{finding.finding_kind}</span>
        </div>
        <h1 className="text-2xl font-bold">{finding.current_title}</h1>
      </div>

      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <span className="text-muted-foreground">Status</span>
          <p className="font-medium">{technicalStateLabel(finding.state) ?? "–"}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Analysis</span>
          <p className="font-medium">
            {analysisStateLabel(finding.analysis_state) ?? "Not triaged"}
          </p>
        </div>
        <div>
          <span className="text-muted-foreground">Gate Effect</span>
          <p className="font-medium">{gateEffectLabel(finding.gate_effect) ?? "–"}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Fingerprint</span>
          <p className="font-mono text-xs">{finding.fingerprint}</p>
        </div>
        <div>
          <span className="text-muted-foreground">First Seen</span>
          <p className="font-medium">{formatTimestamp(finding.first_seen_at)}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Last Seen</span>
          <p className="font-medium">{formatTimestamp(finding.last_seen_at)}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Introduced</span>
          <p className="font-mono text-xs">
            {finding.introduced_commit_sha
              ? finding.introduced_commit_sha.slice(0, 12)
              : "Unattributed"}
          </p>
        </div>
      </div>

      {finding.context && (
        <div className="mt-8 rounded-lg border p-4">
          <h2 className="mb-3 text-sm font-semibold">Context</h2>
          <div className="grid grid-cols-2 gap-4 text-sm">
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
              <div className="col-span-2">
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
      <div className="mt-8 rounded-lg border p-4">
        <h2 className="mb-3 text-sm font-semibold">Where it occurs</h2>
        {finding.location
            && (finding.location.file || finding.location.resource || finding.location.summary)
          ? (
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-muted-foreground">
                  {locationSubjectLabel(finding.finding_kind)}
                </span>
                <p className="font-mono text-xs select-all">
                  {finding.location.file ?? finding.location.resource ?? finding.location.summary}
                  {finding.location.file && finding.location.start_line
                    ? `:${finding.location.start_line}${
                      finding.location.end_line
                        && finding.location.end_line !== finding.location.start_line
                        ? `–${finding.location.end_line}`
                        : ""
                    }`
                    : ""}
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
        <h2 className="mb-3 text-sm font-semibold">History</h2>
        {eventsLoading
          ? <p className="text-muted-foreground text-sm">Loading history...</p>
          : eventsIsError
          ? <p className="text-destructive text-sm">Unable to load history.</p>
          : events && events.length > 0
          ? (
            <ul className="space-y-2 text-sm">
              {events.map((event) => (
                <li key={event.id} className="flex flex-wrap items-baseline gap-x-2">
                  <span className="font-medium">{eventTypeLabel(event.event_type)}</span>
                  {event.old_value != null || event.new_value != null
                    ? (
                      <span className="text-muted-foreground font-mono text-xs">
                        {event.old_value || "–"} → {event.new_value || "–"}
                      </span>
                    )
                    : null}
                  <span className="text-muted-foreground text-xs">
                    {formatTimestamp(event.created_at)}
                  </span>
                </li>
              ))}
            </ul>
          )
          : <p className="text-muted-foreground text-sm">No history yet.</p>}
      </div>

      <div className="mt-8 rounded-lg border p-4">
        <h2 className="mb-3 text-sm font-semibold">Triage</h2>
        <div className="flex flex-wrap gap-2">
          <select
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
              placeholder="Reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          )}
          {selectedOption?.requiresExpiry && (
            <input
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
        {triageMutation.isError && (
          <p className="text-destructive mt-2 text-xs">{triageMutation.error.message}</p>
        )}
        {triageMutation.isSuccess && (
          <p className="text-green-600 mt-2 text-xs">
            Triage saved (effect: {gateEffectLabel(triageMutation.data.gate_effect) ?? "Unknown"})
          </p>
        )}
      </div>

      <div className="mt-8 rounded-lg border p-4">
        <h2 className="mb-3 text-sm font-semibold">Reachability</h2>
        {reachabilityLoading
          ? <p className="text-muted-foreground mb-3 text-xs">Latest: Loading...</p>
          : reachabilityIsError
          ? (
            <p className="text-destructive mb-3 text-xs">
              Unable to load reachability: {reachabilityError?.message ?? "request failed"}
            </p>
          )
          : reachabilityLoaded && latestReachability
          ? (
            <p className="text-muted-foreground mb-3 text-xs">
              Latest:{" "}
              <span className="font-medium">
                {reachabilityStateLabel(latestReachability.state) ?? "Unknown"}
              </span>
              {(() => {
                const evidence = latestReachability.evidence?.trim();
                if (!evidence) return null;
                const visible = truncateText(evidence, MAX_EVIDENCE_LENGTH);
                return (
                  <span title={evidence}>
                    {" — "}
                    {visible}
                  </span>
                );
              })()} ({formatTimestamp(latestReachability.updated_at)})
            </p>
          )
          : reachabilityLoaded
          ? (
            <p className="text-muted-foreground mb-3 text-xs">
              Latest: <span className="font-medium">Unknown</span>{" "}
              — no assessment yet; an unassessed finding still blocks the gate until marked not
              reachable or not applicable.
            </p>
          )
          : <p className="text-muted-foreground mb-3 text-xs">Latest: Loading...</p>}
        <div className="flex flex-wrap gap-2">
          <select
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
            placeholder="Evidence"
            value={reachEvidence}
            onChange={(e) => setReachEvidence(e.target.value)}
          />
          <button
            onClick={() => {
              if (!reachState) return;
              reachabilityMutation.mutate(
                {
                  findingId: findingId ?? "",
                  state: reachState,
                  evidence: reachEvidence,
                },
                {
                  onSuccess: () => {
                    setReachState("");
                    setReachEvidence("");
                  },
                },
              );
            }}
            disabled={!reachState || reachabilityMutation.isPending}
            className="bg-primary text-primary-foreground hover:bg-primary/90 rounded-md px-4 py-1.5 text-sm font-medium disabled:opacity-50"
          >
            {reachabilityMutation.isPending ? "Saving..." : "Assess"}
          </button>
        </div>
        {reachabilityMutation.isError && (
          <p className="text-destructive mt-2 text-xs">{reachabilityMutation.error.message}</p>
        )}
        {reachabilityMutation.isSuccess && (
          <p className="text-green-600 mt-2 text-xs">Reachability saved</p>
        )}
      </div>
    </div>
  );
}
