import { useFinding, useReachability, useTriageFinding, useUpsertReachability } from "@/api/hooks";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";

const REACHABILITY_OPTIONS = [
  { value: "reachable", label: "Reachable" },
  { value: "not_reachable", label: "Not Reachable" },
  { value: "unknown", label: "Unknown" },
  { value: "not_applicable", label: "Not Applicable" },
];

const TRIAGE_OPTIONS = [
  { value: "confirmed", label: "Confirmed", requiresReason: false, requiresExpiry: false },
  { value: "false_positive", label: "False Positive", requiresReason: true, requiresExpiry: false },
  { value: "not_affected", label: "Not Affected", requiresReason: true, requiresExpiry: false },
  { value: "accepted_risk", label: "Accepted Risk", requiresReason: true, requiresExpiry: true },
  { value: "wont_fix", label: "Won't Fix", requiresReason: true, requiresExpiry: true },
];

function triageLabel(state: string): string {
  return TRIAGE_OPTIONS.find((o) => o.value === state)?.label ?? state;
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

  const [selectedState, setSelectedState] = useState("");
  const [reason, setReason] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [reachState, setReachState] = useState("");
  const [reachEvidence, setReachEvidence] = useState("");

  const latestReachability = reachability?.[0];

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
        analysisExpiresAt: selectedOption?.requiresExpiry ? expiresAt || undefined : undefined,
      });
      setSelectedState("");
      setReason("");
      setExpiresAt("");
    } catch {}
  }

  return (
    <div className="mx-auto max-w-3xl px-4 py-8">
      <Link
        to=".."
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
          <p className="font-medium capitalize">{finding.state}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Analysis</span>
          <p className="font-medium">
            {finding.analysis_state ? triageLabel(finding.analysis_state) : "Not triaged"}
          </p>
        </div>
        <div>
          <span className="text-muted-foreground">Gate Effect</span>
          <p className="font-medium">{finding.gate_effect || "–"}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Fingerprint</span>
          <p className="font-mono text-xs">{finding.fingerprint}</p>
        </div>
        <div>
          <span className="text-muted-foreground">First Seen</span>
          <p className="font-medium">{new Date(finding.first_seen_at).toLocaleString()}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Last Seen</span>
          <p className="font-medium">{new Date(finding.last_seen_at).toLocaleString()}</p>
        </div>
      </div>

      <div className="mt-8 rounded-lg border p-4">
        <h2 className="mb-3 text-sm font-semibold">Triage</h2>
        <div className="flex flex-wrap gap-2">
          <select
            className="border-input bg-background rounded-md border px-3 py-1.5 text-sm"
            value={selectedState}
            onChange={(e) => {
              setSelectedState(e.target.value);
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
            disabled={!selectedState || triageMutation.isPending}
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
            Triage saved (effect: {triageMutation.data.gate_effect})
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
              <span className="font-medium capitalize">
                {latestReachability.state.replaceAll("_", " ")}
              </span>
              {latestReachability.evidence ? ` — ${latestReachability.evidence}` : ""}{" "}
              ({new Date(latestReachability.created_at).toLocaleString()})
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
            onChange={(e) => setReachState(e.target.value)}
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
            onClick={() =>
              reachabilityMutation.mutate({
                findingId: findingId ?? "",
                state: reachState,
                evidence: reachEvidence,
              })}
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
