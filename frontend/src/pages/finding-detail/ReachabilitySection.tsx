import { useUpsertReachability } from "@/api/hooks";
import { ErrorState } from "@/components/ErrorState";
import { InfoTip } from "@/components/InfoTip";
import { SelectField } from "@/components/SelectField";
import { SkeletonLines } from "@/components/SkeletonLines";
import { isReachabilityState, type ReachabilityState, reachabilityStateLabel } from "@/lib/enums";
import { formatDateTime } from "@/lib/format";
import { truncateText } from "@/lib/utils";
import type { ReachabilityAssessment } from "@/types/api";
import { type ReactNode, useState } from "react";
import { MAX_EVIDENCE_LENGTH, REACHABILITY_OPTIONS } from "./options";
import { OutcomeRegions } from "./OutcomeRegions";

/** The latest assessment line, with truncated inline evidence. */
function latestAssessmentLine(latest: ReachabilityAssessment | null): ReactNode {
  if (!latest) {
    return (
      <>
        Latest: <span className="font-medium">Unknown</span>.{" "}
        No assessment yet; an unassessed finding still blocks the gate until marked not reachable or
        not applicable.
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
      {evidence && <span title={evidence}>{". "}{truncateText(evidence, MAX_EVIDENCE_LENGTH)}
      </span>} ({formatDateTime(latest.updated_at)})
    </>
  );
}

/** Reachability assessment controls and latest status for one finding. */
export function ReachabilitySection({
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
    body = <SkeletonLines label="Loading reachability" lines={1} className="mb-3" />;
  } else if (isError) {
    body = (
      <ErrorState
        className="mb-3"
        title="Could not load reachability."
        detail={error?.message ?? "request failed"}
      />
    );
  } else if (!isSuccess) {
    body = <SkeletonLines label="Loading reachability" lines={1} className="mb-3" />;
  } else {
    body = <p className="text-muted-foreground mb-3 text-xs">{latestAssessmentLine(latest)}</p>;
  }

  return (
    <section aria-labelledby="reachability-heading" className="mt-6 border-t pt-4">
      <div className="mb-3 flex items-center gap-1">
        <h3 id="reachability-heading" className="text-sm font-medium">Reachability</h3>
        <InfoTip term="reachability" />
      </div>
      {body}
      <div className="flex flex-wrap gap-2">
        <SelectField
          aria-label="Reachability assessment"
          value={reachState}
          onValueChange={(value) => setReachState(isReachabilityState(value) ? value : "")}
          options={[
            { value: "", label: "Select assessment..." },
            ...REACHABILITY_OPTIONS.map((opt) => ({ value: opt.value, label: opt.label })),
          ]}
        />
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
      />
    </section>
  );
}
