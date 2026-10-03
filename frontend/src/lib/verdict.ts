import { triageBucket } from "@/lib/enums";
import type { AnalysisStateCount, GateStatus, ProjectStats } from "@/types/api";

export type Verdict = "blocked" | "passing" | "no_scans" | "unknown";

/**
 * Project-level verdict for a dashboard header.
 *
 * `unknown` while either input is still loading: a verdict must never flash
 * "passing" just because the gate has not arrived yet. A project with no
 * reports cannot be passing either, so it reads `no_scans`.
 */
export function projectVerdict(input: { gate?: GateStatus; stats?: ProjectStats; }): Verdict {
  if (!input.gate || !input.stats) return "unknown";
  if (input.stats.report_count === 0) return "no_scans";
  if (input.gate.threshold_breached) return "blocked";
  return "passing";
}

/**
 * Number of findings blocking the gate. `blocked_by` holds the actual IDs;
 * the count fields on the gate and the stats can desynchronise from it, so
 * they are never used here.
 */
export function blockerCount(gate?: GateStatus): number {
  return gate?.blocked_by?.length ?? 0;
}

/**
 * True while a report is still being processed. The server stores that state as
 * `processing`; openapi.yaml documents it as `pending`, so both are accepted.
 */
export function isReportInProgress(status: string | undefined): boolean {
  return status === "processing" || status === "pending";
}

/** True when the newest report is still running or failed outright. */
export function isDegraded(stats?: ProjectStats): boolean {
  const status = stats?.latest_report?.status;
  return status === "failed" || isReportInProgress(status);
}

/**
 * Why the verdict cannot be fully trusted right now, in one sentence, or null when it can. A failed
 * scan adds no findings, so a project can read PASSING while the evidence is missing; this is the
 * wording used wherever that is said (the project page and the project list).
 */
export function degradedMessage(stats?: ProjectStats): string | null {
  const status = stats?.latest_report?.status;
  if (status === "failed") return "The latest scan failed, so this verdict may be incomplete.";
  if (isReportInProgress(status)) {
    return "The latest scan is still processing, so this verdict may change.";
  }
  return null;
}

export interface TriageBucketCounts {
  needsTriage: number;
  exploitable: number;
  dismissed: number;
}

/**
 * Groups per-state finding counts into the three triage buckets. Returns null
 * when the server did not send the breakdown, so callers can hide the section
 * instead of showing misleading zeros.
 */
export function triageBuckets(byState?: AnalysisStateCount[]): TriageBucketCounts | null {
  if (byState === undefined) return null;

  const counts: TriageBucketCounts = { needsTriage: 0, exploitable: 0, dismissed: 0 };
  for (const { state, count } of byState) {
    switch (triageBucket(state)) {
      case "needs_triage":
        counts.needsTriage += count;
        break;
      case "exploitable":
        counts.exploitable += count;
        break;
      case "dismissed":
        counts.dismissed += count;
        break;
    }
  }
  return counts;
}
