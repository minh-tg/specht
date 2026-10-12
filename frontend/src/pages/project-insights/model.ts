import { ANALYSIS_STATES, analysisStateLabel, severityLabel } from "@/lib/enums";
import type { Aging, AgingBucketName, OverdueFinding, ProjectStats } from "@/types/api";

export type BarTone = "critical" | "high" | "medium" | "low" | "neutral";

export interface BarDatum {
  readonly key: string;
  readonly label: string;
  readonly count: number;
  /** The part of the count that blocks the gate, drawn hatched. */
  readonly blocking: number;
  readonly tone: BarTone;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;

/**
 * One row per severity, most severe first. The four named levels always show, even at zero, so the
 * shape of the chart does not change from scan to scan; a rating the scanner left out shows only
 * when something has it.
 */
export function severityBars(stats: ProjectStats): BarDatum[] {
  const by = new Map(stats.by_severity.map((s) => [s.severity.toLowerCase(), s]));
  const rows: BarDatum[] = SEVERITY_ORDER.map((severity) => ({
    key: severity,
    label: severityLabel(severity) ?? severity,
    count: by.get(severity)?.count ?? 0,
    blocking: by.get(severity)?.blocking_count ?? 0,
    tone: severity,
  }));
  const rest = stats.by_severity.filter((s) =>
    !(SEVERITY_ORDER as readonly string[]).includes(s.severity.toLowerCase()) && s.count > 0
  );
  const other = rest.reduce((n, s) => n + s.count, 0);
  const otherBlocking = rest.reduce((n, s) => n + s.blocking_count, 0);
  if (other > 0) {
    rows.push({
      key: "unrated",
      label: severityLabel("unknown") ?? "Unrated",
      count: other,
      blocking: otherBlocking,
      tone: "neutral",
    });
  }
  return rows;
}

/** Triage states in the order the work moves through them; a state nobody holds is left out. */
export function stateBars(stats: ProjectStats): BarDatum[] {
  const counts = new Map((stats.by_analysis_state ?? []).map((s) => [s.state, s.count]));
  const known = ANALYSIS_STATES.filter((s) => (counts.get(s) ?? 0) > 0);
  const unknown = [...counts.keys()].filter((s) =>
    !(ANALYSIS_STATES as readonly string[]).includes(s) && (counts.get(s) ?? 0) > 0
  );
  return [...known, ...unknown].map((state) => ({
    key: state,
    label: analysisStateLabel(state) ?? state,
    count: counts.get(state) ?? 0,
    blocking: 0,
    tone: "neutral",
  }));
}

const AGE_LABEL: Record<AgingBucketName, string> = {
  new: "Under 7 days",
  aging: "7 to 29 days",
  stale: "30 to 89 days",
  debt: "90 days or more",
};

const AGE_ORDER: readonly AgingBucketName[] = ["new", "aging", "stale", "debt"];

/** The four age buckets, youngest first, always all four. */
export function ageBars(aging: Aging): BarDatum[] {
  return AGE_ORDER.map((bucket) => ({
    key: bucket,
    label: AGE_LABEL[bucket],
    count: aging.buckets.find((b) => b.bucket === bucket)?.count ?? 0,
    blocking: 0,
    tone: "neutral",
  }));
}

/** Counts per week, oldest first. */
export function weeklyCounts(aging: Aging): number[] {
  return aging.new_per_week.map((w) => w.count);
}

const DAY_MS = 24 * 60 * 60 * 1000;

/** How long ago the fix date passed, in whole days. */
export function daysOverdue(finding: OverdueFinding, now: Date): number {
  const due = Date.parse(finding.due_date);
  if (!Number.isFinite(due)) return 0;
  return Math.max(0, Math.floor((now.getTime() - due) / DAY_MS));
}
