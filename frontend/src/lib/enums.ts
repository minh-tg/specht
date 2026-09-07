/**
 * Canonical enum vocabularies shared between the API surface and the UI.
 *
 * The backend persists these values under CHECK constraints (see the
 * migrations and the finding lifecycle package) and sends them over the
 * wire as plain strings. The wire is untrusted, so components must never
 * render a value verbatim: parse with the `is*` guards or format with the
 * `*Label` helpers, which fall back to a controlled "Unknown" instead of
 * echoing unvalidated input.
 */

export const ANALYSIS_STATES = [
  "unanalyzed",
  "in_triage",
  "exploitable",
  "false_positive",
  "not_affected",
  "accepted_risk",
  "wont_fix",
] as const;
export type AnalysisState = typeof ANALYSIS_STATES[number];

export const TECHNICAL_STATES = ["open", "fixed", "reopened"] as const;
export type TechnicalState = typeof TECHNICAL_STATES[number];

export const GATE_EFFECTS = ["block", "ignore"] as const;
export type GateEffect = typeof GATE_EFFECTS[number];

export const REACHABILITY_STATES = [
  "reachable",
  "not_reachable",
  "unknown",
  "not_applicable",
] as const;
export type ReachabilityState = typeof REACHABILITY_STATES[number];

export const SEVERITIES = ["critical", "high", "medium", "low", "unknown"] as const;
export type Severity = typeof SEVERITIES[number];

function isOneOf<T extends string>(
  values: readonly T[],
  value: string | null | undefined,
): value is T {
  return typeof value === "string" && (values as readonly string[]).includes(value);
}

export const isAnalysisState = (
  value: string | null | undefined,
): value is AnalysisState => isOneOf(ANALYSIS_STATES, value);

export const isTechnicalState = (
  value: string | null | undefined,
): value is TechnicalState => isOneOf(TECHNICAL_STATES, value);

export const isGateEffect = (value: string | null | undefined): value is GateEffect =>
  isOneOf(GATE_EFFECTS, value);

export const isReachabilityState = (
  value: string | null | undefined,
): value is ReachabilityState => isOneOf(REACHABILITY_STATES, value);

export const isSeverity = (value: string | null | undefined): value is Severity =>
  isOneOf(SEVERITIES, value);

const ANALYSIS_LABELS: Record<AnalysisState, string> = {
  unanalyzed: "Unanalyzed",
  in_triage: "In Triage",
  exploitable: "Confirmed",
  false_positive: "False Positive",
  not_affected: "Not Affected",
  accepted_risk: "Accepted Risk",
  wont_fix: "Won't Fix",
};

const TECHNICAL_LABELS: Record<TechnicalState, string> = {
  open: "Open",
  fixed: "Fixed",
  reopened: "Reopened",
};

const GATE_EFFECT_LABELS: Record<GateEffect, string> = {
  block: "Block",
  ignore: "Ignore",
};

const REACHABILITY_LABELS: Record<ReachabilityState, string> = {
  reachable: "Reachable",
  not_reachable: "Not Reachable",
  unknown: "Unknown",
  not_applicable: "Not Applicable",
};

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  unknown: "Unknown",
};

/**
 * Human label for an analysis state. Returns null when no analysis has been
 * recorded (empty/absent) so callers can show their own empty state, and a
 * controlled "Unknown" for anything outside the canonical vocabulary.
 */
export function analysisStateLabel(value: string | null | undefined): string | null {
  if (!value) return null;
  return isAnalysisState(value) ? ANALYSIS_LABELS[value] : "Unknown";
}

/** Human label for a technical (scan-derived) state; see analysisStateLabel. */
export function technicalStateLabel(value: string | null | undefined): string | null {
  if (!value) return null;
  return isTechnicalState(value) ? TECHNICAL_LABELS[value] : "Unknown";
}

/** Human label for a gate effect; see analysisStateLabel. */
export function gateEffectLabel(value: string | null | undefined): string | null {
  if (!value) return null;
  return isGateEffect(value) ? GATE_EFFECT_LABELS[value] : "Unknown";
}

/** Human label for a reachability state; see analysisStateLabel. */
export function reachabilityStateLabel(value: string | null | undefined): string | null {
  if (!value) return null;
  return isReachabilityState(value) ? REACHABILITY_LABELS[value] : "Unknown";
}

/** Human label for a severity; see analysisStateLabel. */
export function severityLabel(value: string | null | undefined): string | null {
  if (!value) return null;
  return isSeverity(value) ? SEVERITY_LABELS[value] : "Unknown";
}
