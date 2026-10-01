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

// The API's fifth severity is `none` ("no severity assigned"), NOT `unknown`.
// `unknown` belongs to reachability only — see REACHABILITY_STATES below. These are
// semantically different: a `none`-severity finding is still a finding that must be
// triaged, whereas `unknown` reachability means the path could not be assessed.
// Using `unknown` here made every scanner-reported `none` fail validation and render
// as "Unknown".
export const SEVERITIES = ["critical", "high", "medium", "low", "none"] as const;
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

/**
 * Groups an analysis state into its triage bucket. Returns null for values
 * outside the canonical vocabulary so callers can ignore them; the buckets are
 * `needs_triage` (unanalyzed or in triage), `exploitable` and `dismissed`.
 */
export function triageBucket(
  state: string,
): "needs_triage" | "exploitable" | "dismissed" | null {
  switch (state) {
    case "unanalyzed":
    case "in_triage":
      return "needs_triage";
    case "exploitable":
      return "exploitable";
    case "false_positive":
    case "not_affected":
    case "accepted_risk":
    case "wont_fix":
      return "dismissed";
    default:
      return null;
  }
}

const ANALYSIS_LABELS: Record<AnalysisState, string> = {
  unanalyzed: "Not triaged",
  in_triage: "In triage",
  exploitable: "Exploitable",
  false_positive: "False positive",
  not_affected: "Not affected",
  accepted_risk: "Accepted risk",
  wont_fix: "Won't fix",
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
  none: "None",
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

/**
 * Rank of a severity where higher is more severe, derived from the order of
 * `SEVERITIES` so the two can never drift: `critical` ranks highest and `none`
 * lowest. Anything outside the vocabulary (including null/undefined) ranks -1,
 * below `none`, so an unrecognised value never counts as meeting a floor.
 */
export function severityRank(value: string | null | undefined): number {
  const index = SEVERITIES.indexOf(value as Severity);
  return index === -1 ? -1 : SEVERITIES.length - 1 - index;
}
