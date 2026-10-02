import {
  ANALYSIS_STATES,
  type AnalysisState,
  analysisStateLabel,
  REACHABILITY_STATES,
  type ReachabilityState,
  reachabilityStateLabel,
} from "@/lib/enums";

/** Inline evidence is capped so an oversized payload cannot blow up layout. */
export const MAX_EVIDENCE_LENGTH = 240;

export const REACHABILITY_OPTIONS: Array<{ value: ReachabilityState; label: string; }> =
  REACHABILITY_STATES.map((value) => ({
    value,
    label: reachabilityStateLabel(value) ?? value,
  }));

/**
 * Extra input each decision state needs before it can be applied. A state
 * absent here is not offered by the triage control at all.
 */
export const TRIAGE_REQUIREMENTS: Partial<
  Record<AnalysisState, { requiresReason: boolean; requiresExpiry: boolean; }>
> = {
  exploitable: { requiresReason: false, requiresExpiry: false },
  false_positive: { requiresReason: true, requiresExpiry: false },
  not_affected: { requiresReason: true, requiresExpiry: false },
  accepted_risk: { requiresReason: true, requiresExpiry: true },
  wont_fix: { requiresReason: true, requiresExpiry: true },
};

export const TRIAGE_OPTIONS = ANALYSIS_STATES.flatMap((value) => {
  const requirements = TRIAGE_REQUIREMENTS[value];
  if (!requirements) return [];
  return [{ value, label: analysisStateLabel(value) ?? value, ...requirements }];
});

export const SOURCE_LINK_SCHEMES = new Set(["http:", "https:"]);
