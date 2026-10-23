import { ANALYSIS_STATES, triageBucket } from "@/lib/enums";

/** Matches the open_findings view used by project counters. */
export const OPEN_FINDING_STATES = "open,reopened";
export const NEEDS_TRIAGE_STATES = ANALYSIS_STATES
  .filter((state) => triageBucket(state) === "needs_triage")
  .join(",");

export const NEEDS_TRIAGE_QUERY = new URLSearchParams({
  status: OPEN_FINDING_STATES,
  analysis_state: NEEDS_TRIAGE_STATES,
}).toString();

export const OPEN_CRITICAL_HIGH_QUERY = new URLSearchParams({
  status: OPEN_FINDING_STATES,
  severity: "critical,high",
}).toString();
