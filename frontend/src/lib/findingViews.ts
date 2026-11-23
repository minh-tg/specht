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

/** What the project verdict counts as blocking, the list behind "N findings block this project". */
export const BLOCKS_GATE_QUERY = new URLSearchParams({ blocks_gate: "true" }).toString();

export const OPEN_CRITICAL_HIGH_QUERY = new URLSearchParams({
  status: OPEN_FINDING_STATES,
  severity: "critical,high",
}).toString();
