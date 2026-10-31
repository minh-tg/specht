import type { AnalysisState, ReachabilityState } from "@/lib/enums";
import { localDateValue, toExpiryTimestamp } from "./format";

/** The three answers the decide-first form leads with. Keys 1 to 3 pick them in this order. */
export const DECISIONS = [
  {
    id: "real",
    name: "Real issue",
    effect: "Recorded as exploitable. It counts toward blocking until it is fixed.",
  },
  {
    id: "not_a_problem",
    name: "Not a problem",
    effect: "Never blocks. Needs a reason.",
  },
  {
    id: "accept",
    name: "Accept for now",
    effect: "Stops blocking until a date. Needs a reason.",
  },
] as const;
export type DecisionId = typeof DECISIONS[number]["id"];

/** The second question each decision asks, and the analysis state every answer records. */
export interface DecisionDetail {
  readonly id: string;
  readonly name: string;
  readonly note: string;
  readonly state: AnalysisState;
  /** Days until the decision lapses, for the states the server only takes with an expiry. */
  readonly days?: number;
}

export const NOT_A_PROBLEM_DETAILS: readonly DecisionDetail[] = [
  {
    id: "fp",
    name: "The scanner is wrong",
    note: "recorded as false positive",
    state: "false_positive",
  },
  {
    id: "na",
    name: "The code is not affected",
    note: "recorded as not affected",
    state: "not_affected",
  },
];

export const ACCEPT_DETAILS: readonly DecisionDetail[] = [
  { id: "30", name: "30 days", note: "accepted risk", state: "accepted_risk", days: 30 },
  { id: "90", name: "90 days", note: "accepted risk", state: "accepted_risk", days: 90 },
  {
    id: "wont",
    name: "1 year",
    note: "we will not fix it, review in a year",
    state: "wont_fix",
    days: 365,
  },
];

export function detailsFor(decision: DecisionId): readonly DecisionDetail[] {
  if (decision === "not_a_problem") return NOT_A_PROBLEM_DETAILS;
  if (decision === "accept") return ACCEPT_DETAILS;
  return [];
}

/** The local calendar day `days` from now, as a date-input value. */
export function dayFromNow(days: number, now: Date = new Date()): string {
  const day = new Date(now);
  day.setDate(day.getDate() + days);
  return localDateValue(day);
}

/** What one choice writes: the state, and the end of the expiry day on the person's clock. */
export function triageWrite(
  decision: DecisionId,
  detailId: string | null,
  now: Date = new Date(),
): { state: AnalysisState; expiresAt?: string; needsReason: boolean; } {
  if (decision === "real") return { state: "exploitable", needsReason: false };
  const details = detailsFor(decision);
  const detail = details.find((d) => d.id === detailId) ?? details[0]!;
  return {
    state: detail.state,
    expiresAt: detail.days ? toExpiryTimestamp(dayFromNow(detail.days, now)) : undefined,
    needsReason: true,
  };
}

/** The reachability answers, in the mock's order. */
export const REACH_ANSWERS: readonly { value: ReachabilityState; name: string; }[] = [
  { value: "reachable", name: "Yes" },
  { value: "not_reachable", name: "No" },
  { value: "unknown", name: "Not assessed" },
  { value: "not_applicable", name: "Does not apply" },
];

/** The gate skips a finding nobody can reach (internal/gate reachabilityExemptsFromGate). */
export const exemptsFromGate = (state: ReachabilityState | null): boolean =>
  state === "not_reachable" || state === "not_applicable";

/** What the reachability answer does to the gate, in a sentence. */
export function reachEffect(state: ReachabilityState, realIssue: boolean): string {
  if (realIssue) {
    return "No and Does not apply are off: a real issue keeps counting, and those answers would stop it.";
  }
  if (exemptsFromGate(state)) {
    return "Stops blocking: a finding nobody can reach does not count toward blocking. Add a reason so the audit trail shows why.";
  }
  if (state === "unknown") return "Not assessed still counts toward blocking.";
  return "Reachable keeps counting toward blocking.";
}
