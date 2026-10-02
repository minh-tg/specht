/**
 * The one place that explains Specht's own words. Every explanation shown in a tooltip comes from
 * here, so a wording fix is made once and reviewed once, and no screen invents its own
 * definition. `short` is written for someone who has never patched a dependency: plain words, one
 * or two sentences.
 *
 * Only add a term here when its meaning is stated by the product (the API schema or the gate
 * code). Do not add a guess about what a security term "usually" means.
 */
export interface GlossaryEntry {
  /** The word as the UI shows it, used in the accessible name of its info button. */
  readonly label: string;
  /** At most 25 words. */
  readonly short: string;
}

export const GLOSSARY = {
  verdict: {
    label: "Verdict",
    short:
      "The project's overall gate result: Blocked, Passing or No scans. It tells your CI pipeline whether any finding should stop the release.",
  },
  severityFloor: {
    label: "Severity floor",
    short:
      "The lowest severity that can block the gate. Findings below the floor are shown but never block.",
  },
  policySource: {
    label: "Policy source",
    short:
      "Where the severity floor comes from: a project override, a shared policy template, or the built-in default.",
  },
  blocksGate: {
    label: "Blocks gate",
    short: "Whether this finding is one of the things currently stopping the project from passing.",
  },
  reachability: {
    label: "Reachability",
    short:
      "Whether your code can actually run the vulnerable part of a library. A person records it, with evidence.",
  },
  exploitable: {
    label: "Exploitable",
    short:
      "You have confirmed an attacker could use this against this project. It keeps blocking the gate until it is fixed or waived.",
  },
  falsePositive: {
    label: "False positive",
    short:
      "The scanner got it wrong: this is not a real problem. It stops blocking the gate, and you must say why.",
  },
  notAffected: {
    label: "Not affected",
    short:
      "The issue is real in general but cannot be exploited in how this project uses it. It stops blocking, and you must say why.",
  },
  wontFix: {
    label: "Won't fix",
    short:
      "The team decided not to fix this for now. It stops blocking until the review date, and you must say why.",
  },
  acceptedRisk: {
    label: "Accepted risk",
    short:
      "The team knowingly lives with this finding for a limited time. It stops blocking until the review date.",
  },
  waiver: {
    label: "Waiver",
    short:
      "A rule that excuses specific findings so they stop blocking the gate, until it expires or is switched off.",
  },
} as const satisfies Record<string, GlossaryEntry>;

export type GlossaryKey = keyof typeof GLOSSARY;
