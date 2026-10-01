import { describe, expect, it } from "vitest";
import {
  ANALYSIS_STATES,
  analysisStateLabel,
  GATE_EFFECTS,
  gateEffectLabel,
  isAnalysisState,
  isGateEffect,
  isReachabilityState,
  isSeverity,
  isTechnicalState,
  REACHABILITY_STATES,
  reachabilityStateLabel,
  SEVERITIES,
  severityLabel,
  TECHNICAL_STATES,
  technicalStateLabel,
  triageBucket,
} from "./enums";

describe("enum vocabularies", () => {
  it("mirrors the backend analysis_state CHECK constraint", () => {
    expect(ANALYSIS_STATES).toEqual([
      "unanalyzed",
      "in_triage",
      "exploitable",
      "false_positive",
      "not_affected",
      "accepted_risk",
      "wont_fix",
    ]);
  });

  it("mirrors the backend gate_effect CHECK constraint", () => {
    expect(GATE_EFFECTS).toEqual(["block", "ignore"]);
  });

  it("mirrors the backend technical state vocabulary", () => {
    expect(TECHNICAL_STATES).toEqual(["open", "fixed", "reopened"]);
  });

  it("mirrors the backend reachability vocabulary", () => {
    expect(REACHABILITY_STATES).toEqual([
      "reachable",
      "not_reachable",
      "unknown",
      "not_applicable",
    ]);
  });

  it("mirrors the backend severity scale", () => {
    // `none`, not `unknown`: the API's fifth severity is the absence of a
    // severity, and `unknown` is reserved for reachability.
    expect(SEVERITIES).toEqual(["critical", "high", "medium", "low", "none"]);
    expect(REACHABILITY_STATES).toContain("unknown");
    expect(SEVERITIES).not.toContain("unknown");
  });
});

describe("enum guards", () => {
  it("accepts canonical values and rejects anything else", () => {
    expect(isAnalysisState("accepted_risk")).toBe(true);
    expect(isAnalysisState("bogus")).toBe(false);
    expect(isAnalysisState("")).toBe(false);

    expect(isTechnicalState("reopened")).toBe(true);
    expect(isTechnicalState("closed")).toBe(false);

    expect(isGateEffect("ignore")).toBe(true);
    expect(isGateEffect("waive")).toBe(false);

    expect(isReachabilityState("not_reachable")).toBe(true);
    expect(isReachabilityState("maybe")).toBe(false);

    expect(isSeverity("critical")).toBe(true);
    expect(isSeverity("CRITICAL")).toBe(false);
    expect(isSeverity("info")).toBe(false);
  });
});

describe("analysisStateLabel", () => {
  it("labels every canonical analysis state", () => {
    expect(analysisStateLabel("unanalyzed")).toBe("Unanalyzed");
    expect(analysisStateLabel("in_triage")).toBe("In Triage");
    expect(analysisStateLabel("exploitable")).toBe("Confirmed");
    expect(analysisStateLabel("false_positive")).toBe("False Positive");
    expect(analysisStateLabel("not_affected")).toBe("Not Affected");
    expect(analysisStateLabel("accepted_risk")).toBe("Accepted Risk");
    expect(analysisStateLabel("wont_fix")).toBe("Won't Fix");
  });

  it("returns null when no analysis has been recorded", () => {
    expect(analysisStateLabel("")).toBeNull();
    expect(analysisStateLabel(null)).toBeNull();
    expect(analysisStateLabel(undefined)).toBeNull();
  });

  it("falls back to a controlled label for unvalidated input", () => {
    // An unvalidated server value must never render raw.
    expect(analysisStateLabel("EXPLOITABLE<script>")).toBe("Unknown");
    expect(analysisStateLabel("pending_review")).toBe("Unknown");
  });
});

describe("technicalStateLabel", () => {
  it("labels every canonical technical state", () => {
    expect(technicalStateLabel("open")).toBe("Open");
    expect(technicalStateLabel("fixed")).toBe("Fixed");
    expect(technicalStateLabel("reopened")).toBe("Reopened");
  });

  it("falls back for missing or unvalidated input", () => {
    expect(technicalStateLabel(null)).toBeNull();
    expect(technicalStateLabel("")).toBeNull();
    expect(technicalStateLabel("resolved")).toBe("Unknown");
  });
});

describe("gateEffectLabel", () => {
  it("labels the canonical gate effects", () => {
    expect(gateEffectLabel("block")).toBe("Block");
    expect(gateEffectLabel("ignore")).toBe("Ignore");
  });

  it("falls back for missing or unvalidated input", () => {
    expect(gateEffectLabel(null)).toBeNull();
    expect(gateEffectLabel("")).toBeNull();
    expect(gateEffectLabel("defer")).toBe("Unknown");
  });
});

describe("reachabilityStateLabel", () => {
  it("labels every canonical reachability state", () => {
    expect(reachabilityStateLabel("reachable")).toBe("Reachable");
    expect(reachabilityStateLabel("not_reachable")).toBe("Not Reachable");
    expect(reachabilityStateLabel("unknown")).toBe("Unknown");
    expect(reachabilityStateLabel("not_applicable")).toBe("Not Applicable");
  });

  it("falls back for missing or unvalidated input", () => {
    expect(reachabilityStateLabel(null)).toBeNull();
    expect(reachabilityStateLabel("unreachable")).toBe("Unknown");
  });
});

describe("triageBucket", () => {
  it("groups unanalyzed and in-triage into needs_triage", () => {
    expect(triageBucket("unanalyzed")).toBe("needs_triage");
    expect(triageBucket("in_triage")).toBe("needs_triage");
  });

  it("groups exploitable on its own", () => {
    expect(triageBucket("exploitable")).toBe("exploitable");
  });

  it("groups every settled non-exploitable state as dismissed", () => {
    expect(triageBucket("false_positive")).toBe("dismissed");
    expect(triageBucket("not_affected")).toBe("dismissed");
    expect(triageBucket("accepted_risk")).toBe("dismissed");
    expect(triageBucket("wont_fix")).toBe("dismissed");
  });

  it("returns null for out-of-vocabulary states", () => {
    expect(triageBucket("")).toBeNull();
    expect(triageBucket("pending_review")).toBeNull();
    expect(triageBucket("UNANALYZED")).toBeNull();
  });
});

describe("severityLabel", () => {
  it("labels every canonical severity", () => {
    expect(severityLabel("critical")).toBe("Critical");
    expect(severityLabel("high")).toBe("High");
    expect(severityLabel("medium")).toBe("Medium");
    expect(severityLabel("low")).toBe("Low");
    expect(severityLabel("none")).toBe("None");
    // `unknown` is a reachability value, so it is out of vocabulary for severity
    // and must fall back rather than be treated as the fifth severity.
    expect(severityLabel("unknown")).toBe("Unknown");
  });

  it("falls back for missing or unvalidated input", () => {
    expect(severityLabel(null)).toBeNull();
    expect(severityLabel("severe")).toBe("Unknown");
  });
});
