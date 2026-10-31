import { analysisStateLabel } from "@/lib/enums";
import { formatDate } from "@/lib/format";
import { waiverBucket, waiverTitle } from "@/pages/project-waivers/classify";
import type { Finding, GateStatus, Report, Waiver } from "@/types/api";

/**
 * The findings that blocked the scan a reader was looking at, handed to the page of the scan that
 * replaces it. The server keeps no record of what blocked an earlier scan (a gate is always
 * evaluated against today's findings), so the only exact list is the one the blocked page showed.
 * It travels in the router's location state and survives a reload.
 */
export interface PreviousBlockers {
  readonly slug: string;
  /** The report that blocked. */
  readonly reportId: string;
  readonly ids: readonly string[];
}

const STATE_KEY = "previousBlockers";

/** The location state a blocked page passes to the page of the scan that replaces it. */
export function carryPrevious(previous: PreviousBlockers): { [STATE_KEY]: PreviousBlockers; } {
  return { [STATE_KEY]: previous };
}

/**
 * The blockers a navigation carried, or null. Location state is not trusted: it must have the
 * expected shape, belong to this project, and name another report than the one on screen.
 */
export function readPrevious(
  state: unknown,
  slug: string,
  currentReportId: string | undefined,
): PreviousBlockers | null {
  if (typeof state !== "object" || state === null) return null;
  const value = (state as Record<string, unknown>)[STATE_KEY];
  if (typeof value !== "object" || value === null) return null;
  const { slug: from, reportId, ids } = value as Record<string, unknown>;
  if (from !== slug || typeof reportId !== "string" || reportId === currentReportId) return null;
  if (!Array.isArray(ids) || !ids.every((id) => typeof id === "string")) return null;
  if (ids.length === 0) return null;
  return { slug, reportId, ids: ids as string[] };
}

/** How the page answers "did the earlier blockers clear?". */
export type ClearedVerdict =
  /** Waiting for the gate of the earlier scan. */
  | { readonly kind: "checking"; }
  /** The gate of the earlier scan could not be read, so nothing can be said. */
  | { readonly kind: "unchecked"; }
  /** Every earlier blocker is closed, waived, dismissed or no longer counted. */
  | { readonly kind: "unblocked"; }
  /** These earlier blockers are open and still block the earlier scan. */
  | { readonly kind: "open"; readonly ids: readonly string[]; };

/**
 * Whether the passing scan really cleared what blocked the one before it. The earlier scan's gate,
 * evaluated now, lists the findings it still blocks on. A previous blocker in that list is open and
 * not waived, dismissed or fixed, yet the new scan passed: the new verdict never looked at it
 * (this happens when a scan has no baseline linking it to the earlier one). It must not read as
 * cleared.
 */
export function judgeCleared(
  previous: PreviousBlockers,
  earlierGate: GateStatus | undefined,
  state: "pending" | "error" | "success",
): ClearedVerdict {
  if (state === "pending") return { kind: "checking" };
  if (state === "error" || !earlierGate) return { kind: "unchecked" };
  const stillBlocking = new Set(earlierGate.blocked_by ?? []);
  const open = previous.ids.filter((id) => stillBlocking.has(id));
  return open.length > 0 ? { kind: "open", ids: open } : { kind: "unblocked" };
}

/** Why one earlier blocker no longer blocks, from the server's records only. */
export type Cause =
  /** A scan that examined it no longer finds it. */
  | { readonly kind: "fixed"; }
  /** Its only report was deleted. Nothing says it was fixed. */
  | { readonly kind: "archived"; }
  /** An approved, switched-on waiver covers it. `waiver` is absent when none names this finding. */
  | { readonly kind: "waived"; readonly waiver?: Waiver; }
  /** An analyst set a state the gate ignores. */
  | {
    readonly kind: "triaged";
    readonly state: string;
    readonly until?: string;
  }
  /** Open and not dismissed, but the gate no longer counts it. The server gives no reason. */
  | { readonly kind: "uncounted"; };

export interface CauseContext {
  /** The earlier scan's gate, evaluated now. */
  readonly earlierGate?: GateStatus;
  /** The passing scan's gate. */
  readonly gate?: GateStatus;
  readonly waivers: readonly Waiver[];
  readonly now: Date;
}

/** Analysis states the gate ignores (`finding.GateEffectFor`). */
const DISMISSED = new Set(["false_positive", "not_affected", "accepted_risk", "wont_fix"]);

/** The approved, switched-on, unexpired waiver that names this finding, if one does. */
export function waiverFor(
  findingId: string,
  waivers: readonly Waiver[],
  now: Date,
): Waiver | undefined {
  return waivers.find((waiver) =>
    waiverBucket(waiver, now) === "in_force"
    && (waiver.targets ?? []).some((target) => target.finding_id === findingId)
  );
}

/**
 * How one earlier blocker cleared. The technical state comes first (a fixed finding stays fixed
 * whatever else is recorded), then the gate's own verdict on waivers, then the analysis state. A
 * finding that is none of these is open and uncounted, and the row says exactly that.
 */
export function explainCleared(finding: Finding, context: CauseContext): Cause {
  if (finding.state === "fixed") return { kind: "fixed" };
  if (finding.state === "archived") return { kind: "archived" };

  const waivedIds = new Set([
    ...(context.earlierGate?.waived_finding_ids ?? []),
    ...(context.gate?.waived_finding_ids ?? []),
  ]);
  if (waivedIds.has(finding.id)) {
    return { kind: "waived", waiver: waiverFor(finding.id, context.waivers, context.now) };
  }

  if (finding.gate_effect === "ignore" && DISMISSED.has(finding.analysis_state)) {
    return {
      kind: "triaged",
      state: finding.analysis_state,
      until: finding.analysis_expires_at,
    };
  }
  return { kind: "uncounted" };
}

/** The sentence under a cleared finding's title. */
export function causeText(cause: Cause): string {
  switch (cause.kind) {
    case "fixed":
      return "Fixed: a scan that checks for it no longer finds it.";
    case "archived":
      return "Archived: the report that found it was deleted. Nothing confirms it is fixed.";
    case "waived":
      return waivedText(cause.waiver);
    case "triaged": {
      const label = (analysisStateLabel(cause.state) ?? "dismissed").toLowerCase();
      return cause.until
        ? `Marked ${label} until ${formatDate(cause.until)}. It blocks again after that.`
        : `Marked ${label}. The gate ignores it.`;
    }
    case "uncounted":
      return "Still open, but it no longer counts toward the gate.";
  }
}

function waivedText(waiver: Waiver | undefined): string {
  if (!waiver) return "Waived: an approved waiver covers it.";
  const by = waiver.decided_by_name ? ` by ${waiver.decided_by_name}` : "";
  const name = `“${waiverTitle(waiver)}”`;
  return waiver.expires_at
    ? `Waived by ${name}, approved${by}, until ${
      formatDate(waiver.expires_at)
    }. It blocks again after that.`
    : `Waived by ${name}, approved${by}, with no end date.`;
}

/** What a report says it covered, for the line under the end state. */
export interface ScanCoverage {
  /** True when the report was a full scan with no filter declared. */
  readonly unfiltered: boolean;
  readonly text: string;
}

const SEVERITY_WORDS: Record<string, string> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  unknown: "unrated",
};

function joinWords(words: readonly string[]): string {
  if (words.length <= 1) return words.join("");
  return `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}`;
}

/**
 * What the scan covered, from the report's own fields. The server stores a completeness for every
 * report but does not send it, so a full scan is described as "no filter declared", not as
 * complete: scanners that give no completeness (Semgrep, SARIF, Checkov and others) are stored as
 * unknown. A filtered or incremental scan says what it left out.
 */
export function scanCoverage(report: Report): ScanCoverage {
  const filter = report.scan_filter;
  const severities = filter?.severities ?? [];
  const parts: string[] = [];
  if (severities.length > 0) {
    parts.push(
      `only ${joinWords(severities.map((s) => SEVERITY_WORDS[s] ?? s))} findings`,
    );
  }
  if (filter?.fixable_only) parts.push("only findings with a fix");
  if (parts.length > 0) {
    return {
      unfiltered: false,
      text: `Filtered scan: it kept ${
        parts.join(" and ")
      }. Findings outside the filter were not examined and stay as they were.`,
    };
  }
  if (report.scan_mode === "incremental") {
    const files = report.changed_files?.length ?? 0;
    return {
      unfiltered: false,
      text: `Incremental scan of ${files} changed ${
        files === 1 ? "file" : "files"
      }. Findings in other files were not examined.`,
    };
  }
  return { unfiltered: true, text: "Full scan, no filter declared." };
}
