import { scannedCommit } from "@/lib/commit";
import { reportToolLabel } from "@/lib/reportTool";
import { isReportInProgress } from "@/lib/verdict";
import type { FindingLocation, FindingRemediation, FindingSuggestion, Report } from "@/types/api";

/** Shortest commit prefix the change route accepts and renders. */
export const SHORT_COMMIT_LENGTH = 7;

/** The 7-character form of a commit used in headings and links. */
export function shortCommit(commit: string): string {
  return commit.slice(0, SHORT_COMMIT_LENGTH);
}

/** What the reports of one commit say, scanner by scanner. */
export interface CommitScans {
  /** The full SHA the commit in the route resolved to. */
  readonly sha: string;
  /** Every report of that SHA, newest first. */
  readonly reports: readonly Report[];
  /** The report the header takes its links from: the one a CI link named, else the newest. */
  readonly focus: Report;
  /** The newest report of each scanner, by scanner name. */
  readonly latest: readonly Report[];
  /** At least one report completed, so the commit has a verdict. */
  readonly judged: boolean;
  /** Scanners whose newest report of the commit is still being processed. */
  readonly running: readonly string[];
  /** Scanners whose newest report of the commit failed. Their findings are not counted. */
  readonly failed: readonly string[];
}

/**
 * The scans of the commit a change page is about. Every scanner's reports count: the verdict is
 * the commit's, the same one the pull-request check gives, so it does not depend on which CI step
 * a reader followed. A `reportId` only picks the SHA (when the route's prefix matches more than
 * one) and the report the header links from. A commit prefix is matched case-insensitively and
 * the newest matching report picks the SHA. Null when no report matches.
 */
export function commitScans(
  reports: readonly Report[] | undefined,
  commit: string,
  reportId?: string | null,
): CommitScans | null {
  const matching = (reports ?? []).filter((report) => scannedCommit(report, commit));
  if (matching.length === 0) return null;
  const ordered = [...matching].sort(newestFirst);
  const named = reportId ? ordered.find((report) => report.id === reportId) : undefined;
  const sha = (named ?? ordered[0]).commit_sha?.toLowerCase() ?? "";
  const own = ordered.filter((report) => report.commit_sha?.toLowerCase() === sha);

  const byScanner = new Map<string, Report>();
  for (const report of own) {
    const name = reportToolLabel(report);
    if (!byScanner.has(name)) byScanner.set(name, report);
  }
  const latest = [...byScanner.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([, report]) => report);
  const names = (keep: (report: Report) => boolean) =>
    latest.filter(keep).map((report) => reportToolLabel(report));

  return {
    sha,
    reports: own,
    focus: named ?? own[0],
    latest,
    judged: own.some((report) => report.status === "completed"),
    running: names((report) => isReportInProgress(report.status)),
    failed: names((report) => report.status === "failed"),
  };
}

/**
 * Scanners that reported on the branch's previous scanned commit but have sent nothing for this one:
 * their CI step most likely has not finished. Only the commit just before counts, so a scanner taken
 * out of the pipeline drops off after one push. Empty for the first commit of a branch.
 */
export function missingScanners(
  branchReports: readonly Report[] | undefined,
  scans: CommitScans,
): string[] {
  const start = scans.reports.reduce(
    (oldest, report) => report.created_at < oldest ? report.created_at : oldest,
    scans.reports[0]?.created_at ?? "",
  );
  const earlier = (branchReports ?? [])
    .filter((report) =>
      !!report.commit_sha && report.commit_sha.toLowerCase() !== scans.sha
      && report.created_at < start
    )
    .sort(newestFirst);
  const previous = earlier[0]?.commit_sha?.toLowerCase();
  if (!previous) return [];
  const here = new Set(scans.reports.map((report) => reportToolLabel(report)));
  const expected = new Set(
    earlier
      .filter((report) => report.commit_sha?.toLowerCase() === previous)
      .map((report) => reportToolLabel(report)),
  );
  return [...expected].filter((name) => !here.has(name)).sort((a, b) => a.localeCompare(b));
}

function newestFirst(a: Report, b: Report): number {
  if (a.created_at === b.created_at) return a.id < b.id ? 1 : -1;
  return a.created_at < b.created_at ? 1 : -1;
}

/**
 * One line naming where a finding sits: `file:start_line`, then a resource, then
 * the scanner's free-form summary. Null when the location carries nothing.
 */
export function locationLine(location?: FindingLocation): string | null {
  if (location?.file) {
    return location.start_line != null ? `${location.file}:${location.start_line}` : location.file;
  }
  if (location?.resource) return location.resource;
  if (location?.summary) return location.summary;
  return null;
}

/**
 * Whether a suggestion is an actual fix. When the scanner supplied nothing usable, the server
 * still sends one suggestion (action "review", the file or package as its target) and marks it
 * `fallback`. That is a pointer to where to look, not a fix, so it must not be shown as the thing
 * to do or copied as one.
 */
export function isRealFix(suggestion?: FindingSuggestion): suggestion is FindingSuggestion {
  return !!suggestion && !suggestion.fallback;
}

/**
 * One actionable line for a finding: the first line of the scanner's fix summary, else the
 * reviewable suggestion's action and target. Null when the scanner supplied no fix (including when
 * the summary is only the server's fallback label or the suggestion is the server's generic
 * "review" fallback), so the caller can say so plainly instead of showing a made-up instruction.
 */
export function fixAction(
  finding: { remediation?: FindingRemediation; suggestion?: FindingSuggestion; },
): string | null {
  // `fallback` marks text the server wrote because the scanner supplied nothing; it is a label,
  // not advice, so it must not be offered as the thing to do.
  const summary = finding.remediation?.fallback ? undefined : finding.remediation?.summary;
  if (summary) {
    const first = summary.split("\n")[0].trim();
    if (first) return first;
  }
  if (isRealFix(finding.suggestion)) {
    const { action, target } = finding.suggestion;
    return target ? `${action} ${target}` : action;
  }
  return null;
}

/**
 * The fix as a sentence: the scanner's text as written, except that a suggestion such as
 * "review src/db.ts" starts with a capital. Null when there is no fix to offer.
 */
export function fixSentence(
  finding: { remediation?: FindingRemediation; suggestion?: FindingSuggestion; },
): string | null {
  const raw = fixAction(finding);
  return raw ? raw.charAt(0).toUpperCase() + raw.slice(1) : null;
}

/** Human name for the layer that supplied the effective policy floor. */
export function floorSourceLabel(source: string): string {
  switch (source) {
    case "template":
      return "team template";
    case "override":
      return "project override";
    case "default":
      return "platform default";
    default:
      return source;
  }
}

/**
 * Findings that block the project but were not introduced by the change: the
 * project gate's `blocked_by` minus the change gate's `blocked_by`. Order
 * follows the project gate so it stays stable.
 */
export function existingBlockers(
  projectBlockedBy: string[] | undefined,
  changeBlockedBy: string[] | undefined,
): string[] {
  const introduced = new Set(changeBlockedBy ?? []);
  return (projectBlockedBy ?? []).filter((id) => !introduced.has(id));
}
