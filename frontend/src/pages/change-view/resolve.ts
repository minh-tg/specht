import type { FindingLocation, FindingRemediation, FindingSuggestion, Report } from "@/types/api";

/** Shortest commit prefix the change route accepts and renders. */
export const SHORT_COMMIT_LENGTH = 7;

/** The 7-character form of a commit used in headings and links. */
export function shortCommit(commit: string): string {
  return commit.slice(0, SHORT_COMMIT_LENGTH);
}

/**
 * The report a change resolves to.
 *
 * A commit is matched case-insensitively against the start of each report's
 * `commit_sha`, so both the full SHA and any prefix the route carries resolve
 * to the same scan; the newest by `created_at` wins when several match. An
 * explicit `reportId` wins over the commit match, but only when it names a
 * report that is actually in the list: a stale or unknown override must not
 * silently fall back to a different scan.
 */
export function resolveReport(
  reports: Report[] | undefined,
  commit: string,
  reportId?: string | null,
): Report | null {
  if (!reports?.length) return null;

  if (reportId) {
    return reports.find((report) => report.id === reportId) ?? null;
  }

  if (!commit) return null;

  const prefix = commit.toLowerCase();
  let newest: Report | null = null;
  for (const report of reports) {
    if (!report.commit_sha?.toLowerCase().startsWith(prefix)) continue;
    if (newest === null || report.created_at > newest.created_at) newest = report;
  }
  return newest;
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
 * One actionable line for a finding: the first line of the scanner's fix summary, else the
 * reviewable suggestion's action and target. Null when the scanner supplied no fix (including when
 * the summary is only the server's fallback label), so the caller
 * can say so plainly instead of showing a made-up instruction.
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
  if (finding.suggestion?.action) {
    const { action, target } = finding.suggestion;
    return target ? `${action} ${target}` : action;
  }
  return null;
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
