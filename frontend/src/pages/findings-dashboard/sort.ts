import {
  analysisStateLabel,
  findingKindLabel,
  severityRank,
  technicalStateLabel,
} from "@/lib/enums";
import { formatDate } from "@/lib/format";
import type { Finding } from "@/types/api";

export const PAGE_SIZE = 20;

/** Client-side ordering for the findings on the current page. */
export function sortFindings(findings: Finding[], by: string, dir: "asc" | "desc") {
  return [...findings].sort((a, b) => {
    let cmp = 0;
    if (by === "severity") {
      cmp = severityRank(a.current_severity) - severityRank(b.current_severity);
    } else if (by === "title") {
      cmp = a.current_title.localeCompare(b.current_title);
    } else {
      cmp = new Date(a.last_seen_at).getTime() - new Date(b.last_seen_at).getTime();
    }
    return dir === "desc" ? -cmp : cmp;
  });
}

export const SORT_OPTIONS: ReadonlyArray<{ value: string; label: string; }> = [
  { value: "severity:desc", label: "Most severe first" },
  { value: "severity:asc", label: "Least severe first" },
  { value: "title:asc", label: "Title A–Z" },
  { value: "title:desc", label: "Title Z–A" },
  { value: "last_seen:desc", label: "Last seen, newest first" },
  { value: "last_seen:asc", label: "Last seen, oldest first" },
];

/**
 * The columns that are hidden on narrow screens, as one line under the title,
 * so no field is lost to small viewports or to assistive technology.
 */
export function compactMeta(finding: Finding): string {
  return [
    findingKindLabel(finding.finding_kind),
    technicalStateLabel(finding.state),
    analysisStateLabel(finding.analysis_state),
    `Last seen ${formatDate(finding.last_seen_at)}`,
  ].filter(Boolean).join(" · ");
}
