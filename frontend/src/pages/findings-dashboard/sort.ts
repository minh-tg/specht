import { analysisStateLabel, findingKindLabel, technicalStateLabel } from "@/lib/enums";
import { formatDate } from "@/lib/format";
import type { Finding } from "@/types/api";

export const PAGE_SIZE = 20;

/** The orderings the server offers, as the narrow-screen dropdown lists them. */
export const SORT_OPTIONS: ReadonlyArray<{ value: string; label: string; }> = [
  { value: "severity:desc", label: "Most severe first" },
  { value: "severity:asc", label: "Least severe first" },
  { value: "first_seen:asc", label: "Oldest first" },
  { value: "first_seen:desc", label: "Newest first" },
  { value: "last_seen:desc", label: "Last seen, newest first" },
  { value: "last_seen:asc", label: "Last seen, oldest first" },
  { value: "title:asc", label: "Title A–Z" },
  { value: "title:desc", label: "Title Z–A" },
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
