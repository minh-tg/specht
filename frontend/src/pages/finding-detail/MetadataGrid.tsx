import { DetailList, type DetailRow } from "@/components/DetailList";
import { analysisStateLabel, technicalStateLabel } from "@/lib/enums";
import { EMPTY_VALUE, formatDateTime } from "@/lib/format";
import type { Finding } from "@/types/api";
import { formatPercent } from "./cveText";

/** A date for a row, or nothing when the report carried none or an unreadable one. */
function dateValue(iso: string | undefined): string | undefined {
  const text = formatDateTime(iso);
  return text === EMPTY_VALUE ? undefined : text;
}

/** What is known about one finding, as a plain list of facts beside the page. */
export function MetadataGrid({ finding }: { readonly finding: Finding; }) {
  const intel = finding.intel;
  const rows: DetailRow[] = [
    { label: "Status", value: technicalStateLabel(finding.state) ?? undefined },
    { label: "Triage", value: analysisStateLabel(finding.analysis_state) ?? "Not triaged" },
    ...(typeof finding.current_score === "number"
      ? [{ label: "CVSS", value: finding.current_score.toFixed(1), code: true }]
      : []),
    ...(typeof intel?.epss === "number"
      ? [{ label: "EPSS", value: formatPercent(intel.epss), code: true }]
      : []),
    ...(intel
      ? [{
        label: "Known exploited",
        value: intel.kev
          ? <span className="text-sev-critical-fg">Yes</span>
          : <span className="text-muted-foreground">No</span>,
      }]
      : []),
    { label: "First seen", value: dateValue(finding.first_seen_at) },
    { label: "Last seen", value: dateValue(finding.last_seen_at) },
    {
      label: "Introduced",
      value: finding.introduced_commit_sha
        ? finding.introduced_commit_sha.slice(0, 12)
        : "Unattributed",
      code: true,
    },
    { label: "Fingerprint", value: finding.fingerprint, code: true },
  ];

  return <DetailList variant="inline" className="border-border border-t pt-4" rows={rows} />;
}
