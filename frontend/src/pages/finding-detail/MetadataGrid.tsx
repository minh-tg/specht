import { analysisStateLabel, technicalStateLabel } from "@/lib/enums";
import { EMPTY_VALUE, formatDateTime } from "@/lib/format";
import type { Finding } from "@/types/api";
import { formatPercent } from "./cveText";

function Fact({ label, children, mono = false }: {
  readonly label: string;
  readonly children: React.ReactNode;
  readonly mono?: boolean;
}) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={mono ? "font-mono text-xs break-all" : "font-medium tabular-nums"}>
        {children}
      </dd>
    </>
  );
}

/** What is known about one finding, as a plain list of facts beside the page. */
export function MetadataGrid({ finding }: { readonly finding: Finding; }) {
  const intel = finding.intel;
  return (
    <dl className="border-border grid grid-cols-[auto_1fr] gap-x-5 gap-y-2.5 border-t pt-4 text-sm">
      <Fact label="Status">{technicalStateLabel(finding.state) ?? EMPTY_VALUE}</Fact>
      <Fact label="Triage">{analysisStateLabel(finding.analysis_state) ?? "Not triaged"}</Fact>
      {typeof finding.current_score === "number" && (
        <Fact label="CVSS" mono>{finding.current_score.toFixed(1)}</Fact>
      )}
      {typeof intel?.epss === "number" && <Fact label="EPSS" mono>{formatPercent(intel.epss)}
      </Fact>}
      {intel && (
        <Fact label="Known exploited">
          {intel.kev
            ? <span className="text-sev-critical-fg">Yes</span>
            : <span className="text-muted-foreground">No</span>}
        </Fact>
      )}
      <Fact label="First Seen">{formatDateTime(finding.first_seen_at)}</Fact>
      <Fact label="Last Seen">{formatDateTime(finding.last_seen_at)}</Fact>
      <Fact label="Introduced" mono>
        {finding.introduced_commit_sha
          ? finding.introduced_commit_sha.slice(0, 12)
          : "Unattributed"}
      </Fact>
      <Fact label="Fingerprint" mono>{finding.fingerprint}</Fact>
    </dl>
  );
}
