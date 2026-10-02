import { analysisStateLabel, technicalStateLabel } from "@/lib/enums";
import { formatDateTime } from "@/lib/format";
import type { Finding } from "@/types/api";

/** Status, triage, timestamps and provenance for one finding. */
export function MetadataGrid({ finding }: { readonly finding: Finding; }) {
  return (
    <div className="grid grid-cols-1 gap-4 text-sm sm:grid-cols-2">
      <div>
        <span className="text-muted-foreground">Status</span>
        <p className="font-medium">{technicalStateLabel(finding.state) ?? "–"}</p>
      </div>
      <div>
        <span className="text-muted-foreground">Triage</span>
        <p className="font-medium">
          {analysisStateLabel(finding.analysis_state) ?? "Not triaged"}
        </p>
      </div>
      <div>
        <span className="text-muted-foreground">First Seen</span>
        <p className="font-medium">{formatDateTime(finding.first_seen_at)}</p>
      </div>
      <div>
        <span className="text-muted-foreground">Last Seen</span>
        <p className="font-medium">{formatDateTime(finding.last_seen_at)}</p>
      </div>
      <div>
        <span className="text-muted-foreground">Introduced</span>
        <p className="font-mono text-xs">
          {finding.introduced_commit_sha
            ? finding.introduced_commit_sha.slice(0, 12)
            : "Unattributed"}
        </p>
      </div>
      <div className="sm:col-span-2">
        <span className="text-muted-foreground">Fingerprint</span>
        <p className="font-mono text-xs break-all">{finding.fingerprint}</p>
      </div>
    </div>
  );
}
