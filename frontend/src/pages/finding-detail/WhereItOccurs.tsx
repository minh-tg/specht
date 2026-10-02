import type { Finding } from "@/types/api";
import { locationLineRange, locationSubjectLabel } from "./format";

/** The file, resource or URL the scanner observed the finding at. */
export function WhereItOccurs({ finding }: { readonly finding: Finding; }) {
  return (
    <div className="mt-8 rounded-lg border p-4">
      <h2 className="mb-3 text-sm font-semibold">Where it occurs</h2>
      {finding.location
          && (finding.location.file || finding.location.resource || finding.location.summary)
        ? (
          <div className="grid grid-cols-1 gap-4 text-sm sm:grid-cols-2">
            <div>
              <span className="text-muted-foreground">
                {locationSubjectLabel(finding.finding_kind)}
              </span>
              <p className="font-mono text-xs break-all select-all">
                {finding.location.file ?? finding.location.resource ?? finding.location.summary}
                {locationLineRange(finding.location)}
              </p>
            </div>
            {finding.location.summary && (finding.location.file || finding.location.resource) && (
              <div>
                <span className="text-muted-foreground">Detail</span>
                <p className="font-medium">{finding.location.summary}</p>
              </div>
            )}
          </div>
        )
        : (
          <p className="text-muted-foreground text-sm">
            No location reported — the scanner gave no file, resource, or URL.
          </p>
        )}
    </div>
  );
}
