import type { Finding } from "@/types/api";
import { confidenceLabel, parseSourceLink } from "./format";

/** Remediation guidance and the suggested fix for one finding. */
export function HowToFix({ finding }: { readonly finding: Finding; }) {
  return (
    <div className="mt-8 rounded-lg border p-4">
      <h2 className="mb-3 text-sm font-semibold">How to fix</h2>
      {finding.remediation?.summary
        ? (
          <div className="space-y-2 text-sm">
            <p className="font-medium">{finding.remediation.summary}</p>
            {finding.remediation.fallback && (
              <p className="text-muted-foreground text-xs">
                General guidance — the scanner reported no specific fix.
              </p>
            )}
            {finding.remediation.url && parseSourceLink(finding.remediation.url) && (
              <p>
                <a
                  href={finding.remediation.url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-action hover:text-action/80 text-sm underline underline-offset-4"
                >
                  Remediation reference
                </a>
              </p>
            )}
            {finding.remediation.source && (
              <p className="text-muted-foreground text-xs">
                Source: {finding.remediation.source}
              </p>
            )}
            {finding.suggestion && (
              <p className="text-muted-foreground text-xs">
                Suggested: {finding.suggestion.action}
                {finding.suggestion.target ? ` ${finding.suggestion.target}` : ""} (confidence{" "}
                {confidenceLabel(finding.suggestion.confidence)})
                {finding.suggestion.detail ? ` — ${finding.suggestion.detail}` : ""}
              </p>
            )}
          </div>
        )
        : (
          <p className="text-muted-foreground text-sm">
            No remediation reported for this finding.
          </p>
        )}
    </div>
  );
}
