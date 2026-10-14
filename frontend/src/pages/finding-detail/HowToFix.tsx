import { CopyButton } from "@/components/CopyButton";
import type { Finding } from "@/types/api";
import { confidenceLabel, parseSourceLink } from "./format";

/** Remediation guidance and the suggested fix for one finding. */
export function HowToFix({ finding }: { readonly finding: Finding; }) {
  return (
    <div className="border-border mt-8 border-t pt-5">
      <h2 className="mb-3 text-lg font-semibold">How to fix</h2>
      {finding.remediation?.summary
        ? (
          <div className="space-y-2 text-sm">
            <div className="bg-muted flex items-center gap-3 rounded-md py-2 pr-2 pl-3.5">
              <p className="min-w-0 flex-1 font-medium">{finding.remediation.summary}</p>
              <CopyButton text={finding.remediation.summary} label="fix" />
            </div>
            {finding.remediation.fallback && (
              <p className="text-muted-foreground text-xs">
                General guidance. The scanner reported no specific fix.
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
                {finding.suggestion.detail ? `. ${finding.suggestion.detail}` : ""}
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
