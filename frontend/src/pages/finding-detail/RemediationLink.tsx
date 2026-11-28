import { INLINE_LINK } from "@/components/inlineLink";
import type { Finding } from "@/types/api";
import { parseSourceLink } from "./format";

/**
 * The scanner's page for the finding's rule or policy, opened in a new tab. On a SAST finding it is
 * the rule documentation the fallback text tells people to follow, so the link is named that.
 * Nothing renders without a link, or for one that is not http or https.
 */
export function RemediationLink(
  { finding, className }: { readonly finding: Finding; readonly className?: string; },
) {
  const url = finding.remediation?.url;
  if (!url || !parseSourceLink(url)) return null;
  return (
    <p className={className}>
      <a href={url} target="_blank" rel="noopener noreferrer" className={INLINE_LINK}>
        {finding.finding_kind === "sast" ? "Rule documentation" : "Remediation reference"}{" "}
        <span className="sr-only">(opens in a new tab)</span>
      </a>
    </p>
  );
}
