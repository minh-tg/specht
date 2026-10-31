import { CopyButton } from "@/components/CopyButton";
import { INLINE_LINK } from "@/components/inlineLink";
import { Section } from "@/components/Section";
import type { Finding, FindingSuggestion } from "@/types/api";
import { locationLine } from "../change-view/resolve";
import { confidenceLabel, parseSourceLink } from "./format";

/** The sca fix as the scanner reported it: a package with a version to move to. */
function structuredFix(suggestion?: FindingSuggestion) {
  if (!suggestion || suggestion.fallback) return null;
  if (!suggestion.package || !suggestion.fixed_version) return null;
  const { package: name, installed_version: from, fixed_version: to, ecosystem } = suggestion;
  return {
    sentence: from ? `Upgrade ${name} from ${from} to ${to}` : `Upgrade ${name} to ${to}`,
    ecosystem,
  };
}

/**
 * The fix as one sentence when the scanner gave a real one: its own summary, else the suggestion's
 * action and target. Server-written filler (`fallback`) is not a fix and gives null.
 */
function fixSentence(finding: Finding): string | null {
  const { remediation, suggestion } = finding;
  const summary = remediation?.fallback ? undefined : remediation?.summary?.trim();
  if (summary) return summary;
  if (suggestion && !suggestion.fallback && suggestion.action) {
    const text = suggestion.target
      ? `${suggestion.action} ${suggestion.target}`
      : suggestion.action;
    return text.charAt(0).toUpperCase() + text.slice(1);
  }
  return null;
}

/**
 * What to change on the page of a finding opened from a change. A real fix comes first and can be
 * copied. When the scanner has none, the section says so and names where to start, instead of
 * showing the generic guidance as if it were a fix.
 */
export function FixFirst({ finding }: { readonly finding: Finding; }) {
  const { suggestion, remediation } = finding;
  const structured = structuredFix(suggestion);
  const sentence = structured ? structured.sentence : fixSentence(finding);
  const where = locationLine(finding.location);
  const link = remediation?.url && parseSourceLink(remediation.url) ? remediation.url : null;

  const real = suggestion && !suggestion.fallback ? suggestion : null;
  const meta = [
    structured?.ecosystem,
    real?.confidence ? `Confidence ${confidenceLabel(real.confidence)}` : undefined,
    real?.source ?? remediation?.source,
  ].filter(Boolean).join(" · ");

  return (
    <Section title="How to fix">
      {sentence
        ? (
          <div className="space-y-2 text-body">
            <div className="bg-muted flex items-center gap-3 rounded-md py-2 pr-2 pl-3.5">
              <p className="min-w-0 flex-1 font-medium break-words">{sentence}</p>
              <CopyButton text={sentence} label="fix" />
            </div>
            {!structured && real?.detail && (
              <p className="text-muted-foreground text-meta">{real.detail}</p>
            )}
            {meta && <p className="text-muted-foreground text-meta">{meta}</p>}
          </div>
        )
        : (
          <div className="space-y-2 text-body">
            <p>
              <span className="font-semibold">No known fix.</span> {suggestion?.package
                ? `The scanner reported no fixed version for ${suggestion.package}${
                  suggestion.installed_version ? ` ${suggestion.installed_version}` : ""
                }.`
                : "The scanner reported no fix for this finding."} {where
                ? (
                  <>
                    Start at <code className="font-mono text-code break-all">{where}</code>.
                  </>
                )
                : "It also gave no location, so start from the rule or advisory."}
            </p>
          </div>
        )}
      {link && (
        <p className="mt-2 text-body">
          <a href={link} target="_blank" rel="noreferrer" className={INLINE_LINK}>
            Remediation reference
          </a>
        </p>
      )}
    </Section>
  );
}
