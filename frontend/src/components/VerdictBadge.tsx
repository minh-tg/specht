import { cn } from "@/lib/utils";
import type { Verdict } from "@/lib/verdict";

/**
 * Verdict chip.
 *
 * The label is mandatory: colour alone is never the signal, so `no_scans` and
 * `unknown` share the indeterminate fill but still read as different words.
 * The fill uses the solid `-bg`/`-fg` token pairs, never an alpha tint.
 */
const VERDICT_VARIANTS: Record<Verdict, string> = {
  blocked: "bg-verdict-block text-verdict-block-fg",
  passing: "bg-verdict-pass text-verdict-pass-fg",
  no_scans: "bg-verdict-indeterminate text-verdict-indeterminate-fg",
  unknown: "bg-verdict-indeterminate text-verdict-indeterminate-fg",
};

const VERDICT_LABELS: Record<Verdict, string> = {
  blocked: "BLOCKED",
  passing: "PASSING",
  no_scans: "NO SCANS",
  unknown: "UNKNOWN",
};

export function VerdictBadge({ verdict }: { readonly verdict: Verdict; }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-sm px-1.5 py-0.5 font-label uppercase",
        "text-[11px] leading-4 tracking-[0.06em]",
        VERDICT_VARIANTS[verdict],
      )}
    >
      {VERDICT_LABELS[verdict]}
    </span>
  );
}
