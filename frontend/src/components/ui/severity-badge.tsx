import { isSeverity, type Severity, severityLabel } from "@/lib/enums";
import { cn } from "@/lib/utils";

/**
 * Severity chip.
 *
 * Rules this encodes:
 *
 * - **The label is mandatory.** Colour alone is never the signal: under simulated
 *   deuteranopia `high` and `medium` collapse to a ΔE of ~5.6, so the word is the
 *   only thing separating them.
 * - **`-fg` pairs only with its own `-bg`.** Each variant uses matched tokens rather
 *   than mixing a tinted foreground with a neutral fill — that mistake measured
 *   4.32:1 in a generated screen.
 * - **`none` has no tint.** It is the *absence* of severity, so it renders as an
 *   outline chip. A filled `none` chip measured ΔE 2.2 from `--border` and read as a
 *   disabled control.
 * - Tints are solid tokens, never an alpha such as `bg-critical/10`.
 */
const SEVERITY_VARIANTS: Record<Severity, string> = {
  critical: "bg-sev-critical-bg text-sev-critical-fg",
  high: "bg-sev-high-bg text-sev-high-fg",
  medium: "bg-sev-medium-bg text-sev-medium-fg",
  low: "bg-sev-low-bg text-sev-low-fg",
  none: "border border-border text-sev-none-fg",
};

export function SeverityBadge({ severity }: { readonly severity: string; }) {
  // The wire is untrusted: match case-insensitively, and never render an
  // out-of-vocabulary value verbatim. An unrecognised value gets the quietest
  // treatment (`none`) so it cannot masquerade as a real severity.
  const normalized = severity.trim().toLowerCase();
  const known = isSeverity(normalized);
  const variant = SEVERITY_VARIANTS[(known ? normalized : "none") as Severity];
  const label = severityLabel(normalized) ?? "Unknown";

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-sm px-1.5 py-0.5 font-label uppercase",
        "text-[11px] leading-4 tracking-[0.06em]",
        variant,
      )}
    >
      {label}
    </span>
  );
}
