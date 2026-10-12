import { isSeverity, normalizeSeverity, type Severity, severityLabel } from "@/lib/enums";
import { cn } from "@/lib/utils";

/**
 * Severity label with a depth meter.
 *
 * Rules this encodes:
 *
 * - **The label is mandatory.** Colour alone is never the signal: under simulated
 *   deuteranopia `high` and `medium` collapse to a ΔE of ~5.6, so the word is the
 *   only thing separating them. The four bars repeat the level without colour.
 * - **`-fg` pairs only with its own `-bg`.** Each variant uses matched tokens rather
 *   than mixing a tinted foreground with a neutral fill — that mistake measured
 *   4.32:1 in a generated screen.
 * - **"Unrated" has no tint and no bars.** It is the *absence* of severity (stored as `unknown`),
 *   so it renders as an outline chip. A filled one measured ΔE 2.2 from `--border` and
 *   read as a disabled control.
 * - Tints are solid tokens, never an alpha such as `bg-critical/10`.
 * - `plain` drops the tint for a row of a list or table, where the coloured word and the bars are
 *   enough and a filled chip on every row is noise.
 */
const SEVERITY_VARIANTS: Record<Severity, string> = {
  critical: "bg-sev-critical-bg text-sev-critical-fg",
  high: "bg-sev-high-bg text-sev-high-fg",
  medium: "bg-sev-medium-bg text-sev-medium-fg",
  low: "bg-sev-low-bg text-sev-low-fg",
  unknown: "border-input text-sev-none-fg border",
};

const PLAIN_VARIANTS: Record<Severity, string> = {
  critical: "text-sev-critical-fg",
  high: "text-sev-high-fg",
  medium: "text-sev-medium-fg",
  low: "text-sev-low-fg",
  unknown: "text-sev-none-fg",
};

/** Bars lit per severity; the heights step up so the shape reads at a glance. */
const LEVEL: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
const BAR_HEIGHTS = ["h-[3px]", "h-[5.5px]", "h-2", "h-2.5"] as const;

function Bars({ level }: { readonly level: number; }) {
  return (
    <span aria-hidden="true" className="inline-flex h-2.5 items-end gap-[1.5px]">
      {BAR_HEIGHTS.map((height, index) => (
        <i
          key={height}
          data-lit={index < level ? "true" : "false"}
          className={cn("w-[2.5px] bg-current", height, index >= level && "opacity-30")}
        />
      ))}
    </span>
  );
}

export function SeverityBadge(
  { severity, plain = false }: { readonly severity: string; readonly plain?: boolean; },
) {
  // The wire is untrusted: match case-insensitively, and never render an
  // out-of-vocabulary value verbatim. An unrecognised value gets the quietest
  // treatment (the unrated one) so it cannot masquerade as a real severity.
  const normalized = normalizeSeverity(severity);
  const known = isSeverity(normalized);
  const key = (known ? normalized : "unknown") as Severity;
  const label = severityLabel(normalized) ?? "Unknown";

  return (
    <span
      className={cn(
        "font-label inline-flex items-center gap-[7px] text-xs leading-4 whitespace-nowrap",
        plain ? PLAIN_VARIANTS[key] : cn("h-6 rounded px-2", SEVERITY_VARIANTS[key]),
      )}
    >
      {LEVEL[key] > 0 && <Bars level={LEVEL[key]} />}
      {label}
    </span>
  );
}
