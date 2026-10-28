import { SEVERITIES, type Severity, severityLabel } from "@/lib/enums";
import type { SeverityCount } from "@/types/api";

/** The chips follow the severity order; "unknown" (unrated) shows only when something has it. */
const CHIP_SEVERITIES = SEVERITIES.filter((s) => s !== "unknown");

/**
 * Severity filters as toggles, with how many open findings each holds. Any number can be on at
 * once; none on means every severity. The selection is a comma list, in severity order, so the same
 * view always has the same URL.
 */
export function SeverityChips({ value, counts, onChange }: {
  /** The comma list the URL holds. */
  readonly value: string;
  readonly counts?: readonly SeverityCount[];
  readonly onChange: (value: string) => void;
}) {
  const on = new Set(value.split(",").filter(Boolean));
  const countOf = (severity: string) => counts?.find((c) => c.severity === severity)?.count;
  const shown: Severity[] = [
    ...CHIP_SEVERITIES,
    ...((countOf("unknown") ?? 0) > 0 || on.has("unknown") ? (["unknown"] as const) : []),
  ];

  function toggle(severity: Severity) {
    const next = new Set(on);
    if (next.has(severity)) next.delete(severity);
    else next.add(severity);
    onChange(SEVERITIES.filter((s) => next.has(s)).join(","));
  }

  return (
    <div role="group" aria-label="Filter by severity" className="flex flex-wrap gap-2">
      {shown.map((severity) => {
        const pressed = on.has(severity);
        const count = countOf(severity);
        return (
          <button
            key={severity}
            type="button"
            aria-pressed={pressed}
            aria-label={count === undefined
              ? undefined
              : `${severityLabel(severity)} ${count} open`}
            onClick={() => toggle(severity)}
            className={`inline-flex h-8 items-center gap-1.5 rounded border px-2.5 text-meta font-semibold transition-[background-color,color,scale] duration-(--dur-instant) active:scale-[0.97] pointer-coarse:min-h-11 ${
              pressed
                ? "border-foreground bg-foreground text-background"
                : "border-input hover:bg-muted"
            }`}
          >
            {severityLabel(severity)}
            {count !== undefined && (
              <b className="font-semibold tabular-nums opacity-75">{count}</b>
            )}
          </button>
        );
      })}
    </div>
  );
}
