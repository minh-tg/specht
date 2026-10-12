import { cn } from "@/lib/utils";
import type { BarDatum, BarTone } from "./model";

const TONE_COLOR: Record<BarTone, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  neutral: "var(--foreground)",
};

/**
 * Horizontal bars with the count written out beside each, so the numbers carry the meaning and the
 * bars only show proportion. The hatched part is the share that blocks the gate; hatching is a
 * pattern, not a colour, so it survives colour blindness.
 */
export function BarChart({ label, rows, className }: {
  readonly label: string;
  readonly rows: readonly BarDatum[];
  readonly className?: string;
}) {
  const max = Math.max(1, ...rows.map((r) => r.count));
  return (
    <ul aria-label={label} className={cn("m-0 grid list-none gap-0.5 p-0", className)}>
      {rows.map((row) => {
        const color = TONE_COLOR[row.tone];
        const solid = Math.max(0, row.count - row.blocking);
        return (
          <li
            key={row.key}
            className="grid grid-cols-[7rem_minmax(0,1fr)_2.75rem] items-center gap-3 py-1.5 text-[0.8125rem]"
          >
            <span>{row.label}</span>
            <span
              aria-hidden="true"
              className="bg-muted flex h-2.5 overflow-hidden rounded-[2px]"
            >
              <span
                className="h-full"
                style={{ width: `${(solid / max) * 100}%`, backgroundColor: color }}
              />
              {row.blocking > 0 && (
                <span
                  data-blocking="true"
                  className="h-full"
                  style={{
                    width: `${(row.blocking / max) * 100}%`,
                    borderRight: `1px solid ${color}`,
                    backgroundImage:
                      `repeating-linear-gradient(135deg, ${color} 0 3px, transparent 3px 6px)`,
                  }}
                />
              )}
            </span>
            <span className="text-right tabular-nums">
              {row.count}
              {row.blocking > 0 && <span className="sr-only">, {row.blocking} block the gate</span>}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

/** Columns for a short series, drawn to one scale. Words carry the numbers for anyone who cannot see it. */
export function Sparkline({ label, values, startLabel, endLabel }: {
  readonly label: string;
  readonly values: readonly number[];
  readonly startLabel: string;
  readonly endLabel: string;
}) {
  const max = Math.max(1, ...values);
  return (
    <div>
      <div
        role="img"
        aria-label={`${label}: ${values.join(", ")}`}
        className="border-foreground flex h-[70px] items-end gap-1 border-b"
      >
        {values.map((value, index) => (
          <i
            // The series has no ids; a column is identified by its place.
            key={index}
            title={String(value)}
            className="bg-foreground block min-h-0.5 flex-1"
            style={{ height: `${Math.max(2, (value / max) * 68)}px` }}
          />
        ))}
      </div>
      <div className="text-muted-foreground mt-1.5 flex justify-between text-xs">
        <span>{startLabel}</span>
        <span>{endLabel}</span>
      </div>
    </div>
  );
}
