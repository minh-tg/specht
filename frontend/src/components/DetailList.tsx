import { cn } from "@/lib/utils";
import { Fragment, type ReactNode } from "react";

/** One label and its value. A row without a value is left out of the list. */
export type DetailRow = {
  label: string;
  value?: ReactNode;
  code?: boolean;
};

function isEmptyValue(value: ReactNode): boolean {
  if (value == null || value === false) return true;
  return typeof value === "string" && value.trim() === "";
}

/** Whether any row carries a value, so a caller can tell an empty list from a full one. */
export function hasDetails(rows: readonly DetailRow[]): boolean {
  return rows.some((row) => !isEmptyValue(row.value));
}

function valueClass(code: boolean | undefined): string {
  return code ? "m-0 font-mono text-code break-all" : "m-0 font-medium tabular-nums";
}

/**
 * Label and value pairs. Rows without a value are left out rather than printed
 * as "None", and a list with nothing to show renders nothing at all.
 *
 * `stacked` pairs sit two to a row on wide screens; `inline` keeps the labels in
 * one narrow column, for a sidebar.
 */
export function DetailList({
  rows,
  variant = "stacked",
  className,
}: {
  readonly rows: readonly DetailRow[];
  readonly variant?: "stacked" | "inline";
  readonly className?: string;
}) {
  const shown = rows.filter((row) => !isEmptyValue(row.value));
  if (shown.length === 0) return null;

  if (variant === "inline") {
    return (
      <dl className={cn("grid grid-cols-[auto_1fr] gap-x-5 gap-y-2.5 text-body", className)}>
        {shown.map((row) => (
          <Fragment key={row.label}>
            <dt className="text-muted-foreground">{row.label}</dt>
            <dd className={valueClass(row.code)}>{row.value}</dd>
          </Fragment>
        ))}
      </dl>
    );
  }

  return (
    <dl className={cn("grid grid-cols-1 gap-4 text-body sm:grid-cols-2", className)}>
      {shown.map((row) => (
        <div key={row.label}>
          <dt className="text-muted-foreground">{row.label}</dt>
          <dd className={valueClass(row.code)}>{row.value}</dd>
        </div>
      ))}
    </dl>
  );
}
