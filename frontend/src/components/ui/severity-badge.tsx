import { isSeverity, type Severity } from "@/lib/enums";
import { cn } from "@/lib/utils";

const severityColors: Record<Severity, string> = {
  critical: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400",
  medium: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400",
  low: "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400",
  unknown: "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400",
};

export function SeverityBadge({ severity }: { readonly severity: string; }) {
  // The wire is untrusted: match case-insensitively, and never render an
  // out-of-vocabulary value verbatim — show a controlled "Unknown" instead.
  const normalized = severity.trim().toLowerCase();
  const known = isSeverity(normalized);
  const color = severityColors[normalized as Severity] ?? severityColors.unknown;
  const label = known ? severity : "Unknown";

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium",
        color,
      )}
    >
      {label}
    </span>
  );
}
