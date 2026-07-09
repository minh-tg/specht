import { cn } from "@/lib/utils";

const severityColors: Record<string, string> = {
  critical: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400",
  medium: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400",
  low: "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400",
};

export function SeverityBadge({ severity }: { severity: string; }) {
  const s = severity.toLowerCase();
  const color = severityColors[s] ?? severityColors.low;

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium",
        color,
      )}
    >
      {severity}
    </span>
  );
}
