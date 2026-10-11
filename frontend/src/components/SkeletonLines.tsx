import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

const WIDTHS = ["w-3/5", "w-11/12", "w-4/5", "w-2/3"];

/**
 * Placeholder lines for a region whose data is still loading. The label is what a
 * screen reader announces, for example "Loading members".
 */
export function SkeletonLines({ label, lines = 3, className }: {
  readonly label: string;
  readonly lines?: number;
  readonly className?: string;
}) {
  return (
    <div role="status" aria-label={label} className={cn("space-y-2", className)}>
      {Array.from(
        { length: lines },
        (_, i) => <Skeleton key={i} className={cn("h-3.5", WIDTHS[i % WIDTHS.length])} />,
      )}
    </div>
  );
}
