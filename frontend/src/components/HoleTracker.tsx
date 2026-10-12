import { cn } from "@/lib/utils";

/**
 * Progress as holes in timber: one hole per blocker, and handling it fills the hole. It tracks the
 * reader's own progress and never the verdict, which only a scan can change.
 */
export function HoleTracker(
  { total, filled, className }: {
    readonly total: number;
    readonly filled: number;
    readonly className?: string;
  },
) {
  const count = Math.max(0, total);
  const done = Math.min(Math.max(0, filled), count);
  return (
    <div
      role="img"
      aria-label={`${done} of ${count} handled`}
      className={cn("flex flex-wrap gap-2", className)}
    >
      {Array.from({ length: count }, (_, index) => (
        <i
          key={index}
          data-filled={index < done ? "true" : "false"}
          className={cn(
            "ease-entering size-4 rounded-full shadow-[inset_0_0_0_2px_var(--foreground)]",
            "transition-colors duration-(--dur-quick)",
            index < done && "bg-foreground",
          )}
        />
      ))}
    </div>
  );
}
