import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

/**
 * What is empty, optionally why, and the one thing to do about it. Use it for a
 * list or panel with nothing to show; it is not for a failed load (see ErrorState).
 */
export function EmptyState({ title, description, action, className }: {
  readonly title: string;
  readonly description?: ReactNode;
  readonly action?: ReactNode;
  readonly className?: string;
}) {
  return (
    <div className={cn("bg-card border-border rounded-lg border p-12 text-center", className)}>
      <p className="text-foreground text-sm font-medium">{title}</p>
      {description && <p className="text-muted-foreground mt-1 text-sm">{description}</p>}
      {action && <div className="mt-4 flex justify-center">{action}</div>}
    </div>
  );
}
