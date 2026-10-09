import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { ReactElement } from "react";

/**
 * Says why a control is disabled. A disabled button takes no pointer events and
 * no focus, so a `title` on it never shows and keyboard and touch users never
 * learn the reason. This wraps it in a focusable element that shows the reason
 * on hover and focus and also puts it in the accessible name. With no reason
 * the control is returned untouched.
 */
export function DisabledReason({ reason, children }: {
  readonly reason: string | undefined;
  readonly children: ReactElement;
}) {
  if (!reason) return children;

  return (
    <Tooltip>
      <TooltipTrigger render={<span tabIndex={0} className="inline-flex rounded-md" />}>
        {children}
        <span className="sr-only">{reason}</span>
      </TooltipTrigger>
      <TooltipContent>{reason}</TooltipContent>
    </Tooltip>
  );
}
