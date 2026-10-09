import { Alert, AlertAction, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { TriangleAlertIcon } from "lucide-react";

/**
 * A region that failed to load: say what failed and offer to try again. The
 * title names the thing, for example "Could not load members".
 */
export function ErrorState({ title, onRetry, className }: {
  readonly title: string;
  readonly onRetry?: () => void;
  readonly className?: string;
}) {
  return (
    <Alert variant="destructive" className={className}>
      <TriangleAlertIcon aria-hidden="true" />
      <AlertTitle>{title}</AlertTitle>
      {onRetry && (
        <AlertAction>
          <Button variant="outline" size="xs" onClick={onRetry}>Retry</Button>
        </AlertAction>
      )}
    </Alert>
  );
}
