import { CopyButton } from "@/components/CopyButton";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { TriangleAlertIcon } from "lucide-react";
import type { ReactNode } from "react";

/**
 * A region that failed to load: say what failed and offer to try again. The
 * title names the thing, for example "Could not load members"; the optional detail
 * carries the server's reason. When the server sent a request ID, it is shown with a
 * copy button so the person can give it to whoever runs the server.
 */
export function ErrorState({ title, detail, requestId, retryLabel = "Retry", onRetry, className }: {
  readonly title: string;
  readonly detail?: ReactNode;
  /** The `X-Request-Id` of the failed response. */
  readonly requestId?: string;
  /** The retry button's text. */
  readonly retryLabel?: string;
  readonly onRetry?: () => void;
  readonly className?: string;
}) {
  return (
    <Alert variant="destructive" className={className}>
      <TriangleAlertIcon aria-hidden="true" />
      <AlertTitle>{title}</AlertTitle>
      {detail && <AlertDescription>{detail}</AlertDescription>}
      {requestId && (
        <AlertDescription className="group-has-[>svg]/alert:col-start-2 mt-1.5 flex flex-wrap items-center gap-x-1.5 text-meta">
          <span>If it keeps failing, give your admin this request ID:</span>
          <code className="text-foreground text-code [overflow-wrap:anywhere]">{requestId}</code>
          <CopyButton text={requestId} label="request ID" />
        </AlertDescription>
      )}
      {onRetry && (
        <AlertAction>
          <Button variant="outline" size="xs" onClick={onRetry}>{retryLabel}</Button>
        </AlertAction>
      )}
    </Alert>
  );
}
