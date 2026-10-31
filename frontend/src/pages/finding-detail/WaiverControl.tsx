import { DisabledReason } from "@/components/DisabledReason";
import { Button } from "@/components/ui/button";
import type { WaiverAction } from "@/lib/waiverRequest";

/** The "Request waiver" button, the note that a request is waiting, or the reason it is off. */
export function WaiverControl({ waiver, onRequest }: {
  readonly waiver: WaiverAction;
  readonly onRequest: () => void;
}) {
  if (waiver.kind === "pending") {
    return (
      <p className="bg-muted text-muted-foreground rounded-md px-3.5 py-3 text-meta">
        Waiver requested. A manager will decide. The verdict does not change until they approve it.
      </p>
    );
  }
  return (
    <DisabledReason reason={waiver.kind === "disabled" ? waiver.reason : undefined}>
      <Button variant="outline" disabled={waiver.kind === "disabled"} onClick={onRequest}>
        Request waiver
      </Button>
    </DisabledReason>
  );
}
