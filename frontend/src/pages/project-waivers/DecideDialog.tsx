import { useDecideWaiver } from "@/api/hooks";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import type { Waiver } from "@/types/api";
import { type SubmitEvent, useState } from "react";
import { waiverTitle } from "./classify";

export type Decision = "approve" | "reject";

const MAX_NOTE = 1000;

/**
 * The step before a decision. Approving takes an optional note; rejecting needs one, because the
 * person who asked is waiting to hear why.
 */
export function DecideDialog({ slug, waiver, decision, onClose }: {
  readonly slug: string;
  readonly waiver: Waiver | null;
  readonly decision: Decision;
  readonly onClose: () => void;
}) {
  const mutation = useDecideWaiver(slug);
  const [note, setNote] = useState("");
  const approving = decision === "approve";
  const trimmed = note.trim();
  const canSubmit = approving || trimmed.length > 0;

  function close() {
    mutation.reset();
    setNote("");
    onClose();
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!waiver || !canSubmit) return;
    try {
      await mutation.mutateAsync({ id: waiver.id, decision, note: trimmed });
      close();
    } catch {}
  }

  return (
    <Dialog open={waiver !== null} onOpenChange={(open) => !open && close()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{approving ? "Approve this waiver?" : "Reject this waiver?"}</DialogTitle>
          <DialogDescription>
            {waiver
              ? approving
                ? `${waiverTitle(waiver)} will stop blocking${
                  waiver.expires_at ? " until it expires" : ""
                }.`
                : `${waiverTitle(waiver)} keeps blocking.`
              : ""}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={(e) => void submit(e)} className="grid gap-4">
          <div className="grid gap-1.5">
            <label htmlFor="decision-note" className="text-sm font-medium">
              Note {approving
                ? <span className="text-muted-foreground font-normal">(optional)</span>
                : <span className="text-muted-foreground font-normal">(required)</span>}
            </label>
            <Textarea
              id="decision-note"
              value={note}
              maxLength={MAX_NOTE}
              required={!approving}
              placeholder="Visible to the person who asked."
              onChange={(e) => setNote(e.target.value)}
            />
          </div>
          {mutation.isError && (
            <p role="alert" className="text-destructive text-sm">
              {mutation.error.message || "Could not save the decision."}
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={close}>Cancel</Button>
            <Button
              type="submit"
              variant={approving ? "default" : "destructive"}
              disabled={!canSubmit || mutation.isPending}
            >
              {approving ? "Approve" : "Reject"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
