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
 * person who asked is waiting to hear why. A manager approving their own request, which the server
 * allows only when nobody else can decide it, needs one too, so the record says why.
 */
export function DecideDialog({ slug, waiver, decision, ownRequest = false, onClose }: {
  readonly slug: string;
  readonly waiver: Waiver | null;
  readonly decision: Decision;
  /** The viewer asked for this waiver and is not a global admin. */
  readonly ownRequest?: boolean;
  readonly onClose: () => void;
}) {
  const mutation = useDecideWaiver(slug);
  const [note, setNote] = useState("");
  const approving = decision === "approve";
  const noteRequired = !approving || ownRequest;
  const trimmed = note.trim();
  const canSubmit = !noteRequired || trimmed.length > 0;

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
            {approving && ownRequest
              && " You asked for this and no other manager can decide it, so say why you approve it."}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={(e) => void submit(e)} className="grid gap-4">
          <div className="grid gap-1.5">
            <label htmlFor="decision-note" className="text-body font-medium">
              Note {noteRequired
                ? <span className="text-muted-foreground font-normal">(required)</span>
                : <span className="text-muted-foreground font-normal">(optional)</span>}
            </label>
            <Textarea
              id="decision-note"
              value={note}
              maxLength={MAX_NOTE}
              required={noteRequired}
              placeholder={approving && ownRequest
                ? "Why you approve your own request. It stays on the waiver's record."
                : "Visible to the person who asked."}
              onChange={(e) => setNote(e.target.value)}
            />
          </div>
          {mutation.isError && (
            <p role="alert" className="text-destructive text-body">
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
