import { APIError } from "@/api/client";
import { useRequestWaiver } from "@/api/hooks";
import { SelectField } from "@/components/SelectField";
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
import { type FormEvent, useState } from "react";

const EXPIRY_OPTIONS = [
  { value: "7", label: "7 days" },
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
];
const DEFAULT_EXPIRY = "30";
const MAX_REASON = 1000;

export interface WaiverRequestDialogProps {
  readonly slug: string;
  readonly findingId: string;
  readonly findingTitle: string;
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  /** Called once the request is saved, so the page can show it as waiting. */
  readonly onRequested: () => void;
}

function expiryFromNow(days: number): string {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
}

/**
 * Asks a manager to let one finding through until a date. The request does not change the verdict:
 * the dialog says so, because the page keeps saying Blocked until someone approves.
 */
export function WaiverRequestDialog(
  { slug, findingId, findingTitle, open, onOpenChange, onRequested }: WaiverRequestDialogProps,
) {
  const mutation = useRequestWaiver(slug);
  const [reason, setReason] = useState("");
  const [days, setDays] = useState(DEFAULT_EXPIRY);
  const trimmed = reason.trim();

  function handleOpenChange(next: boolean) {
    if (!next) mutation.reset();
    onOpenChange(next);
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!trimmed) return;
    mutation.mutate(
      { findingIds: [findingId], reason: trimmed, expiresAt: expiryFromNow(Number(days)) },
      {
        onSuccess: () => {
          setReason("");
          setDays(DEFAULT_EXPIRY);
          onOpenChange(false);
          onRequested();
        },
      },
    );
  }

  const error = mutation.error instanceof APIError
    ? mutation.error.message
    : mutation.isError
    ? "Could not send the request."
    : null;

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent>
        <form onSubmit={submit} className="grid gap-4">
          <DialogHeader>
            <DialogTitle>Request a waiver</DialogTitle>
            <DialogDescription>
              Ask a manager to let <strong className="text-foreground">{findingTitle}</strong>{" "}
              through until the date you pick. The verdict does not change until they approve it.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-1.5">
            <label htmlFor="waiver-reason" className="text-sm font-medium">
              Why is this safe to ship?
            </label>
            <Textarea
              id="waiver-reason"
              value={reason}
              maxLength={MAX_REASON}
              required
              onChange={(event) => setReason(event.target.value)}
              placeholder="For example: the vulnerable path is not reachable from the public API."
            />
          </div>
          <div className="grid gap-1.5">
            <label htmlFor="waiver-expiry" className="text-sm font-medium">Waive it for</label>
            <SelectField
              id="waiver-expiry"
              value={days}
              onValueChange={setDays}
              options={EXPIRY_OPTIONS}
              className="w-full"
            />
            <p className="text-muted-foreground text-[13px]">
              It expires on its own. After that the finding blocks again.
            </p>
          </div>
          {error && <p role="alert" className="text-destructive text-sm">{error}</p>}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => handleOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!trimmed || mutation.isPending}>
              {mutation.isPending ? "Sending…" : "Send request"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
