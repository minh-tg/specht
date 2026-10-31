import { useRequestWaiver } from "@/api/hooks";
import { ErrorState } from "@/components/ErrorState";
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
import { formatDate, pluralize } from "@/lib/format";
import { cn } from "@/lib/utils";
import {
  reasonLength,
  WAIVER_EXPIRY_MAX_DAYS,
  WAIVER_REASON_MAX,
  WAIVER_TARGETS_MAX,
  waiverRequestFailure,
} from "@/lib/waiverRequest";
import { type FormEvent, useState } from "react";

const EXPIRY_OPTIONS = [
  { value: "7", label: "7 days" },
  { value: "30", label: "30 days" },
  { value: String(WAIVER_EXPIRY_MAX_DAYS), label: `${WAIVER_EXPIRY_MAX_DAYS} days` },
];
const DEFAULT_EXPIRY = "30";
/** Taken off the end date so a clock a few minutes fast does not push it past the server's limit. */
const CLOCK_MARGIN_MS = 5 * 60 * 1000;

export interface WaiverRequestDialogProps {
  readonly slug: string;
  /** The findings the request names: one from the change view, several from the list. */
  readonly findingIds: readonly string[];
  /** What to call them in the sentence: a title, or "3 findings". */
  readonly subject: string;
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  /** Called once the request is saved, so the page can show it as waiting. */
  readonly onRequested: () => void;
}

function expiryFromNow(days: number): string {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000 - CLOCK_MARGIN_MS).toISOString();
}

/**
 * Asks a manager to let one finding through until a date. The request does not change the verdict:
 * the dialog says so, because the page keeps saying Blocked until someone approves. The limits the
 * server enforces show before send. A failed send keeps what the person typed and says what to do.
 */
export function WaiverRequestDialog(
  { slug, findingIds, subject, open, onOpenChange, onRequested }: WaiverRequestDialogProps,
) {
  const mutation = useRequestWaiver(slug);
  const [reason, setReason] = useState("");
  const [days, setDays] = useState(DEFAULT_EXPIRY);
  const trimmed = reason.trim();
  const length = reasonLength(reason);
  const overBy = length - WAIVER_REASON_MAX;
  const tooMany = findingIds.length > WAIVER_TARGETS_MAX;
  const failure = mutation.isError ? waiverRequestFailure(mutation.error) : null;

  function handleOpenChange(next: boolean) {
    if (!next) mutation.reset();
    onOpenChange(next);
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!trimmed || overBy > 0 || tooMany) return;
    mutation.mutate(
      { findingIds: [...findingIds], reason: trimmed, expiresAt: expiryFromNow(Number(days)) },
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

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent>
        <form onSubmit={submit} className="grid gap-4">
          <DialogHeader>
            <DialogTitle>Request a waiver</DialogTitle>
            <DialogDescription>
              Ask a manager to let <strong className="text-foreground">{subject}</strong>{" "}
              through until the date you pick. The verdict does not change until they approve it.
            </DialogDescription>
          </DialogHeader>
          {tooMany && (
            <p role="alert" className="text-destructive text-body">
              One request can name at most {pluralize(WAIVER_TARGETS_MAX, "finding")}. You chose
              {" "}
              {findingIds.length}. Close this, clear some and send again.
            </p>
          )}
          <div className="grid gap-1.5">
            <label htmlFor="waiver-reason" className="text-body font-medium">
              Why is this safe to ship?
            </label>
            <Textarea
              id="waiver-reason"
              value={reason}
              required
              aria-invalid={overBy > 0}
              aria-describedby="waiver-reason-count"
              onChange={(event) => setReason(event.target.value)}
              placeholder="For example: the vulnerable path is not reachable from the public API."
            />
            <p
              id="waiver-reason-count"
              className={cn(
                "text-meta tabular-nums",
                overBy > 0 ? "text-destructive" : "text-muted-foreground",
              )}
            >
              {length} of {WAIVER_REASON_MAX} characters
              {overBy > 0 && `. Shorten it by ${overBy} to send.`}
            </p>
          </div>
          <div className="grid gap-1.5">
            <label htmlFor="waiver-expiry" className="text-body font-medium">Waive it for</label>
            <SelectField
              id="waiver-expiry"
              value={days}
              onValueChange={setDays}
              options={EXPIRY_OPTIONS}
              className="w-full"
            />
            <p className="text-muted-foreground text-meta">
              Ends on{" "}
              {formatDate(expiryFromNow(Number(days)))}, then the finding blocks again. The longest
              a waiver can last is {WAIVER_EXPIRY_MAX_DAYS} days.
            </p>
          </div>
          {failure && (
            <ErrorState
              title={failure.title}
              detail={failure.detail}
              requestId={failure.requestId}
            />
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => handleOpenChange(false)}>
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={!trimmed || overBy > 0 || tooMany || mutation.isPending}
            >
              {mutation.isPending ? "Sending…" : failure ? "Try again" : "Send request"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
