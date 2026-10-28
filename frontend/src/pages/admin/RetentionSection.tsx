import { usePurgeRetention, useRetentionPreview } from "@/api/admin";
import { SelectField } from "@/components/SelectField";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { formatDate, pluralize } from "@/lib/format";
import { useState } from "react";

const WINDOWS = [
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "180", label: "180 days" },
  { value: "365", label: "365 days" },
  { value: "730", label: "2 years" },
];
const DEFAULT_WINDOW = "365";

/**
 * Removes finished reports older than a window. It previews first, so the button always says how many
 * reports it would remove, and asks again before it does. Findings are kept.
 */
export function RetentionSection() {
  const [days, setDays] = useState(DEFAULT_WINDOW);
  const [confirming, setConfirming] = useState(false);
  const preview = useRetentionPreview(Number(days));
  const purge = usePurgeRetention();

  const count = preview.data?.stale_reports ?? 0;
  const settled = preview.data !== undefined && !preview.isPlaceholderData;

  async function remove() {
    try {
      await purge.mutateAsync(Number(days));
    } catch {}
    setConfirming(false);
  }

  return (
    <section aria-labelledby="retention-heading" className="grid gap-3">
      <div>
        <h3 id="retention-heading" className="text-body font-semibold">Old reports</h3>
        <p className="text-muted-foreground mt-0.5 max-w-[68ch] text-[0.8125rem]">
          Removes finished reports older than the window. Findings whose only evidence was in them
          are archived, not deleted.
        </p>
      </div>

      <div className="border-foreground border-t-2">
        <div className="border-border flex flex-wrap items-center justify-between gap-x-6 gap-y-3 border-b px-0.5 py-4">
          <div className="flex items-center gap-2.5">
            <label htmlFor="retention-window" className="text-sm">Older than</label>
            <SelectField
              id="retention-window"
              size="sm"
              className="w-36"
              value={days}
              options={WINDOWS}
              onValueChange={(next) => {
                purge.reset();
                setDays(next);
              }}
            />
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <p role="status" className="text-muted-foreground text-[0.8125rem]">
              {preview.isError
                ? "Could not count the reports."
                : !settled
                ? "Counting…"
                : count === 0
                ? "Nothing to remove"
                : `${pluralize(count, "report")} would be removed`}
            </p>
            <Button
              disabled={!settled || count === 0 || purge.isPending}
              onClick={() => setConfirming(true)}
            >
              Remove them…
            </Button>
          </div>
        </div>
      </div>

      {purge.isError && (
        <p role="alert" className="bg-destructive/10 text-destructive rounded-md px-3 py-2 text-sm">
          {purge.error.message || "Could not remove the reports."}
        </p>
      )}
      {purge.data?.truncated && (
        <p
          role="status"
          className="bg-muted text-muted-foreground rounded-md px-3.5 py-3 text-[0.8125rem]"
        >
          More reports are past the window than one run removes. Run it again for the rest.
        </p>
      )}

      <AlertDialog open={confirming} onOpenChange={setConfirming}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove {pluralize(count, "report")}?</AlertDialogTitle>
            <AlertDialogDescription>
              Finished reports from before {formatDate(preview.data?.cutoff)}{" "}
              are removed for good. Findings stay; the ones whose only evidence was in these reports
              are archived.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={() => void remove()}>
              Remove
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}
