import { useBulkTriage } from "@/api/hooks";
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
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { type AnalysisState, isAnalysisState } from "@/lib/enums";
import { GLOSSARY } from "@/lib/glossary";
import { toExpiryTimestamp } from "@/pages/finding-detail/format";
import { TRIAGE_GLOSSARY, TRIAGE_OPTIONS } from "@/pages/finding-detail/options";
import { type FormEvent, useState } from "react";

/**
 * One triage decision for every selected finding. It follows the single-finding rules: a decision
 * that ignores the gate needs a reason, and one that accepts the risk needs an expiry as well. The
 * server applies it to all of them or to none.
 */
export function BulkTriageDialog({ findingIds, open, onOpenChange, onApplied }: {
  readonly findingIds: readonly string[];
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  /** Called once the decision is saved, so the page can drop the selection. */
  readonly onApplied: () => void;
}) {
  const mutation = useBulkTriage();
  const [state, setState] = useState<AnalysisState | "">("");
  const [reason, setReason] = useState("");
  const [expiresAt, setExpiresAt] = useState("");

  const option = TRIAGE_OPTIONS.find((o) => o.value === state);
  const hintKey = state ? TRIAGE_GLOSSARY[state] : undefined;
  const hint = hintKey ? GLOSSARY[hintKey].short : null;
  const minExpiryDate = new Date().toISOString().slice(0, 10);
  const ready = state !== ""
    && (!option?.requiresReason || reason.trim() !== "")
    && (!option?.requiresExpiry || expiresAt >= minExpiryDate);
  const count = findingIds.length;
  const noun = count === 1 ? "finding" : "findings";

  function handleOpenChange(next: boolean) {
    if (!next) mutation.reset();
    onOpenChange(next);
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!ready) return;
    mutation.mutate(
      {
        findingIds,
        analysisState: state,
        reason: option?.requiresReason ? reason.trim() : undefined,
        analysisExpiresAt: option?.requiresExpiry ? toExpiryTimestamp(expiresAt) : undefined,
      },
      {
        onSuccess: () => {
          setState("");
          setReason("");
          setExpiresAt("");
          onOpenChange(false);
          onApplied();
        },
      },
    );
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent>
        <form onSubmit={submit} className="grid gap-4">
          <DialogHeader>
            <DialogTitle>Triage {count} {noun}</DialogTitle>
            <DialogDescription>
              One decision for all {count}. If any of them cannot take it, none is changed.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-1.5">
            <label htmlFor="bulk-triage-state" className="text-sm font-medium">Decision</label>
            <SelectField
              id="bulk-triage-state"
              className="w-full"
              value={state}
              aria-describedby={hint ? "bulk-triage-hint" : undefined}
              onValueChange={(value) => {
                setState(isAnalysisState(value) ? value : "");
                setReason("");
                setExpiresAt("");
              }}
              options={[
                { value: "", label: "Select a decision…" },
                ...TRIAGE_OPTIONS.map((o) => ({ value: o.value, label: o.label })),
              ]}
            />
            {hint && (
              <p id="bulk-triage-hint" className="text-muted-foreground text-[0.8125rem]">
                {hint}
              </p>
            )}
          </div>
          {option?.requiresReason && (
            <div className="grid gap-1.5">
              <label htmlFor="bulk-triage-reason" className="text-sm font-medium">Reason</label>
              <Textarea
                id="bulk-triage-reason"
                value={reason}
                required
                onChange={(event) => setReason(event.target.value)}
                placeholder="Why is this the right call? It is kept with each finding's history."
              />
            </div>
          )}
          {option?.requiresExpiry && (
            <div className="grid gap-1.5">
              <label htmlFor="bulk-triage-expiry" className="text-sm font-medium">
                Review again on
              </label>
              <Input
                id="bulk-triage-expiry"
                type="date"
                min={minExpiryDate}
                value={expiresAt}
                onChange={(event) => setExpiresAt(event.target.value)}
              />
              <p className="text-muted-foreground text-[0.8125rem]">
                After this date the findings go back to untriaged.
              </p>
            </div>
          )}
          {mutation.isError && (
            <p role="alert" className="text-destructive text-sm">
              {mutation.error.message || "Could not save the decision."}
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => handleOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!ready || mutation.isPending}>
              {mutation.isPending ? "Saving…" : `Apply to ${count} ${noun}`}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
