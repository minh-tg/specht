import { useUpdateWaiver } from "@/api/waiverActions";
import { FormField } from "@/components/FormField";
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
import { changedFields, expiryDateValue, type WaiverDraft } from "./waiverEdit";

/**
 * Edits a waiver's name, description and expiry. A manager only; the update schema has no other
 * fields, so the reason and the findings a waiver covers stay as they were.
 */
export function WaiverEditDialog({ slug, waiver, onClose }: {
  readonly slug: string;
  readonly waiver: Waiver | null;
  readonly onClose: () => void;
}) {
  return (
    <Dialog open={waiver !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md">
        {waiver && <EditFields key={waiver.id} slug={slug} waiver={waiver} onClose={onClose} />}
      </DialogContent>
    </Dialog>
  );
}

function EditFields({ slug, waiver, onClose }: {
  readonly slug: string;
  readonly waiver: Waiver;
  readonly onClose: () => void;
}) {
  const mutation = useUpdateWaiver(slug);
  const [draft, setDraft] = useState<WaiverDraft>(() => ({
    name: waiver.name,
    description: waiver.description,
    expiry: expiryDateValue(waiver.expires_at),
    noExpiry: !waiver.expires_at,
  }));
  const update = changedFields(waiver, draft);
  const hasChanges = Object.keys(update).length > 0;
  const nameMissing = draft.name.trim() === "";
  const expiryMissing = !draft.noExpiry && draft.expiry === "";
  const canSave = hasChanges && !nameMissing && !expiryMissing && !mutation.isPending;

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!canSave) return;
    try {
      await mutation.mutateAsync({ id: waiver.id, update });
      onClose();
    } catch {}
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>Edit waiver</DialogTitle>
        <DialogDescription>{waiverTitle(waiver)}</DialogDescription>
      </DialogHeader>
      <form onSubmit={(e) => void submit(e)} className="grid gap-4">
        <FormField
          label="Name"
          value={draft.name}
          onChange={(e) => setDraft({ ...draft, name: e.target.value })}
        />
        <div className="grid gap-1.5">
          <label htmlFor="waiver-edit-description" className="text-body font-medium">
            Description
          </label>
          <Textarea
            id="waiver-edit-description"
            value={draft.description}
            onChange={(e) => setDraft({ ...draft, description: e.target.value })}
          />
        </div>
        <div className="grid gap-2">
          <FormField
            label="Expires"
            type="date"
            value={draft.expiry}
            disabled={draft.noExpiry}
            onChange={(e) => setDraft({ ...draft, expiry: e.target.value })}
          />
          <label className="flex items-center gap-2 text-body">
            <input
              type="checkbox"
              className="size-4"
              checked={draft.noExpiry}
              onChange={(e) => setDraft({ ...draft, noExpiry: e.target.checked })}
            />
            No expiry
          </label>
        </div>
        {mutation.isError && (
          <p role="alert" className="text-destructive text-body">
            {mutation.error.message || "Could not save the waiver."}
          </p>
        )}
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={!canSave}>Save</Button>
        </DialogFooter>
      </form>
    </>
  );
}
