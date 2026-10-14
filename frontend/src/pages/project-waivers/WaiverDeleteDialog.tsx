import { useDeleteWaiver } from "@/api/waiverActions";
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
import type { Waiver } from "@/types/api";

/**
 * Confirms a delete. Deleting a waiver makes the gate block the findings it covered again, so the
 * step before it names that consequence and cannot be skipped.
 */
export function WaiverDeleteDialog({ slug, waiver, onClose }: {
  readonly slug: string;
  readonly waiver: Waiver | null;
  readonly onClose: () => void;
}) {
  const mutation = useDeleteWaiver(slug);

  async function confirm() {
    if (!waiver) return;
    try {
      await mutation.mutateAsync(waiver.id);
      onClose();
    } catch {}
  }

  return (
    <AlertDialog
      open={waiver !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete this waiver?</AlertDialogTitle>
          <AlertDialogDescription>
            Findings it covered start blocking the gate again. The waiver and its history are
            removed. This cannot be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction
            variant="destructive"
            disabled={mutation.isPending}
            onClick={(event) => {
              event.preventDefault();
              void confirm();
            }}
          >
            Delete
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
