import { useWithdrawWaiver } from "@/api/hooks";
import { ErrorState } from "@/components/ErrorState";
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
import { waiverWithdrawFailure } from "@/lib/waiverRequest";
import { waiverPathId } from "@/pages/change-view/waiverState";

export interface WithdrawWaiverDialogProps {
  readonly slug: string;
  /** The request to take back. Kept after the dialog closes so its text holds while it fades out. */
  readonly target: {
    readonly waiverId: string;
    readonly findingId: string;
    readonly title: string;
  } | null;
  readonly open: boolean;
  readonly onClose: () => void;
}

/**
 * Asks before the requester takes back a waiting request. A failure stays in the dialog with the
 * request id, so the person can try again or close it. When it closes, focus goes to the finding's
 * waiver block: the Withdraw button it came from is gone once the request is withdrawn.
 */
export function WithdrawWaiverDialog({ slug, target, open, onClose }: WithdrawWaiverDialogProps) {
  const mutation = useWithdrawWaiver(slug);
  const failure = mutation.isError ? waiverWithdrawFailure(mutation.error) : null;

  function close() {
    mutation.reset();
    onClose();
  }

  function confirm() {
    if (!target) return;
    mutation.mutate(target.waiverId, { onSuccess: close });
  }

  return (
    <AlertDialog
      open={open}
      onOpenChange={(open) => {
        if (!open) close();
      }}
    >
      <AlertDialogContent
        finalFocus={() =>
          (target && document.getElementById(waiverPathId(target.findingId))) ?? true}
      >
        <AlertDialogHeader>
          <AlertDialogTitle>Withdraw this request?</AlertDialogTitle>
          <AlertDialogDescription>
            {target ? <strong className="text-foreground">{target.title}</strong> : "This finding"}
            {" "}
            keeps blocking this change. You can ask again later.
          </AlertDialogDescription>
        </AlertDialogHeader>
        {failure && (
          <ErrorState title={failure.title} detail={failure.detail} requestId={failure.requestId} />
        )}
        <AlertDialogFooter>
          <AlertDialogCancel>{failure ? "Close" : "Keep request"}</AlertDialogCancel>
          <AlertDialogAction
            variant="destructive"
            disabled={mutation.isPending}
            onClick={(event) => {
              event.preventDefault();
              confirm();
            }}
          >
            {mutation.isPending ? "Withdrawing…" : failure ? "Try again" : "Withdraw request"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
