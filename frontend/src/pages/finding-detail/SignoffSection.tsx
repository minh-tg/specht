import { useSaveSignoff, useSignoff } from "@/api/findingEvidence";
import { useMe, useProjectRole } from "@/api/hooks";
import { actorLabel, useUserDirectory } from "@/api/users";
import { ErrorState } from "@/components/ErrorState";
import { SelectField } from "@/components/SelectField";
import { SkeletonLines } from "@/components/SkeletonLines";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { formatDateTime } from "@/lib/format";
import type { SignoffStatus } from "@/types/api";
import { type FormEvent, type ReactNode, useState } from "react";
import { useParams } from "react-router-dom";
import { OutcomeRegions } from "./OutcomeRegions";

const DECISIONS: ReadonlyArray<{ value: SignoffStatus; label: string; }> = [
  { value: "pending", label: "Pending" },
  { value: "approved", label: "Approved" },
  { value: "rejected", label: "Rejected" },
];

function decisionLabel(status: SignoffStatus): string {
  return DECISIONS.find((d) => d.value === status)?.label ?? status;
}

/** The reviewer's sign-off on one finding, with a form to record or change it. */
export function SignoffSection({
  findingId,
  projectSlug,
}: {
  readonly findingId: string;
  readonly projectSlug?: string;
}) {
  const params = useParams<{ slug: string; }>();
  const slug = projectSlug ?? params.slug ?? "";
  const { canTriage } = useProjectRole(slug);
  const { data: me } = useMe();
  const { data: directory } = useUserDirectory();
  const { data: signoff, isLoading, isError, refetch } = useSignoff(findingId);
  const saveMutation = useSaveSignoff();

  // Null until the person edits a field, so the form shows the recorded sign-off by default.
  const [draftStatus, setDraftStatus] = useState<SignoffStatus | null>(null);
  const [draftComment, setDraftComment] = useState<string | null>(null);

  const shownStatus: SignoffStatus = draftStatus ?? signoff?.status ?? "pending";
  const shownComment = draftComment ?? signoff?.comment ?? "";

  async function handleSave(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canTriage) return;
    try {
      await saveMutation.mutateAsync({
        findingId,
        status: shownStatus,
        comment: shownComment.trim(),
      });
      setDraftStatus(null);
      setDraftComment(null);
    } catch {}
  }

  let body: ReactNode;
  if (isLoading) {
    body = <SkeletonLines label="Loading sign-off" />;
  } else if (isError) {
    body = <ErrorState title="Could not load the sign-off." onRetry={() => void refetch()} />;
  } else if (!signoff) {
    body = <p className="text-muted-foreground text-sm">Not signed off yet.</p>;
  } else {
    body = (
      <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
        <dt className="text-muted-foreground text-xs">Decision</dt>
        <dd className="font-medium">{decisionLabel(signoff.status)}</dd>
        {signoff.comment && (
          <>
            <dt className="text-muted-foreground text-xs">Note</dt>
            <dd className="break-words">{signoff.comment}</dd>
          </>
        )}
        <dt className="text-muted-foreground text-xs">Recorded</dt>
        <dd className="text-muted-foreground text-xs">
          <span>by {actorLabel({ user_id: signoff.reviewed_by }, { me, directory })}</span>
          {" · "}
          <span>{formatDateTime(signoff.updated_at)}</span>
        </dd>
      </dl>
    );
  }

  return (
    <div className="border-border mt-8 border-t pt-5">
      <h2 className="mb-3 text-lg font-semibold">Reviewer sign-off</h2>
      {body}

      {canTriage && !isLoading && !isError && (
        <form onSubmit={handleSave} className="mt-5 grid gap-3" aria-label="Record sign-off">
          <div className="flex flex-wrap items-end gap-2">
            <SelectField
              aria-label="Sign-off decision"
              value={shownStatus}
              onValueChange={(value) => {
                const next = DECISIONS.find((d) =>
                  d.value === value
                );
                if (next) {
                  setDraftStatus(next.value);
                }
              }}
              options={DECISIONS.map((d) => ({ value: d.value, label: d.label }))}
            />
          </div>
          <div>
            <label htmlFor="signoff-note" className="text-muted-foreground mb-1 block text-xs">
              Note
            </label>
            <Textarea
              id="signoff-note"
              rows={2}
              value={shownComment}
              onChange={(e) =>
                setDraftComment(e.target.value)}
            />
          </div>
          <div>
            <Button type="submit" disabled={saveMutation.isPending}>
              {saveMutation.isPending ? "Saving..." : "Save"}
            </Button>
          </div>
          <OutcomeRegions
            label="Sign-off"
            error={saveMutation.isError ? saveMutation.error.message : null}
          />
        </form>
      )}
    </div>
  );
}
