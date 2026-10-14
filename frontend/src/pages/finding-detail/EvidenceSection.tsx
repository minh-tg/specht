import { useAddEvidence, useDeleteEvidence, useEvidence } from "@/api/findingEvidence";
import { useMe, useProjectRole } from "@/api/hooks";
import { actorLabel, useUserDirectory } from "@/api/users";
import { ErrorState } from "@/components/ErrorState";
import { SelectField } from "@/components/SelectField";
import { SkeletonLines } from "@/components/SkeletonLines";
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
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { formatDateTime } from "@/lib/format";
import type { FindingEvidence } from "@/types/api";
import { type FormEvent, type ReactNode, useState } from "react";
import { useParams } from "react-router-dom";
import { OutcomeRegions } from "./OutcomeRegions";

/** Evidence kinds a person can attach by hand. The watcher writes `automated` itself. */
const EVIDENCE_TYPES = [
  { value: "reference", label: "Reference" },
  { value: "log", label: "Log" },
  { value: "screenshot", label: "Screenshot" },
] as const;

const URL_ERROR = "Use an http or https link.";

function evidenceTypeLabel(type: string): string {
  return EVIDENCE_TYPES.find((t) => t.value === type)?.label ?? type;
}

function isHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

/** Evidence attached to one finding, with a form and delete for people who can triage. */
export function EvidenceSection({
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
  const { data: evidence, isLoading, isError, refetch } = useEvidence(findingId);
  const addMutation = useAddEvidence();
  const deleteMutation = useDeleteEvidence();

  const [type, setType] = useState<string>("reference");
  const [url, setUrl] = useState("");
  const [description, setDescription] = useState("");
  const [urlError, setUrlError] = useState<string | null>(null);
  const [toDelete, setToDelete] = useState<FindingEvidence | null>(null);

  async function handleAdd(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canTriage) return;
    const trimmed = url.trim();
    if (!isHttpUrl(trimmed)) {
      setUrlError(URL_ERROR);
      return;
    }
    setUrlError(null);
    try {
      await addMutation.mutateAsync({
        findingId,
        type,
        url: trimmed,
        description: description.trim(),
      });
      setUrl("");
      setDescription("");
    } catch {}
  }

  async function handleDelete() {
    if (!toDelete) return;
    const evidenceId = toDelete.id;
    setToDelete(null);
    try {
      await deleteMutation.mutateAsync({ findingId, evidenceId });
    } catch {}
  }

  let body: ReactNode;
  if (isLoading) {
    body = <SkeletonLines label="Loading evidence" />;
  } else if (isError) {
    body = (
      <ErrorState
        title="Could not load evidence."
        onRetry={() => void refetch()}
      />
    );
  } else if (!Array.isArray(evidence) || evidence.length === 0) {
    body = <p className="text-muted-foreground text-sm">No evidence attached yet.</p>;
  } else {
    body = (
      <ul className="space-y-3 text-sm">
        {evidence.map((item) => (
          <li
            key={item.id}
            className="border-border flex flex-wrap items-start gap-x-3 gap-y-1 border-b pb-3 last:border-b-0"
          >
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-baseline gap-x-2">
                <span className="font-medium">{evidenceTypeLabel(item.type)}</span>
                <a
                  href={item.url}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="text-primary break-all underline underline-offset-2"
                >
                  {item.url}
                </a>
              </div>
              {item.description && (
                <p className="text-muted-foreground mt-1 break-words text-xs">{item.description}</p>
              )}
              <p className="text-muted-foreground mt-1 text-xs">
                <span>by {actorLabel({ user_id: item.uploaded_by ?? "" }, { me, directory })}</span>
                {" · "}
                <span>{formatDateTime(item.created_at)}</span>
              </p>
            </div>
            {canTriage && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setToDelete(item)}
              >
                Delete
              </Button>
            )}
          </li>
        ))}
      </ul>
    );
  }

  return (
    <div className="border-border mt-8 border-t pt-5">
      <h2 className="mb-3 text-lg font-semibold">Evidence</h2>
      {body}

      {canTriage && (
        <form onSubmit={handleAdd} className="mt-5 grid gap-3" aria-label="Add evidence">
          <div className="flex flex-wrap gap-2">
            <SelectField
              aria-label="Evidence type"
              value={type}
              onValueChange={setType}
              options={EVIDENCE_TYPES.map((t) => ({ value: t.value, label: t.label }))}
            />
            <div className="min-w-[240px] flex-1">
              <label htmlFor="evidence-url" className="sr-only">Evidence URL</label>
              <Input
                id="evidence-url"
                type="url"
                placeholder="https://"
                value={url}
                aria-invalid={urlError ? true : undefined}
                aria-describedby={urlError ? "evidence-url-error" : undefined}
                onChange={(e) => {
                  setUrl(e.target.value);
                  if (urlError) {
                    setUrlError(null);
                  }
                }}
              />
            </div>
          </div>
          {urlError && (
            <p id="evidence-url-error" className="text-destructive text-xs">{urlError}</p>
          )}
          <div>
            <label
              htmlFor="evidence-description"
              className="text-muted-foreground mb-1 block text-xs"
            >
              Description
            </label>
            <Textarea
              id="evidence-description"
              rows={2}
              value={description}
              onChange={(e) =>
                setDescription(e.target.value)}
            />
          </div>
          <div>
            <Button type="submit" disabled={addMutation.isPending}>
              {addMutation.isPending ? "Adding..." : "Add evidence"}
            </Button>
          </div>
          <OutcomeRegions
            label="Evidence"
            error={addMutation.isError ? addMutation.error.message : null}
          />
        </form>
      )}

      <AlertDialog
        open={toDelete !== null}
        onOpenChange={(open) => {
          if (!open) setToDelete(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete this evidence?</AlertDialogTitle>
            <AlertDialogDescription>
              The link is detached from this finding. You can attach it again later.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={() => void handleDelete()}>
              Delete evidence
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
