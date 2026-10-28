import { useProject, useProjectRole } from "@/api/hooks";
import { type ProjectChange, useDeleteProject, useUpdateProject } from "@/api/projectActions";
import { ErrorState } from "@/components/ErrorState";
import { SkeletonLines } from "@/components/SkeletonLines";
import {
  AlertDialog,
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
import type { Project } from "@/types/api";
import { type SubmitEvent, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

/**
 * The project's settings for its admins: the details (name and description) and the delete area.
 * Everyone else sees a line saying the page is for project admins.
 */
export function ProjectSettings() {
  const { slug } = useParams<{ slug: string; }>();
  const currentSlug = slug ?? "";
  const { data: project, isLoading, isError, refetch } = useProject(currentSlug);
  const { isAdmin, isLoading: roleLoading } = useProjectRole(currentSlug);

  if (roleLoading || isLoading) return <SkeletonLines label="Loading the settings" />;
  if (!isAdmin) {
    return (
      <p className="bg-muted text-muted-foreground rounded-md px-3.5 py-3 text-meta">
        Only project admins can change these settings.
      </p>
    );
  }
  if (isError || !project) {
    return (
      <ErrorState
        title="Could not load the project settings."
        onRetry={() => void refetch()}
      />
    );
  }

  return (
    <section aria-labelledby="settings-heading" className="grid gap-8">
      <h2 id="settings-heading" className="text-section font-semibold">Settings</h2>
      <DetailsForm key={project.updated_at} project={project} />
      <DeleteSection project={project} />
    </section>
  );
}

/**
 * Name and description. The form is keyed on the project's last update, so a saved change resets
 * it to what the server now holds.
 */
function DetailsForm({ project }: { project: Project; }) {
  const update = useUpdateProject(project.slug);
  const [name, setName] = useState(project.name);
  const [description, setDescription] = useState(project.description ?? "");

  const trimmedName = name.trim();
  const nameError = trimmedName === "" ? "Enter a name." : null;
  const change: ProjectChange = {};
  if (trimmedName !== project.name) change.name = trimmedName;
  if (description.trim() !== (project.description ?? "")) change.description = description.trim();
  const dirty = Object.keys(change).length > 0;

  function save(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!dirty || nameError || update.isPending) return;
    update.mutate(change);
  }

  return (
    <div className="border-foreground border-t-2">
      <h3 className="pt-4 text-body font-semibold">Details</h3>
      <form onSubmit={save} className="mt-4 grid max-w-xl gap-5" noValidate>
        <div className="grid gap-1.5">
          <label htmlFor="settings-slug" className="text-body font-medium">Slug</label>
          <Input id="settings-slug" value={project.slug} readOnly className="font-mono" />
          <p className="text-muted-foreground text-meta">
            The slug is part of the project's links and cannot change.
          </p>
        </div>

        <div className="grid gap-1.5">
          <label htmlFor="settings-name" className="text-body font-medium">Name</label>
          <Input
            id="settings-name"
            value={name}
            aria-invalid={nameError ? true : undefined}
            aria-describedby={nameError ? "settings-name-error" : undefined}
            onChange={(event) => setName(event.target.value)}
          />
          {nameError && (
            <p id="settings-name-error" className="text-destructive text-meta">{nameError}</p>
          )}
        </div>

        <div className="grid gap-1.5">
          <label htmlFor="settings-description" className="text-body font-medium">
            Description
          </label>
          <Textarea
            id="settings-description"
            value={description}
            onChange={(event) => setDescription(event.target.value)}
          />
        </div>

        {update.isError && (
          <p
            role="alert"
            className="bg-destructive/10 text-destructive rounded-md px-3 py-2 text-body"
          >
            {update.error.message || "Could not save the project."}
          </p>
        )}

        <div>
          <Button type="submit" disabled={!dirty || nameError !== null || update.isPending}>
            Save
          </Button>
        </div>
      </form>
    </div>
  );
}

/**
 * The danger area. Deleting asks for the project's slug to be typed, so the button stays off until
 * the person has typed it exactly. A failed delete keeps the dialog open with the server's reason.
 */
function DeleteSection({ project }: { project: Project; }) {
  const navigate = useNavigate();
  const remove = useDeleteProject(project.slug);
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const matches = typed === project.slug;

  function changeOpen(next: boolean) {
    if (remove.isPending) return;
    setOpen(next);
    if (!next) {
      setTyped("");
      remove.reset();
    }
  }

  function confirm() {
    if (!matches || remove.isPending) return;
    remove.mutate(undefined, {
      onSuccess: () => navigate("/", { replace: true }),
    });
  }

  return (
    <section
      aria-labelledby="delete-heading"
      className="border-destructive grid max-w-xl gap-3 rounded-md border-2 p-4"
    >
      <h3 id="delete-heading" className="text-body font-semibold">
        Delete this project
      </h3>
      <p className="text-muted-foreground text-body">
        Reports, findings, waivers, members and API keys of this project are deleted for good. This
        cannot be undone.
      </p>
      <div>
        <Button variant="destructive" onClick={() => changeOpen(true)}>Delete project…</Button>
      </div>

      <AlertDialog open={open} onOpenChange={changeOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete {project.name}?</AlertDialogTitle>
            <AlertDialogDescription>
              The project and everything in it is removed. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="grid gap-1.5">
            <label htmlFor="delete-confirm" className="text-body font-medium">
              Type {project.slug} to confirm
            </label>
            <Input
              id="delete-confirm"
              autoComplete="off"
              value={typed}
              onChange={(event) => setTyped(event.target.value)}
            />
          </div>
          {remove.isError && (
            <p
              role="alert"
              className="bg-destructive/10 text-destructive rounded-md px-3 py-2 text-body"
            >
              {remove.error.message || "Could not delete the project."}
            </p>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={remove.isPending}>Cancel</AlertDialogCancel>
            <Button
              variant="destructive"
              disabled={!matches || remove.isPending}
              onClick={confirm}
            >
              Delete this project
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}
