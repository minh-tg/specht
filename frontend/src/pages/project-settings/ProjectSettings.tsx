import { useProject, useProjectRole } from "@/api/hooks";
import { type ProjectChange, useUpdateProject } from "@/api/projectActions";
import { ErrorState } from "@/components/ErrorState";
import { SkeletonLines } from "@/components/SkeletonLines";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import type { Project } from "@/types/api";
import { type SubmitEvent, useState } from "react";
import { useParams } from "react-router-dom";

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
      <p className="bg-muted text-muted-foreground rounded-md px-3.5 py-3 text-[0.8125rem]">
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
      <h2 id="settings-heading" className="text-lg font-semibold">Settings</h2>
      <DetailsForm key={project.updated_at} project={project} />
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
      <h3 className="pt-4 text-[0.9375rem] font-semibold">Details</h3>
      <form onSubmit={save} className="mt-4 grid max-w-xl gap-5" noValidate>
        <div className="grid gap-1.5">
          <label htmlFor="settings-slug" className="text-sm font-medium">Slug</label>
          <Input id="settings-slug" value={project.slug} readOnly className="font-mono" />
          <p className="text-muted-foreground text-xs">
            The slug is part of the project's links and cannot change.
          </p>
        </div>

        <div className="grid gap-1.5">
          <label htmlFor="settings-name" className="text-sm font-medium">Name</label>
          <Input
            id="settings-name"
            value={name}
            aria-invalid={nameError ? true : undefined}
            aria-describedby={nameError ? "settings-name-error" : undefined}
            onChange={(event) => setName(event.target.value)}
          />
          {nameError && (
            <p id="settings-name-error" className="text-destructive text-xs">{nameError}</p>
          )}
        </div>

        <div className="grid gap-1.5">
          <label htmlFor="settings-description" className="text-sm font-medium">
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
            className="bg-destructive/10 text-destructive rounded-md px-3 py-2 text-sm"
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
