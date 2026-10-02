import { APIError } from "@/api/client";
import { useCreateProject, useMe } from "@/api/hooks";
import { isValidSlug, slugify } from "@/lib/slug";
import { type ChangeEvent, type SubmitEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

interface FieldErrors {
  name?: string;
  slug?: string;
  form?: string;
}

const INPUT_CLASS =
  "border-input bg-background mt-1 block w-full rounded-md border px-3 py-2 text-sm";

/** A rejected slug is reported under the slug field; everything else is a
 * form-level error. */
function slugError(error: unknown): boolean {
  return error instanceof APIError
    && (error.status === 409 || /exists|used|taken/i.test(error.message));
}

export function NewProject() {
  const navigate = useNavigate();
  const { data: me, isLoading } = useMe();
  const createProject = useCreateProject();

  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugEdited, setSlugEdited] = useState(false);
  const [description, setDescription] = useState("");
  const [errors, setErrors] = useState<FieldErrors>({});

  function handleNameChange(event: ChangeEvent<HTMLInputElement>) {
    const value = event.target.value;
    setName(value);
    // Keep the slug in step with the name until the user touches the field.
    if (!slugEdited) setSlug(slugify(value));
  }

  function handleSlugChange(event: ChangeEvent<HTMLInputElement>) {
    setSlugEdited(true);
    setSlug(event.target.value);
  }

  function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();

    const next: FieldErrors = {};
    if (!name.trim()) next.name = "Name is required";
    if (!isValidSlug(slug)) {
      next.slug = "Use 3-48 lowercase letters, numbers and hyphens, for example my-project";
    }
    setErrors(next);
    if (next.name || next.slug) return;

    createProject.mutate(
      { name: name.trim(), slug, description: description.trim() || undefined },
      {
        onSuccess: (project) => navigate(`/${project.slug}/setup`),
        onError: (error) => {
          const message = error instanceof APIError ? error.message : "Failed to create project";
          setErrors(slugError(error) ? { slug: message } : { form: message });
        },
      },
    );
  }

  if (isLoading) {
    return (
      <div className="mx-auto max-w-2xl px-4 py-8">
        <div className="bg-muted h-8 w-48 animate-pulse rounded" />
        <div className="bg-muted mt-6 h-64 animate-pulse rounded-lg" />
      </div>
    );
  }

  if (me?.role !== "admin") {
    return (
      <div className="mx-auto max-w-2xl px-4 py-8">
        <h1 className="mb-6 text-2xl font-bold">New project</h1>
        <p className="text-muted-foreground text-sm">Only administrators can create projects.</p>
        <Link
          to="/"
          className="text-action hover:text-action/80 mt-2 inline-block text-sm underline"
        >
          Back to projects
        </Link>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-2xl px-4 py-8">
      <h1 className="mb-6 text-2xl font-bold">New project</h1>

      <form onSubmit={handleSubmit} noValidate className="space-y-4">
        <div>
          <label htmlFor="new-project-name" className="text-sm font-medium">Name</label>
          <span className="text-muted-foreground ml-1 text-xs">(required)</span>
          <input
            id="new-project-name"
            className={INPUT_CLASS}
            value={name}
            onChange={handleNameChange}
            required
            aria-invalid={errors.name ? true : undefined}
            aria-describedby={errors.name ? "new-project-name-error" : undefined}
          />
          {errors.name && (
            <p id="new-project-name-error" role="alert" className="text-destructive mt-1 text-xs">
              {errors.name}
            </p>
          )}
        </div>

        <div>
          <label htmlFor="new-project-slug" className="text-sm font-medium">Slug</label>
          <input
            id="new-project-slug"
            className={INPUT_CLASS}
            value={slug}
            onChange={handleSlugChange}
            aria-invalid={errors.slug ? true : undefined}
            aria-describedby={`new-project-slug-help${
              errors.slug ? " new-project-slug-error" : ""
            }`}
          />
          <p id="new-project-slug-help" className="text-muted-foreground mt-1 text-xs">
            Lowercase letters, numbers and hyphens, 3-48 characters. Used in URLs and by CI.
          </p>
          {errors.slug && (
            <p id="new-project-slug-error" role="alert" className="text-destructive mt-1 text-xs">
              {errors.slug}
            </p>
          )}
        </div>

        <div>
          <label htmlFor="new-project-description" className="text-sm font-medium">
            Description
          </label>
          <span className="text-muted-foreground ml-1 text-xs">(optional)</span>
          <textarea
            id="new-project-description"
            className={INPUT_CLASS}
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            rows={3}
          />
        </div>

        {errors.form && <p role="alert" className="text-destructive text-sm">{errors.form}</p>}

        <button
          type="submit"
          disabled={createProject.isPending}
          className="bg-primary text-primary-foreground hover:bg-primary/90 rounded-md px-4 py-2 text-sm font-medium disabled:opacity-50"
        >
          {createProject.isPending ? "Creating..." : "Create project"}
        </button>
      </form>
    </div>
  );
}
