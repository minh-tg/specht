import {
  expiresAtFor,
  EXPIRY_OPTIONS,
  type ExpiryOption,
  keyEndLabel,
  useApiKeys,
  useRevokeApiKey,
} from "@/api/apiKeys";
import { APIError } from "@/api/client";
import { useCiManagedProjects, useCreateApiKey } from "@/api/hooks";
import { CopyButton } from "@/components/CopyButton";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState } from "@/components/ErrorState";
import { INLINE_LINK } from "@/components/inlineLink";
import { SelectField } from "@/components/SelectField";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import type { Project } from "@/types/api";
import { type ReactNode, useState } from "react";
import { Link } from "react-router-dom";

/**
 * Keys are minted, listed and revoked per project by its managers and by
 * administrators (the `manage_ci` permission). The picker offers only the
 * projects the signed-in person manages; the server refuses everything else.
 */
export function ApiKeys() {
  const managed = useCiManagedProjects();

  if (managed.isLoading) {
    return (
      <div className="mx-auto max-w-2xl px-4 py-8">
        <Skeleton className="h-8 w-48 rounded" />
        <Skeleton className="mt-6 h-64 rounded-lg" />
      </div>
    );
  }

  if (managed.data.length === 0) {
    return (
      <div className="mx-auto max-w-2xl px-4 py-8">
        <h1 className="mb-6 text-title font-bold">API keys</h1>
        <p className="text-muted-foreground text-sm">
          You do not manage any project's CI. Ask a project manager or an admin.
        </p>
        <Link
          to="/"
          className={`${INLINE_LINK} mt-2 inline-block text-sm`}
        >
          Back to projects
        </Link>
      </div>
    );
  }

  return <ApiKeysManager projects={managed.data} />;
}

function ApiKeysManager({ projects }: { projects: Project[]; }) {
  const [selectedProject, setSelectedProject] = useState("");
  const keysQuery = useApiKeys(selectedProject);
  const keys = keysQuery.data ?? [];

  const [newKeyName, setNewKeyName] = useState("");
  const [expiry, setExpiry] = useState<ExpiryOption>("none");
  const createKey = useCreateApiKey();
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [createError, setCreateError] = useState<string | null>(null);

  const revoke = useRevokeApiKey(selectedProject);
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
  const [revokeError, setRevokeError] = useState<string | null>(null);

  function handleProjectChange(slug: string) {
    setSelectedProject(slug);
    setCreatedKey(null);
    setConfirmRevoke(null);
    setRevokeError(null);
  }

  function handleCreate(e: React.SubmitEvent) {
    e.preventDefault();
    if (!newKeyName.trim() || !selectedProject) {
      setCreateError(newKeyName.trim() ? "Project is required" : "Name is required");
      return;
    }
    setCreateError(null);
    createKey.mutate({
      project: selectedProject,
      name: newKeyName.trim(),
      expiresAt: expiresAtFor(expiry, new Date()),
    }, {
      // The server's one-time secret rides in raw_key (APIKeyResponse);
      // reading any other field silently discards the only copy.
      onSuccess: (created) => {
        setCreatedKey(created.raw_key);
        setNewKeyName("");
      },
      onError: (err) => {
        setCreateError(err instanceof APIError ? err.message : "Failed to create key");
      },
    });
  }

  function handleRevoke(id: string) {
    setRevokeError(null);
    revoke.mutate(id, {
      onSuccess: () => setConfirmRevoke(null),
      onError: (err) => {
        setRevokeError(err instanceof APIError ? err.message : "Failed to revoke key");
      },
    });
  }

  const now = new Date();
  let keysBody: ReactNode;
  if (keysQuery.isPending && selectedProject) {
    keysBody = <Skeleton className="h-20 rounded" />;
  } else if (keysQuery.isError) {
    keysBody = (
      <ErrorState
        title="Could not load API keys."
        detail={keysQuery.error instanceof APIError
          ? keysQuery.error.message
          : "Failed to load API keys"}
        onRetry={() => void keysQuery.refetch()}
      />
    );
  } else if (keys.length === 0) {
    keysBody = <EmptyState title="No API keys yet" description="Create one above." />;
  } else {
    keysBody = (
      <div className="space-y-2">
        {keys.map((k) => {
          const end = keyEndLabel(k.expires_at, now);
          return (
            <div key={k.id} className="bg-card rounded-lg border p-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium">{k.name}</p>
                  <p className="text-muted-foreground text-xs">
                    {k.key_prefix}...{k.last_four ?? ""} &middot; created{" "}
                    {new Date(k.created_at).toLocaleDateString()}
                  </p>
                  <p className="text-xs">
                    <span className="text-muted-foreground">Ends</span>
                    <span className={end.expired ? "text-destructive font-medium" : undefined}>
                      {end.label}
                    </span>
                  </p>
                </div>
                {confirmRevoke === k.id
                  ? (
                    <div className="flex items-center gap-2">
                      <button
                        className="text-destructive hover:text-destructive/80 text-xs font-medium"
                        onClick={() => handleRevoke(k.id)}
                        disabled={revoke.isPending && revoke.variables === k.id}
                      >
                        {revoke.isPending && revoke.variables === k.id ? "Revoking..." : "Confirm"}
                      </button>
                      <button
                        className="text-muted-foreground hover:text-foreground text-xs"
                        onClick={() => {
                          setConfirmRevoke(null);
                          setRevokeError(null);
                        }}
                      >
                        Cancel
                      </button>
                    </div>
                  )
                  : (
                    <button
                      className="text-destructive hover:text-destructive/80 text-xs font-medium"
                      onClick={() => {
                        setConfirmRevoke(k.id);
                        setRevokeError(null);
                      }}
                    >
                      Revoke
                    </button>
                  )}
              </div>
              {confirmRevoke === k.id && revokeError && (
                <p role="alert" className="text-destructive mt-2 text-xs">{revokeError}</p>
              )}
            </div>
          );
        })}
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-2xl px-4 py-8">
      <h1 className="mb-6 text-title font-bold">API keys</h1>

      <div className="mb-6">
        <label htmlFor="apikeys-project" className="text-sm font-medium">Project</label>
        <SelectField
          id="apikeys-project"
          className="mt-1 w-full"
          value={selectedProject}
          onValueChange={handleProjectChange}
          options={[
            { value: "", label: "Select a project" },
            ...projects.map((p) => ({ value: p.slug, label: p.name })),
          ]}
        />
      </div>

      {selectedProject && (
        <>
          <section className="mb-8">
            <h2 className="mb-3 text-section font-semibold">Create Key</h2>
            <form onSubmit={handleCreate} className="flex flex-wrap gap-2">
              <Input
                id="apikeys-name"
                className="w-auto flex-1"
                placeholder="Key name"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
              />
              <div className="w-40">
                <label htmlFor="apikeys-expiry" className="sr-only">Expires</label>
                <SelectField
                  id="apikeys-expiry"
                  className="w-full"
                  value={expiry}
                  onValueChange={(v) => setExpiry(v as ExpiryOption)}
                  options={EXPIRY_OPTIONS.map((o) => ({ value: o.value, label: o.label }))}
                />
              </div>
              <Button
                type="submit"
                disabled={createKey.isPending}
              >
                {createKey.isPending ? "Creating..." : "Create"}
              </Button>
            </form>
            {createError && <p className="text-destructive mt-1 text-xs">{createError}</p>}
          </section>

          {createdKey && (
            <div className="bg-card mb-8 rounded-lg border p-4">
              <p className="text-destructive mb-2 text-xs font-medium">
                This key will not be shown again
              </p>
              <div className="flex items-center gap-2">
                <code className="bg-muted flex-1 rounded px-2 py-1 text-xs">{createdKey}</code>
                <CopyButton text={createdKey} label="API key" />
              </div>
              <button
                className="text-muted-foreground hover:text-foreground mt-2 text-xs"
                onClick={() => setCreatedKey(null)}
              >
                Dismiss
              </button>
            </div>
          )}

          <section>
            <h2 className="mb-3 text-section font-semibold">Active Keys</h2>
            {keysBody}
          </section>
        </>
      )}
    </div>
  );
}
