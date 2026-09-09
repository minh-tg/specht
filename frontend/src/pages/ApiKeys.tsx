import { APIError, apiFetch } from "@/api/client";
import { useProjects } from "@/api/hooks";
import type { ApiKey } from "@/types/api";
import { useState } from "react";

export function ApiKeys() {
  const { data: projects } = useProjects();

  const [selectedProject, setSelectedProject] = useState("");
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loadingKeys, setLoadingKeys] = useState(false);

  const [newKeyName, setNewKeyName] = useState("");
  const [creating, setCreating] = useState(false);
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [createError, setCreateError] = useState<string | null>(null);

  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);

  async function loadKeys(project: string) {
    if (!project) return;
    setLoadingKeys(true);
    try {
      const data = await apiFetch<ApiKey[]>(`/api/v1/auth/apikeys?project=${project}`);
      setKeys(data);
    } catch {
      setKeys([]);
    } finally {
      setLoadingKeys(false);
    }
  }

  function handleProjectChange(slug: string) {
    setSelectedProject(slug);
    setCreatedKey(null);
    if (slug) {
      loadKeys(slug);
    } else {
      setKeys([]);
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!newKeyName.trim() || !selectedProject) {
      setCreateError(newKeyName.trim() ? "Project is required" : "Name is required");
      return;
    }
    setCreateError(null);
    setCreating(true);
    try {
      const res = await apiFetch<{ key: string; }>("/api/v1/auth/apikeys", {
        method: "POST",
        body: JSON.stringify({ project: selectedProject, name: newKeyName.trim() }),
      });
      setCreatedKey(res.key);
      setNewKeyName("");
      loadKeys(selectedProject);
    } catch (err) {
      setCreateError(err instanceof APIError ? err.message : "Failed to create key");
    } finally {
      setCreating(false);
    }
  }

  async function handleRevoke(id: string) {
    setRevokingId(id);
    try {
      await apiFetch(`/api/v1/auth/apikeys/${id}?project=${selectedProject}`, {
        method: "DELETE",
      });
      setKeys((prev) => prev.filter((k) => k.id !== id));
    } catch {
      // silent
    } finally {
      setRevokingId(null);
      setConfirmRevoke(null);
    }
  }

  return (
    <div className="mx-auto max-w-2xl px-4 py-8">
      <h1 className="mb-6 text-2xl font-bold">API Keys</h1>

      <div className="mb-6">
        <label htmlFor="apikeys-project" className="text-sm font-medium">Project</label>
        <select
          id="apikeys-project"
          className="border-input bg-background mt-1 block w-full rounded-md border px-3 py-2 text-sm"
          value={selectedProject}
          onChange={(e) => handleProjectChange(e.target.value)}
        >
          <option value="">Select a project</option>
          {projects?.map((p) => (
            <option key={p.id} value={p.slug}>
              {p.name}
            </option>
          ))}
        </select>
      </div>

      {selectedProject && (
        <>
          <section className="mb-8">
            <h2 className="mb-3 text-lg font-semibold">Create Key</h2>
            <form onSubmit={handleCreate} className="flex gap-2">
              <input
                id="apikeys-name"
                className="border-input bg-background flex-1 rounded-md border px-3 py-2 text-sm"
                placeholder="Key name"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
              />
              <button
                type="submit"
                disabled={creating}
                className="bg-primary text-primary-foreground hover:bg-primary/90 rounded-md px-4 py-2 text-sm font-medium disabled:opacity-50"
              >
                {creating ? "Creating..." : "Create"}
              </button>
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
                <button
                  className="text-primary hover:text-primary/80 text-xs font-medium"
                  onClick={() => navigator.clipboard.writeText(createdKey)}
                >
                  Copy
                </button>
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
            <h2 className="mb-3 text-lg font-semibold">Active Keys</h2>
            {loadingKeys
              ? <div className="bg-muted h-20 animate-pulse rounded" />
              : keys.length === 0
              ? (
                <div className="flex flex-col items-center gap-2 py-8">
                  <p className="text-muted-foreground text-sm">No API keys yet</p>
                  <p className="text-muted-foreground text-xs">Create one above</p>
                </div>
              )
              : (
                <div className="space-y-2">
                  {keys.map((k) => (
                    <div
                      key={k.id}
                      className="bg-card flex items-center justify-between rounded-lg border p-3"
                    >
                      <div>
                        <p className="text-sm font-medium">{k.name}</p>
                        <p className="text-muted-foreground text-xs">
                          {k.key_prefix}... &middot; {new Date(k.created_at).toLocaleDateString()}
                        </p>
                      </div>
                      {confirmRevoke === k.id
                        ? (
                          <div className="flex items-center gap-2">
                            <button
                              className="text-destructive hover:text-destructive/80 text-xs font-medium"
                              onClick={() => handleRevoke(k.id)}
                              disabled={revokingId === k.id}
                            >
                              {revokingId === k.id ? "Revoking..." : "Confirm"}
                            </button>
                            <button
                              className="text-muted-foreground hover:text-foreground text-xs"
                              onClick={() => setConfirmRevoke(null)}
                            >
                              Cancel
                            </button>
                          </div>
                        )
                        : (
                          <button
                            className="text-destructive hover:text-destructive/80 text-xs font-medium"
                            onClick={() => setConfirmRevoke(k.id)}
                          >
                            Revoke
                          </button>
                        )}
                    </div>
                  ))}
                </div>
              )}
          </section>
        </>
      )}
    </div>
  );
}
