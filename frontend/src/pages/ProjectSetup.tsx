import { APIError } from "@/api/client";
import {
  queryKeys,
  useCreateApiKey,
  useMe,
  useProject,
  useProjectStats,
  useVersion,
} from "@/api/hooks";
import { adapterRefFor, githubActionsSnippet, gitlabCiSnippet } from "@/lib/ciSnippets";
import { pluralize } from "@/lib/format";
import type { ProjectStats } from "@/types/api";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";

const BUTTON_CLASS =
  "bg-primary text-primary-foreground hover:bg-primary/90 rounded-md px-4 py-2 text-sm font-medium disabled:opacity-50";
const LINK_CLASS = "text-primary hover:text-primary/80 text-sm underline";
const PRE_CLASS = "bg-muted rounded-md p-3 text-xs overflow-x-auto";
const COPY_BUTTON_CLASS = "text-primary hover:text-primary/80 shrink-0 text-xs font-medium";

export function ProjectSetup() {
  const { slug = "" } = useParams<{ slug: string; }>();
  const queryClient = useQueryClient();
  const { data: me, isLoading: meLoading } = useMe();
  const { data: project, isLoading: projectLoading } = useProject(slug);
  // Until the version resolves the snippets point at main; the text updates
  // in place once the build info arrives.
  const { data: serverVersion } = useVersion();

  const createKey = useCreateApiKey();
  const [rawKey, setRawKey] = useState<string | null>(null);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const copyTimer = useRef<number | undefined>(undefined);

  // Poll every five seconds until a report lands, then stop. The hook reads
  // refetchInterval again on every result update, so the cached stats decide
  // whether the next poll is still needed.
  const cachedStats = queryClient.getQueryData<ProjectStats>(queryKeys.projectStats(slug));
  const firstReportReceived = (cachedStats?.report_count ?? 0) > 0;
  const stats = useProjectStats(slug, {
    refetchInterval: firstReportReceived ? false : 5000,
  });

  useEffect(() => () => {
    if (copyTimer.current !== undefined) window.clearTimeout(copyTimer.current);
  }, []);

  async function writeToClipboard(text: string) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Clipboard access can be denied; the text stays visible for manual copy.
    }
  }

  function copy(id: string, text: string) {
    void writeToClipboard(text);
    setCopied(id);
    if (copyTimer.current !== undefined) window.clearTimeout(copyTimer.current);
    copyTimer.current = window.setTimeout(() => setCopied(null), 2000);
  }

  function handleCreateKey() {
    setKeyError(null);
    createKey.mutate({ project: slug, name: "CI" }, {
      onSuccess: (created) => setRawKey(created.raw_key),
      onError: (error) => {
        setRawKey(null);
        setKeyError(error instanceof APIError ? error.message : "Failed to create the API key");
      },
    });
  }

  if (meLoading || projectLoading) {
    return (
      <div className="mx-auto max-w-2xl px-4 py-8">
        <div className="bg-muted h-8 w-72 animate-pulse rounded" />
        <div className="bg-muted mt-6 h-96 animate-pulse rounded-lg" />
      </div>
    );
  }

  if (me?.role !== "admin") {
    return (
      <div className="mx-auto max-w-2xl px-4 py-8">
        <h1 className="mb-6 text-2xl font-bold">CI setup</h1>
        <p className="text-muted-foreground text-sm">
          Only administrators can set up CI for a project.
        </p>
        <Link to="/" className={`${LINK_CLASS} mt-2 inline-block`}>Back to projects</Link>
      </div>
    );
  }

  const apiUrl = window.location.origin;
  const adapterRef = adapterRefFor(serverVersion);
  const githubSnippet = githubActionsSnippet({ apiUrl, project: slug, adapterRef });
  const gitlabSnippet = gitlabCiSnippet({ apiUrl, project: slug, adapterRef });
  const reportCount = stats.data?.report_count ?? 0;
  const totalFindings = stats.data?.total_findings ?? 0;

  return (
    <div className="mx-auto max-w-2xl px-4 py-8">
      <h1 className="mb-6 text-2xl font-bold">Set up CI for {project?.name ?? slug}</h1>

      <ol className="list-decimal space-y-8 pl-5">
        <li>
          <h2 className="text-lg font-semibold">Create an API key</h2>
          <p className="text-muted-foreground mt-1 text-sm">
            Create a key for your pipeline. It is shown only once.
          </p>
          <button
            type="button"
            className={`${BUTTON_CLASS} mt-3`}
            onClick={handleCreateKey}
            disabled={createKey.isPending}
          >
            {createKey.isPending ? "Creating..." : "Create key"}
          </button>
          {keyError && <p role="alert" className="text-destructive mt-2 text-xs">{keyError}</p>}
          {rawKey && (
            <div className="mt-3">
              <div className="flex items-center gap-2">
                <code className={`${PRE_CLASS} flex-1`}>{rawKey}</code>
                <button
                  type="button"
                  className={COPY_BUTTON_CLASS}
                  onClick={() => copy("key", rawKey)}
                >
                  {copied === "key" ? "Copied" : "Copy"}
                </button>
              </div>
              <p className="text-destructive mt-2 text-xs">
                Copy it now. It will not be shown again.
              </p>
              <p className="text-muted-foreground mt-1 text-xs">
                This key can upload reports and read results. It cannot change findings, waivers or
                policies.
              </p>
            </div>
          )}
        </li>

        <li>
          <h2 className="text-lg font-semibold">Add it to your pipeline</h2>
          <p className="text-muted-foreground mt-1 text-sm">
            Store the key you just created as the SPECHT_API_KEY secret, then commit one of these
            pipelines. The snippets only reference the secret; they never contain the key itself.
          </p>

          <div className="mt-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-medium">GitHub Actions</h3>
              <button
                type="button"
                className={COPY_BUTTON_CLASS}
                onClick={() => copy("github", githubSnippet)}
              >
                {copied === "github" ? "Copied" : "Copy"}
              </button>
            </div>
            <pre className={`${PRE_CLASS} mt-1`}>
              <code>{githubSnippet}</code>
            </pre>
          </div>

          <div className="mt-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-medium">GitLab CI</h3>
              <button
                type="button"
                className={COPY_BUTTON_CLASS}
                onClick={() => copy("gitlab", gitlabSnippet)}
              >
                {copied === "gitlab" ? "Copied" : "Copy"}
              </button>
            </div>
            <pre className={`${PRE_CLASS} mt-1`}>
              <code>{gitlabSnippet}</code>
            </pre>
          </div>

          <p className="text-muted-foreground mt-2 text-xs">
            More examples: examples/ci/ in the repository.
          </p>
        </li>

        <li>
          <h2 className="text-lg font-semibold">Or upload a report by hand</h2>
          <p className="mt-1 text-sm">
            <Link to={`/${slug}/reports/upload`} className={LINK_CLASS}>Upload a report</Link>
          </p>
        </li>

        <li>
          <h2 className="text-lg font-semibold">Waiting for the first report</h2>
          {reportCount > 0
            ? (
              <div className="mt-1">
                <p className="text-sm">
                  First report received: {pluralize(totalFindings, "finding")}.
                </p>
                <div className="mt-2 flex gap-4">
                  <Link to={`/${slug}/findings`} className={LINK_CLASS}>View findings</Link>
                  <Link to="/" className={LINK_CLASS}>Back to projects</Link>
                </div>
              </div>
            )
            : (
              <p role="status" className="text-muted-foreground mt-1 text-sm">
                Waiting for the first report...
              </p>
            )}
        </li>
      </ol>
    </div>
  );
}
