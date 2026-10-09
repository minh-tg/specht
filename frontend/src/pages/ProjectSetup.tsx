import { APIError } from "@/api/client";
import {
  queryKeys,
  useCreateApiKey,
  useMe,
  useProject,
  useProjectStats,
  useVersion,
} from "@/api/hooks";
import { CopyButton } from "@/components/CopyButton";
import { adapterRefFor, githubActionsSnippet, gitlabCiSnippet } from "@/lib/ciSnippets";
import { pluralize } from "@/lib/format";
import { isReportInProgress } from "@/lib/verdict";
import type { ProjectStats } from "@/types/api";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

const BUTTON_CLASS =
  "bg-primary text-primary-foreground hover:bg-primary/90 rounded-md px-4 py-2 text-sm font-medium disabled:opacity-50";
const LINK_CLASS = "text-action hover:text-action/80 text-sm underline";
const PRE_CLASS = "bg-muted rounded-md p-3 text-xs break-words whitespace-pre-wrap";

type FirstReport = "waiting" | "processing" | "failed" | "received";

/**
 * Where the project's first report stands. A report counts the moment its row
 * exists, but it can still be processing or have failed, so "received" needs a
 * report that finished; with no latest report to judge by, a counted report is
 * taken as received.
 */
function firstReportState(stats: ProjectStats | undefined): FirstReport {
  if ((stats?.report_count ?? 0) === 0) return "waiting";
  const status = stats?.latest_report?.status;
  if (isReportInProgress(status)) return "processing";
  if (status === "failed") return "failed";
  return "received";
}

const FIRST_REPORT_COPY: Record<FirstReport, { heading: string; message: string; }> = {
  waiting: {
    heading: "Waiting for the first report",
    message: "Waiting for the first report...",
  },
  processing: {
    heading: "Processing the first report",
    message: "A report arrived and is still being processed...",
  },
  failed: {
    heading: "The first report failed",
    message: "The report arrived but could not be processed. Check the CI step and send it again.",
  },
  received: { heading: "First report received", message: "" },
};

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

  // The secret must not outlive this page: drop it from the mutation cache too.
  const resetKeyMutation = createKey.reset;
  useEffect(() => resetKeyMutation, [resetKeyMutation]);

  // Poll every five seconds until a report has been received and processed, then
  // stop. The hook reads refetchInterval again on every result update, so the
  // cached stats decide whether the next poll is still needed. A failed report
  // keeps the poll going: the next attempt from CI may succeed.
  const cachedStats = queryClient.getQueryData<ProjectStats>(queryKeys.projectStats(slug));
  const stats = useProjectStats(slug, {
    refetchInterval: firstReportState(cachedStats) === "received" ? false : 5000,
  });
  // A failed poll says nothing about the report, so it must not read as "waiting".
  const statsFailed = stats.isError;

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

  if (!project) {
    return (
      <div className="mx-auto max-w-2xl px-4 py-8">
        <h1 className="mb-6 text-2xl font-bold">Project not found</h1>
        <p className="text-muted-foreground text-sm">
          There is no project with this address, or you don&apos;t have access to it.
        </p>
        <Link to="/" className={`${LINK_CLASS} mt-2 inline-block`}>Back to projects</Link>
      </div>
    );
  }

  const apiUrl = window.location.origin;
  const adapterRef = adapterRefFor(serverVersion);
  // The snippets use the slug the server returned, never the raw URL segment.
  const githubSnippet = githubActionsSnippet({ apiUrl, project: project.slug, adapterRef });
  const gitlabSnippet = gitlabCiSnippet({ apiUrl, project: project.slug, adapterRef });
  const firstReport = firstReportState(stats.data);
  const totalFindings = stats.data?.total_findings ?? 0;

  return (
    <div className="mx-auto max-w-2xl px-4 py-8">
      <h1 className="mb-6 text-2xl font-bold">Set up CI for {project.name}</h1>

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
                <code className={`${PRE_CLASS} flex-1 break-all`}>{rawKey}</code>
                <CopyButton text={rawKey} label="API key" />
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
              <CopyButton text={githubSnippet} label="GitHub Actions workflow" />
            </div>
            <pre className={`${PRE_CLASS} mt-1`}>
              <code>{githubSnippet}</code>
            </pre>
          </div>

          <div className="mt-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-medium">GitLab CI</h3>
              <CopyButton text={gitlabSnippet} label="GitLab CI pipeline" />
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
          <h2 className="text-lg font-semibold">
            {statsFailed
              ? "First report status unavailable"
              : FIRST_REPORT_COPY[firstReport].heading}
          </h2>
          {statsFailed
            ? (
              <div className="mt-1 flex items-center gap-3">
                <p role="alert" className="text-destructive text-sm">
                  Could not check for the first report.
                </p>
                <button
                  type="button"
                  className={LINK_CLASS}
                  onClick={() => stats.refetch()}
                >
                  Retry
                </button>
              </div>
            )
            : (
              <p role="status" className="text-muted-foreground mt-1 text-sm">
                {firstReport === "received"
                  ? `First report received: ${pluralize(totalFindings, "finding")}.`
                  : FIRST_REPORT_COPY[firstReport].message}
              </p>
            )}
          {!statsFailed && firstReport === "failed" && (
            <div className="mt-2">
              <Link to={`/${project.slug}/reports`} className={LINK_CLASS}>View reports</Link>
            </div>
          )}
          {!statsFailed && firstReport === "received" && (
            <div className="mt-2 flex gap-4">
              <Link to={`/${project.slug}/findings`} className={LINK_CLASS}>View findings</Link>
              <Link to="/" className={LINK_CLASS}>Back to projects</Link>
            </div>
          )}
        </li>
      </ol>
    </div>
  );
}
