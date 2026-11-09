import type { Report } from "@/types/api";

/** The code hosts whose URL layout Specht knows. */
export type CodeHost = "github" | "gitlab";

/** Where a report's code lives, enough to link to its pull request and files. */
export interface CodeSource {
  readonly repoUrl: string;
  readonly host: CodeHost;
  /** The scanned commit, when it is a full or short hex SHA. */
  readonly commit?: string;
}

const HEX_SHA = /^[0-9a-f]{7,64}$/i;

/**
 * The code source a report names, or null when it names no repository or a host whose URL
 * layout is unknown. GitHub and GitLab are recognized by their public hosts, and a self-hosted
 * instance by its CI run address (`/actions/runs/` or `/-/jobs/`), which the adapter sends from
 * the same server. A link Specht cannot build correctly is better left out than broken.
 */
export function codeSource(
  report: Pick<Report, "repository_url" | "ci_run_url" | "commit_sha">,
): CodeSource | null {
  const repoUrl = report.repository_url?.replace(/\/+$/, "").replace(/\.git$/, "");
  if (!repoUrl || !/^https?:\/\//.test(repoUrl)) return null;
  let hostname: string;
  try {
    hostname = new URL(repoUrl).hostname.toLowerCase();
  } catch {
    return null;
  }
  const run = report.ci_run_url ?? "";
  const host: CodeHost | null = hostname === "github.com" || run.includes("/actions/runs/")
    ? "github"
    : hostname === "gitlab.com" || hostname.startsWith("gitlab.") || run.includes("/-/jobs/")
    ? "gitlab"
    : null;
  if (!host) return null;
  const commit = report.commit_sha && HEX_SHA.test(report.commit_sha)
    ? report.commit_sha
    : undefined;
  return { repoUrl, host, commit };
}

/** The pull or merge request page, or null without a usable number. */
export function pullRequestUrl(source: CodeSource, n?: number | null): string | null {
  if (!n || !Number.isInteger(n) || n < 1) return null;
  return source.host === "github"
    ? `${source.repoUrl}/pull/${n}`
    : `${source.repoUrl}/-/merge_requests/${n}`;
}

/**
 * The file at the scanned commit, at its line when known, or null. Only a relative path inside
 * the repository gets a link: an absolute path, a URL or a `..` step names something the
 * repository page cannot show.
 */
export function fileUrl(
  source: CodeSource,
  file?: string | null,
  line?: number | null,
): string | null {
  if (!source.commit || !file) return null;
  const path = file.replace(/^\.\//, "");
  if (path.startsWith("/") || path.includes("://") || path.includes("\\")) return null;
  const segments = path.split("/");
  if (segments.some((s) => s === "" || s === "." || s === "..")) return null;
  const encoded = segments.map(encodeURIComponent).join("/");
  const anchor = line && Number.isInteger(line) && line > 0 ? `#L${line}` : "";
  return source.host === "github"
    ? `${source.repoUrl}/blob/${source.commit}/${encoded}${anchor}`
    : `${source.repoUrl}/-/blob/${source.commit}/${encoded}${anchor}`;
}
