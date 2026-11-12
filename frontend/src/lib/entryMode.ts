/**
 * How a person arrived at a finding decides what the page leads with. From the change view they
 * are unblocking a change and want the fix first ("unblock"). From the findings list, or a link
 * with no origin, they are triaging and want the decision first ("triage"). The names match the
 * `[data-mode]` tokens in index.css.
 */
export type EntryMode = "unblock" | "triage";

const FROM_PARAM = "from";
const FROM_CHANGE = "change";

/**
 * Reads the mode from a location's search string. Only `from=change` gives "unblock"; a missing,
 * empty or unknown value gives "triage". With a repeated `from`, the first one counts.
 */
export function entryModeFromSearch(search: string): EntryMode {
  const from = new URLSearchParams(search).get(FROM_PARAM);
  return from === FROM_CHANGE ? "unblock" : "triage";
}

/**
 * The gate a change view judged its blockers with: the commit, and the scope and severity its CI
 * link carried. A finding opened from a blocker is judged with the same gate, so the finding page
 * cannot say "does not block" about a finding the change view lists as blocking.
 */
export interface ChangeScope {
  readonly commit: string;
  readonly projectWide: boolean;
  readonly severity?: string;
  /** The commit's branch; the project-wide gate adds the findings seen on it. */
  readonly branch?: string;
}

const COMMIT_PARAM = "commit";
const SCOPE_PARAM = "scope";
const SEVERITY_PARAM = "severity";
const BRANCH_PARAM = "branch";
const SCOPE_PROJECT = "project";
// The server's commit_sha pattern and length (POST /reports), so a hand-edited link fails here
// instead of asking the gate for something it refuses.
const COMMIT_PATTERN = /^[0-9A-Za-z._-]{1,64}$/;
const SEVERITY_PATTERN = /^[a-z]+(,[a-z]+)*$/;

/**
 * Marks a path as opened from the change view, keeping its other query params and its hash. With
 * a scope, the link also names the change's gate, so a link opened in a new tab still has it.
 */
export function fromChangePath(path: string, scope?: ChangeScope): string {
  const hashAt = path.indexOf("#");
  const hash = hashAt === -1 ? "" : path.slice(hashAt);
  const rest = hashAt === -1 ? path : path.slice(0, hashAt);
  const queryAt = rest.indexOf("?");
  const pathname = queryAt === -1 ? rest : rest.slice(0, queryAt);
  const params = new URLSearchParams(queryAt === -1 ? "" : rest.slice(queryAt + 1));
  params.set(FROM_PARAM, FROM_CHANGE);
  if (scope) {
    params.set(COMMIT_PARAM, scope.commit);
    if (scope.projectWide) params.set(SCOPE_PARAM, SCOPE_PROJECT);
    if (scope.severity) params.set(SEVERITY_PARAM, scope.severity);
    if (scope.projectWide && scope.branch) params.set(BRANCH_PARAM, scope.branch);
  }
  return `${pathname}?${params}${hash}`;
}

/**
 * Reads the change's gate back from a finding link, or null when the link has none or names a
 * commit or severity the server would refuse. Only a link opened from a change counts.
 */
export function changeScopeFromSearch(search: string): ChangeScope | null {
  const params = new URLSearchParams(search);
  if (params.get(FROM_PARAM) !== FROM_CHANGE) return null;
  const commit = params.get(COMMIT_PARAM);
  if (!commit || !COMMIT_PATTERN.test(commit)) return null;
  const severity = params.get(SEVERITY_PARAM) || undefined;
  if (severity && !SEVERITY_PATTERN.test(severity)) return null;
  const projectWide = params.get(SCOPE_PARAM) === SCOPE_PROJECT;
  const branch = projectWide ? params.get(BRANCH_PARAM) || undefined : undefined;
  return { commit, projectWide, severity, branch };
}

/** Router state that lets the finding page link back to the exact change view the person left. */
export interface ChangeViewState {
  changeView: string;
}

export function changeViewState(location: { pathname: string; search: string; }): ChangeViewState {
  return { changeView: location.pathname + location.search };
}

/**
 * The change view to return to, or null. Only a path under this project's changes is accepted,
 * since router state comes from the history entry and is not trusted as a link target.
 */
export function changeViewBackPath(slug: string, state: unknown): string | null {
  const path = (state as { changeView?: unknown; } | null)?.changeView;
  if (typeof path !== "string") return null;
  return path.startsWith(`/${slug}/changes/`) ? path : null;
}

/**
 * The findings list query the person opened this finding from (`state.from`), or null when they
 * did not come from the list. Only "" or a "?" query is accepted, since router state is not trusted.
 */
export function findingsListSearch(state: unknown): string | null {
  const from = (state as { from?: unknown; } | null)?.from;
  return typeof from === "string" && (from === "" || from.startsWith("?")) ? from : null;
}
