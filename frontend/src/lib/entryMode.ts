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

/** Marks a path as opened from the change view, keeping its other query params and its hash. */
export function fromChangePath(path: string): string {
  const hashAt = path.indexOf("#");
  const hash = hashAt === -1 ? "" : path.slice(hashAt);
  const rest = hashAt === -1 ? path : path.slice(0, hashAt);
  const queryAt = rest.indexOf("?");
  const pathname = queryAt === -1 ? rest : rest.slice(0, queryAt);
  const params = new URLSearchParams(queryAt === -1 ? "" : rest.slice(queryAt + 1));
  params.set(FROM_PARAM, FROM_CHANGE);
  return `${pathname}?${params}${hash}`;
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
