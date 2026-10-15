/** The order the palette shows its groups in. */
export const COMMAND_GROUPS = ["This project", "Projects", "Go to", "Do"] as const;
export type CommandGroup = typeof COMMAND_GROUPS[number];

export interface Command {
  readonly id: string;
  readonly group: CommandGroup;
  readonly label: string;
  /** A short second line, such as a project's slug. */
  readonly hint?: string;
  /** Extra words that should find it, such as "logout" for "Sign out". */
  readonly keywords?: string;
  /**
   * `from` is the element that had focus before the palette opened, for a command that opens
   * another dialog and should hand focus back there when it closes.
   */
  readonly run: (from?: HTMLElement | null) => void;
}

/** The sections of a project, which are the second part of its address. */
const PROJECT_SECTIONS = [
  "findings",
  "reports",
  "access",
  "policy",
  "waivers",
  "insights",
  "watcher",
  "setup",
  "changes",
  "settings",
];

const PROJECT_PATH = new RegExp(`^/([^/]+)/(${PROJECT_SECTIONS.join("|")})(?:/|$)`);

/** The project a page belongs to, or null on a page that is not inside one. */
export function currentProjectSlug(pathname: string): string | null {
  const match = PROJECT_PATH.exec(pathname);
  return match ? decodeURIComponent(match[1]!) : null;
}

/** Whether the page is the new-project form or one of a project's own pages. */
export function isProjectsPath(pathname: string): boolean {
  return pathname === "/projects/new" || currentProjectSlug(pathname) !== null;
}

const words = (text: string) => text.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

/** Whether the letters of `needle` appear in `haystack` in order, with anything between them. */
function isSubsequence(needle: string, haystack: string): boolean {
  let at = 0;
  for (const ch of haystack) {
    if (ch === needle[at]) at += 1;
    if (at === needle.length) return true;
  }
  return needle.length === 0;
}

function tokenScore(token: string, command: Command): number {
  const label = command.label.toLowerCase();
  if (label.startsWith(token)) return 4;
  if (words(command.label).some((w) => w.startsWith(token))) return 3;
  if (label.includes(token)) return 2;
  const extra = `${command.hint ?? ""} ${command.keywords ?? ""}`.toLowerCase();
  if (words(extra).some((w) => w.startsWith(token))) return 1.5;
  if (extra.includes(token)) return 1;
  if (token.length > 2 && isSubsequence(token, label)) return 0.5;
  return 0;
}

/** How well a command answers a query: 0 when any word of the query finds nothing. */
export function commandScore(query: string, command: Command): number {
  const tokens = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return 1;
  let total = 0;
  for (const token of tokens) {
    const score = tokenScore(token, command);
    if (score === 0) return 0;
    total += score;
  }
  return total;
}

/** The commands that answer the query, best first and the order they came in on a tie. */
export function searchCommands(commands: readonly Command[], query: string): Command[] {
  if (query.trim() === "") return [...commands];
  return commands
    .map((command, index) => ({ command, index, score: commandScore(query, command) }))
    .filter((r) => r.score > 0)
    .sort((a, b) => b.score - a.score || a.index - b.index)
    .map((r) => r.command);
}

export interface CommandSection {
  readonly group: CommandGroup;
  readonly items: readonly Command[];
}

/**
 * The commands under their group headings. With no query the groups keep their fixed order; with a
 * query the best match leads, so the group that holds it comes first.
 */
export function sectionCommands(commands: readonly Command[], query: string): CommandSection[] {
  const found = searchCommands(commands, query);
  const byGroup = new Map<CommandGroup, Command[]>();
  for (const command of found) {
    byGroup.set(command.group, [...(byGroup.get(command.group) ?? []), command]);
  }
  const order = query.trim() === ""
    ? [...COMMAND_GROUPS]
    : [...new Set(found.map((c) => c.group))];
  return order
    .filter((g) => byGroup.has(g))
    .map((group) => ({ group, items: byGroup.get(group)! }));
}
