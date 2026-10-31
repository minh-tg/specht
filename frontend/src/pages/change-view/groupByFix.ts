import { normalizeSeverity } from "@/lib/enums";
import { fixSentence } from "@/pages/change-view/resolve";
import type { Finding } from "@/types/api";

/** The one upgrade that fixes a dependency finding. */
export interface FixTarget {
  readonly packageName: string;
  readonly ecosystem: string;
  readonly fixedVersion: string;
}

/** A blocker that stands on its own row. */
export interface SingleItem {
  readonly kind: "single";
  readonly key: string;
  readonly id: string;
  /** 1-based place of the finding in the gate's list, which the ledger number shows. */
  readonly position: number;
}

/** Blockers that one upgrade clears together. */
export interface GroupItem {
  readonly kind: "group";
  readonly key: string;
  readonly target: FixTarget;
  readonly ids: readonly string[];
  /** The place of each member in the gate's list, in the same order as `ids`. */
  readonly positions: readonly number[];
  /** The place of the first member, which numbers the group's entry. */
  readonly position: number;
}

export type BlockerItem = SingleItem | GroupItem;

function present(value: string | undefined): string {
  return (value ?? "").trim();
}

/**
 * The upgrade a finding names, or null when it does not name one. Only a dependency finding whose
 * suggestion is a real fix (`fallback` false) and that carries package, ecosystem and fixed
 * version qualifies. The server's generic "review" suggestion never does, and neither does a
 * finding of another kind, whatever its text says.
 */
export function fixTarget(finding: Finding | undefined): FixTarget | null {
  if (!finding || finding.finding_kind !== "sca") return null;
  const suggestion = finding.suggestion;
  if (!suggestion || suggestion.fallback) return null;
  const packageName = present(suggestion.package);
  const ecosystem = present(suggestion.ecosystem);
  const fixedVersion = present(suggestion.fixed_version);
  if (!packageName || !ecosystem || !fixedVersion) return null;
  return { packageName, ecosystem, fixedVersion };
}

function groupKey(target: FixTarget): string {
  return JSON.stringify([target.ecosystem, target.packageName, target.fixedVersion]);
}

/**
 * Turns the gate's blocker ids into ledger items. Blockers that share ecosystem, package and fixed
 * version form one group; a different fixed version for the same package is a different upgrade
 * and stays apart. A group needs two members, so a lone match stays a plain row. Findings that
 * have not loaded stay plain rows too. Every item carries the place of its first finding in the
 * original list, so the ledger numbers do not change when rows are folded together, and items
 * come out in that order.
 */
export function buildBlockerItems(
  ids: readonly string[],
  findings: ReadonlyMap<string, Finding>,
): BlockerItem[] {
  const members = new Map<string, { target: FixTarget; at: number[]; }>();
  ids.forEach((id, index) => {
    const target = fixTarget(findings.get(id));
    if (!target) return;
    const key = groupKey(target);
    const entry = members.get(key);
    if (entry) entry.at.push(index);
    else members.set(key, { target, at: [index] });
  });

  const items: BlockerItem[] = [];
  const emitted = new Set<string>();
  ids.forEach((id, index) => {
    const target = fixTarget(findings.get(id));
    const key = target ? groupKey(target) : null;
    const entry = key ? members.get(key) : undefined;
    if (!key || !entry || entry.at.length < 2) {
      items.push({ kind: "single", key: id, id, position: index + 1 });
      return;
    }
    if (emitted.has(key)) return;
    emitted.add(key);
    items.push({
      kind: "group",
      key: `fix:${key}`,
      target: entry.target,
      ids: entry.at.map((at) => ids[at]),
      positions: entry.at.map((at) => at + 1),
      position: index + 1,
    });
  });
  return items;
}

/** The finding ids an item stands for. */
export function itemIds(item: BlockerItem): readonly string[] {
  return item.kind === "group" ? item.ids : [item.id];
}

/** A short, stable hash (FNV-1a, 32 bits) in hex, to keep slugs of different keys apart. */
function shortHash(text: string): string {
  let hash = 0x811c9dc5;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0").slice(0, 6);
}

/**
 * The id of a group's waiver note, so focus can go back to it after a request is sent. It is made
 * of letters, digits and hyphens, so it works in `#id` selectors and CSS. The hash suffix keeps
 * apart two keys that slug to the same words (npm "a-b" and "c" against npm "a" and "b-c").
 */
export function groupWaiverNoteId(key: string): string {
  const slug = key.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return `group-waiver-${slug.replace(/^fix-/, "")}-${shortHash(key)}`;
}

/** What to do, as one instruction a person can paste. */
export function upgradeInstruction(target: FixTarget): string {
  return `Upgrade ${target.packageName} to ${target.fixedVersion}`;
}

/** The worst severity among a group's loaded members, for its badge and edge colour. */
export function worstSeverity(
  ids: readonly string[],
  findings: ReadonlyMap<string, Finding>,
): string {
  const order = ["critical", "high", "medium", "low"];
  let best = order.length;
  let name = "";
  for (const id of ids) {
    const finding = findings.get(id);
    if (!finding) continue;
    const rank = order.indexOf(normalizeSeverity(finding.current_severity));
    const at = rank === -1 ? order.length : rank;
    if (!name || at < best) {
      best = at;
      name = finding.current_severity;
    }
  }
  return name;
}

/**
 * The numbered lines behind "Copy all fixes". A group is one line, numbered like its entry; a plain
 * row is "title: fix". Rows that are still loading or have no real fix are left out but keep
 * their number, so a line matches the ledger entry it came from.
 */
export function itemFixesText(
  items: readonly BlockerItem[],
  findings: ReadonlyMap<string, Finding>,
): string {
  return items
    .map((item) => {
      if (item.kind === "group") {
        return `${item.position}. ${
          upgradeInstruction(item.target)
        } (clears ${item.ids.length} blockers)`;
      }
      const finding = findings.get(item.id);
      const fix = finding ? fixSentence(finding) : null;
      return finding && fix ? `${item.position}. ${finding.current_title}: ${fix}` : null;
    })
    .filter((line): line is string => line !== null)
    .join("\n");
}
