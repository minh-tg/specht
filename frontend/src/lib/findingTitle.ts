/** Longest title that still reads as a title in a row or a page heading. */
const MAX_HEADLINE = 110;

export interface FindingTitleParts {
  /** What to show as the finding's name. */
  readonly headline: string;
  /** The rest of a scanner message that was too long to be a name. */
  readonly rest: string | null;
}

/** Some scanners repeat the package: "lodash: lodash: Arbitrary code execution". */
function withoutRepeatedPrefix(title: string): string {
  const match = /^([^:\s]+): \1: /i.exec(title);
  return match ? title.slice(match[1].length + 2) : title;
}

/**
 * Splits a scanner's text into a name and the rest. SAST rules often put a paragraph where a title
 * belongs: the name is its first sentence, or its first words when that sentence is long too.
 */
function split(title: string): FindingTitleParts {
  if (title.length <= MAX_HEADLINE) return { headline: title, rest: null };
  const sentence = /^.{20,}?[.!?](?=\s)/.exec(title)?.[0];
  if (sentence && sentence.length <= MAX_HEADLINE) {
    return { headline: sentence, rest: title.slice(sentence.length).trim() };
  }
  const cut = title.lastIndexOf(" ", MAX_HEADLINE);
  const end = cut > 40 ? cut : MAX_HEADLINE;
  return { headline: `${title.slice(0, end)}…`, rest: `…${title.slice(end).trim()}` };
}

/** A title that is only an advisory id, such as "GHSA-35jh-r3h4-6jhm" or "CVE-2021-23337". */
const BARE_ID = /^(CVE-\d{4}-\d+|GHSA(-[a-z0-9]{4}){3}|OSV-\d{4}-\d+)$/i;

/** "lodash 4.17.20 in package-lock.json" reads as "lodash 4.17.20". */
function packageOf(summary: string | undefined): string | null {
  const name = summary?.split(" in ")[0]?.trim();
  return name && name !== summary ? name : null;
}

/**
 * What to call a finding on screen. The stored title is left alone: search matches it, and it stays
 * the finding's identity everywhere else.
 */
export function findingTitleParts(
  finding: {
    readonly current_title: string;
    readonly location?: { readonly summary?: string; } | null;
  },
): FindingTitleParts {
  const title = withoutRepeatedPrefix(finding.current_title.trim());
  if (BARE_ID.test(title)) {
    const pkg = packageOf(finding.location?.summary);
    return { headline: pkg ? `${title} in ${pkg}` : title, rest: null };
  }
  return split(title);
}

export function findingHeadline(
  finding: {
    readonly current_title: string;
    readonly location?: { readonly summary?: string; } | null;
  },
): string {
  return findingTitleParts(finding).headline;
}
