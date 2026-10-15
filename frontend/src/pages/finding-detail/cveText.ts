import { EMPTY_VALUE, formatDate, formatRelativeTime } from "@/lib/format";
import type { CveCvss, CveProvenance } from "@/types/cve";

const PROVIDER_NAMES: Readonly<Record<string, string>> = {
  nvd: "NVD",
  vulncheck: "VulnCheck",
  osv: "OSV",
  epss: "EPSS",
  kev: "CISA KEV",
};

/** What people call a provider or feed. An unknown one keeps its own name. */
export function providerName(name: string | undefined): string {
  if (!name) return "an external source";
  return PROVIDER_NAMES[name] ?? name;
}

/**
 * A probability as a percentage. Anything under one percent keeps two decimals, so an EPSS of
 * 0.00043 reads "0.04%" and not "0%"; a value too small even for that reads "<0.01%".
 */
export function formatPercent(probability: number): string {
  const percent = probability * 100;
  if (percent === 0) return "0%";
  if (percent < 0.005) return "<0.01%";
  if (percent < 1) return `${percent.toFixed(2)}%`;
  return `${percent.toFixed(1)}%`;
}

const DAY_FORMATTER = new Intl.DateTimeFormat(undefined, {
  day: "numeric",
  month: "short",
  year: "numeric",
  timeZone: "UTC",
});

/**
 * A calendar date ("2024-04-22", or a timestamp's date part) in the same short form as the rest of
 * the page. It is read in UTC so a date-only value does not slip a day in a western time zone.
 */
export function formatDay(iso: string | null | undefined): string {
  if (!iso) return EMPTY_VALUE;
  const date = new Date(iso.length === 10 ? `${iso}T00:00:00Z` : iso);
  return Number.isNaN(date.getTime()) ? EMPTY_VALUE : DAY_FORMATTER.format(date);
}

/**
 * Where a value came from, in words. A provider's value never reads as the scanner's: each kind
 * names its own source, and a kind this client does not know says so instead of guessing.
 */
export function provenanceLabel(p: CveProvenance, now: Date = new Date()): string {
  switch (p.kind) {
    case "scan_report": {
      const parts = [p.tool, p.observed_at ? formatDate(p.observed_at) : undefined].filter(
        Boolean,
      );
      return parts.length > 0
        ? `From the scan report (${parts.join(", ")})`
        : "From the scan report";
    }
    case "watcher":
      return "From the CVE watcher";
    case "provider":
      return `From ${providerName(p.provider)}${fetchedAgo(p, now)}`;
    case "feed":
      return `From the ${providerName(p.provider)} feed${fetchedAgo(p, now)}`;
    default:
      return "From an unknown source";
  }
}

function fetchedAgo(p: CveProvenance, now: Date): string {
  return p.fetched_at ? `, fetched ${formatRelativeTime(p.fetched_at, now)}` : "";
}

/** Who printed a score, as the subject of a sentence: "The scanner (grype)", "NVD". */
export function reporterOf(p: CveProvenance): string {
  switch (p.kind) {
    case "scan_report":
      return p.tool ? `The scanner (${p.tool})` : "The scanner";
    case "watcher":
      return "The CVE watcher";
    case "provider":
    case "feed":
      return providerName(p.provider);
    default:
      return "The source";
  }
}

const CWE_NUMBER = /^CWE-(\d{1,6})$/i;

/** The MITRE page for a CWE identifier, or null when the identifier is not "CWE-<number>". */
export function cweLink(id: string): string | null {
  const match = CWE_NUMBER.exec(id.trim());
  return match ? `https://cwe.mitre.org/data/definitions/${Number(match[1])}.html` : null;
}

function scoreOf(cvss: CveCvss): number | null {
  return cvss.base_score ?? cvss.reported_score;
}

/** The entry with the highest score; the first of equal ones, which is the report's before a provider's. */
export function highestCvss(list: readonly CveCvss[]): CveCvss | undefined {
  let best: CveCvss | undefined;
  for (const cvss of list) {
    const score = scoreOf(cvss);
    if (score === null) continue;
    if (!best || score > (scoreOf(best) ?? -1)) best = cvss;
  }
  return best;
}

const PROVIDER_STATUS_TEXT: Readonly<Record<string, string>> = {
  found: "found",
  not_found: "no record",
  error: "failed, will retry later",
  pending: "looking up",
  skipped: "not asked, nothing more was needed",
  disabled: "not configured",
};

/** A provider's status in words. */
export function providerStatusText(status: string): string {
  return PROVIDER_STATUS_TEXT[status] ?? status;
}
