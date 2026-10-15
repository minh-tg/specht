import type { CveCvss, CveProvenance } from "@/types/cve";
import { describe, expect, it } from "vitest";
import {
  cweLink,
  formatDay,
  formatPercent,
  highestCvss,
  provenanceLabel,
  providerStatusText,
  reporterOf,
} from "./cveText";

const NOW = new Date("2026-10-15T12:00:00Z");

describe("formatPercent", () => {
  it("shows small probabilities with enough digits not to read as zero", () => {
    expect(formatPercent(0.00043)).toBe("0.04%");
    expect(formatPercent(0.000012)).toBe("<0.01%");
    expect(formatPercent(0)).toBe("0%");
  });

  it("uses one decimal from one percent up", () => {
    expect(formatPercent(0.005)).toBe("0.50%");
    expect(formatPercent(0.0123)).toBe("1.2%");
    expect(formatPercent(0.85)).toBe("85.0%");
    expect(formatPercent(1)).toBe("100.0%");
  });
});

describe("formatDay", () => {
  it("formats a date-only value without shifting it by the local time zone", () => {
    // The order of day and month follows the browser locale; the day number must not move.
    expect(formatDay("2026-10-14")).toMatch(/^(?=.*\b14\b)(?=.*Oct)(?=.*2026)/);
    expect(formatDay("2024-04-01")).toMatch(/^(?=.*\b1\b)(?=.*Apr)(?=.*2024)/);
  });

  it("reads the date part of a timestamp", () => {
    expect(formatDay("2024-04-22T00:00:00Z")).toMatch(/^(?=.*\b22\b)(?=.*Apr)(?=.*2024)/);
  });

  it("returns the empty value for nothing", () => {
    expect(formatDay(null)).toBe("None");
    expect(formatDay("not a date")).toBe("None");
  });
});

describe("provenanceLabel", () => {
  it("names the scanner and the observation day for the scan report", () => {
    const p: CveProvenance = {
      kind: "scan_report",
      tool: "grype",
      observed_at: "2026-10-14T08:00:00Z",
    };
    expect(provenanceLabel(p, NOW)).toMatch(
      /^From the scan report \(grype, (?=.*\b14\b)(?=.*Oct)(?=.*2026).*\)$/,
    );
  });

  it("says a scan report value came from the scan report even without a tool", () => {
    expect(provenanceLabel({ kind: "scan_report" }, NOW)).toBe("From the scan report");
  });

  it("names the CVE watcher", () => {
    expect(provenanceLabel({ kind: "watcher", tool: "cve_watcher" }, NOW)).toBe(
      "From the CVE watcher",
    );
  });

  it("names the provider and how long ago it was fetched, never the scanner", () => {
    const label = provenanceLabel(
      { kind: "provider", provider: "nvd", fetched_at: "2026-10-15T10:00:00Z" },
      NOW,
    );
    expect(label).toBe("From NVD, fetched 2 h ago");
    expect(label).not.toMatch(/scan/i);
    expect(provenanceLabel({ kind: "provider", provider: "vulncheck" }, NOW)).toBe(
      "From VulnCheck",
    );
  });

  it("shows an unknown provider as its own name", () => {
    expect(provenanceLabel({ kind: "provider", provider: "acme" }, NOW)).toBe("From acme");
  });

  it("names the intel feed", () => {
    expect(provenanceLabel({ kind: "feed", provider: "epss" }, NOW)).toBe("From the EPSS feed");
    expect(provenanceLabel({ kind: "feed", provider: "kev" }, NOW)).toBe(
      "From the CISA KEV feed",
    );
  });

  it("does not claim the scan report for a source it does not know", () => {
    const p = { kind: "mystery" } as unknown as CveProvenance;
    expect(provenanceLabel(p, NOW)).toBe("From an unknown source");
  });
});

describe("reporterOf", () => {
  it("is the scanner for a report, and the provider's name for a provider", () => {
    expect(reporterOf({ kind: "scan_report", tool: "trivy" })).toBe("The scanner (trivy)");
    expect(reporterOf({ kind: "scan_report" })).toBe("The scanner");
    expect(reporterOf({ kind: "provider", provider: "nvd" })).toBe("NVD");
    expect(reporterOf({ kind: "watcher" })).toBe("The CVE watcher");
  });
});

describe("cweLink", () => {
  it("links a CWE identifier to the MITRE definition", () => {
    expect(cweLink("CWE-79")).toBe("https://cwe.mitre.org/data/definitions/79.html");
    expect(cweLink("cwe-1321")).toBe("https://cwe.mitre.org/data/definitions/1321.html");
  });

  it("gives no link for anything that is not a CWE number", () => {
    expect(cweLink("CWE-")).toBeNull();
    expect(cweLink("NVD-CWE-Other")).toBeNull();
    expect(cweLink("CWE-79/../x")).toBeNull();
  });
});

describe("highestCvss", () => {
  const entry = (version: CveCvss["version"], base: number | null, reported: number | null) =>
    ({
      version,
      vector: "",
      base_score: base,
      reported_score: reported,
      severity: null,
      valid: base !== null,
      metrics: [],
      provenance: { kind: "scan_report" },
    }) as CveCvss;

  it("picks the highest score and keeps the first of equal ones", () => {
    const first = entry("3.1", 7.5, 7.5);
    const list = [entry("2.0", 5, 5), first, entry("4.0", 7.5, null)];
    expect(highestCvss(list)).toBe(first);
  });

  it("falls back to the reported score when the vector does not parse", () => {
    const list = [entry("3.1", null, 9.1), entry("2.0", 5, 5)];
    expect(highestCvss(list)?.version).toBe("3.1");
  });

  it("is undefined when nothing has a score", () => {
    expect(highestCvss([entry("3.1", null, null)])).toBeUndefined();
    expect(highestCvss([])).toBeUndefined();
  });
});

describe("providerStatusText", () => {
  it("says each status in words", () => {
    expect(providerStatusText("found")).toBe("found");
    expect(providerStatusText("not_found")).toBe("no record");
    expect(providerStatusText("error")).toBe("failed, will retry later");
    expect(providerStatusText("pending")).toBe("looking up");
    expect(providerStatusText("skipped")).toBe("not asked, nothing more was needed");
    expect(providerStatusText("disabled")).toBe("not configured");
  });

  it("passes an unknown status through", () => {
    expect(providerStatusText("future")).toBe("future");
  });
});
