import type { CveCvss, CveDetail, CveProvenance, CvssMetric } from "@/types/cve";

const GROUP_OF: Record<string, CvssMetric["group"]> = {
  E: "threat",
  CR: "environmental",
  IR: "environmental",
  AR: "environmental",
  AU: "supplemental",
};

/** Splits a vector the way the server does: in vector order, with the metric's group. */
export function metricsOf(vector: string, version: CveCvss["version"]): CvssMetric[] {
  return vector
    .replace(/^CVSS:[0-9.]+\//, "")
    .split("/")
    .map((part) => {
      const [key, value] = part.split(":");
      const group = version === "4.0" ? GROUP_OF[key] ?? "base" : "base";
      return { group, key, value };
    });
}

export const REPORT: CveProvenance = {
  kind: "scan_report",
  tool: "grype",
  report_id: "5d1e3c6e-0000-4000-8000-000000000001",
  observed_at: "2026-10-14T08:00:00Z",
};

export const NVD: CveProvenance = {
  kind: "provider",
  provider: "nvd",
  fetched_at: "2026-10-15T10:00:00Z",
};

export const V31_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
export const V30_VECTOR = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
export const V20_VECTOR = "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P";
export const V40_VECTOR =
  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:H/AU:Y";

export function cvss(
  version: CveCvss["version"],
  vector: string,
  base: number,
  severity: CveCvss["severity"],
  provenance: CveProvenance = REPORT,
  overrides: Partial<CveCvss> = {},
): CveCvss {
  return {
    version,
    vector,
    base_score: base,
    reported_score: base,
    severity,
    valid: true,
    metrics: metricsOf(vector, version),
    provenance,
    ...overrides,
  };
}

/** A CVE every field of which the scan report supplied, with all four CVSS versions. */
export function completeReport(): CveDetail {
  return {
    cve_id: "CVE-2024-3094",
    pending: false,
    cvss: [
      cvss("3.1", V31_VECTOR, 10, "critical"),
      cvss("3.0", V30_VECTOR, 9.8, "critical"),
      cvss("2.0", V20_VECTOR, 7.5, "high"),
      cvss("4.0", V40_VECTOR, 9.3, "critical"),
    ],
    epss: {
      probability: 0.00043,
      percentile: 0.12,
      date: "2026-10-14",
      provenance: { kind: "feed", provider: "epss", fetched_at: "2026-10-15T09:00:00Z" },
    },
    kev: {
      listed: true,
      date_added: "2024-04-01",
      due_date: "2024-04-22",
      known_ransomware_use: "Unknown",
      provenance: { kind: "feed", provider: "kev", fetched_at: "2026-10-15T09:00:00Z" },
    },
    cwes: [{ id: "CWE-506", provenance: REPORT }, { id: "CWE-79", provenance: REPORT }],
    published_at: { value: "2024-03-29T17:15:21Z", provenance: REPORT },
    modified_at: null,
    references: [
      { url: "https://example.org/advisory/1", provenance: REPORT },
      { url: "http://example.org/not-https", provenance: REPORT },
    ],
    providers: [
      { name: "nvd", status: "skipped" },
      { name: "vulncheck", status: "disabled" },
      { name: "osv", status: "disabled" },
    ],
  };
}

/** The scan report had no vector; NVD filled it in. */
export function providerFilled(): CveDetail {
  return {
    ...completeReport(),
    cvss: [cvss("3.1", V31_VECTOR, 10, "critical", NVD)],
    cwes: [{ id: "CWE-787", provenance: NVD }],
    published_at: { value: "2024-03-29T17:15:21Z", provenance: NVD },
    references: [{ url: "https://nvd.example/ref", provenance: NVD }],
    providers: [
      { name: "nvd", status: "found", fetched_at: "2026-10-15T10:00:00Z" },
      { name: "vulncheck", status: "skipped" },
      { name: "osv", status: "disabled" },
    ],
  };
}
