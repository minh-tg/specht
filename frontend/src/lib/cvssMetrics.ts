import type { CveCvss, CvssMetric } from "@/types/cve";

export type CvssVersion = CveCvss["version"];

/** One metric of a CVSS vector: its plain name, where it sits on the page, and its value words. */
export interface MetricDef {
  readonly key: string;
  readonly name: string;
  readonly section: string;
  readonly values: Readonly<Record<string, string>>;
}

const NOT_DEFINED = "Not defined";

const CIA_LEVEL = { H: "High", L: "Low", N: "None" } as const;
const V2_IMPACT = { N: "None", P: "Partial", C: "Complete" } as const;
const V2_REQUIREMENT = { L: "Low", M: "Medium", H: "High", ND: NOT_DEFINED } as const;
const V3_REQUIREMENT = { X: NOT_DEFINED, L: "Low", M: "Medium", H: "High" } as const;
const V3_MODIFIED_LEVEL = { X: NOT_DEFINED, N: "None", L: "Low", H: "High" } as const;
const V3_ATTACK_VECTOR = { N: "Network", A: "Adjacent", L: "Local", P: "Physical" } as const;
const V4_REQUIREMENT = { X: NOT_DEFINED, H: "High", M: "Medium", L: "Low" } as const;
const V4_MODIFIED_IMPACT = { X: NOT_DEFINED, H: "High", L: "Low", N: "None" } as const;

function def(
  key: string,
  name: string,
  section: string,
  values: Readonly<Record<string, string>>,
): MetricDef {
  return { key, name, section, values };
}

const V2: readonly MetricDef[] = [
  def("AV", "Access Vector", "Exploitability", { L: "Local", A: "Adjacent network", N: "Network" }),
  def("AC", "Access Complexity", "Exploitability", { H: "High", M: "Medium", L: "Low" }),
  def("Au", "Authentication", "Exploitability", { M: "Multiple", S: "Single", N: "None" }),
  def("C", "Confidentiality Impact", "Impact", V2_IMPACT),
  def("I", "Integrity Impact", "Impact", V2_IMPACT),
  def("A", "Availability Impact", "Impact", V2_IMPACT),
  def("E", "Exploitability", "Temporal", {
    U: "Unproven",
    POC: "Proof of concept",
    F: "Functional",
    H: "High",
    ND: NOT_DEFINED,
  }),
  def("RL", "Remediation Level", "Temporal", {
    OF: "Official fix",
    TF: "Temporary fix",
    W: "Workaround",
    U: "Unavailable",
    ND: NOT_DEFINED,
  }),
  def("RC", "Report Confidence", "Temporal", {
    UC: "Unconfirmed",
    UR: "Uncorroborated",
    C: "Confirmed",
    ND: NOT_DEFINED,
  }),
  def("CDP", "Collateral Damage Potential", "Environmental", {
    N: "None",
    L: "Low",
    LM: "Low to medium",
    MH: "Medium to high",
    H: "High",
    ND: NOT_DEFINED,
  }),
  def("TD", "Target Distribution", "Environmental", {
    N: "None",
    L: "Low",
    M: "Medium",
    H: "High",
    ND: NOT_DEFINED,
  }),
  def("CR", "Confidentiality Requirement", "Environmental", V2_REQUIREMENT),
  def("IR", "Integrity Requirement", "Environmental", V2_REQUIREMENT),
  def("AR", "Availability Requirement", "Environmental", V2_REQUIREMENT),
];

const V3: readonly MetricDef[] = [
  def("AV", "Attack Vector", "Exploitability", V3_ATTACK_VECTOR),
  def("AC", "Attack Complexity", "Exploitability", { L: "Low", H: "High" }),
  def("PR", "Privileges Required", "Exploitability", { N: "None", L: "Low", H: "High" }),
  def("UI", "User Interaction", "Exploitability", { N: "None", R: "Required" }),
  def("S", "Scope", "Scope", { U: "Unchanged", C: "Changed" }),
  def("C", "Confidentiality", "Impact", CIA_LEVEL),
  def("I", "Integrity", "Impact", CIA_LEVEL),
  def("A", "Availability", "Impact", CIA_LEVEL),
  def("E", "Exploit Code Maturity", "Temporal", {
    X: NOT_DEFINED,
    U: "Unproven",
    P: "Proof of concept",
    F: "Functional",
    H: "High",
  }),
  def("RL", "Remediation Level", "Temporal", {
    X: NOT_DEFINED,
    O: "Official fix",
    T: "Temporary fix",
    W: "Workaround",
    U: "Unavailable",
  }),
  def("RC", "Report Confidence", "Temporal", {
    X: NOT_DEFINED,
    U: "Unknown",
    R: "Reasonable",
    C: "Confirmed",
  }),
  def("CR", "Confidentiality Requirement", "Environmental", V3_REQUIREMENT),
  def("IR", "Integrity Requirement", "Environmental", V3_REQUIREMENT),
  def("AR", "Availability Requirement", "Environmental", V3_REQUIREMENT),
  def("MAV", "Modified Attack Vector", "Environmental", { X: NOT_DEFINED, ...V3_ATTACK_VECTOR }),
  def("MAC", "Modified Attack Complexity", "Environmental", {
    X: NOT_DEFINED,
    L: "Low",
    H: "High",
  }),
  def("MPR", "Modified Privileges Required", "Environmental", V3_MODIFIED_LEVEL),
  def("MUI", "Modified User Interaction", "Environmental", {
    X: NOT_DEFINED,
    N: "None",
    R: "Required",
  }),
  def("MS", "Modified Scope", "Environmental", { X: NOT_DEFINED, U: "Unchanged", C: "Changed" }),
  def("MC", "Modified Confidentiality", "Environmental", V3_MODIFIED_LEVEL),
  def("MI", "Modified Integrity", "Environmental", V3_MODIFIED_LEVEL),
  def("MA", "Modified Availability", "Environmental", V3_MODIFIED_LEVEL),
];

const V4_VULNERABLE = "Vulnerable system impact";
const V4_SUBSEQUENT = "Subsequent system impact";

const V4: readonly MetricDef[] = [
  def("AV", "Attack Vector", "Exploitability", V3_ATTACK_VECTOR),
  def("AC", "Attack Complexity", "Exploitability", { L: "Low", H: "High" }),
  def("AT", "Attack Requirements", "Exploitability", { N: "None", P: "Present" }),
  def("PR", "Privileges Required", "Exploitability", { N: "None", L: "Low", H: "High" }),
  def("UI", "User Interaction", "Exploitability", { N: "None", P: "Passive", A: "Active" }),
  def("VC", "Confidentiality", V4_VULNERABLE, CIA_LEVEL),
  def("VI", "Integrity", V4_VULNERABLE, CIA_LEVEL),
  def("VA", "Availability", V4_VULNERABLE, CIA_LEVEL),
  def("SC", "Confidentiality", V4_SUBSEQUENT, CIA_LEVEL),
  def("SI", "Integrity", V4_SUBSEQUENT, CIA_LEVEL),
  def("SA", "Availability", V4_SUBSEQUENT, CIA_LEVEL),
  def("E", "Exploit Maturity", "Threat", {
    X: NOT_DEFINED,
    A: "Attacked",
    P: "Proof of concept",
    U: "Unreported",
  }),
  def("CR", "Confidentiality Requirement", "Environmental", V4_REQUIREMENT),
  def("IR", "Integrity Requirement", "Environmental", V4_REQUIREMENT),
  def("AR", "Availability Requirement", "Environmental", V4_REQUIREMENT),
  def("MAV", "Modified Attack Vector", "Environmental", { X: NOT_DEFINED, ...V3_ATTACK_VECTOR }),
  def("MAC", "Modified Attack Complexity", "Environmental", {
    X: NOT_DEFINED,
    L: "Low",
    H: "High",
  }),
  def("MAT", "Modified Attack Requirements", "Environmental", {
    X: NOT_DEFINED,
    N: "None",
    P: "Present",
  }),
  def("MPR", "Modified Privileges Required", "Environmental", V3_MODIFIED_LEVEL),
  def("MUI", "Modified User Interaction", "Environmental", {
    X: NOT_DEFINED,
    N: "None",
    P: "Passive",
    A: "Active",
  }),
  def("MVC", "Modified Vulnerable System Confidentiality", "Environmental", V4_MODIFIED_IMPACT),
  def("MVI", "Modified Vulnerable System Integrity", "Environmental", V4_MODIFIED_IMPACT),
  def("MVA", "Modified Vulnerable System Availability", "Environmental", V4_MODIFIED_IMPACT),
  def("MSC", "Modified Subsequent System Confidentiality", "Environmental", V4_MODIFIED_IMPACT),
  def("MSI", "Modified Subsequent System Integrity", "Environmental", {
    ...V4_MODIFIED_IMPACT,
    S: "Safety",
  }),
  def("MSA", "Modified Subsequent System Availability", "Environmental", {
    ...V4_MODIFIED_IMPACT,
    S: "Safety",
  }),
  def("S", "Safety", "Supplemental", { X: NOT_DEFINED, N: "Negligible", P: "Present" }),
  def("AU", "Automatable", "Supplemental", { X: NOT_DEFINED, N: "No", Y: "Yes" }),
  def("R", "Recovery", "Supplemental", {
    X: NOT_DEFINED,
    A: "Automatic",
    U: "User",
    I: "Irrecoverable",
  }),
  def("V", "Value Density", "Supplemental", { X: NOT_DEFINED, D: "Diffuse", C: "Concentrated" }),
  def("RE", "Vulnerability Response Effort", "Supplemental", {
    X: NOT_DEFINED,
    L: "Low",
    M: "Moderate",
    H: "High",
  }),
  def("U", "Provider Urgency", "Supplemental", {
    X: NOT_DEFINED,
    Clear: "Clear",
    Green: "Green",
    Amber: "Amber",
    Red: "Red",
  }),
];

/** The label tables, one per CVSS version, in the order the specification lists the metrics. */
export const CVSS_METRIC_TABLES: Readonly<Record<CvssVersion, readonly MetricDef[]>> = {
  "2.0": V2,
  "3.0": V3,
  "3.1": V3,
  "4.0": V4,
};

/** The order the sections appear in, whatever order the vector spells its metrics. */
const SECTION_ORDER: Readonly<Record<CvssVersion, readonly string[]>> = {
  "2.0": ["Exploitability", "Impact", "Temporal", "Environmental"],
  "3.0": ["Exploitability", "Scope", "Impact", "Temporal", "Environmental"],
  "3.1": ["Exploitability", "Scope", "Impact", "Temporal", "Environmental"],
  "4.0": [
    "Exploitability",
    V4_VULNERABLE,
    V4_SUBSEQUENT,
    "Threat",
    "Environmental",
    "Supplemental",
  ],
};

/** Where a metric the table does not know goes: under the group the server put it in. */
const SERVER_GROUP_SECTION: Readonly<Record<CvssMetric["group"], string>> = {
  base: "Other base metrics",
  temporal: "Temporal",
  threat: "Threat",
  environmental: "Environmental",
  supplemental: "Supplemental",
};

export interface DescribedMetric {
  readonly key: string;
  readonly name: string;
  readonly value: string;
  /** False when the key or the value is not in the table; the raw code is shown instead. */
  readonly known: boolean;
}

export interface MetricGroup {
  readonly title: string;
  readonly rows: readonly DescribedMetric[];
}

function lookup(version: CvssVersion, key: string): MetricDef | undefined {
  return CVSS_METRIC_TABLES[version]?.find((metric) => metric.key === key);
}

/**
 * The plain name and value words for one metric. A key or value the table does not know is shown as
 * the vector spelled it, so a new specification revision degrades to codes instead of failing.
 */
export function describeMetric(version: CvssVersion, key: string, value: string): DescribedMetric {
  const metric = lookup(version, key);
  if (!metric) return { key, name: key, value, known: false };
  const word = Object.hasOwn(metric.values, value) ? metric.values[value] : undefined;
  return { key, name: metric.name, value: word ?? value, known: word !== undefined };
}

/** Splits a vector's metrics into the sections a reader scans: exploitability, scope, impact and so on. */
export function groupMetrics(
  version: CvssVersion,
  metrics: readonly CvssMetric[],
): MetricGroup[] {
  const sections = new Map<string, DescribedMetric[]>();
  for (const metric of metrics) {
    const section = lookup(version, metric.key)?.section
      ?? SERVER_GROUP_SECTION[metric.group]
      ?? "Other";
    const rows = sections.get(section) ?? [];
    rows.push(describeMetric(version, metric.key, metric.value));
    sections.set(section, rows);
  }
  const order = SECTION_ORDER[version] ?? [];
  const rank = (title: string) => {
    const index = order.indexOf(title);
    return index === -1 ? order.length : index;
  };
  return [...sections.entries()]
    .sort(([a], [b]) => rank(a) - rank(b))
    .map(([title, rows]) => ({ title, rows }));
}

/**
 * A plain sentence when the score a source printed cannot be trusted as the vector's score, or null
 * when the two agree. `reporter` names who printed it ("The scanner", "NVD").
 */
export function scoreMismatch(
  cvss: Pick<CveCvss, "valid" | "base_score" | "reported_score">,
  reporter = "The source",
): string | null {
  const { valid, base_score: computed, reported_score: reported } = cvss;
  if (!valid || computed === null) {
    return reported === null
      ? "This vector could not be read, so it has no score and its metrics are not listed."
      : `This vector could not be read, so its metrics are not listed. ${reporter} reported ${
        reported.toFixed(1)
      }.`;
  }
  if (reported === null || reported === computed) return null;
  return `${reporter} reported ${reported.toFixed(1)}; the vector computes to ${
    computed.toFixed(1)
  }.`;
}
