import { describe, expect, it } from "vitest";
import {
  CVSS_METRIC_TABLES,
  type CvssVersion,
  describeMetric,
  groupMetrics,
  scoreMismatch,
} from "./cvssMetrics";

const NOT_DEFINED_V3 = "X";

/** Every metric key and value each specification's vector grammar allows, written out independently of the label tables. */
const GRAMMAR: Record<CvssVersion, Record<string, readonly string[]>> = {
  "2.0": {
    AV: ["L", "A", "N"],
    AC: ["H", "M", "L"],
    Au: ["M", "S", "N"],
    C: ["N", "P", "C"],
    I: ["N", "P", "C"],
    A: ["N", "P", "C"],
    E: ["U", "POC", "F", "H", "ND"],
    RL: ["OF", "TF", "W", "U", "ND"],
    RC: ["UC", "UR", "C", "ND"],
    CDP: ["N", "L", "LM", "MH", "H", "ND"],
    TD: ["N", "L", "M", "H", "ND"],
    CR: ["L", "M", "H", "ND"],
    IR: ["L", "M", "H", "ND"],
    AR: ["L", "M", "H", "ND"],
  },
  "3.0": v3Grammar(),
  "3.1": v3Grammar(),
  "4.0": {
    AV: ["N", "A", "L", "P"],
    AC: ["L", "H"],
    AT: ["N", "P"],
    PR: ["N", "L", "H"],
    UI: ["N", "P", "A"],
    VC: ["H", "L", "N"],
    VI: ["H", "L", "N"],
    VA: ["H", "L", "N"],
    SC: ["H", "L", "N"],
    SI: ["H", "L", "N"],
    SA: ["H", "L", "N"],
    E: ["X", "A", "P", "U"],
    CR: ["X", "H", "M", "L"],
    IR: ["X", "H", "M", "L"],
    AR: ["X", "H", "M", "L"],
    MAV: ["X", "N", "A", "L", "P"],
    MAC: ["X", "L", "H"],
    MAT: ["X", "N", "P"],
    MPR: ["X", "N", "L", "H"],
    MUI: ["X", "N", "P", "A"],
    MVC: ["X", "H", "L", "N"],
    MVI: ["X", "H", "L", "N"],
    MVA: ["X", "H", "L", "N"],
    MSC: ["X", "H", "L", "N"],
    MSI: ["X", "S", "H", "L", "N"],
    MSA: ["X", "S", "H", "L", "N"],
    S: ["X", "N", "P"],
    AU: ["X", "N", "Y"],
    R: ["X", "A", "U", "I"],
    V: ["X", "D", "C"],
    RE: ["X", "L", "M", "H"],
    U: ["X", "Clear", "Green", "Amber", "Red"],
  },
};

function v3Grammar(): Record<string, readonly string[]> {
  const cia = ["H", "L", "N"];
  const req = [NOT_DEFINED_V3, "L", "M", "H"];
  return {
    AV: ["N", "A", "L", "P"],
    AC: ["L", "H"],
    PR: ["N", "L", "H"],
    UI: ["N", "R"],
    S: ["U", "C"],
    C: cia,
    I: cia,
    A: cia,
    E: ["X", "U", "P", "F", "H"],
    RL: ["X", "O", "T", "W", "U"],
    RC: ["X", "U", "R", "C"],
    CR: req,
    IR: req,
    AR: req,
    MAV: ["X", "N", "A", "L", "P"],
    MAC: ["X", "L", "H"],
    MPR: ["X", "N", "L", "H"],
    MUI: ["X", "N", "R"],
    MS: ["X", "U", "C"],
    MC: ["X", "N", "L", "H"],
    MI: ["X", "N", "L", "H"],
    MA: ["X", "N", "L", "H"],
  };
}

const VERSIONS = Object.keys(GRAMMAR) as CvssVersion[];

describe("CVSS metric label tables", () => {
  it.each(VERSIONS)("v%s labels every metric key and value the grammar allows", (version) => {
    for (const [key, values] of Object.entries(GRAMMAR[version])) {
      for (const value of values) {
        const described = describeMetric(version, key, value);
        expect(described.known, `${version} ${key}:${value}`).toBe(true);
        expect(described.name).not.toBe(key);
        // The v4.0 provider urgency values are already words; every other value is a code.
        if (!["Clear", "Green", "Amber", "Red"].includes(value)) {
          expect(described.value).not.toBe(value);
        }
      }
    }
  });

  it.each(VERSIONS)("v%s has no label for a key or value the grammar does not allow", (version) => {
    const table = CVSS_METRIC_TABLES[version];
    for (const def of table) {
      expect(Object.keys(GRAMMAR[version]), `${version} table key ${def.key}`).toContain(def.key);
      expect(Object.keys(def.values).sort(), `${version} ${def.key} values`).toEqual(
        [...GRAMMAR[version][def.key]].sort(),
      );
    }
    expect(table.map((def) => def.key).sort()).toEqual(Object.keys(GRAMMAR[version]).sort());
  });

  it("names the v3 base metrics in plain words", () => {
    expect(describeMetric("3.1", "AV", "N")).toMatchObject({
      name: "Attack Vector",
      value: "Network",
    });
    expect(describeMetric("3.1", "PR", "L")).toMatchObject({
      name: "Privileges Required",
      value: "Low",
    });
    expect(describeMetric("3.0", "S", "C")).toMatchObject({ name: "Scope", value: "Changed" });
  });

  it("uses the specification names for v4.0", () => {
    expect(describeMetric("4.0", "AT", "P")).toMatchObject({
      name: "Attack Requirements",
      value: "Present",
    });
    expect(describeMetric("4.0", "V", "D").name).toBe("Value Density");
    expect(describeMetric("4.0", "R", "I").value).toBe("Irrecoverable");
    expect(describeMetric("4.0", "S", "P").name).toBe("Safety");
  });

  it("names the v2 metrics, which spell authentication 'Au'", () => {
    expect(describeMetric("2.0", "Au", "N")).toMatchObject({
      name: "Authentication",
      value: "None",
    });
    expect(describeMetric("2.0", "C", "P")).toMatchObject({
      name: "Confidentiality Impact",
      value: "Partial",
    });
  });

  it("shows an unknown key or value as the raw code and does not throw", () => {
    expect(describeMetric("3.1", "ZZ", "Q")).toMatchObject({
      name: "ZZ",
      value: "Q",
      known: false,
    });
    expect(describeMetric("3.1", "AV", "Q")).toMatchObject({
      name: "Attack Vector",
      value: "Q",
      known: false,
    });
  });
});

describe("groupMetrics", () => {
  it("splits a v3.1 vector into exploitability, scope and impact in specification order", () => {
    const groups = groupMetrics("3.1", [
      { group: "base", key: "AV", value: "N" },
      { group: "base", key: "AC", value: "L" },
      { group: "base", key: "PR", value: "N" },
      { group: "base", key: "UI", value: "N" },
      { group: "base", key: "S", value: "C" },
      { group: "base", key: "C", value: "H" },
      { group: "base", key: "I", value: "H" },
      { group: "base", key: "A", value: "H" },
    ]);
    expect(groups.map((g) => g.title)).toEqual(["Exploitability", "Scope", "Impact"]);
    expect(groups[0].rows.map((r) => `${r.name}: ${r.value}`)).toEqual([
      "Attack Vector: Network",
      "Attack Complexity: Low",
      "Privileges Required: None",
      "User Interaction: None",
    ]);
    expect(groups[2].rows.map((r) => r.name)).toEqual([
      "Confidentiality",
      "Integrity",
      "Availability",
    ]);
  });

  it("lists the four v4.0 groups when the vector carries them", () => {
    const groups = groupMetrics("4.0", [
      { group: "base", key: "AV", value: "N" },
      { group: "base", key: "VC", value: "H" },
      { group: "base", key: "SC", value: "N" },
      { group: "threat", key: "E", value: "A" },
      { group: "environmental", key: "CR", value: "H" },
      { group: "supplemental", key: "AU", value: "Y" },
    ]);
    expect(groups.map((g) => g.title)).toEqual([
      "Exploitability",
      "Vulnerable system impact",
      "Subsequent system impact",
      "Threat",
      "Environmental",
      "Supplemental",
    ]);
  });

  it("keeps a metric the table does not know, under the group the server named", () => {
    const groups = groupMetrics("3.1", [
      { group: "base", key: "AV", value: "N" },
      { group: "temporal", key: "ZZ", value: "Q" },
    ]);
    const temporal = groups.find((g) => g.title === "Temporal");
    expect(temporal?.rows).toEqual([
      { key: "ZZ", name: "ZZ", value: "Q", known: false },
    ]);
  });

  it("returns no groups for no metrics", () => {
    expect(groupMetrics("3.1", [])).toEqual([]);
  });
});

describe("scoreMismatch", () => {
  it("is quiet when the scores agree", () => {
    expect(scoreMismatch({ valid: true, base_score: 9.8, reported_score: 9.8 })).toBeNull();
    expect(scoreMismatch({ valid: true, base_score: 9.8, reported_score: null })).toBeNull();
  });

  it("says the scanner reported a different score than the vector computes", () => {
    expect(scoreMismatch({ valid: true, base_score: 10, reported_score: 9.8 }, "The scanner")).toBe(
      "The scanner reported 9.8; the vector computes to 10.0.",
    );
  });

  it("says plainly that an unparseable vector cannot be scored", () => {
    expect(scoreMismatch({ valid: false, base_score: null, reported_score: 7.5 }, "NVD")).toBe(
      "This vector could not be read, so its metrics are not listed. NVD reported 7.5.",
    );
    expect(scoreMismatch({ valid: false, base_score: null, reported_score: null })).toBe(
      "This vector could not be read, so it has no score and its metrics are not listed.",
    );
  });
});
