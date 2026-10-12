import type { PolicyEffective } from "@/types/api";
import { describe, expect, it } from "vitest";
import { optionLabel, overridesOf, SEVERITY_FLOOR_OPTIONS, watcherGateHelp } from "./policyCopy";

const base: PolicyEffective = {
  template_name: null,
  template_version: 0,
  severity_floor: "high",
  severity_source: "default",
  watcher_gate: "require_triage",
  watcher_source: "default",
};

describe("overridesOf", () => {
  it("is empty when nothing is overridden", () => {
    expect(overridesOf(base)).toEqual({});
  });

  it("ignores values that come from a template", () => {
    expect(overridesOf({ ...base, severity_floor: "critical", severity_source: "template" }))
      .toEqual({});
  });

  it("recovers each overridden key with its value", () => {
    expect(
      overridesOf({
        ...base,
        severity_floor: "low",
        severity_source: "override",
        watcher_gate: "off",
        watcher_source: "override",
      }),
    ).toEqual({ severity_floor: "low", watcher_gate: "off" });
  });
});

describe("labels", () => {
  it("names a known option and falls back to the raw value", () => {
    expect(optionLabel(SEVERITY_FLOOR_OPTIONS, "medium")).toBe("Medium");
    expect(optionLabel(SEVERITY_FLOOR_OPTIONS, "weird")).toBe("weird");
  });

  it("explains each watcher mode and stays quiet for an unknown one", () => {
    expect(watcherGateHelp("immediate")).toMatch(/as soon as they are found/);
    expect(watcherGateHelp("require_triage")).toMatch(/until someone has looked/);
    expect(watcherGateHelp("off")).toMatch(/never block/);
    expect(watcherGateHelp("nope")).toBe("");
  });
});
