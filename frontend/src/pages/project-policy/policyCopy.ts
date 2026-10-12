import type { PolicyEffective } from "@/types/api";

export type PolicyKey = "severity_floor" | "watcher_gate";
export type PolicySource = PolicyEffective["severity_source"];

export interface PolicyOption {
  readonly value: string;
  readonly label: string;
}

export const SEVERITY_FLOOR_OPTIONS: readonly PolicyOption[] = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

export const WATCHER_GATE_OPTIONS: readonly PolicyOption[] = [
  { value: "require_triage", label: "Needs triage" },
  { value: "immediate", label: "Immediately" },
  { value: "off", label: "Never" },
];

export const SOURCE_LABEL: Record<PolicySource, string> = {
  default: "Default",
  template: "Template",
  override: "Override",
};

const WATCHER_GATE_HELP: Record<string, string> = {
  require_triage: "New CVEs found by the watcher stay out of the gate until someone has looked.",
  immediate: "New CVEs found by the watcher block a change as soon as they are found.",
  off: "New CVEs found by the watcher never block a change.",
};

export function optionLabel(options: readonly PolicyOption[], value: string): string {
  return options.find((o) => o.value === value)?.label ?? value;
}

export function watcherGateHelp(value: string): string {
  return WATCHER_GATE_HELP[value] ?? "";
}

/**
 * The project's own overrides, rebuilt from the effective policy. The server replaces the whole
 * set on every write, and a key whose source is "override" carries the override's value, so the
 * map can be recovered without a second endpoint.
 */
export function overridesOf(policy: PolicyEffective): Record<string, string> {
  const out: Record<string, string> = {};
  if (policy.severity_source === "override") out["severity_floor"] = policy.severity_floor;
  if (policy.watcher_source === "override") out["watcher_gate"] = policy.watcher_gate;
  return out;
}
