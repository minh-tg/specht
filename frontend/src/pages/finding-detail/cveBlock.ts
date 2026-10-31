import type { Finding } from "@/types/api";

/**
 * Finding kinds whose findings can carry a CVE: a dependency (sca), an image's packages
 * (image_config) and a feed match (cve_watcher). These are codes of the `finding_kinds` table
 * (migrations 3, 17 and 26). The CVE endpoint answers by the finding's vulnerability id and not
 * by kind, so a finding of another kind that the intel feeds matched still shows the block.
 */
const CVE_KINDS: readonly string[] = ["sca", "image_config", "cve_watcher"];

/** Whether the finding page should show the CVE block, and ask the server for its details. */
export function showsCveBlock(finding: Pick<Finding, "finding_kind" | "intel">): boolean {
  return CVE_KINDS.includes(finding.finding_kind) || !!finding.intel;
}
