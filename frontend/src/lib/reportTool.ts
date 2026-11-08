import type { Report } from "@/types/api";

/**
 * The name to show for the tool behind a report. A generic SARIF upload is parsed by the "sarif"
 * scanner, so it shows the tool the file names instead, such as "Gosec (SARIF)".
 */
export function reportToolLabel(report: Pick<Report, "tool_name" | "producer">): string {
  const producer = report.producer?.trim();
  if (report.tool_name === "sarif" && producer) return `${producer} (SARIF)`;
  return report.tool_name;
}
