import type { Report } from "@/types/api";

/** Whether a report scanned this commit: its SHA starts with `commit`, ignoring case. */
export function scannedCommit(report: Pick<Report, "commit_sha">, commit: string): boolean {
  return !!commit && !!report.commit_sha?.toLowerCase().startsWith(commit.toLowerCase());
}
