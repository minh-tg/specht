import type { FindingLocation } from "@/types/api";

/** The exact place a finding was seen, in the shortest form the observation gives. */
export function locationText(location: FindingLocation | undefined): string {
  if (!location) return "–";
  if (location.summary) return location.summary;
  if (location.file) {
    return location.start_line ? `${location.file}:${location.start_line}` : location.file;
  }
  return location.resource ?? "–";
}
