import { EMPTY_VALUE } from "@/lib/format";
import type { FindingLocation } from "@/types/api";

/** The exact place a finding was seen, in the shortest form the observation gives. */
export function locationText(location: FindingLocation | undefined): string {
  if (!location) return EMPTY_VALUE;
  if (location.summary) return location.summary;
  if (location.file) {
    return location.start_line ? `${location.file}:${location.start_line}` : location.file;
  }
  return location.resource ?? EMPTY_VALUE;
}

/**
 * A location for a narrow column. A long path keeps its end, because the file name is what someone
 * looks for, and the tooltip holds the whole thing.
 */
export function shortLocation(location: FindingLocation | undefined): string {
  const text = locationText(location);
  // "golang.org/x/crypto v0.57.0 in go.mod" is a package, not a path.
  if (text.includes(" ")) return text;
  const parts = text.split("/");
  return parts.length > 3 ? `…/${parts.slice(-2).join("/")}` : text;
}
