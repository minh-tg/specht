import type { FindingLocation } from "@/types/api";
import { SOURCE_LINK_SCHEMES } from "./options";

/** Parses a source link only when its scheme is http/https; otherwise null. */
export function parseSourceLink(value: string | undefined): URL | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return SOURCE_LINK_SCHEMES.has(url.protocol) ? url : null;
  } catch {
    return null;
  }
}

/** Subject label per finding kind for the location section. */
export function locationSubjectLabel(kind: string | undefined): string {
  switch (kind) {
    case "sca":
      return "Package";
    case "sast":
      return "File";
    case "iac":
      return "Resource";
    case "secret":
      return "File";
    case "dast":
      return "URL";
    default:
      return "Subject";
  }
}

/** Humanizes a confidence value; an unrecognised or missing value renders as
 * "Unknown" instead of echoing the wire value. */
export function confidenceLabel(value: string | undefined): string {
  switch (value) {
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
    default:
      return "Unknown";
  }
}

/** Humanizes a lifecycle event type for the history list. */
export function eventTypeLabel(value: string | undefined): string {
  if (!value) return "Unknown";
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

/** Normalizes a date-input value to a server-accepted RFC3339 expiry. */
export function toExpiryTimestamp(value: string): string | undefined {
  if (!value) return undefined;
  const iso = /^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value}T23:59:59.999Z` : value;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

/** ":start" or ":start–end" when lines are known; empty otherwise. */
export function locationLineRange(location: FindingLocation): string {
  if (!location.file || !location.start_line) return "";
  let range = `:${location.start_line}`;
  if (location.end_line && location.end_line !== location.start_line) {
    range += `–${location.end_line}`;
  }
  return range;
}
