import { analysisStateLabel, technicalStateLabel } from "@/lib/enums";
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

/**
 * A before or after value in the history, in words. Triage and lifecycle events carry states from
 * the shared vocabularies, so they get the same labels as the rest of the page; the wire value is
 * never echoed for those. Events of any other kind keep their value as sent.
 */
export function eventValueLabel(eventType: string | undefined, value: string): string {
  switch (eventType) {
    case "analysis_changed":
    case "bulk_triage_applied":
      return analysisStateLabel(value) ?? value;
    case "state_changed":
    case "regression":
    case "verified_fixed":
      return technicalStateLabel(value) ?? value;
    default:
      return value;
  }
}

/**
 * Normalizes a date-input value to a server-accepted RFC3339 expiry. A bare date means the end of
 * that day on the user's own clock, the same local day the expiry is later shown and edited as.
 */
export function toExpiryTimestamp(value: string): string | undefined {
  if (!value) return undefined;
  const day = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  const date = day
    ? new Date(Number(day[1]), Number(day[2]) - 1, Number(day[3]), 23, 59, 59, 999)
    : new Date(value);
  if (Number.isNaN(date.getTime())) return undefined;
  if (day && date.getDate() !== Number(day[3])) return undefined;
  return date.toISOString();
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
