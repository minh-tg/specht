import { describe, expect, it } from "vitest";
import {
  confidenceLabel,
  eventTypeLabel,
  locationLineRange,
  locationSubjectLabel,
  parseSourceLink,
  toExpiryTimestamp,
} from "./format";

describe("parseSourceLink", () => {
  it("parses http and https links", () => {
    expect(parseSourceLink("https://github.com/acme/repo/blob/abc/main.go")?.hostname).toBe(
      "github.com",
    );
    expect(parseSourceLink("http://example.com/path")?.protocol).toBe("http:");
  });

  it("rejects non-http(s) schemes", () => {
    expect(parseSourceLink("javascript:alert(1)")).toBeNull();
    expect(parseSourceLink("data:text/html,<script>alert(1)</script>")).toBeNull();
    expect(parseSourceLink("file:///etc/passwd")).toBeNull();
    expect(parseSourceLink("ftp://example.com/file")).toBeNull();
    expect(parseSourceLink("mailto:security@example.com")).toBeNull();
  });

  it("returns null for missing or unparsable input", () => {
    expect(parseSourceLink(undefined)).toBeNull();
    expect(parseSourceLink("")).toBeNull();
    expect(parseSourceLink("not a url")).toBeNull();
  });
});

describe("toExpiryTimestamp", () => {
  it("anchors a bare date to the end of that day in UTC", () => {
    expect(toExpiryTimestamp("2026-10-01")).toBe("2026-10-01T23:59:59.999Z");
  });

  it("normalizes a full timestamp to ISO", () => {
    expect(toExpiryTimestamp("2026-10-01T12:30:00Z")).toBe("2026-10-01T12:30:00.000Z");
  });

  it("returns undefined for empty or invalid input", () => {
    expect(toExpiryTimestamp("")).toBeUndefined();
    expect(toExpiryTimestamp("13/13/2026")).toBeUndefined();
  });
});

describe("locationLineRange", () => {
  it("renders a single start line", () => {
    expect(locationLineRange({ file: "main.go", start_line: 10 })).toBe(":10");
  });

  it("renders an inclusive range when the end line differs", () => {
    expect(locationLineRange({ file: "main.go", start_line: 10, end_line: 12 })).toBe(":10–12");
  });

  it("collapses a range whose end equals its start", () => {
    expect(locationLineRange({ file: "main.go", start_line: 10, end_line: 10 })).toBe(":10");
  });

  it("is empty without a file or a start line", () => {
    expect(locationLineRange({})).toBe("");
    expect(locationLineRange({ start_line: 10 })).toBe("");
    expect(locationLineRange({ file: "main.go" })).toBe("");
  });
});

describe("locationSubjectLabel", () => {
  it("maps each finding kind to its subject", () => {
    expect(locationSubjectLabel("sca")).toBe("Package");
    expect(locationSubjectLabel("sast")).toBe("File");
    expect(locationSubjectLabel("iac")).toBe("Resource");
    expect(locationSubjectLabel("secret")).toBe("File");
    expect(locationSubjectLabel("dast")).toBe("URL");
  });

  it("falls back to a generic subject", () => {
    expect(locationSubjectLabel(undefined)).toBe("Subject");
    expect(locationSubjectLabel("unknown-kind")).toBe("Subject");
  });
});

describe("confidenceLabel", () => {
  it("humanizes the known confidence values", () => {
    expect(confidenceLabel("high")).toBe("High");
    expect(confidenceLabel("medium")).toBe("Medium");
    expect(confidenceLabel("low")).toBe("Low");
  });

  it("renders unknown for missing or unrecognised values", () => {
    expect(confidenceLabel(undefined)).toBe("Unknown");
    expect(confidenceLabel("")).toBe("Unknown");
    expect(confidenceLabel("certain")).toBe("Unknown");
  });
});

describe("eventTypeLabel", () => {
  it("title-cases each underscore-separated part", () => {
    expect(eventTypeLabel("created")).toBe("Created");
    expect(eventTypeLabel("state_changed")).toBe("State Changed");
    expect(eventTypeLabel("analysis_state_updated")).toBe("Analysis State Updated");
  });

  it("renders unknown for missing input", () => {
    expect(eventTypeLabel(undefined)).toBe("Unknown");
    expect(eventTypeLabel("")).toBe("Unknown");
  });
});
