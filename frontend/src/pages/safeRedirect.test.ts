import { describe, expect, it } from "vitest";
import { safeRedirect } from "./safeRedirect";

describe("safeRedirect", () => {
  it.each([
    "/dashboard",
    "/reports/42?tab=details",
    "/p/slug/changes/abc123?scope=main#top",
    "/invite/token-1",
  ])("keeps the internal path %j", (path) => {
    expect(safeRedirect(path)).toBe(path);
  });

  it.each([null, "", "dashboard", "//evil.example.com", "https://evil.example.com"])(
    "falls back to / for %j",
    (value) => {
      expect(safeRedirect(value)).toBe("/");
    },
  );

  it.each([
    ["tab", "/\t/evil.example.com"],
    ["line feed", "/\n/evil.example.com"],
    ["carriage return", "/\r/evil.example.com"],
    ["NUL", "/\u0000/evil.example.com"],
    ["unit separator", "/\u001f/evil.example.com"],
    ["DEL", "/\u007f/evil.example.com"],
    ["control character after the path start", "/ok\t"],
    ["backslash second", "/\\evil.example.com"],
    ["backslash later", "/ok\\evil.example.com"],
  ])("rejects a redirect with a %s", (_name, value) => {
    expect(safeRedirect(value)).toBe("/");
  });
});
