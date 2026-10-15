import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = import.meta.dirname;
const read = (path: string) => readFileSync(join(SRC, path), "utf8");

const polish = read("styles/polish.css");

/** The text of the first rule block whose selector contains `selector`, inside `scope`. */
function block(scope: string, selector: string): string {
  const start = scope.indexOf(selector);
  expect(start, `no rule for ${selector}`).toBeGreaterThanOrEqual(0);
  return scope.slice(scope.indexOf("{", start) + 1, scope.indexOf("}", start));
}

const coarse = polish.slice(polish.indexOf("@media (pointer: coarse)"));
const base = polish.slice(
  polish.indexOf("@layer base"),
  polish.indexOf("@media (pointer: coarse)"),
);

describe("polish.css", () => {
  it("is imported once from index.css", () => {
    const matches = read("index.css").match(/@import "\.\/styles\/polish\.css";/g);
    expect(matches).toHaveLength(1);
  });

  it("defines the 44px touch target as a token", () => {
    expect(block(polish, ":root")).toContain("--hit-coarse: 44px;");
  });

  it("raises hit areas only under a coarse pointer", () => {
    expect(polish.match(/--hit-coarse/g)!.length).toBeGreaterThan(2);
    const outside = polish.slice(0, polish.indexOf("@media (pointer: coarse)"));
    expect(outside.replace(/--hit-coarse: 44px;/, "")).not.toContain("var(--hit-coarse)");
  });

  it.each([
    "button",
    "[role=\"tab\"]",
    "[role^=\"menuitem\"]",
    "a[class~=\"group/button\"]",
  ])("gives %s the coarse minimum height", (selector) => {
    const rule = coarse.slice(0, coarse.indexOf("button:has("));
    expect(rule).toContain(selector);
    expect(block(coarse, "button,")).toContain("min-height: var(--hit-coarse);");
  });

  it("targets roles and elements, never component class names from other slices", () => {
    expect(polish).not.toMatch(/navLink|\.nav|header\s*\{|AccountMenu|ThemeToggle/);
  });

  it("extends the tap area of a switch without resizing it", () => {
    const after = block(coarse, "[role=\"switch\"]::after");
    expect(after).toContain("min-width: var(--hit-coarse);");
    expect(after).toContain("min-height: var(--hit-coarse);");
  });

  it("balances headings and prettifies paragraphs once, in the base layer", () => {
    expect(block(base, "h1,")).toContain("text-wrap: balance;");
    expect(block(base, "p,")).toContain("text-wrap: pretty;");
  });

  it("sets touch-action, a clear tap highlight and contained overscroll", () => {
    expect(block(base, "a,")).toContain("touch-action: manipulation;");
    expect(block(base, "html")).toContain("-webkit-tap-highlight-color: transparent;");
    const overscroll = block(base, "[role=\"dialog\"]");
    expect(overscroll).toContain("overscroll-behavior: contain;");
    expect(base).toMatch(/\[role="menu"\]/);
  });

  it("pads the page for the safe areas without touching the header", () => {
    expect(block(base, "body")).toContain("env(safe-area-inset-left)");
    expect(block(base, "body")).toContain("env(safe-area-inset-right)");
    expect(block(base, "main")).toContain("env(safe-area-inset-bottom)");
    expect(polish).not.toContain("safe-area-inset-top");
  });
});

describe("viewport and fixed elements", () => {
  it("lets the page extend under the notch", () => {
    const html = readFileSync(join(SRC, "..", "index.html"), "utf8");
    expect(html).toMatch(/<meta name="viewport" content="[^"]*viewport-fit=cover[^"]*"/);
  });

  it("lifts the bulk action bar above the home indicator", () => {
    expect(read("pages/findings-dashboard/BulkBar.tsx")).toContain("env(safe-area-inset-bottom)");
  });
});

describe("tabular figures", () => {
  const sites: [file: string, needle: RegExp][] = [
    ["components/RelativeTime.tsx", /<time[^>]*tabular-nums/],
    ["pages/ProjectList.tsx", /tabular-nums">\{blocking\}/],
    ["pages/ProjectList.tsx", /tabular-nums">\{findings\}/],
    ["pages/ReportHistory.tsx", /tabular-nums">\s*\{formatDateTime\(r\.created_at\)/],
    ["pages/finding-detail/MetadataGrid.tsx", /font-medium tabular-nums/],
    ["pages/finding-detail/HistorySection.tsx", /tabular-nums">\s*\{formatDateTime/],
    ["pages/project-waivers/WaiverHistory.tsx", /tabular-nums">\s*\{formatDateTime/],
    ["pages/finding-detail/SignoffSection.tsx", /tabular-nums">\{formatDateTime/],
    ["pages/finding-detail/EvidenceSection.tsx", /tabular-nums">\{formatDateTime/],
    ["components/FileDropzone.tsx", /tabular-nums">\s*\{formatSize/],
    ["pages/admin/WatcherHealthSection.tsx", /text-\[0\.9375rem\] tabular-nums/],
    ["pages/upload-report/UploadResultCard.tsx", /tabular-nums">\s*\{pluralize/],
    ["pages/change-view/ChangeHero.tsx", /text-\[13px\] tabular-nums/],
    ["components/VerdictBand.tsx", /tabular-nums">\{verdictSentence/],
  ];
  it.each(sites)("%s sets tabular figures where digits line up", (file, needle) => {
    expect(read(file)).toMatch(needle);
  });
});
