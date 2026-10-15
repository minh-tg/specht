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

const base = polish.slice(polish.indexOf("@layer base"));

describe("polish.css", () => {
  it("is imported once from index.css", () => {
    const matches = read("index.css").match(/@import "\.\/styles\/polish\.css";/g);
    expect(matches).toHaveLength(1);
  });

  it("balances headings and prettifies paragraphs once, in the base layer", () => {
    expect(block(base, "h1,")).toContain("text-wrap: balance;");
    expect(block(base, "p,")).toContain("text-wrap: pretty;");
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
