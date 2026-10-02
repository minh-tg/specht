import { describe, expect, it } from "vitest";
import { GLOSSARY, type GlossaryEntry } from "./glossary";

const entries = Object.entries(GLOSSARY) as Array<[string, GlossaryEntry]>;

describe("glossary", () => {
  it("has entries", () => {
    expect(entries.length).toBeGreaterThan(0);
  });

  it.each(entries)("%s has a label and a short, plain explanation", (_key, entry) => {
    expect(entry.label.trim()).not.toBe("");
    const words = entry.short.trim().split(/\s+/);
    expect(words.length, "short must stay at 25 words or fewer").toBeLessThanOrEqual(25);
    expect(entry.short.trim().endsWith("."), "short is a full sentence").toBe(true);
  });

  it("never reuses a label", () => {
    const labels = entries.map(([, entry]) => entry.label.toLowerCase());
    expect(new Set(labels).size).toBe(labels.length);
  });
});
