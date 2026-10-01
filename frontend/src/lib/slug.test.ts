import { describe, expect, it } from "vitest";
import { isValidSlug, slugify } from "./slug";

describe("slugify", () => {
  it("lowercases and hyphenates words", () => {
    expect(slugify("Specht Demo")).toBe("specht-demo");
    expect(slugify("My Cool Project")).toBe("my-cool-project");
  });

  it("collapses every run of separators into a single hyphen", () => {
    expect(slugify("Hello   ---   World")).toBe("hello-world");
    expect(slugify("a/ b__c")).toBe("a-b-c");
    expect(slugify("...leading and trailing...")).toBe("leading-and-trailing");
  });

  it("drops characters outside the ASCII alphanumeric range", () => {
    expect(slugify("Café — Déjà Vu")).toBe("caf-d-j-vu");
    expect(slugify("héllo wörld")).toBe("h-llo-w-rld");
  });

  it("returns an empty string when nothing usable is left", () => {
    expect(slugify("")).toBe("");
    expect(slugify("   ")).toBe("");
    expect(slugify("!!!")).toBe("");
    expect(slugify("---")).toBe("");
  });

  it("keeps digits and mixed alphanumeric tokens", () => {
    expect(slugify("API v2 Gateway")).toBe("api-v2-gateway");
    expect(slugify("2026-Q1")).toBe("2026-q1");
  });

  it("truncates long input to 48 characters", () => {
    expect(slugify("a".repeat(60))).toBe("a".repeat(48));
    expect(slugify("a".repeat(60)).length).toBe(48);
  });

  it("never leaves a trailing hyphen when truncating", () => {
    const long = `${"a".repeat(47)} ${"b".repeat(10)}`;
    const slug = slugify(long);
    expect(slug).toBe("a".repeat(47));
    expect(slug.endsWith("-")).toBe(false);
    expect(isValidSlug(slug)).toBe(true);
  });

  it("keeps a slug of exactly the maximum length", () => {
    expect(slugify("a".repeat(48))).toHaveLength(48);
  });
});

describe("isValidSlug", () => {
  it("accepts lowercase alphanumeric groups separated by hyphens", () => {
    expect(isValidSlug("abc")).toBe(true);
    expect(isValidSlug("my-project-2")).toBe(true);
    expect(isValidSlug("a1b")).toBe(true);
    expect(isValidSlug("a".repeat(48))).toBe(true);
  });

  it("rejects slugs shorter than 3 or longer than 48 characters", () => {
    expect(isValidSlug("")).toBe(false);
    expect(isValidSlug("ab")).toBe(false);
    expect(isValidSlug("a".repeat(49))).toBe(false);
  });

  it("rejects uppercase, underscores and leading, trailing or doubled hyphens", () => {
    expect(isValidSlug("Abc")).toBe(false);
    expect(isValidSlug("my_project")).toBe(false);
    expect(isValidSlug("-abc")).toBe(false);
    expect(isValidSlug("abc-")).toBe(false);
    expect(isValidSlug("ab--c")).toBe(false);
    expect(isValidSlug("my project")).toBe(false);
  });
});
