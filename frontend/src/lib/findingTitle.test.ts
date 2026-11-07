import { describe, expect, it } from "vitest";
import { findingHeadline, findingTitleParts } from "./findingTitle";

const named = (current_title: string, summary?: string) => ({
  current_title,
  location: summary ? { summary } : null,
});

describe("findingTitleParts", () => {
  it("leaves a normal title alone", () => {
    expect(findingTitleParts(named("S3 Access block should block public ACL"))).toEqual({
      headline: "S3 Access block should block public ACL",
      rest: null,
    });
  });

  it("drops a repeated package prefix", () => {
    expect(findingHeadline(named("lodash: lodash: Arbitrary code execution")))
      .toBe("lodash: Arbitrary code execution");
    expect(findingHeadline(named("nodejs-lodash: command injection")))
      .toBe("nodejs-lodash: command injection");
  });

  it("names the package when the title is only an advisory id", () => {
    expect(findingHeadline(named("GHSA-35jh-r3h4-6jhm", "lodash 4.17.20 in package-lock.json")))
      .toBe("GHSA-35jh-r3h4-6jhm in lodash 4.17.20");
    expect(findingHeadline(named("CVE-2021-23337"))).toBe("CVE-2021-23337");
  });

  it("makes the first sentence of a paragraph the name", () => {
    const parts = findingTitleParts(named(
      "`Clean` is not intended to sanitize against path traversal attacks. This function is for finding the shortest path name equivalent to the given input.",
    ));
    expect(parts.headline).toBe(
      "`Clean` is not intended to sanitize against path traversal attacks.",
    );
    expect(parts.rest).toMatch(/^This function is for finding/);
  });

  it("cuts a long sentence at a word and keeps the rest", () => {
    const long = `${"word ".repeat(40)}end`;
    const parts = findingTitleParts(named(long));
    expect(parts.headline.length).toBeLessThanOrEqual(111);
    expect(parts.headline.endsWith("…")).toBe(true);
    expect(parts.rest).toMatch(/end$/);
  });
});
