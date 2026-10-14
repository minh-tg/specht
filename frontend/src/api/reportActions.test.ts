import { describe, expect, it } from "vitest";
import { archivedFindingsMessage } from "./reportActions";

describe("archivedFindingsMessage", () => {
  it("names the archived count in the success toast", () => {
    expect(archivedFindingsMessage({ archived: 3 })).toBe("Report deleted. 3 findings archived.");
  });

  it("uses the singular for one finding", () => {
    expect(archivedFindingsMessage({ archived: 1 })).toBe("Report deleted. 1 finding archived.");
  });

  it("says zero findings when the report settled none", () => {
    expect(archivedFindingsMessage({ archived: 0 })).toBe("Report deleted. 0 findings archived.");
  });
});
