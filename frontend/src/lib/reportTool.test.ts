import { describe, expect, it } from "vitest";
import { reportToolLabel } from "./reportTool";

describe("reportToolLabel", () => {
  it("names the tool a generic SARIF file says wrote it", () => {
    expect(reportToolLabel({ tool_name: "sarif", producer: "Gosec" })).toBe("Gosec (SARIF)");
  });

  it("keeps the scanner name when the file names no tool", () => {
    expect(reportToolLabel({ tool_name: "sarif" })).toBe("sarif");
    expect(reportToolLabel({ tool_name: "sarif", producer: "  " })).toBe("sarif");
  });

  it("keeps a scanner's own name even when the file names a tool", () => {
    expect(reportToolLabel({ tool_name: "semgrep", producer: "Semgrep OSS" })).toBe("semgrep");
  });
});
