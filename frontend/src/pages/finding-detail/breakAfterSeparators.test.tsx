import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { breakAfterSeparators } from "./breakAfterSeparators";

function html(text: string): string {
  return render(<span>{breakAfterSeparators(text)}</span>).container.innerHTML;
}

describe("breakAfterSeparators", () => {
  it("offers a line break after each separator and nowhere inside a part", () => {
    expect(html("CVE-2026-4800:pkg:npm/lodash@4.17.20")).toBe(
      "<span>CVE-2026-4800:<wbr>pkg:<wbr>npm/<wbr>lodash@<wbr>4.17.20</span>",
    );
  });

  it("keeps the text as it was, so copying the fingerprint gives the same string", () => {
    const text = "semgrep|python.lang.security.audit.eval|app/views.py";
    expect(render(<span>{breakAfterSeparators(text)}</span>).container.textContent).toBe(text);
  });

  it("leaves a value without separators whole", () => {
    expect(html("0123456789abcdef")).toBe("<span>0123456789abcdef</span>");
  });
});
