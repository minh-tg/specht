import { renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { useDocumentTitle } from "./useDocumentTitle";

describe("useDocumentTitle", () => {
  afterEach(() => {
    document.title = "";
  });

  it("appends the Specht suffix to the given title", () => {
    renderHook(() => useDocumentTitle("Sign in"));

    expect(document.title).toBe("Sign in · Specht");
  });

  it("restores the previous title on unmount", () => {
    document.title = "Original title";

    const { unmount } = renderHook(() => useDocumentTitle("Sign in"));
    expect(document.title).toBe("Sign in · Specht");

    unmount();
    expect(document.title).toBe("Original title");
  });

  it("updates the title when the argument changes", () => {
    const { rerender } = renderHook(({ title }) => useDocumentTitle(title), {
      initialProps: { title: "Findings" },
    });
    expect(document.title).toBe("Findings · Specht");

    rerender({ title: "Reports" });
    expect(document.title).toBe("Reports · Specht");
  });
});
