import { describe, expect, it } from "vitest";
import {
  changeViewBackPath,
  changeViewState,
  entryModeFromSearch,
  fromChangePath,
} from "./entryMode";

describe("entryModeFromSearch", () => {
  it("is fix-first only for from=change", () => {
    expect(entryModeFromSearch("?from=change")).toBe("unblock");
    expect(entryModeFromSearch("from=change")).toBe("unblock");
    expect(entryModeFromSearch("?tab=history&from=change")).toBe("unblock");
  });

  it("is decide-first when the param is absent", () => {
    expect(entryModeFromSearch("")).toBe("triage");
    expect(entryModeFromSearch("?tab=history")).toBe("triage");
  });

  it("is decide-first for an empty, unknown or differently cased value without throwing", () => {
    for (
      const search of ["?from=", "?from", "?from=list", "?from=Change", "?from=%E0%A4%A", "?%"]
    ) {
      expect(entryModeFromSearch(search)).toBe("triage");
    }
  });

  it("uses the first value when the param repeats", () => {
    expect(entryModeFromSearch("?from=change&from=list")).toBe("unblock");
    expect(entryModeFromSearch("?from=list&from=change")).toBe("triage");
  });
});

describe("fromChangePath", () => {
  it("adds the param to a bare path", () => {
    expect(fromChangePath("/acme/findings/f1")).toBe("/acme/findings/f1?from=change");
  });

  it("keeps other query params and the hash", () => {
    expect(fromChangePath("/acme/findings/f1?tab=history#evidence")).toBe(
      "/acme/findings/f1?tab=history&from=change#evidence",
    );
    expect(fromChangePath("/acme/findings/f1#evidence")).toBe(
      "/acme/findings/f1?from=change#evidence",
    );
  });

  it("replaces an existing from instead of repeating it", () => {
    expect(fromChangePath("/acme/findings/f1?from=list")).toBe("/acme/findings/f1?from=change");
  });

  it("gives the fix-first mode when read back", () => {
    const search = fromChangePath("/acme/findings/f1?tab=history").split("?")[1];
    expect(entryModeFromSearch(search)).toBe("unblock");
  });
});

describe("changeViewBackPath", () => {
  it("returns the change view stored in the router state", () => {
    const state = changeViewState({ pathname: "/acme/changes/abc1234", search: "?report=r1" });
    expect(changeViewBackPath("acme", state)).toBe("/acme/changes/abc1234?report=r1");
  });

  it("refuses anything that is not a change of this project", () => {
    expect(changeViewBackPath("acme", undefined)).toBeNull();
    expect(changeViewBackPath("acme", null)).toBeNull();
    expect(changeViewBackPath("acme", "oops")).toBeNull();
    expect(changeViewBackPath("acme", { changeView: 7 })).toBeNull();
    expect(changeViewBackPath("acme", { changeView: "http://evil.example/acme/changes/x" }))
      .toBeNull();
    expect(changeViewBackPath("acme", { changeView: "/other/changes/abc1234" })).toBeNull();
    expect(changeViewBackPath("acme", { changeView: "/acme/findings" })).toBeNull();
  });
});
