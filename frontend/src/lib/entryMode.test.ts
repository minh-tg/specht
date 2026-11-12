import { describe, expect, it } from "vitest";
import {
  changeScopeFromSearch,
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

describe("changeScopeFromSearch", () => {
  const SHA = "0123456789abcdef0123456789abcdef01234567";
  const search = (path: string) => `?${path.split("?")[1]}`;

  it("reads back the gate of an introduced-scope link", () => {
    const path = fromChangePath("/acme/findings/f1", {
      commit: SHA,
      projectWide: false,
      severity: "critical,high",
      branch: "feat/x",
    });
    // The introduced gate has no branch; only the project-wide one reads it.
    expect(path).toBe(`/acme/findings/f1?from=change&commit=${SHA}&severity=critical%2Chigh`);
    expect(changeScopeFromSearch(search(path))).toEqual({
      commit: SHA,
      projectWide: false,
      severity: "critical,high",
      branch: undefined,
    });
  });

  it("reads back a project-wide link with its branch", () => {
    const path = fromChangePath("/acme/findings/f1", {
      commit: SHA,
      projectWide: true,
      branch: "feat/x",
    });
    expect(changeScopeFromSearch(search(path))).toEqual({
      commit: SHA,
      projectWide: true,
      severity: undefined,
      branch: "feat/x",
    });
  });

  it("has no scope without a commit or outside a change", () => {
    expect(changeScopeFromSearch("?from=change")).toBeNull();
    expect(changeScopeFromSearch(`?commit=${SHA}`)).toBeNull();
    expect(changeScopeFromSearch(`?from=list&commit=${SHA}`)).toBeNull();
  });

  it("refuses a commit or severity the server would refuse", () => {
    expect(changeScopeFromSearch("?from=change&commit=abc%20def")).toBeNull();
    expect(changeScopeFromSearch(`?from=change&commit=${"a".repeat(65)}`)).toBeNull();
    expect(changeScopeFromSearch(`?from=change&commit=${SHA}&severity=HIGH%3B`)).toBeNull();
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
