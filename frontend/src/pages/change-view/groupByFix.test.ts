import type { Finding, FindingSuggestion } from "@/types/api";
import { describe, expect, it } from "vitest";
import {
  buildBlockerItems,
  fixTarget,
  groupWaiverNoteId,
  itemFixesText,
  itemIds,
  upgradeInstruction,
  worstSeverity,
} from "./groupByFix";

function upgrade(
  packageName: string,
  fixedVersion: string,
  extra: Partial<FindingSuggestion> = {},
): FindingSuggestion {
  return {
    action: "upgrade",
    target: packageName,
    confidence: "high",
    fallback: false,
    package: packageName,
    ecosystem: "npm",
    installed_version: "1.0.0",
    fixed_version: fixedVersion,
    ...extra,
  };
}

function found(id: string, overrides: Partial<Finding> = {}): Finding {
  return {
    id,
    project_id: "p1",
    finding_kind: "sca",
    fingerprint: id,
    current_title: `Finding ${id}`,
    current_severity: "high",
    current_score: null,
    state: "open",
    triage_status: "untriaged",
    analysis_state: "unanalyzed",
    gate_effect: "block",
    first_seen_at: "",
    last_seen_at: "",
    created_at: "",
    updated_at: "",
    suggestion: upgrade("lodash", "4.17.21"),
    ...overrides,
  };
}

function byId(...findings: Finding[]): Map<string, Finding> {
  return new Map(findings.map((finding) => [finding.id, finding]));
}

describe("fixTarget", () => {
  it("reads package, ecosystem and fixed version from a real dependency fix", () => {
    expect(fixTarget(found("a"))).toEqual({
      packageName: "lodash",
      ecosystem: "npm",
      fixedVersion: "4.17.21",
    });
  });

  it("is null for a fallback suggestion, however complete its fields look", () => {
    expect(fixTarget(found("a", { suggestion: upgrade("lodash", "4.17.21", { fallback: true }) })))
      .toBeNull();
  });

  it("is null for a finding of another kind", () => {
    expect(fixTarget(found("a", { finding_kind: "sast" }))).toBeNull();
    expect(fixTarget(found("a", { finding_kind: "image_config" }))).toBeNull();
  });

  it("is null when package, ecosystem or fixed version is missing or blank", () => {
    expect(fixTarget(found("a", { suggestion: upgrade("lodash", "") }))).toBeNull();
    expect(fixTarget(found("a", { suggestion: upgrade("lodash", "  ") }))).toBeNull();
    expect(fixTarget(found("a", { suggestion: upgrade("lodash", "4.17.21", { package: "" }) })))
      .toBeNull();
    expect(
      fixTarget(found("a", { suggestion: upgrade("lodash", "4.17.21", { ecosystem: undefined }) })),
    ).toBeNull();
    expect(fixTarget(found("a", { suggestion: undefined }))).toBeNull();
    expect(fixTarget(undefined)).toBeNull();
  });
});

describe("buildBlockerItems", () => {
  it("groups findings that share package, ecosystem and fixed version", () => {
    const items = buildBlockerItems(["a", "b", "c"], byId(found("a"), found("b"), found("c")));

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      kind: "group",
      ids: ["a", "b", "c"],
      positions: [1, 2, 3],
      position: 1,
      target: { packageName: "lodash", fixedVersion: "4.17.21" },
    });
  });

  it("keeps different fixed versions of one package apart", () => {
    const items = buildBlockerItems(
      ["a", "b", "c", "d"],
      byId(
        found("a"),
        found("b", { suggestion: upgrade("lodash", "4.17.19") }),
        found("c"),
        found("d", { suggestion: upgrade("lodash", "4.17.19") }),
      ),
    );

    expect(items.map((item) => [item.kind, itemIds(item)])).toEqual([
      ["group", ["a", "c"]],
      ["group", ["b", "d"]],
    ]);
  });

  it("does not group a lone match, and leaves it a plain row", () => {
    const items = buildBlockerItems(
      ["a", "b"],
      byId(found("a"), found("b", { suggestion: upgrade("express", "4.19.0") })),
    );

    expect(items.map((item) => item.kind)).toEqual(["single", "single"]);
  });

  it("does not group across ecosystems", () => {
    const items = buildBlockerItems(
      ["a", "b"],
      byId(
        found("a"),
        found("b", { suggestion: upgrade("lodash", "4.17.21", { ecosystem: "pypi" }) }),
      ),
    );

    expect(items.map((item) => item.kind)).toEqual(["single", "single"]);
  });

  it("does not group fallback suggestions", () => {
    const fallback = upgrade("lodash", "4.17.21", { fallback: true });
    const items = buildBlockerItems(
      ["a", "b", "c"],
      byId(
        found("a", { suggestion: fallback }),
        found("b", { suggestion: fallback }),
        found("c", { suggestion: { action: "review", confidence: "low", fallback: true } }),
      ),
    );

    expect(items.map((item) => item.kind)).toEqual(["single", "single", "single"]);
  });

  it("does not group findings that are not dependency findings", () => {
    const items = buildBlockerItems(
      ["a", "b"],
      byId(found("a", { finding_kind: "sast" }), found("b", { finding_kind: "sast" })),
    );

    expect(items.map((item) => item.kind)).toEqual(["single", "single"]);
  });

  it("keeps findings that have not loaded as plain rows", () => {
    const items = buildBlockerItems(["a", "b", "c"], byId(found("a"), found("c")));

    expect(items.map((item) => [item.kind, itemIds(item)])).toEqual([
      ["group", ["a", "c"]],
      ["single", ["b"]],
    ]);
  });

  it("numbers every item by its first finding's place in the original list", () => {
    const items = buildBlockerItems(
      ["a", "b", "c", "d", "e"],
      byId(
        found("a", { suggestion: undefined }),
        found("b"),
        found("c", { suggestion: undefined }),
        found("d"),
        found("e"),
      ),
    );

    expect(items.map((item) => [item.key.startsWith("fix:") ? "group" : item.key, item.position]))
      .toEqual([["a", 1], ["group", 2], ["c", 3]]);
    expect(items[1]).toMatchObject({ positions: [2, 4, 5] });
  });

  it("returns nothing for an empty list", () => {
    expect(buildBlockerItems([], new Map())).toEqual([]);
  });
});

describe("worstSeverity", () => {
  it("picks the most severe loaded member", () => {
    const map = byId(
      found("a", { current_severity: "medium" }),
      found("b", { current_severity: "critical" }),
      found("c", { current_severity: "high" }),
    );

    expect(worstSeverity(["a", "b", "c", "missing"], map)).toBe("critical");
    expect(worstSeverity(["missing"], map)).toBe("");
  });
});

describe("itemFixesText", () => {
  it("writes one numbered line for a group and keeps plain rows' numbers", () => {
    const findings = byId(
      found("a", {
        suggestion: { action: "review", target: "src/db.ts", confidence: "low", fallback: true },
      }),
      found("b"),
      found("c"),
      found("d", { suggestion: undefined, remediation: { summary: "Rotate the token" } }),
    );
    const items = buildBlockerItems(["a", "b", "c", "d"], findings);

    expect(itemFixesText(items, findings)).toBe(
      "2. Upgrade lodash to 4.17.21 (clears 2 blockers)\n4. Finding d: Rotate the token",
    );
  });

  it("is empty when no row has a real fix", () => {
    const findings = byId(found("a", { suggestion: undefined }));

    expect(itemFixesText(buildBlockerItems(["a"], findings), findings)).toBe("");
    expect(itemFixesText([], new Map())).toBe("");
  });
});

describe("upgradeInstruction", () => {
  it("is one instruction a person can paste", () => {
    expect(upgradeInstruction({ packageName: "lodash", ecosystem: "npm", fixedVersion: "4.17.21" }))
      .toBe("Upgrade lodash to 4.17.21");
  });
});

describe("groupWaiverNoteId", () => {
  function keyOf(packageName: string, fixed: string, ecosystem = "npm"): string {
    const findings = byId(
      found("a", { suggestion: upgrade(packageName, fixed, { ecosystem }) }),
      found("b", { suggestion: upgrade(packageName, fixed, { ecosystem }) }),
    );
    return buildBlockerItems(["a", "b"], findings)[0].key;
  }

  it("is made of words, digits and hyphens, so a selector and CSS can use it", () => {
    const id = groupWaiverNoteId(keyOf("lodash", "4.17.21"));

    expect(id).toMatch(/^group-waiver-npm-lodash-4-17-21-[0-9a-f]{6}$/);
    document.body.innerHTML = `<p id="${id}"></p>`;
    expect(document.querySelector(`#${id}`)).not.toBeNull();
  });

  it("handles scoped packages and odd characters", () => {
    expect(groupWaiverNoteId(keyOf("@types/node", "20.1.0"))).toMatch(
      /^group-waiver-npm-types-node-20-1-0-[0-9a-f]{6}$/,
    );
    expect(groupWaiverNoteId(keyOf("a b\"c", "1"))).toMatch(/^[a-z0-9-]+$/);
  });

  it("keeps apart keys that slug to the same words", () => {
    const first = groupWaiverNoteId(keyOf("a-b", "c"));
    const second = groupWaiverNoteId(keyOf("a", "b-c"));

    expect(first.replace(/-[0-9a-f]{6}$/, "")).toBe(second.replace(/-[0-9a-f]{6}$/, ""));
    expect(first).not.toBe(second);
  });

  it("is the same for the same key", () => {
    expect(groupWaiverNoteId(keyOf("lodash", "4.17.21"))).toBe(
      groupWaiverNoteId(keyOf("lodash", "4.17.21")),
    );
  });
});
