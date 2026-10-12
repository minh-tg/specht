import { describe, expect, it } from "vitest";
import {
  type Command,
  commandScore,
  currentProjectSlug,
  searchCommands,
  sectionCommands,
} from "./commands";

const cmd = (id: string, label: string, extra: Partial<Command> = {}): Command => ({
  id,
  group: "Go to",
  label,
  run: () => {},
  ...extra,
});

describe("currentProjectSlug", () => {
  it("finds the project on each of its pages", () => {
    expect(currentProjectSlug("/payments/findings")).toBe("payments");
    expect(currentProjectSlug("/payments/findings/f1")).toBe("payments");
    expect(currentProjectSlug("/payments/changes/abc1234")).toBe("payments");
    expect(currentProjectSlug("/payments/reports/upload")).toBe("payments");
    expect(currentProjectSlug("/payments/watcher")).toBe("payments");
  });

  it("is null on pages that belong to no project", () => {
    for (const path of ["/", "/admin", "/teams", "/api-keys", "/projects/new", "/login"]) {
      expect(currentProjectSlug(path), path).toBeNull();
    }
  });

  it("reads an encoded slug", () => {
    expect(currentProjectSlug("/my%20app/policy")).toBe("my app");
  });
});

describe("searching", () => {
  const list = [
    cmd("1", "Findings"),
    cmd("2", "Access & Members"),
    cmd("3", "Sign out", { keywords: "logout" }),
    cmd("4", "payments-api", { hint: "payments-api", group: "Projects" }),
    cmd("5", "Waivers"),
  ];

  it("keeps everything in order for an empty query", () => {
    expect(searchCommands(list, "  ").map((c) => c.id)).toEqual(["1", "2", "3", "4", "5"]);
  });

  it("matches the start of a word anywhere in the label", () => {
    expect(searchCommands(list, "mem").map((c) => c.id)).toEqual(["2"]);
  });

  it("finds a command by its keywords", () => {
    expect(searchCommands(list, "logout").map((c) => c.id)).toEqual(["3"]);
  });

  it("needs every word of the query to find something", () => {
    expect(searchCommands(list, "sign out").map((c) => c.id)).toEqual(["3"]);
    expect(searchCommands(list, "sign banana")).toEqual([]);
  });

  it("puts a label that starts with the query ahead of one that only contains it", () => {
    const l = [cmd("a", "Open waivers"), cmd("b", "Waivers")];
    expect(searchCommands(l, "wai").map((c) => c.id)).toEqual(["b", "a"]);
  });

  it("falls back to letters in order for a longer query", () => {
    expect(searchCommands(list, "fnd").map((c) => c.id)).toEqual(["1"]);
    expect(commandScore("zz", cmd("x", "Findings"))).toBe(0);
  });

  it("is case-insensitive", () => {
    expect(searchCommands(list, "FINDINGS").map((c) => c.id)).toEqual(["1"]);
  });
});

describe("sectionCommands", () => {
  const list: Command[] = [
    cmd("1", "Findings", { group: "This project" }),
    cmd("2", "payments-api", { group: "Projects" }),
    cmd("3", "Teams"),
    cmd("4", "Sign out", { group: "Do" }),
  ];

  it("keeps the groups in their fixed order with no query", () => {
    expect(sectionCommands(list, "").map((s) => s.group)).toEqual([
      "This project",
      "Projects",
      "Go to",
      "Do",
    ]);
  });

  it("leaves out a group with nothing in it", () => {
    expect(sectionCommands(list.slice(2), "").map((s) => s.group)).toEqual(["Go to", "Do"]);
  });

  it("leads with the group of the best match once there is a query", () => {
    expect(sectionCommands(list, "sign").map((s) => s.group)).toEqual(["Do"]);
    expect(sectionCommands(list, "t").map((s) => s.group)).toEqual(["Go to", "Projects", "Do"]);
  });
});
