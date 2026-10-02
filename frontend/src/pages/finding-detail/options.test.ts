import { GLOSSARY } from "@/lib/glossary";
import { describe, expect, it } from "vitest";
import { TRIAGE_GLOSSARY, TRIAGE_OPTIONS } from "./options";

describe("triage explanations", () => {
  it.each(TRIAGE_OPTIONS.map((o) => [o.label, o.value] as const))(
    "%s has a glossary explanation",
    (_label, value) => {
      const key = TRIAGE_GLOSSARY[value];
      expect(key, `${value} needs an entry in TRIAGE_GLOSSARY`).toBeDefined();
      expect(GLOSSARY[key]).toBeDefined();
    },
  );

  it("labels the glossary entry the way the triage option is labelled", () => {
    for (const option of TRIAGE_OPTIONS) {
      expect(GLOSSARY[TRIAGE_GLOSSARY[option.value]].label).toBe(option.label);
    }
  });
});
