import { describe, expect, it } from "vitest";
import { passwordUserInputs } from "./passwordRules";

describe("passwordUserInputs", () => {
  it("returns the email, its local part and each word of the name", () => {
    expect(passwordUserInputs("ada.lovelace@acme.example", "Ada King Lovelace")).toEqual([
      "ada.lovelace@acme.example",
      "ada.lovelace",
      "Ada",
      "King",
      "Lovelace",
    ]);
  });

  it("skips empty values and extra white space", () => {
    expect(passwordUserInputs("", "")).toEqual([]);
    expect(passwordUserInputs("ada@acme.example")).toEqual(["ada@acme.example", "ada"]);
    expect(passwordUserInputs("", "  Ada   Lovelace ")).toEqual(["Ada", "Lovelace"]);
    expect(passwordUserInputs("@acme.example", null)).toEqual(["@acme.example"]);
  });

  it("takes the local part up to the last at sign", () => {
    expect(passwordUserInputs("a@b@acme.example")).toEqual(["a@b@acme.example", "a@b"]);
  });

  it("gives an address without an at sign as it is typed", () => {
    expect(passwordUserInputs("ada")).toEqual(["ada"]);
  });
});
