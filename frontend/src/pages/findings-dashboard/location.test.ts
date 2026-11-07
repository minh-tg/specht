import { describe, expect, it } from "vitest";
import { shortLocation } from "./location";

describe("shortLocation", () => {
  it("keeps the end of a long path", () => {
    expect(shortLocation({ summary: "projects/specht/deploy/terraform/main.tf:1" }))
      .toBe("…/terraform/main.tf:1");
  });

  it("leaves a short path alone", () => {
    expect(shortLocation({ summary: "deploy/main.tf:1" })).toBe("deploy/main.tf:1");
  });

  it("does not treat a package as a path", () => {
    const summary = "golang.org/x/crypto/ssh v0.57.0 in go.mod";
    expect(shortLocation({ summary })).toBe(summary);
  });
});
