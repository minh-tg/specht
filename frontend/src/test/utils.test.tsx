import { describe, expect, it } from "vitest";
import { createTestQueryClient, jsonResponse } from "./utils";

describe("jsonResponse", () => {
  it("defaults the status to 200", () => {
    const response = jsonResponse({ ok: true });

    expect(response.status).toBe(200);
    expect(response.ok).toBe(true);
  });

  it("uses the provided status", async () => {
    const response = jsonResponse({ error: { message: "not found" } }, 404);

    expect(response.status).toBe(404);
    expect(response.ok).toBe(false);
    await expect(response.json()).resolves.toEqual({ error: { message: "not found" } });
  });

  it("round-trips the JSON body and marks it as JSON", async () => {
    const body = { nested: { findings: [1, 2, 3] } };
    const response = jsonResponse(body);

    expect(response.headers.get("Content-Type")).toBe("application/json");
    await expect(response.json()).resolves.toEqual(body);
  });
});

describe("createTestQueryClient", () => {
  it("disables query retries", () => {
    const client = createTestQueryClient();

    expect(client.getDefaultOptions().queries?.retry).toBe(false);
  });
});
