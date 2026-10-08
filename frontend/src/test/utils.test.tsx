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

  it.each([204, 205, 304])("builds a bodyless %i response from a null body", async (status) => {
    const response = jsonResponse(null, status);

    expect(response.status).toBe(status);
    expect(response.body).toBeNull();
    await expect(response.text()).resolves.toBe("");
  });

  it("treats an undefined body like null for a status that cannot carry one", () => {
    expect(jsonResponse(undefined, 204).status).toBe(204);
  });

  it("refuses to attach a body to a status that cannot carry one", () => {
    expect(() => jsonResponse({ ok: true }, 204)).toThrow(/204.*cannot carry a body/);
  });

  it("still serializes a null body as JSON for statuses that can carry one", async () => {
    const response = jsonResponse(null);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toBeNull();
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
