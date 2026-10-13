import { jsonResponse } from "@/test/utils";
import { cleanup, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

beforeEach(() => {
  window.history.replaceState(null, "", "/");
  document.body.innerHTML = "<div id=\"root\"></div>";
  globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
    if (String(input).endsWith("/api/v1/capabilities")) {
      return jsonResponse({
        registration: { enabled: true },
        sso: { enabled: false },
        setup: { required: false },
        version: "test",
        commit: "none",
      });
    }
    return jsonResponse([]);
  });
});

afterEach(() => {
  cleanup();
  document.body.innerHTML = "";
});

describe("application entry point", () => {
  it("mounts the public sign-in experience in the application root", async () => {
    await import("./main");

    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Register" })).toBeInTheDocument();
  });
});
