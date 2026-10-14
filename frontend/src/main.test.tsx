import { jsonResponse } from "@/test/utils";
import { act, cleanup, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// main.tsx creates its own root, which testing-library's cleanup does not know about. A root left
// mounted keeps React's scheduler working after the test ends and the DOM is gone, which fails the
// whole run intermittently with "window is not defined". Keep every root so the test can unmount it.
const roots = vi.hoisted(() => [] as Array<{ unmount: () => void; }>);
vi.mock("react-dom/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-dom/client")>();
  return {
    ...actual,
    createRoot: (...args: Parameters<typeof actual.createRoot>) => {
      const root = actual.createRoot(...args);
      roots.push(root);
      return root;
    },
  };
});

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

afterEach(async () => {
  await act(async () => {
    for (const root of roots.splice(0)) root.unmount();
  });
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
