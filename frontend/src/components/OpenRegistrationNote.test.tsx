import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { OpenRegistrationNote } from "./OpenRegistrationNote";

function mockCapabilities(registrationEnabled: boolean | "error") {
  globalThis.fetch = vi.fn().mockImplementation(async () => {
    if (registrationEnabled === "error") {
      return jsonResponse({ error: { code: "x", message: "x" } }, 503);
    }
    return jsonResponse({
      registration: { enabled: registrationEnabled },
      sso: { enabled: false },
      setup: { required: false },
      version: "test",
      commit: "none",
    });
  });
}

function renderNote() {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <OpenRegistrationNote />
    </QueryClientProvider>,
  );
}

describe("OpenRegistrationNote", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("warns that an address may belong to a stranger while sign-up is open", async () => {
    mockCapabilities(true);
    renderNote();
    expect(await screen.findByText(/anyone could have created an account with this address/i))
      .toBeInTheDocument();
  });

  it("says nothing when sign-up is closed", async () => {
    mockCapabilities(false);
    renderNote();
    await vi.waitFor(() => expect(globalThis.fetch).toHaveBeenCalled());
    expect(screen.queryByText(/anyone could have created/i)).not.toBeInTheDocument();
  });

  it("says nothing when the server's settings cannot be read", async () => {
    mockCapabilities("error");
    renderNote();
    await vi.waitFor(() => expect(globalThis.fetch).toHaveBeenCalled());
    expect(screen.queryByText(/anyone could have created/i)).not.toBeInTheDocument();
  });
});
