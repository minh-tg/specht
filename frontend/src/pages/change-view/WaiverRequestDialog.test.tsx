import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { WaiverRequestDialog } from "./WaiverRequestDialog";

let posts: Array<{ target_ids: string[]; reason: string; expires_at: string; }>;
let response: () => Response;

beforeEach(() => {
  posts = [];
  response = () => jsonResponse({ id: "w1" }, 201);
  globalThis.fetch = vi.fn().mockImplementation((_url: RequestInfo | URL, init?: RequestInit) => {
    if (init?.method === "POST") posts.push(JSON.parse(String(init.body)));
    return Promise.resolve(response());
  });
});

function renderDialog(findingIds: readonly string[] = ["f1"], onRequested = vi.fn()) {
  render(
    <QueryClientProvider client={createTestQueryClient()}>
      <WaiverRequestDialog
        slug="acme"
        findingIds={findingIds}
        subject="SQL injection"
        open
        onOpenChange={vi.fn()}
        onRequested={onRequested}
      />
    </QueryClientProvider>,
  );
  return { reason: screen.getByLabelText("Why is this safe to ship?"), onRequested };
}

function paste(field: HTMLElement, text: string) {
  fireEvent.change(field, { target: { value: text } });
}

describe("WaiverRequestDialog limits", () => {
  it("counts characters as the person types", async () => {
    const { reason } = renderDialog();
    expect(screen.getByText("0 of 1000 characters")).toBeInTheDocument();
    await userEvent.type(reason, "abc");
    expect(screen.getByText("3 of 1000 characters")).toBeInTheDocument();
    expect(reason).toHaveAccessibleDescription("3 of 1000 characters");
  });

  it("allows exactly 1000 characters and sends them", async () => {
    const { reason } = renderDialog();
    paste(reason, "a".repeat(1000));
    const send = screen.getByRole("button", { name: "Send request" });
    expect(send).toBeEnabled();
    await userEvent.click(send);
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0].reason).toHaveLength(1000);
  });

  it("blocks a longer reason, says by how much, and keeps the text", async () => {
    const { reason } = renderDialog();
    paste(reason, "a".repeat(1012));
    expect(screen.getByText("1012 of 1000 characters. Shorten it by 12 to send."))
      .toBeInTheDocument();
    expect(reason).toBeInvalid();
    expect(screen.getByRole("button", { name: "Send request" })).toBeDisabled();
    expect((reason as HTMLTextAreaElement).value).toHaveLength(1012);
    expect(posts).toHaveLength(0);
  });

  it("does not count surrounding spaces against the limit", () => {
    const { reason } = renderDialog();
    paste(reason, `  ${"a".repeat(1000)}  `);
    expect(screen.getByRole("button", { name: "Send request" })).toBeEnabled();
  });

  it("offers at most 90 days and says the longest a waiver can last", async () => {
    renderDialog();
    expect(screen.getByText(/The longest a waiver can last is 90 days/)).toBeInTheDocument();
    await userEvent.click(screen.getByLabelText("Waive it for"));
    const options = (await screen.findAllByRole("option")).map((o) => o.textContent);
    expect(options).toEqual(["7 days", "30 days", "90 days"]);
  });

  it("never sends an end date past 90 days", async () => {
    const { reason } = renderDialog();
    await userEvent.click(screen.getByLabelText("Waive it for"));
    await userEvent.click(await screen.findByRole("option", { name: "90 days" }));
    await userEvent.type(reason, "Because.");
    const before = Date.now();
    await userEvent.click(screen.getByRole("button", { name: "Send request" }));
    await waitFor(() => expect(posts).toHaveLength(1));
    const ends = Date.parse(posts[0].expires_at);
    expect(ends).toBeLessThan(before + 90 * 24 * 3600 * 1000);
    expect(ends).toBeGreaterThan(before + 89 * 24 * 3600 * 1000);
  });

  it("allows 50 findings and refuses 51 with a reason", async () => {
    const ids = (n: number) => Array.from({ length: n }, (_, i) => `f${i}`);
    const { reason } = renderDialog(ids(50));
    await userEvent.type(reason, "Because.");
    expect(screen.queryByText(/at most 50 findings/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Send request" })).toBeEnabled();
  });

  it("refuses 51 findings", async () => {
    const ids = Array.from({ length: 51 }, (_, i) => `f${i}`);
    const { reason } = renderDialog(ids);
    await userEvent.type(reason, "Because.");
    expect(screen.getByRole("alert")).toHaveTextContent(
      "One request can name at most 50 findings. You chose 51.",
    );
    expect(screen.getByRole("button", { name: "Send request" })).toBeDisabled();
    expect(posts).toHaveLength(0);
  });
});

describe("WaiverRequestDialog failure", () => {
  it("keeps every input, shows the request id and sends again on retry", async () => {
    response = () => {
      const failure = jsonResponse(
        { error: { code: "internal_error", message: "could not request waiver" } },
        500,
      );
      failure.headers.set("X-Request-Id", "req-42");
      return failure;
    };
    const { reason, onRequested } = renderDialog(["f1", "f2"]);
    await userEvent.type(reason, "Not reachable.");
    await userEvent.click(screen.getByLabelText("Waive it for"));
    await userEvent.click(await screen.findByRole("option", { name: "7 days" }));
    await userEvent.click(screen.getByRole("button", { name: "Send request" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Could not send the request.");
    expect(alert).toHaveTextContent("Your text is kept");
    expect(within(alert).getByText("req-42")).toBeInTheDocument();
    expect((reason as HTMLTextAreaElement).value).toBe("Not reachable.");
    expect(screen.getByLabelText("Waive it for")).toHaveTextContent("7 days");
    expect(onRequested).not.toHaveBeenCalled();

    response = () => jsonResponse({ id: "w1" }, 201);
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() => expect(onRequested).toHaveBeenCalled());
    expect(posts).toHaveLength(2);
    expect(posts[1]).toMatchObject({ target_ids: ["f1", "f2"], reason: "Not reachable." });
  });

  it("explains a conflict with a request that is already waiting", async () => {
    response = () => jsonResponse({ error: { code: "waiver_request_exists", message: "x" } }, 409);
    const { reason } = renderDialog();
    await userEvent.type(reason, "Because.");
    await userEvent.click(screen.getByRole("button", { name: "Send request" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "already waiting for a manager",
    );
    expect((reason as HTMLTextAreaElement).value).toBe("Because.");
  });

  it("shows the server's message for a 400 and for a 422", async () => {
    response = () =>
      jsonResponse(
        { error: { code: "invalid_body", message: "expires_at must be in the future" } },
        400,
      );
    const { reason } = renderDialog();
    await userEvent.type(reason, "Because.");
    await userEvent.click(screen.getByRole("button", { name: "Send request" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Expires_at must be in the future. Your text is kept.",
    );

    response = () => jsonResponse({ error: { code: "unprocessable", message: "Too vague." } }, 422);
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent("Too vague. Your text is kept.")
    );
  });
});
