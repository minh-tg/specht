import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { CopyButton } from "./CopyButton";

afterEach(() => {
  // @ts-expect-error remove the test double again
  delete navigator.clipboard;
});

function stubClipboard(writeText: (text: string) => Promise<void>) {
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
}

it("gives each button a distinct accessible name that starts with the visible word", () => {
  render(
    <>
      <CopyButton text="a" label="API key" />
      <CopyButton text="b" label="GitHub Actions workflow" />
    </>,
  );

  expect(screen.getByRole("button", { name: /^Copy\s+API key$/ })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /^Copy\s+GitHub Actions workflow$/ }))
    .toBeInTheDocument();
});

it("copies the text, shows Copied and announces it", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  stubClipboard(writeText);
  const user = userEvent.setup();
  stubClipboard(writeText);
  render(<CopyButton text="vuln_secret" label="API key" />);

  await user.click(screen.getByRole("button", { name: /Copy/ }));

  expect(writeText).toHaveBeenCalledWith("vuln_secret");
  expect(screen.getByRole("button", { name: /^Copied\s+API key$/ })).toBeInTheDocument();
  expect(screen.getByRole("status")).toHaveTextContent("API key copied");
});

it("says so when the clipboard write fails instead of claiming success", async () => {
  const user = userEvent.setup();
  stubClipboard(vi.fn().mockRejectedValue(new Error("denied")));
  render(<CopyButton text="vuln_secret" label="API key" />);

  await user.click(screen.getByRole("button", { name: /Copy/ }));

  expect(await screen.findByText(/Select the text and copy it manually/)).toBeVisible();
  expect(screen.getByRole("status")).toHaveTextContent("Couldn't copy to the clipboard");
  expect(screen.getByRole("status")).not.toHaveClass("sr-only");
  expect(screen.getByRole("button", { name: /^Copy failed\s+API key$/ })).toBeInTheDocument();
});

it("keeps its single live region mounted and empty before anything happens", () => {
  render(<CopyButton text="x" label="API key" />);

  expect(screen.getAllByRole("status")).toHaveLength(1);
  expect(screen.getByRole("status")).toBeEmptyDOMElement();
});
