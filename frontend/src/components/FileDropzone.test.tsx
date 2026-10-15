import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createRef } from "react";
import { describe, expect, it, vi } from "vitest";
import { FileDropzone } from "./FileDropzone";

const ACCEPT = [".json", ".jsonl", ".ndjson", ".sarif"];

function file(name = "report.json", content = "{}") {
  return new File([content], name, { type: "application/json" });
}

function setup(props: Partial<Parameters<typeof FileDropzone>[0]> = {}) {
  const onFile = vi.fn();
  const onChange = vi.fn();
  const onClear = vi.fn();
  const inputRef = createRef<HTMLInputElement>();
  render(
    <>
      <label htmlFor="scan">Scan file</label>
      <p id="scan-hint">Takes .json</p>
      <FileDropzone
        id="scan"
        inputRef={inputRef}
        accept={ACCEPT}
        describedBy="scan-hint"
        fileName={null}
        fileSize={null}
        error={null}
        onFile={onFile}
        onChange={onChange}
        onClear={onClear}
        {...props}
      />
    </>,
  );
  return { onFile, onChange, onClear, inputRef, zone: screen.getByTestId("file-dropzone") };
}

function drop(zone: HTMLElement, files: File[]) {
  fireEvent.drop(zone, { dataTransfer: { files } });
}

describe("FileDropzone", () => {
  it("offers one labelled file input and a visible Choose file label bound to it", () => {
    setup();

    const input = screen.getByLabelText("Scan file");
    expect(input).toHaveAttribute("type", "file");
    expect(input).toHaveAttribute("accept", ".json,.jsonl,.ndjson,.sarif");
    expect(screen.getByText("Choose file")).toHaveAttribute("for", "scan");
    expect(screen.getByText("or drop it here")).toBeInTheDocument();
    // The label is not focusable, so Tab stops once on the input.
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });

  it("passes a chosen file to onChange", async () => {
    const { onChange } = setup();

    await userEvent.setup().upload(screen.getByLabelText("Scan file"), file());

    expect(onChange).toHaveBeenCalledOnce();
  });

  it("passes a dropped file to onFile", () => {
    const { onFile, zone } = setup();

    drop(zone, [file("scan.sarif")]);

    expect(onFile).toHaveBeenCalledOnce();
    expect(onFile.mock.calls[0]![0].name).toBe("scan.sarif");
  });

  it("refuses a dropped file with an extension the input would not accept", () => {
    const { onFile, zone } = setup();

    drop(zone, [file("notes.txt")]);

    expect(onFile).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "notes.txt is not a supported file. Use .json, .jsonl, .ndjson or .sarif.",
    );
  });

  it("matches the extension without regard to case", () => {
    const { onFile, zone } = setup();

    drop(zone, [file("REPORT.JSON")]);

    expect(onFile).toHaveBeenCalledOnce();
  });

  it("refuses a drop of several files", () => {
    const { onFile, zone } = setup();

    drop(zone, [file("a.json"), file("b.json")]);

    expect(onFile).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent("Drop one file at a time.");
  });

  it("clears its own drop error when a valid file is dropped next", () => {
    const { zone } = setup();

    drop(zone, [file("notes.txt")]);
    drop(zone, [file("ok.json")]);

    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("marks the area while a file is dragged over it and unmarks it on leave", () => {
    const { zone } = setup();

    fireEvent.dragEnter(zone, { dataTransfer: { files: [] } });
    expect(zone).toHaveAttribute("data-dragging", "true");
    fireEvent.dragLeave(zone, { dataTransfer: { files: [] } });
    expect(zone).not.toHaveAttribute("data-dragging");
  });

  it("names the hint and the error in aria-describedby", () => {
    setup({ error: "Invalid JSON" });

    const input = screen.getByLabelText("Scan file");
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("Invalid JSON");
    expect(input.getAttribute("aria-describedby")).toBe(`scan-hint ${alert.id}`);
    expect(input).toHaveAttribute("aria-invalid", "true");
  });

  it("describes only the hint when there is no error", () => {
    setup();

    expect(screen.getByLabelText("Scan file")).toHaveAttribute("aria-describedby", "scan-hint");
  });

  it("shows the file name and size with a Remove action when filled", async () => {
    const { onClear, inputRef } = setup({ fileName: "report.json", fileSize: 2048 });

    expect(screen.getByText("report.json")).toBeInTheDocument();
    expect(screen.getByText("2.0 KB")).toBeInTheDocument();
    expect(screen.queryByText("Choose file")).not.toBeInTheDocument();
    // The button is the only tab stop while a file is held.
    expect(screen.getByLabelText("Scan file")).toHaveAttribute("tabindex", "-1");
    await userEvent.setup().click(screen.getByRole("button", { name: "Remove report.json" }));
    expect(onClear).toHaveBeenCalledOnce();
    expect(inputRef.current).toHaveFocus();
  });

  it("ignores drops and disables the input when disabled", () => {
    const { onFile, zone } = setup({ disabled: true });

    drop(zone, [file()]);

    expect(onFile).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Scan file")).toBeDisabled();
  });
});
