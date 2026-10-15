import { describe, expect, it } from "vitest";
import { readScanFile } from "./scanFile";

describe("readScanFile", () => {
  it("parses a .json file as one JSON value", () => {
    expect(readScanFile("trivy.json", "{\"Results\":[]}")).toEqual({
      ok: true,
      value: { Results: [] },
    });
  });

  it("keeps a JSON array as it is", () => {
    expect(readScanFile("events.json", "[{\"a\":1},{\"a\":2}]")).toEqual({
      ok: true,
      value: [{ a: 1 }, { a: 2 }],
    });
  });

  it("reads a .jsonl file as an array with one entry per line", () => {
    const text = "{\"template-id\":\"a\"}\n{\"template-id\":\"b\"}\n";
    expect(readScanFile("nuclei.jsonl", text)).toEqual({
      ok: true,
      value: [{ "template-id": "a" }, { "template-id": "b" }],
    });
  });

  it("skips blank lines and tolerates Windows line endings", () => {
    const text = "{\"a\":1}\r\n\r\n   \r\n{\"a\":2}\r\n";
    expect(readScanFile("scan.jsonl", text)).toEqual({ ok: true, value: [{ a: 1 }, { a: 2 }] });
  });

  it("accepts .ndjson as the same format", () => {
    expect(readScanFile("scan.ndjson", "{\"a\":1}")).toEqual({ ok: true, value: [{ a: 1 }] });
  });

  it("matches the extension without regard to case", () => {
    expect(readScanFile("SCAN.JSONL", "{\"a\":1}")).toEqual({ ok: true, value: [{ a: 1 }] });
    expect(readScanFile("SCAN.JSON", "{\"a\":1}")).toEqual({ ok: true, value: { a: 1 } });
  });

  it("names the line that is not JSON", () => {
    expect(readScanFile("scan.jsonl", "{\"a\":1}\nnot json\n{\"a\":3}")).toEqual({
      ok: false,
      error: "Line 2 is not valid JSON",
    });
  });

  it("refuses a .jsonl file with nothing in it", () => {
    expect(readScanFile("scan.jsonl", "\n  \n")).toEqual({ ok: false, error: "The file is empty" });
  });

  it("refuses a .json file that is not JSON", () => {
    expect(readScanFile("scan.json", "not json")).toEqual({ ok: false, error: "Invalid JSON" });
  });

  it("refuses other extensions", () => {
    expect(readScanFile("scan.txt", "{}")).toEqual({ ok: false, error: "Unsupported file format" });
    expect(readScanFile("scan", "{}")).toEqual({ ok: false, error: "Unsupported file format" });
  });
});
