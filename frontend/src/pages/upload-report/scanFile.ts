/** What reading a scan file gave: the value to send as `raw_data`, or why the file was refused. */
export type ScanFile =
  | { readonly ok: true; readonly value: unknown; }
  | { readonly ok: false; readonly error: string; };

const JSONL_EXTENSIONS = [".jsonl", ".ndjson"];

function parseLines(text: string): ScanFile {
  const events: unknown[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (line === "") continue;
    try {
      events.push(JSON.parse(line));
    } catch {
      return { ok: false, error: `Line ${i + 1} is not valid JSON` };
    }
  }
  if (events.length === 0) return { ok: false, error: "The file is empty" };
  return { ok: true, value: events };
}

/**
 * Reads a scan file the way the server takes it. A `.json` or `.sarif` file is one JSON value. A `.jsonl` or
 * `.ndjson` file (Nuclei writes one) has one JSON value per line and goes as an array of them,
 * which is the form the API accepts for line-based output.
 */
export function readScanFile(name: string, text: string): ScanFile {
  const lower = name.toLowerCase();
  if (JSONL_EXTENSIONS.some((ext) => lower.endsWith(ext))) return parseLines(text);
  if (!lower.endsWith(".json") && !lower.endsWith(".sarif")) {
    return { ok: false, error: "Unsupported file format" };
  }
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false, error: "Invalid JSON" };
  }
}
