import { APIError, apiFetch } from "@/api/client";
import { useProjects, useScanners } from "@/api/hooks";
import type { IngestResponse } from "@/types/api";
import { type ChangeEvent, type ReactNode, type SubmitEvent, useRef, useState } from "react";

const MAX_FILE_SIZE = 10 * 1024 * 1024;

// NEUTRAL_SCANNER_COLOR is applied to scanners the UI does not know about;
// unknown tool names render with this neutral fallback instead of requiring
// a core change per tool.
const NEUTRAL_SCANNER_COLOR = "bg-slate-500";

// KNOWN_TOOL_COLORS maps familiar scanner names to a chip color; anything
// else falls back to NEUTRAL_SCANNER_COLOR.
const KNOWN_TOOL_COLORS: Record<string, string> = {
  trivy: "bg-emerald-500",
  "osv-scanner": "bg-amber-500",
  semgrep: "bg-purple-500",
  checkov: "bg-rose-500",
  grype: "bg-sky-500",
  "dependency-check": "bg-orange-500",
};

function scannerColor(name: string): string {
  return KNOWN_TOOL_COLORS[name] ?? NEUTRAL_SCANNER_COLOR;
}

export function Ingest() {
  const { data: projects } = useProjects();
  const {
    data: scanners,
    isLoading: scannersLoading,
    isError: scannersError,
  } = useScanners();

  const [selectedProject, setSelectedProject] = useState("");
  const [selectedScanner, setSelectedScanner] = useState("");
  const [fileContent, setFileContent] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<
    { success: boolean; reportId?: string; error?: string; } | null
  >(null);
  const fileRef = useRef<HTMLInputElement>(null);

  async function handleFileChange(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;

    setFileError(null);
    setResult(null);

    if (!file.name.endsWith(".json")) {
      setFileError("Unsupported file format");
      setFileContent(null);
      setFileName(null);
      return;
    }

    if (file.size > MAX_FILE_SIZE) {
      setFileError("File too large (max 10MB)");
      setFileContent(null);
      setFileName(null);
      return;
    }

    const text = await file.text();
    // The wire carries raw_data as a JSON value, not a string — accept the
    // file only when it parses, so a malformed upload is a local error
    // instead of a server-side parse failure.
    try {
      JSON.parse(text);
    } catch {
      setFileError("Invalid JSON");
      setFileName(null);
      setFileContent(null);
      return;
    }

    setFileName(file.name);
    setFileContent(text);
  }

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    if (!selectedProject || !selectedScanner || !fileContent) return;

    setSubmitting(true);
    setResult(null);

    try {
      const report = await apiFetch<IngestResponse>("/api/v1/reports", {
        method: "POST",
        body: JSON.stringify({
          project: selectedProject,
          scanner: selectedScanner,
          // Validated at file selection: the wire needs a JSON value.
          raw_data: JSON.parse(fileContent),
        }),
      });
      setResult({ success: true, reportId: report.report_id });
      setFileContent(null);
      setFileName(null);
      setFileError(null);
      if (fileRef.current) fileRef.current.value = "";
    } catch (err) {
      const msg = err instanceof APIError ? err.message : "Upload failed";
      setResult({ success: false, error: msg });
    } finally {
      setSubmitting(false);
    }
  }

  const selected = scanners?.find((s) => s.name === selectedScanner);

  let scannerPicker: ReactNode;
  if (scannersLoading) {
    scannerPicker = <div className="text-muted-foreground mt-1 text-sm">Loading scanners…</div>;
  } else if (scannersError) {
    scannerPicker = (
      <div className="text-destructive mt-1 text-sm">
        Failed to load scanners. Refresh to retry.
      </div>
    );
  } else if (!scanners || scanners.length === 0) {
    scannerPicker = (
      <div className="text-muted-foreground mt-1 text-sm">No scanners available.</div>
    );
  } else {
    scannerPicker = (
      <select
        id="ingest-scanner"
        className="border-input bg-background mt-1 block w-full rounded-md border px-3 py-2 text-sm"
        value={selectedScanner}
        onChange={(e) => setSelectedScanner(e.target.value)}
      >
        <option value="">Select a scanner</option>
        {scanners.map((s) => (
          <option key={s.name} value={s.name}>
            {s.name} ({s.version})
          </option>
        ))}
      </select>
    );
  }

  return (
    <div className="mx-auto max-w-lg px-4 py-8">
      <h1 className="mb-6 text-2xl font-bold">Ingest Scan Report</h1>

      {result?.success && (
        <div className="bg-green-100 dark:bg-green-900/30 mb-6 rounded-md px-4 py-3 text-sm">
          Report submitted. ID: {result.reportId}
        </div>
      )}

      {result?.success === false && (
        <div className="bg-destructive/10 text-destructive mb-6 rounded-md px-4 py-3 text-sm">
          {result.error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="ingest-project" className="text-sm font-medium">Project</label>
          <select
            id="ingest-project"
            required
            className="border-input bg-background mt-1 block w-full rounded-md border px-3 py-2 text-sm"
            value={selectedProject}
            onChange={(e) => setSelectedProject(e.target.value)}
          >
            <option value="">Select a project</option>
            {projects?.map((p) => (
              <option key={p.id} value={p.slug}>
                {p.name}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label htmlFor="ingest-scanner" className="text-sm font-medium">Scanner</label>
          {scannerPicker}
          {selected && (
            <p className="text-muted-foreground mt-2 flex items-center gap-2 text-xs">
              <span
                className={`inline-block h-2 w-2 rounded-full ${scannerColor(selected.name)}`}
                aria-hidden="true"
              />
              {selected.finding_kinds.join(", ")}
              {selected.provides_packages ? " · package inventory" : ""}
            </p>
          )}
        </div>

        <div>
          <label htmlFor="ingest-file" className="text-sm font-medium">Scan File (.json)</label>
          <input
            id="ingest-file"
            ref={fileRef}
            type="file"
            accept=".json"
            onChange={handleFileChange}
            className="mt-1 block w-full text-sm"
          />
          {fileName && <p className="text-muted-foreground mt-1 text-xs">{fileName} loaded</p>}
          {fileError && <p className="text-destructive mt-1 text-xs">{fileError}</p>}
        </div>

        <button
          type="submit"
          disabled={submitting || !selectedProject || !selectedScanner || !fileContent}
          className="bg-primary text-primary-foreground hover:bg-primary/90 w-full rounded-md px-4 py-2 text-sm font-medium disabled:opacity-50"
        >
          {submitting ? "Uploading..." : "Upload"}
        </button>
      </form>
    </div>
  );
}
