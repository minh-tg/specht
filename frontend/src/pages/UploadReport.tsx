import { APIError, apiFetch } from "@/api/client";
import { queryKeys, useProject, useScanners } from "@/api/hooks";
import { VerdictBadge } from "@/components/VerdictBadge";
import { pluralize } from "@/lib/format";
import type { IngestResponse } from "@/types/api";
import { useQueryClient } from "@tanstack/react-query";
import { type ChangeEvent, type ReactNode, type SubmitEvent, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";

const MAX_FILE_SIZE = 10 * 1024 * 1024;

export function UploadReport() {
  const { slug = "" } = useParams<{ slug: string; }>();
  const queryClient = useQueryClient();
  const { data: project } = useProject(slug);
  const {
    data: scanners,
    isLoading: scannersLoading,
    isError: scannersError,
    refetch: refetchScanners,
  } = useScanners();

  const [selectedScanner, setSelectedScanner] = useState("");
  const [fileContent, setFileContent] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [result, setResult] = useState<IngestResponse | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const projectName = project?.name ?? slug;

  async function handleFileChange(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;

    setFileError(null);
    setUploadError(null);
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

  function resetForm() {
    setSelectedScanner("");
    setFileContent(null);
    setFileName(null);
    setFileError(null);
    setUploadError(null);
    setResult(null);
    if (fileRef.current) fileRef.current.value = "";
  }

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    if (!slug || !selectedScanner || !fileContent) return;

    setSubmitting(true);
    setUploadError(null);
    setResult(null);

    try {
      const report = await apiFetch<IngestResponse>("/api/v1/reports", {
        method: "POST",
        body: JSON.stringify({
          project: slug,
          scanner: selectedScanner,
          // Validated at file selection: the wire needs a JSON value.
          raw_data: JSON.parse(fileContent),
        }),
      });
      setResult(report);
      setFileContent(null);
      setFileName(null);
      setFileError(null);
      if (fileRef.current) fileRef.current.value = "";

      queryClient.invalidateQueries({ queryKey: queryKeys.reports(slug) });
      queryClient.invalidateQueries({ queryKey: queryKeys.gate(slug) });
      queryClient.invalidateQueries({ queryKey: queryKeys.projectStats(slug) });
    } catch (err) {
      if (err instanceof APIError && err.status === 403) {
        setUploadError("You don't have permission to upload reports to this project.");
      } else if (err instanceof APIError) {
        setUploadError(err.message);
      } else {
        setUploadError("Upload failed");
      }
    } finally {
      setSubmitting(false);
    }
  }

  let scannerPicker: ReactNode;
  if (scannersLoading) {
    scannerPicker = <div className="text-muted-foreground mt-1 text-sm">Loading scanners…</div>;
  } else if (scannersError) {
    scannerPicker = (
      <div className="text-destructive mt-1 text-sm">
        Failed to load scanners.
        <button
          type="button"
          onClick={() => refetchScanners()}
          className="text-primary ml-2 text-sm underline underline-offset-2 hover:no-underline"
        >
          Retry
        </button>
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
      <Link
        to={`/${slug}/reports`}
        className="text-muted-foreground hover:text-foreground mb-6 inline-block text-sm"
      >
        &larr; {projectName}
      </Link>

      <h1 className="mb-2 text-2xl font-bold">Upload a report</h1>
      <p className="text-muted-foreground mb-6 text-sm">Uploading to {projectName}</p>

      {result && (
        <div role="status" className="bg-card mb-6 rounded-lg border p-4">
          <div className="flex items-center gap-3">
            <span className="text-sm font-medium">
              {pluralize(result.total_findings, "finding")} found
            </span>
            <VerdictBadge verdict={result.threshold_breached ? "blocked" : "passing"} />
          </div>
          <p className="text-muted-foreground mt-2 text-sm">
            {result.threshold_breached ? "The gate would block this project." : "The gate passes."}
          </p>
          <div className="mt-3 flex items-center gap-4 text-sm">
            <Link to={`/${slug}/findings`} className="text-primary underline hover:no-underline">
              View findings
            </Link>
            <Link to={`/${slug}/reports`} className="text-primary underline hover:no-underline">
              Back to reports
            </Link>
            <button
              type="button"
              onClick={resetForm}
              className="text-muted-foreground hover:text-foreground underline hover:no-underline"
            >
              Upload another
            </button>
          </div>
        </div>
      )}

      {uploadError && (
        <div
          role="alert"
          className="bg-destructive/10 text-destructive mb-6 rounded-md px-4 py-3 text-sm"
        >
          {uploadError}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="ingest-scanner" className="text-sm font-medium">Scanner</label>
          {scannerPicker}
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
          {fileError && <p role="alert" className="text-destructive mt-1 text-xs">{fileError}</p>}
        </div>

        <button
          type="submit"
          disabled={submitting || !selectedScanner || !fileContent}
          className="bg-primary text-primary-foreground hover:bg-primary/90 w-full rounded-md px-4 py-2 text-sm font-medium disabled:opacity-50"
        >
          {submitting ? "Uploading..." : "Upload"}
        </button>
      </form>
    </div>
  );
}
