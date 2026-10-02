import { useProject, useScanners } from "@/api/hooks";
import { type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { UploadResultCard } from "./upload-report/UploadResultCard";
import { useReportUpload } from "./upload-report/useReportUpload";

export function UploadReport() {
  const { slug = "" } = useParams<{ slug: string; }>();
  const { data: project } = useProject(slug);
  const {
    data: scanners,
    isLoading: scannersLoading,
    isError: scannersError,
    refetch: refetchScanners,
  } = useScanners();
  const {
    selectedScanner,
    setSelectedScanner,
    fileName,
    fileError,
    submitting,
    canSubmit,
    uploadError,
    result,
    fileRef,
    handleFileChange,
    handleSubmit,
    resetForm,
  } = useReportUpload(slug);

  const projectName = project?.name ?? slug;

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

      {result && <UploadResultCard result={result} slug={slug} onReset={resetForm} />}

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
          disabled={!canSubmit}
          className="bg-primary text-primary-foreground hover:bg-primary/90 w-full rounded-md px-4 py-2 text-sm font-medium disabled:opacity-50"
        >
          {submitting ? "Uploading..." : "Upload"}
        </button>
      </form>
    </div>
  );
}
