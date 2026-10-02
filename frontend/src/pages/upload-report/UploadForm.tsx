import type { ScannerDescriptor } from "@/types/api";
import { type ReactNode } from "react";
import type { ReportUpload } from "./useReportUpload";

interface UploadFormProps extends ReportUpload {
  scanners: ScannerDescriptor[] | undefined;
  scannersLoading: boolean;
  scannersError: boolean;
  onRetryScanners: () => void;
}

/** The report upload form: scanner choice, scan file and submit. */
export function UploadForm({
  scanners,
  scannersLoading,
  scannersError,
  onRetryScanners,
  selectedScanner,
  setSelectedScanner,
  fileName,
  fileError,
  submitting,
  canSubmit,
  fileRef,
  handleFileChange,
  handleSubmit,
}: UploadFormProps) {
  let scannerPicker: ReactNode;
  if (scannersLoading) {
    scannerPicker = <div className="text-muted-foreground mt-1 text-sm">Loading scanners…</div>;
  } else if (scannersError) {
    scannerPicker = (
      <div className="text-destructive mt-1 text-sm">
        Failed to load scanners.
        <button
          type="button"
          onClick={() => onRetryScanners()}
          className="text-action ml-2 text-sm underline underline-offset-2 hover:no-underline"
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
  );
}
