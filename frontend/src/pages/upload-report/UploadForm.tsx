import { ErrorState } from "@/components/ErrorState";
import { SelectField } from "@/components/SelectField";
import { SkeletonLines } from "@/components/SkeletonLines";
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
    scannerPicker = <SkeletonLines label="Loading scanners" lines={1} className="mt-1" />;
  } else if (scannersError) {
    scannerPicker = (
      <ErrorState
        className="mt-1"
        title="Could not load scanners."
        onRetry={() => onRetryScanners()}
      />
    );
  } else if (!scanners || scanners.length === 0) {
    scannerPicker = (
      <div className="text-muted-foreground mt-1 text-sm">No scanners available.</div>
    );
  } else {
    scannerPicker = (
      <SelectField
        id="ingest-scanner"
        className="mt-1 w-full"
        value={selectedScanner}
        onValueChange={setSelectedScanner}
        options={[
          { value: "", label: "Select a scanner" },
          ...scanners.map((s) => ({ value: s.name, label: `${s.name} (${s.version})` })),
        ]}
      />
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
