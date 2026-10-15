import { ErrorState } from "@/components/ErrorState";
import { FileDropzone } from "@/components/FileDropzone";
import { SelectField } from "@/components/SelectField";
import { SkeletonLines } from "@/components/SkeletonLines";
import { Button } from "@/components/ui/button";
import type { ScannerDescriptor } from "@/types/api";
import { type ReactNode } from "react";
import { SCAN_FILE_EXTENSIONS } from "./scanFile";
import { ScannerHelp } from "./ScannerHelp";
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
  fileSize,
  fileError,
  submitting,
  canSubmit,
  fileRef,
  handleFileChange,
  handleFile,
  clearFile,
  handleSubmit,
}: UploadFormProps) {
  const chosen = scanners?.find((s) => s.name === selectedScanner);
  const takes = [...new Set((chosen?.formats ?? []).flatMap((f) => f.extensions))];
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
          ...scanners.map((s) => ({ value: s.name, label: s.display_name || s.name })),
        ]}
      />
    );
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label htmlFor="ingest-scanner" className="text-sm font-medium">Scanner</label>
        {scannerPicker}
        <ScannerHelp scanner={chosen} />
      </div>

      <div>
        <label htmlFor="ingest-file" className="text-sm font-medium">
          Scan file
        </label>
        {takes.length > 0 && (
          <p id="ingest-file-takes" className="text-muted-foreground text-xs">
            Takes {takes.join(", ")}
          </p>
        )}
        <FileDropzone
          id="ingest-file"
          inputRef={fileRef}
          accept={SCAN_FILE_EXTENSIONS}
          describedBy={takes.length > 0 ? "ingest-file-takes" : undefined}
          fileName={fileName}
          fileSize={fileSize}
          error={fileError}
          disabled={submitting}
          onChange={handleFileChange}
          onFile={(file) => void handleFile(file)}
          onClear={clearFile}
        />
      </div>

      <Button type="submit" disabled={!canSubmit} className="w-full">
        {submitting ? "Uploading..." : "Upload"}
      </Button>
    </form>
  );
}
