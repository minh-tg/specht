import { useProject, useScanners } from "@/api/hooks";
import { Button } from "@/components/ui/button";
import { Link, useParams } from "react-router-dom";
import { UploadForm } from "./upload-report/UploadForm";
import { UploadResultCard } from "./upload-report/UploadResultCard";
import { useReportUpload } from "./upload-report/useReportUpload";

/** The scanner a refused file looks like, when the server named exactly one. */
export function suggestedScanner(message: string | null): string | null {
  return message ? (/choose (\S+) as the scanner/.exec(message)?.[1] ?? null) : null;
}

export function UploadReport() {
  const { slug = "" } = useParams<{ slug: string; }>();
  const { data: project } = useProject(slug);
  const {
    data: scanners,
    isLoading: scannersLoading,
    isError: scannersError,
    refetch: refetchScanners,
  } = useScanners();
  const upload = useReportUpload(slug);

  const projectName = project?.name ?? slug;

  if (project?.permissions?.upload_reports === false) {
    return (
      <div className="mx-auto max-w-lg px-4 py-8">
        <Link
          to={`/${slug}/reports`}
          className="text-muted-foreground hover:text-foreground mb-6 inline-block text-body"
        >
          &larr; {projectName}
        </Link>
        <h1 className="mb-2 text-title font-bold">Upload a report</h1>
        <p className="text-muted-foreground text-body">
          Only project managers and administrators can upload reports to {projectName}.
        </p>
      </div>
    );
  }

  const suggested = suggestedScanner(upload.uploadError);

  return (
    <div className="mx-auto max-w-lg px-4 py-8">
      <Link
        to={`/${slug}/reports`}
        className="text-muted-foreground hover:text-foreground mb-6 inline-block text-body"
      >
        &larr; {projectName}
      </Link>

      <h1 className="mb-2 text-title font-bold">Upload a report</h1>
      <p className="text-muted-foreground mb-6 text-body">Uploading to {projectName}</p>

      {upload.result && (
        <UploadResultCard result={upload.result} slug={slug} onReset={upload.resetForm} />
      )}

      {upload.uploadError && (
        <div
          role="alert"
          className="bg-destructive/10 text-destructive mb-6 rounded-md px-4 py-3 text-body"
        >
          {upload.uploadError}
          {suggested && (
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="ml-2"
              onClick={() => upload.setSelectedScanner(suggested)}
            >
              Use {suggested}
            </Button>
          )}
        </div>
      )}

      <UploadForm
        {...upload}
        scanners={scanners}
        scannersLoading={scannersLoading}
        scannersError={scannersError}
        onRetryScanners={() => refetchScanners()}
      />
    </div>
  );
}
