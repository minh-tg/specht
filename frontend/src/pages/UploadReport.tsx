import { useProject, useScanners } from "@/api/hooks";
import { Link, useParams } from "react-router-dom";
import { UploadForm } from "./upload-report/UploadForm";
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
  const upload = useReportUpload(slug);

  const projectName = project?.name ?? slug;

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

      {upload.result && (
        <UploadResultCard result={upload.result} slug={slug} onReset={upload.resetForm} />
      )}

      {upload.uploadError && (
        <div
          role="alert"
          className="bg-destructive/10 text-destructive mb-6 rounded-md px-4 py-3 text-sm"
        >
          {upload.uploadError}
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
