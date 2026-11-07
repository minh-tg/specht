import { queryKeys } from "@/api/hooks";
import { useUploadReport } from "@/api/pageRequests";
import { Button } from "@/components/ui/button";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

/**
 * Sends a small report the product ships with, through the same path as an upload, so someone can
 * see findings, a verdict and a fix before touching a pipeline. It is an ordinary report, so the
 * Reports page removes it.
 */
export function SampleReportButton({ slug }: { readonly slug: string; }) {
  const queryClient = useQueryClient();
  const upload = useUploadReport(slug);
  const [failed, setFailed] = useState(false);
  const [loading, setLoading] = useState(false);

  async function send() {
    setFailed(false);
    setLoading(true);
    try {
      const response = await fetch("/sample-trivy-report.json");
      if (!response.ok) throw new Error("the sample report is missing");
      await upload.mutateAsync({ scanner: "trivy", raw_data: await response.json() });
      await queryClient.invalidateQueries({ queryKey: queryKeys.projectStats(slug) });
    } catch {
      setFailed(true);
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <Button type="button" variant="outline" disabled={loading} onClick={() => void send()}>
        {loading ? "Sending the sample..." : "Try a sample report"}
      </Button>
      {failed && (
        <p role="alert" className="text-destructive w-full text-meta">
          Could not send the sample report. Try again, or upload a report of your own.
        </p>
      )}
    </>
  );
}
