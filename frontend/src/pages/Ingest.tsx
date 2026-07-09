import { APIError, apiFetch } from "@/api/client";
import { useProjects } from "@/api/hooks";
import type { Report } from "@/types/api";
import { type ChangeEvent, type FormEvent, useRef, useState } from "react";

const MAX_FILE_SIZE = 10 * 1024 * 1024;
const SCANNERS = ["trivy", "osv-scanner"];

export function Ingest() {
  const { data: projects } = useProjects();

  const [selectedProject, setSelectedProject] = useState("");
  const [selectedScanner, setSelectedScanner] = useState("trivy");
  const [fileContent, setFileContent] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<
    { success: boolean; reportId?: string; error?: string; } | null
  >(null);
  const fileRef = useRef<HTMLInputElement>(null);

  function handleFileChange(e: ChangeEvent<HTMLInputElement>) {
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

    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = () => {
      setFileContent(reader.result as string);
    };
    reader.readAsText(file);
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!selectedProject || !selectedScanner || !fileContent) return;

    setSubmitting(true);
    setResult(null);

    try {
      const report = await apiFetch<Report>("/api/v1/reports", {
        method: "POST",
        body: JSON.stringify({
          project: selectedProject,
          scanner: selectedScanner,
          raw_data: fileContent,
        }),
      });
      setResult({ success: true, reportId: report.id });
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
          <select
            id="ingest-scanner"
            className="border-input bg-background mt-1 block w-full rounded-md border px-3 py-2 text-sm"
            value={selectedScanner}
            onChange={(e) => setSelectedScanner(e.target.value)}
          >
            {SCANNERS.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
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
