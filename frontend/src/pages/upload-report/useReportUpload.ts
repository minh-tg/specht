import { APIError, apiFetch } from "@/api/client";
import { queryKeys } from "@/api/hooks";
import type { IngestResponse } from "@/types/api";
import { useQueryClient } from "@tanstack/react-query";
import { type ChangeEvent, type RefObject, type SubmitEvent, useRef, useState } from "react";

export const MAX_FILE_SIZE = 10 * 1024 * 1024;

export interface ReportUpload {
  selectedScanner: string;
  setSelectedScanner: (value: string) => void;
  fileName: string | null;
  fileError: string | null;
  submitting: boolean;
  canSubmit: boolean;
  uploadError: string | null;
  result: IngestResponse | null;
  fileRef: RefObject<HTMLInputElement | null>;
  handleFileChange: (e: ChangeEvent<HTMLInputElement>) => Promise<void>;
  handleSubmit: (e: SubmitEvent) => Promise<void>;
  resetForm: () => void;
}

/** Owns the report upload form: scanner choice, file validation, submit and result. */
export function useReportUpload(slug: string): ReportUpload {
  const queryClient = useQueryClient();

  const [selectedScanner, setSelectedScanner] = useState("");
  const [fileContent, setFileContent] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [result, setResult] = useState<IngestResponse | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

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

  return {
    selectedScanner,
    setSelectedScanner,
    fileName,
    fileError,
    submitting,
    canSubmit: !submitting && !!selectedScanner && !!fileContent,
    uploadError,
    result,
    fileRef,
    handleFileChange,
    handleSubmit,
    resetForm,
  };
}
