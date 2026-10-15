import { APIError } from "@/api/client";
import { queryKeys } from "@/api/hooks";
import { useUploadReport } from "@/api/pageRequests";
import { playCue } from "@/lib/sound";
import type { IngestResponse } from "@/types/api";
import { useQueryClient } from "@tanstack/react-query";
import { type ChangeEvent, type RefObject, type SubmitEvent, useRef, useState } from "react";
import { readScanFile } from "./scanFile";

export const MAX_FILE_SIZE = 10 * 1024 * 1024;

export interface ReportUpload {
  selectedScanner: string;
  setSelectedScanner: (value: string) => void;
  fileName: string | null;
  fileSize: number | null;
  fileError: string | null;
  submitting: boolean;
  canSubmit: boolean;
  uploadError: string | null;
  result: IngestResponse | null;
  fileRef: RefObject<HTMLInputElement | null>;
  handleFileChange: (e: ChangeEvent<HTMLInputElement>) => Promise<void>;
  /** Takes a file from the picker or a drop through the same checks. */
  handleFile: (file: File) => Promise<void>;
  clearFile: () => void;
  handleSubmit: (e: SubmitEvent) => Promise<void>;
  resetForm: () => void;
}

/** Owns the report upload form: scanner choice, file validation, submit and result. */
export function useReportUpload(slug: string): ReportUpload {
  const queryClient = useQueryClient();
  const upload = useUploadReport(slug);

  const [selectedScanner, setSelectedScanner] = useState("");
  // The parsed file, wrapped so a file whose value is `null` still counts as chosen.
  const [scan, setScan] = useState<{ readonly value: unknown; } | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [fileSize, setFileSize] = useState<number | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [result, setResult] = useState<IngestResponse | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  function emptyInput() {
    if (fileRef.current) fileRef.current.value = "";
  }

  function dropFile() {
    setScan(null);
    setFileName(null);
    setFileSize(null);
  }

  /** Refused files also empty the input, so choosing the same file again still fires change. */
  function refuse(message: string) {
    setFileError(message);
    dropFile();
    emptyInput();
  }

  async function handleFile(file: File) {
    setFileError(null);
    setUploadError(null);
    setResult(null);

    if (file.size > MAX_FILE_SIZE) {
      refuse("File too large (max 10MB)");
      return;
    }

    // The wire carries raw_data as a JSON value, not a string. Accept the file only when it
    // reads, so a malformed upload is a local error instead of a server-side parse failure.
    const read = readScanFile(file.name, await file.text());
    if (!read.ok) {
      refuse(read.error);
      return;
    }

    setFileName(file.name);
    setFileSize(file.size);
    setScan({ value: read.value });
  }

  async function handleFileChange(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) await handleFile(file);
  }

  function clearFile() {
    dropFile();
    setFileError(null);
    emptyInput();
  }

  function resetForm() {
    setSelectedScanner("");
    clearFile();
    setUploadError(null);
    setResult(null);
  }

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    if (!slug || !selectedScanner || !scan) return;

    setSubmitting(true);
    setUploadError(null);
    setResult(null);

    try {
      const report = await upload.mutateAsync({
        scanner: selectedScanner,
        raw_data: scan.value,
      });
      setResult(report);
      playCue(report.threshold_breached ? "block" : "pass");
      clearFile();

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
    fileSize,
    fileError,
    submitting,
    canSubmit: !submitting && !!selectedScanner && !!scan,
    uploadError,
    result,
    fileRef,
    handleFileChange,
    handleFile,
    clearFile,
    handleSubmit,
    resetForm,
  };
}
