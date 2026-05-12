// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useState, useCallback } from "react";
import { Upload, FileUp, CheckCircle, AlertCircle } from "lucide-react";
import { useSubmitSample } from "#hooks/use-submit";
import { formatBytes } from "#lib/utils";

export function SubmitPage() {
  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const submitMutation = useSubmitSample();

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) setSelectedFile(file);
  }, []);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) setSelectedFile(file);
  }, []);

  const handleSubmit = async () => {
    if (!selectedFile) return;
    submitMutation.mutate(selectedFile);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Upload className="h-5 w-5 text-[var(--color-text-secondary)]" />
        <h1 className="text-xl font-semibold text-[var(--color-text-primary)]">Submit Sample</h1>
      </div>

      {/* Drop zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        className={`flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-12 text-center transition-colors ${
          dragOver
            ? "border-[var(--color-accent)] bg-[var(--color-accent)]/5"
            : "border-[var(--color-border)] bg-[var(--color-surface)]"
        }`}
      >
        <FileUp className="mb-3 h-10 w-10 text-[var(--color-text-muted)]" />
        <p className="text-sm text-[var(--color-text-secondary)]">
          Drag and drop a malware sample here
        </p>
        <p className="mt-1 text-xs text-[var(--color-text-muted)]">or</p>
        <label className="mt-3 cursor-pointer rounded-md border border-[var(--color-border)] bg-[var(--color-background)] px-4 py-2 text-sm text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-hover)]">
          Browse files
          <input type="file" className="hidden" onChange={handleFileSelect} />
        </label>
        <p className="mt-3 text-xs text-[var(--color-text-muted)]">Max 100 MB</p>
      </div>

      {/* Selected file info */}
      {selectedFile && !submitMutation.isSuccess && (
        <div className="flex items-center justify-between rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
          <div>
            <div className="text-sm font-medium text-[var(--color-text-primary)]">
              {selectedFile.name}
            </div>
            <div className="text-xs text-[var(--color-text-muted)]">
              {formatBytes(selectedFile.size)}
            </div>
          </div>
          <button
            onClick={handleSubmit}
            disabled={submitMutation.isPending}
            className="rounded-md bg-[var(--color-accent)] px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-[var(--color-accent-hover)] disabled:opacity-50"
          >
            {submitMutation.isPending ? "Submitting..." : "Submit for Analysis"}
          </button>
        </div>
      )}

      {/* Success */}
      {submitMutation.isSuccess && submitMutation.data && (
        <div className="flex items-start gap-3 rounded-md border border-green-800 bg-green-900/20 p-4">
          <CheckCircle className="mt-0.5 h-5 w-5 shrink-0 text-green-400" />
          <div>
            <div className="text-sm font-medium text-green-400">Sample submitted</div>
            <div className="mt-1 text-xs text-[var(--color-text-muted)]">
              {submitMutation.data.message}
            </div>
            <div className="mt-1 font-mono text-xs text-[var(--color-text-muted)]">
              Submission ID: {submitMutation.data.submission_id}
            </div>
          </div>
        </div>
      )}

      {/* Error */}
      {submitMutation.isError && (
        <div className="flex items-start gap-3 rounded-md border border-red-800 bg-red-900/20 p-4">
          <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-red-400" />
          <div>
            <div className="text-sm font-medium text-red-400">Submission failed</div>
            <div className="mt-1 text-xs text-[var(--color-text-muted)]">
              {(submitMutation.error as Error)?.message ?? "Unknown error"}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
