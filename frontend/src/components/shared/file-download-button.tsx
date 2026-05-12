// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// Auth-aware download button. Fetches via axios (with API key header),
// creates a blob URL, and triggers a browser download.

import { useState } from "react";
import { Download, Loader2 } from "lucide-react";
import apiClient from "#lib/api-client";
import { cn } from "#lib/utils";

interface FileDownloadButtonProps {
  url: string;
  filename: string;
  label: string;
  className?: string;
}

export function FileDownloadButton({
  url,
  filename,
  label,
  className,
}: FileDownloadButtonProps) {
  const [loading, setLoading] = useState(false);

  const handleDownload = async () => {
    setLoading(true);
    try {
      const response = await apiClient.get(url, { responseType: "blob" });
      const blobUrl = URL.createObjectURL(response.data as Blob);
      const a = document.createElement("a");
      a.href = blobUrl;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(blobUrl);
    } catch {
      // silently fail — the error will show in network tab
    } finally {
      setLoading(false);
    }
  };

  return (
    <button
      onClick={handleDownload}
      disabled={loading}
      className={cn(
        "flex items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text-primary)] disabled:opacity-50",
        className,
      )}
    >
      {loading ? (
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
      ) : (
        <Download className="h-3.5 w-3.5" />
      )}
      {label}
    </button>
  );
}
