// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { FileDownloadButton } from "#components/shared/file-download-button";

interface DownloadBarProps {
  analysisId: number;
  taskId: string;
  pdfGenerated: boolean | null;
}

export function DownloadBar({ analysisId, taskId, pdfGenerated }: DownloadBarProps) {
  return (
    <div className="flex flex-wrap gap-2">
      {pdfGenerated && (
        <FileDownloadButton
          url={`/api/analyses/${analysisId}/pdf`}
          filename={`lamware_${taskId}.pdf`}
          label="PDF Report"
        />
      )}
      <FileDownloadButton
        url={`/api/analyses/${analysisId}/logs`}
        filename={`lamware_${taskId}.log`}
        label="Pipeline Log"
      />
      <FileDownloadButton
        url={`/api/analyses/${analysisId}/iocs/csv`}
        filename={`lamware_${taskId}_iocs.csv`}
        label="IOCs (CSV)"
      />
      <FileDownloadButton
        url={`/api/analyses/${analysisId}/iocs/stix`}
        filename={`lamware_${taskId}_iocs.stix.json`}
        label="IOCs (STIX)"
      />
    </div>
  );
}
