// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
import type { AnalysisDetail } from "./types";

/**
 * Per-stage completion for the analysis page's progress bar (#804).
 *
 * Seven stages have a boolean column on the analysis row. PCAP does not: the
 * page used to read `stageFlags["pcap"]`, get `undefined`, and draw that bar as
 * pending on every analysis ever shown, including ones where Zeek and Suricata
 * ran. The pipeline records a `pcap` entry in `stage_timings` when the stage
 * ran, so that is the flag; `null` (unknown) when timings are absent, matching
 * what the column-backed flags return for an old row.
 */
export function stageFlagsFor(
  analysis: Pick<
    AnalysisDetail,
    | "triage_completed"
    | "cape_completed"
    | "volatility_completed"
    | "ghidra_completed"
    | "interpret_completed"
    | "summary_completed"
    | "pdf_generated"
    | "stage_timings"
  >,
): Record<string, boolean | null> {
  const timings = analysis.stage_timings;
  return {
    triage: analysis.triage_completed,
    cape: analysis.cape_completed,
    pcap: timings ? Object.prototype.hasOwnProperty.call(timings, "pcap") : null,
    volatility: analysis.volatility_completed,
    ghidra: analysis.ghidra_completed,
    interpret: analysis.interpret_completed,
    summary: analysis.summary_completed,
    pdf: analysis.pdf_generated,
  };
}
