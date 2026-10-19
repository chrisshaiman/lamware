// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { PIPELINE_STAGES } from "./constants";
import { stageFlagsFor } from "./stage-flags";

const base = {
  triage_completed: true,
  cape_completed: true,
  volatility_completed: true,
  ghidra_completed: true,
  interpret_completed: true,
  summary_completed: true,
  pdf_generated: true,
};

describe("stageFlagsFor (#804)", () => {
  it("covers every stage the progress bar draws", () => {
    const flags = stageFlagsFor({ ...base, stage_timings: { pcap: 1.6 } });
    for (const stage of PIPELINE_STAGES) {
      expect(flags, `no flag for ${stage}`).toHaveProperty(stage);
    }
  });

  it("marks PCAP complete when the pipeline timed the stage", () => {
    expect(stageFlagsFor({ ...base, stage_timings: { pcap: 1.6, cape: 454.3 } }).pcap).toBe(true);
  });

  it("marks PCAP not complete when the run recorded no pcap stage", () => {
    expect(stageFlagsFor({ ...base, stage_timings: { cape: 454.3 } }).pcap).toBe(false);
  });

  it("is unknown, like the column flags, when timings are absent", () => {
    expect(stageFlagsFor({ ...base, stage_timings: null }).pcap).toBeNull();
  });
});
