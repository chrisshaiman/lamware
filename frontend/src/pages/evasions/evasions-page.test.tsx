// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// The evasions dashboard gets one row per MITRE technique and loads evidence only
// when asked (2026-11-28: it used to receive ~718k characters of evidence up front).

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

const evidenceEnabled: boolean[] = [];

vi.mock("#hooks/use-evasions", () => ({
  useEvasions: () => ({
    isLoading: false,
    isError: false,
    data: {
      total_analyses_with_evasion: 9,
      techniques: [
        {
          group: "T1614.001", technique: "Language/Locale Geofencing", mitre_id: "T1614.001",
          name_variants: 3, evidence: "GetUserDefaultLangID == 0x419", sample_count: 3,
          category: "guest_image", status: "open",
        },
      ],
      recommendations: [{ recommendation: "Set the guest locale to en-US", frequency: 4 }],
      recommendations_total: 30,
    },
  }),
  useEvasionEvidence: (_group: string, enabled: boolean) => {
    evidenceEnabled.push(enabled);
    return {
      data: enabled
        ? { pages: [{ total: 3, offset: 0, items: [{ analysis_id: 7, technique: "Geofencing", evidence: "locale check" }] }] }
        : undefined,
      hasNextPage: enabled,
      isLoading: false,
      isError: false,
      isFetchingNextPage: false,
      fetchNextPage: () => {},
    };
  },
  useMoreRecommendations: () => ({
    data: undefined, hasNextPage: false, isFetching: false, fetchNextPage: () => {},
  }),
}));

import { EvasionsPage } from "./evasions-page";

describe("EvasionsPage", () => {
  it("shows a grouped row with its variants and example, and no evidence until asked", () => {
    render(<EvasionsPage />);
    expect(screen.getByText("Named 3 ways by the analysis")).toBeTruthy();
    expect(screen.getByText(/Example: GetUserDefaultLangID/)).toBeTruthy();
    expect(screen.queryByText(/locale check/)).toBeNull();
    expect(evidenceEnabled.every((e) => !e)).toBe(true);
  });

  it("loads a technique's evidence when asked, with a link to each analysis", () => {
    render(<EvasionsPage />);
    fireEvent.click(screen.getByText("Show evidence (3 samples)"));
    expect(screen.getByText("#7").getAttribute("href")).toBe("/analyses/7");
    expect(screen.getByText(/locale check/)).toBeTruthy();
    expect(screen.getByText("Load more")).toBeTruthy();
  });

  it("offers the rest of the recommendations on request", () => {
    render(<EvasionsPage />);
    expect(screen.getByText("Load more (29 more)")).toBeTruthy();
  });
});
