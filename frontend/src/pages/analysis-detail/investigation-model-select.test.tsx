// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// The investigation panel's model selector shows the operator's list from the API
// (ADR-038), not a list compiled into the frontend.

import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("#hooks/use-investigation", async (orig) => ({
  ...(await orig<typeof import("#hooks/use-investigation")>()),
  useInvestigationModels: () => ({
    data: [
      { name: "local-qwen-llamacpp", label: "Local" },
      { name: "claude-haiku-4-5", label: "Haiku" },
    ],
  }),
}));

import { ModelSelect } from "./investigation-panel";

const labels = () => screen.getAllByRole("option").map((o) => o.textContent);

describe("ModelSelect", () => {
  it("offers exactly the models the API lists, with their labels, in order", () => {
    render(<ModelSelect value="claude-haiku-4-5" onChange={() => {}} />);
    expect(labels()).toEqual(["Local", "Haiku"]);
    expect((screen.getByRole("combobox") as HTMLSelectElement).value).toBe("claude-haiku-4-5");
  });

  it("still shows a session's model when the list no longer has it", () => {
    render(<ModelSelect value="claude-opus-4-6" onChange={() => {}} />);
    expect(labels()).toEqual(["claude-opus-4-6", "Local", "Haiku"]);
  });
});
