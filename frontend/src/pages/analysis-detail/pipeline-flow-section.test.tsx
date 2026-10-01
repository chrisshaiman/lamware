// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

/**
 * The flow card must make a missing or skipped hand-off obvious (#653).
 *
 * Properties under test:
 *  - ok, skipped, failed and absent render differently, and `absent` never
 *    renders as a count: "0 items" for a key the report does not have is the
 *    silent-success reading #644/#646/#647/#648 hid behind.
 *  - report strings are text. Payload labels are attacker-controlled; a label
 *    that is an HTML tag must appear as characters, not as an element.
 */

import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { FlowEdge, PipelineFlow } from "#lib/types";
import { PipelineFlowView } from "./pipeline-flow-section";

const HOSTILE = "<img src=x onerror=alert(1)>";

function edge(partial: Partial<FlowEdge> & Pick<FlowEdge, "id" | "status">): FlowEdge {
  return {
    from: "cape",
    to: "ghidra",
    label: "CAPE payloads",
    reason: null,
    expected: null,
    carried: null,
    items: null,
    items_truncated: 0,
    counts: null,
    ...partial,
  };
}

const FLOW: PipelineFlow = {
  analysis_id: 1,
  has_report: true,
  nodes: [
    { id: "sample", label: HOSTILE, status: "ok", detail: "PE32", reason: null },
    { id: "cape", label: "CAPE", status: "ok", detail: "task 1", reason: null },
    { id: "ghidra", label: "Ghidra", status: "ok", detail: "3 programs loaded", reason: null },
  ],
  edges: [
    edge({
      id: "cape-ghidra-payloads",
      status: "ok",
      expected: 5,
      carried: 3,
      items: [
        { label: HOSTILE, status: "loaded", detail: null, functions: 377, sha256: "21e85e73cdd7" },
        { label: "Unpacked Shellcode", status: "empty", detail: "loaded, no functions recovered" },
      ],
      counts: { loaded: 1, empty: 1 },
    }),
    edge({
      id: "sample-ghidra",
      from: "sample",
      label: "original sample",
      status: "skipped",
      carried: 0,
      reason: "routed to ILSpy (wrapper, not a native program)",
    }),
    edge({
      id: "sample-ghidra-failed",
      from: "sample",
      label: "original sample",
      status: "failed",
      expected: 1,
      carried: 0,
      reason: "Import failed for file",
    }),
    // A server that wrongly sent 0 with absent must still not show a zero.
    edge({
      id: "cape-ghidra-injections",
      label: "injection buffers",
      status: "absent",
      carried: 0,
      reason: "report records no cape.injection_buffers",
    }),
  ],
};

function row(id: string): HTMLElement {
  return screen.getByTestId(`flow-edge-${id}`);
}

describe("PipelineFlowView", () => {
  it("renders ok, skipped, failed and absent edges differently", () => {
    render(<PipelineFlowView flow={FLOW} />);
    const ids = ["cape-ghidra-payloads", "sample-ghidra", "sample-ghidra-failed", "cape-ghidra-injections"];
    const statuses = ids.map((id) => within(row(id)).getByTestId("flow-status").textContent);
    expect(statuses).toEqual(["ok", "skipped", "failed", "absent"]);
    const classes = ids.map((id) => row(id).className);
    expect(new Set(classes).size).toBe(4);
    expect(row("sample-ghidra").className).toMatch(/amber/);
    expect(row("sample-ghidra-failed").className).toMatch(/red/);
    expect(row("cape-ghidra-injections").className).toMatch(/dashed/);
  });

  it("shows an ok edge's count against what was due", () => {
    render(<PipelineFlowView flow={FLOW} />);
    expect(within(row("cape-ghidra-payloads")).getByTestId("flow-carried")).toHaveTextContent("3 of 5 carried");
  });

  it("never renders an absent edge as a count", () => {
    render(<PipelineFlowView flow={FLOW} />);
    const absent = row("cape-ghidra-injections");
    expect(within(absent).getByTestId("flow-carried")).toHaveTextContent("not recorded");
    expect(absent.textContent).not.toMatch(/\b0\b/);
    expect(absent.textContent).toContain("report records no cape.injection_buffers");
  });

  it("shows a skipped edge's zero and its reason", () => {
    render(<PipelineFlowView flow={FLOW} />);
    const skipped = row("sample-ghidra");
    expect(within(skipped).getByTestId("flow-carried")).toHaveTextContent("0 carried");
    expect(skipped).toHaveTextContent("routed to ILSpy");
  });

  it("expands an edge to list its items", () => {
    render(<PipelineFlowView flow={FLOW} />);
    const r = row("cape-ghidra-payloads");
    expect(within(r).queryByText("Unpacked Shellcode")).toBeNull();
    fireEvent.click(within(r).getByRole("button"));
    expect(within(r).getByText("Unpacked Shellcode")).toBeInTheDocument();
    expect(within(r).getByText("377 functions")).toBeInTheDocument();
  });

  it("renders an attacker-controlled label as text, not markup", () => {
    const { container } = render(<PipelineFlowView flow={FLOW} />);
    fireEvent.click(within(row("cape-ghidra-payloads")).getByRole("button"));
    expect(container.querySelector("img")).toBeNull();
    // The node label and the item label both show the literal characters.
    expect(screen.getAllByText(HOSTILE).length).toBeGreaterThanOrEqual(2);
  });
});
