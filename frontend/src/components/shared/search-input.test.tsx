// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// SearchInput keeps a local value that follows the prop. The sync moved from an
// effect to render (react-hooks/set-state-in-effect); its behaviour must not change.

import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SearchInput } from "./search-input";

describe("SearchInput", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("shows a new value from outside without being typed into", () => {
    const { rerender } = render(<SearchInput value="old" onChange={() => {}} />);
    rerender(<SearchInput value="new" onChange={() => {}} />);
    expect((screen.getByRole("textbox") as HTMLInputElement).value).toBe("new");
  });

  it("reports typing once, after the debounce", () => {
    const onChange = vi.fn();
    render(<SearchInput value="" onChange={onChange} debounceMs={300} />);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "emotet" } });
    expect(onChange).not.toHaveBeenCalled();
    act(() => vi.advanceTimersByTime(300));
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith("emotet");
  });
});
