// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// A "–" written directly in JSX text is shown as those six characters: JSX
// text does not interpret JavaScript escapes, only string literals do. Two shipped
// that way (the analyses footer and an empty status, found 2026-11-27). Structural,
// because the only other way to see it is to render every page: scan the sources
// for a \uXXXX right after a tag or an expression's closing brace.

import { describe, expect, it } from "vitest";

// Every component's source, as text (Vite's glob with ?raw; no Node APIs needed).
const SOURCES = import.meta.glob<string>("/src/**/*.tsx", {
  query: "?raw",
  import: "default",
  eager: true,
});

const LITERAL_ESCAPE_IN_JSX_TEXT = /(>|\})\\u[0-9a-fA-F]{4}/;

describe("JSX text", () => {
  it("has no \\uXXXX escapes written as text", () => {
    const files = Object.keys(SOURCES);
    expect(files.length).toBeGreaterThan(20); // the glob found the components
    const hits = files.filter((f) => LITERAL_ESCAPE_IN_JSX_TEXT.test(SOURCES[f]));
    expect(hits).toEqual([]);
  });

  it("the pattern catches the shape that shipped", () => {
    expect(LITERAL_ESCAPE_IN_JSX_TEXT.test("Showing {a}\\u2013{b}")).toBe(true);
    expect(LITERAL_ESCAPE_IN_JSX_TEXT.test('<span>\\u2014</span>')).toBe(true);
    expect(LITERAL_ESCAPE_IN_JSX_TEXT.test('Showing {a}{"\\u2013"}{b}')).toBe(false);
  });
});
