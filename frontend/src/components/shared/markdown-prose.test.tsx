// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

/**
 * The property under test: model-authored prose must never render something an
 * analyst can click through to live malware infrastructure (#212).
 *
 * The assertion that matters is "no anchor with a navigable href exists" — not "the
 * text looks defanged". Those come apart exactly where the bug lived: an explicit
 * markdown link hides the indicator in the href, where a text-only defang never sees
 * it, while the visible label reads as harmless prose.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MarkdownProse } from "#components/shared/markdown-prose";

function navigableAnchors(container: HTMLElement): HTMLAnchorElement[] {
  return Array.from(container.querySelectorAll("a")).filter((a) =>
    /^\s*(https?|ftp|file|data|javascript|vbscript):/i.test(a.getAttribute("href") ?? ""),
  );
}

describe("MarkdownProse — no live links from model output", () => {
  it("renders a bare C2 URL as inert text", () => {
    const { container } = render(
      <MarkdownProse>{"C2 is at http://evil.com:8080/gate.php"}</MarkdownProse>,
    );
    expect(navigableAnchors(container)).toHaveLength(0);
    expect(container.textContent).toContain("hxxp://evil[.]com[:]8080");
  });

  it("neutralises an explicit markdown link whose href hides the indicator", () => {
    // The regression case: visible text is innocuous, the C2 is only in the href.
    const { container } = render(
      <MarkdownProse>{"See [the report](http://evil.com/payload)"}</MarkdownProse>,
    );
    expect(navigableAnchors(container)).toHaveLength(0);
    expect(screen.getByText("the report")).toBeInTheDocument();
  });

  it("neutralises a javascript: href", () => {
    const { container } = render(
      <MarkdownProse>{"[click](javascript:alert(1))"}</MarkdownProse>,
    );
    expect(navigableAnchors(container)).toHaveLength(0);
  });

  it("defangs a bare hostname in prose", () => {
    const { container } = render(
      <MarkdownProse>{"It beacons to evil.com every minute."}</MarkdownProse>,
    );
    expect(container.textContent).toContain("evil[.]com");
    expect(navigableAnchors(container)).toHaveLength(0);
  });

  it("defangs IPv4 C2 addresses", () => {
    const { container } = render(
      <MarkdownProse>{"Connects to 203.0.113.5 on port 443."}</MarkdownProse>,
    );
    expect(container.textContent).toContain("203[.]0[.]113[.]5");
  });

  // The cases below are the reason the anchor override exists. defang() only
  // recognises dotted hostnames and IPv4, so these hrefs pass through it untouched
  // and would render as live anchors if the override were removed. Verified by
  // deleting the override and watching exactly these fail.
  it("neutralises an IPv6-literal C2 that defang() cannot rewrite", () => {
    const { container } = render(
      <MarkdownProse>{"[beacon](http://[2001:db8::1]:8080/gate)"}</MarkdownProse>,
    );
    expect(navigableAnchors(container)).toHaveLength(0);
  });

  it("neutralises a single-label host that defang() cannot rewrite", () => {
    const { container } = render(
      <MarkdownProse>{"[internal](http://internal-c2:8080/x)"}</MarkdownProse>,
    );
    expect(navigableAnchors(container)).toHaveLength(0);
  });

  it("neutralises a PROTOCOL-RELATIVE href (//host) — the deny-list bypass", () => {
    // No scheme colon, so the original deny-list rendered this as a live anchor and the
    // browser resolved it against the page protocol -> https://evil.com/payload.
    const { container } = render(
      <MarkdownProse>{"See [the report](//evil.com/payload)"}</MarkdownProse>,
    );
    const anchors = Array.from(container.querySelectorAll("a"));
    expect(anchors.filter((a) => (a.getAttribute("href") ?? "").startsWith("//")))
      .toHaveLength(0);
    expect(navigableAnchors(container)).toHaveLength(0);
  });

  it("does not mangle DLL and EXE names in narrative prose", () => {
    const text = "It calls CreateFileW in kernel32.dll and drops payload.exe.";
    const { container } = render(<MarkdownProse>{text}</MarkdownProse>);
    expect(container.textContent).toContain("kernel32.dll");
    expect(container.textContent).toContain("payload.exe");
    expect(container.textContent).not.toContain("[.]dll");
  });

  it("keeps in-app relative links clickable", () => {
    const { container } = render(
      <MarkdownProse>{"[analysis](/analyses/42)"}</MarkdownProse>,
    );
    const anchor = container.querySelector("a");
    expect(anchor).not.toBeNull();
    expect(anchor?.getAttribute("href")).toBe("/analyses/42");
    expect(navigableAnchors(container)).toHaveLength(0);
  });

  it("still renders ordinary markdown structure", () => {
    const { container } = render(
      <MarkdownProse>{"## Findings\n\n- one\n- two"}</MarkdownProse>,
    );
    expect(container.querySelector("h2")?.textContent).toBe("Findings");
    expect(container.querySelectorAll("li")).toHaveLength(2);
  });

  it("leaves benign prose untouched", () => {
    const text = "The sample decrypts its configuration and exits.";
    const { container } = render(<MarkdownProse>{text}</MarkdownProse>);
    expect(container.textContent).toContain(text);
  });
});

/**
 * #731: an <img> fetches on render, so the property is "no <img> element exists at
 * all" — not "the src looks defanged". Every form below rendered a live <img src>
 * before this change, reproduced with the real unified/remark-gfm/rehype-sanitize.
 */
describe("MarkdownProse — no images from model output (#731)", () => {
  const cases: Array<[string, string]> = [
    ["protocol-relative", "![beacon](//evil.onion/a.png)"],
    ["non-TLD host", "![x](http://c2host/pixel.gif)"],
    ["decimal IPv4", "![x](http://3232235777/p.png)"],
    ["same-origin path", "![x](/api/analyses/1/beacon.png)"],
    ["reference style", "![x][r]\n\n[r]: //evil.onion/r.png"],
    ["data URI", "![x](data:image/png;base64,iVBORw0KGgo=)"],
  ];
  for (const [label, md] of cases) {
    it(`renders no <img> for a ${label} image`, () => {
      const { container } = render(<MarkdownProse>{md}</MarkdownProse>);
      expect(container.querySelectorAll("img")).toHaveLength(0);
    });
  }

  it("still tells the analyst an image was referenced, by its alt text", () => {
    const { container } = render(<MarkdownProse>{"![payload screenshot](//host/s.png)"}</MarkdownProse>);
    expect(container.textContent).toContain("[image: payload screenshot]");
    const marker = container.querySelector("[data-neutralised-image]");
    expect(marker?.getAttribute("title") ?? "").not.toMatch(/https?:\/\//i);
  });
});

describe("MarkdownProse — anchors carry HTML attributes only", () => {
  it("does not spread react-markdown's node prop onto <a>", () => {
    const { container } = render(<MarkdownProse>{"[home](/analyses)"}</MarkdownProse>);
    const a = container.querySelector("a");
    expect(a).not.toBeNull();
    expect(a?.hasAttribute("node")).toBe(false);
  });
});
