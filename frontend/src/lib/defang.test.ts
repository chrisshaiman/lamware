// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { defang, isNavigableHref } from "#lib/defang";

describe("defang", () => {
  it("neutralises a full C2 URL", () => {
    expect(defang("http://evil.com:8080/gate.php")).toBe(
      "hxxp://evil[.]com[:]8080/gate.php",
    );
  });

  it("neutralises https and preserves the path", () => {
    expect(defang("https://bad.example.org/a/b?c=1")).toBe(
      "hxxps://bad[.]example[.]org/a/b?c=1",
    );
  });

  it("neutralises a bare hostname with no scheme", () => {
    expect(defang("beacon traffic to evil.com every 60s")).toBe(
      "beacon traffic to evil[.]com every 60s",
    );
  });

  it("neutralises IPv4 addresses", () => {
    expect(defang("connects to 192.168.1.1")).toBe("connects to 192[.]168[.]1[.]1");
  });

  it("neutralises an IP-literal C2 URL completely — scheme, dots and port", () => {
    // Regression: the hostname pattern required an alphabetic TLD, so IP-literal
    // URLs skipped it and kept a live-looking `http://` and port.
    expect(defang("http://10.0.0.5:443/x")).toBe("hxxp://10[.]0[.]0[.]5[:]443/x");
  });

  it("round-trips to what the pipeline's normalize() expects", () => {
    // grounding_check.normalize() maps hxxp->http and [.]->. ; defang is its inverse,
    // so an indicator defanged here is still comparable after normalisation.
    const defanged = defang("http://evil.com");
    expect(defanged.replace(/hxxp/g, "http").replace(/\[\.\]/g, ".")).toBe(
      "http://evil.com",
    );
  });

  it("leaves ordinary prose alone", () => {
    const prose = "The sample decrypts its config and then exits.";
    expect(defang(prose)).toBe(prose);
  });

  it("is idempotent — defanging twice does not double-mangle", () => {
    const once = defang("http://evil.com");
    expect(defang(once)).toBe(once);
  });

  it("handles empty input", () => {
    expect(defang("")).toBe("");
  });
});

describe("isNavigableHref", () => {
  it.each(["http://x.com", "https://x.com", "ftp://x.com", "file:///etc/passwd"])(
    "treats %s as navigable",
    (href) => expect(isNavigableHref(href)).toBe(true),
  );

  it.each(["javascript:alert(1)", "data:text/html,<script>", "vbscript:msgbox"])(
    "treats %s as navigable (so it gets neutralised)",
    (href) => expect(isNavigableHref(href)).toBe(true),
  );

  it.each(["#section", "/analyses/1", "", undefined])(
    "treats %s as in-app, not navigable",
    (href) => expect(isNavigableHref(href)).toBe(false),
  );

  it("is not fooled by leading whitespace", () => {
    expect(isNavigableHref("  javascript:alert(1)")).toBe(true);
  });
});
