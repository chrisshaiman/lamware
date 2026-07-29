// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { defang, isInAppHref, isNavigableHref } from "#lib/defang";

describe("defang leaves ordinary malware-report tokens alone", () => {
  // Regression: the first version matched ANY `word.word` with a 2+ letter tail, so
  // every filename and version string in a report was mangled — 10 of 10 tested.
  // Over-defanging makes reports unreadable, which is the failure this module's
  // docstring warns about in the other direction.
  it.each([
    "kernel32.dll", "ntdll.dll", "advapi32.dll",
    "payload.exe", "sample.bin", "config.dat", "driver.sys", "report.pdf",
    "version 1.2.3", "Ghidra 11.0.3",
  ])("leaves %s untouched", (token) => {
    expect(defang(token)).toBe(token);
  });

  it("DOES defang a 4-part version string, because it is a valid IP", () => {
    // "CAPE 2.4.1.3" — genuinely ambiguous: 2.4.1.3 is a routable address, so no
    // pattern can tell it from a C2. Resolved toward defanging deliberately: leaving a
    // real address live is worse than a cosmetically-defanged version, and the result
    // stays readable. Asserted so the trade-off is explicit rather than accidental.
    expect(defang("CAPE 2.4.1.3")).toBe("CAPE 2[.]4[.]1[.]3");
  });

  it("leaves an out-of-range dotted quad alone", () => {
    expect(defang("build 1.2.3.400")).toBe("build 1.2.3.400");
    expect(defang("999.0.0.1")).toBe("999.0.0.1");
  });

  it("leaves a whole sentence of filenames untouched", () => {
    const s = "The sample calls CreateFileW in kernel32.dll and drops payload.exe.";
    expect(defang(s)).toBe(s);
  });

  it("still defangs a real domain in the same sentence", () => {
    expect(defang("kernel32.dll beacons to evil.com")).toBe(
      "kernel32.dll beacons to evil[.]com",
    );
  });

  it("defangs a filename-looking host when it carries a scheme", () => {
    // With an explicit scheme it is unambiguously a URL, whatever the tail looks like.
    expect(defang("http://evil.dll/x")).toBe("hxxp://evil[.]dll/x");
  });
});

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

describe("isInAppHref — allowlist, not deny-list", () => {
  it.each(["#section", "#", "/analyses/1", "/", "  /analyses/1  "])(
    "treats %s as in-app",
    (href) => expect(isInAppHref(href)).toBe(true),
  );

  // The bypass this replaced: no scheme colon, so the deny-list said "not navigable"
  // and it rendered as a live anchor. The browser resolves it against the page
  // protocol, giving https://evil.com/x.
  it.each([
    "//evil.com/x", "//evil.com", "  //evil.com/x",
    "/\\evil.com/x", "/\\/evil.com",
    "http://evil.com", "https://evil.com", "javascript:alert(1)",
    "data:text/html,<script>", "vbscript:msgbox", "ftp://evil.com",
    "mailto:a@b.com", "tel:+1234", "unknownscheme:whatever",
  ])("treats %s as NOT in-app (so it gets neutralised)", (href) => {
    expect(isInAppHref(href)).toBe(false);
  });

  it.each(["", undefined])("treats %s as not in-app", (href) => {
    expect(isInAppHref(href)).toBe(false);
  });

  it("is the exact inverse of isNavigableHref for real hrefs", () => {
    for (const h of ["#a", "/a", "//evil.com", "http://x.com", "javascript:1"]) {
      expect(isNavigableHref(h)).toBe(!isInAppHref(h));
    }
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
