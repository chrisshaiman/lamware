// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

/**
 * Defang indicators so an analyst cannot navigate to live malware infrastructure
 * by mis-clicking a rendered report.
 *
 * The pipeline already has the opposite direction: `grounding_check.normalize()`
 * turns `hxxp://evil[.]com` into `http://evil.com` so claims can be compared against
 * decompilation. Nothing did the inverse before display, so an LLM narrative naming a
 * C2 rendered as a live clickable link (#212).
 *
 * This is the standard threat-intel convention (CISA, MISP, abuse.ch): a defanged
 * indicator stays readable and copy-pasteable but is inert as a URL.
 *
 * Deliberately conservative — it defangs the transport-relevant parts (scheme, dots in
 * hostnames, the port colon) and leaves everything else alone. Over-defanging mangles
 * legitimate prose; under-defanging leaves a live link.
 *
 * KNOWN GAPS, measured rather than assumed. These forms pass through untouched:
 *   - IPv6 literals      `http://[2001:db8::1]:8080/x`
 *   - single-label hosts `http://internal-c2:8080/x`, `http://localhost:8080/x`
 *   - userinfo           `http://user:pass@evil.com/x` (host is defanged, scheme is not)
 *
 * They are safe in the UI regardless: MarkdownProse's anchor override renders any
 * navigable href as inert text, so these display as non-clickable. The gap is
 * cosmetic (the text still reads like a live URL), not a click-through risk — and it
 * is why that override is load-bearing rather than belt-and-braces. Widening the
 * pattern to cover them is a fine follow-up; doing it carelessly starts mangling
 * ordinary prose, which is the failure mode that matters in the other direction.
 */

// Matches a host or URL: optional scheme, then EITHER a dotted quad OR a dotted
// hostname with a TLD-like final label, then optional port and path.
//
// The IPv4 alternative is listed first and is not optional cleverness: an earlier
// version only matched alphabetic TLDs, so `http://10.0.0.5:443/x` fell through to a
// separate IP pass that defanged the dots but left `http://` and the port colon
// intact. IP-literal C2s are common enough that missing them defeats the point.
const URLISH = new RegExp(
  [
    "\\b((?:https?|ftp)://)?", // 1: scheme
    "((?:\\d{1,3}(?:\\.\\d{1,3}){3})", // 2: IPv4 ...
    "|(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,})", //    ... or hostname
    "(:\\d{1,5})?", // 3: port
    "((?:/[^\\s<>\"']*)?)", // 4: path/query
  ].join(""),
  "gi",
);

/**
 * A bare `label.label` is only treated as a hostname when the final label is a real TLD.
 *
 * Without this, the pattern matched ANY `word.word` with a 2+ letter tail — which is
 * every filename in a malware report. Measured on the shipped version: `kernel32.dll`,
 * `ntdll.dll`, `payload.exe`, `report.pdf`, `config.dat`, `driver.sys` and the version
 * string `CAPE 2.4.1.3` were ALL mangled — 10 of 10 ordinary strings. That is the
 * over-defanging this module's own docstring calls the failure mode that matters, and it
 * would have made every rendered report unreadable.
 *
 * A TLD list is the fix because the collision is one-sided: `.dll`, `.exe`, `.bin`,
 * `.sys`, `.dat`, `.pdf` are not TLDs. It is not exhaustive — new gTLDs appear — but a
 * miss here only means an indicator renders un-defanged as TEXT. It is never a
 * click-through risk: MarkdownProse neutralises any navigable href regardless.
 *
 * Anything with an explicit scheme is defanged whatever its tail (`http://evil.dll` is
 * unambiguously a URL), and bare IPv4 is always defanged.
 */
const TLDS = new Set([
  // generic
  "com", "net", "org", "info", "biz", "name", "pro", "mobi", "app", "dev", "io",
  "co", "me", "tv", "cc", "xyz", "top", "site", "online", "shop", "store", "club",
  "live", "life", "world", "space", "website", "tech", "cloud", "digital", "link",
  "click", "download", "stream", "gdn", "loan", "work", "party", "review", "date",
  "faith", "science", "racing", "win", "bid", "trade", "accountant", "cricket",
  "men", "webcam", "press", "host", "fun", "icu", "monster", "quest", "cyou",
  "buzz", "rest", "wiki", "email", "network", "systems", "solutions", "services",
  // sponsored / restricted
  "edu", "gov", "mil", "int", "arpa",
  // ccTLDs commonly seen in C2 infrastructure
  "ru", "su", "cn", "br", "in", "ir", "kp", "ua", "by", "pl", "cz", "ro", "bg",
  "rs", "tr", "kz", "uz", "vn", "th", "id", "my", "sg", "hk", "tw", "jp", "kr",
  "de", "fr", "nl", "be", "ch", "at", "it", "es", "pt", "se", "no", "fi", "dk",
  "uk", "ie", "gr", "hu", "sk", "si", "hr", "lt", "lv", "ee", "md", "ge", "am",
  "az", "us", "ca", "mx", "ar", "cl", "pe", "ve", "za", "ng", "ke", "eg", "ma",
  "au", "nz", "il", "ae", "sa", "pk", "bd", "lk", "np", "ph", "eu", "tk", "ml",
  "ga", "cf", "gq", "pw", "ws", "to", "nu", "cx", "ai", "sh", "st", "im", "gg",
]);

function defangScheme(scheme: string | undefined): string {
  if (!scheme) return "";
  return scheme.replace(/^http/i, "hxxp").replace(/^ftp/i, "fxp");
}

/**
 * Rewrite URLs, hostnames and IPv4 addresses into their defanged forms.
 *
 * `http://evil.com:8080/x` -> `hxxp://evil[.]com[:]8080/x`
 * `192.168.1.1`            -> `192[.]168[.]1[.]1`
 */
export function defang(text: string): string {
  if (!text) return text;

  // One pass handles hostnames and IPv4 alike. Already-defanged input contains `[.]`,
  // which the pattern cannot match, so this is naturally idempotent.
  return text.replace(URLISH, (match, scheme, host, port, rest) => {
    // A dotted quad is only an IP if every octet is in range. This rejects
    // "1.2.3.400" and "999.0.0.1" — but note it CANNOT separate a 4-part version
    // string from an address, because "2.4.1.3" is a valid IP. That ambiguity is
    // resolved toward defanging: the cost of leaving a real C2 address live is
    // higher than the cost of a cosmetically-defanged version number, and the
    // defanged form is still readable and copy-pasteable.
    const isIpv4 =
      /^\d{1,3}(\.\d{1,3}){3}$/.test(host) &&
      host.split(".").every((octet: string) => Number(octet) <= 255);
    if (!scheme && !isIpv4) {
      // Bare `something.something` — only a hostname if the tail is a real TLD.
      // Otherwise it is a filename (kernel32.dll) or a version (2.4.1.3): leave it.
      const tld = host.slice(host.lastIndexOf(".") + 1).toLowerCase();
      if (!TLDS.has(tld)) return match;
    }
    const defangedHost = host.replace(/\./g, "[.]");
    const defangedPort = port ? port.replace(":", "[:]") : "";
    return `${defangScheme(scheme)}${defangedHost}${defangedPort}${rest ?? ""}`;
  });
}

/**
 * True if the href is safe to leave as a working in-app link.
 *
 * ALLOWLIST, deliberately. The first version was a deny-list of known-navigable schemes
 * (`https?|ftp|file|data|javascript|vbscript:`) and anything unmatched was rendered as a
 * live anchor. **`//evil.com/x` has no scheme colon, so it fell through and rendered
 * clickable** — the browser resolves a protocol-relative URL against the page protocol,
 * giving `https://evil.com/x`. `rehype-sanitize` permits it for the same reason: its
 * protocol check sees no scheme.
 *
 * A deny-list on a security boundary has to enumerate every way to express "off-site",
 * and it will always be incomplete. This enumerates the two forms that are unambiguously
 * in-app instead:
 *
 *   `#fragment`          same-document anchor
 *   `/path` (not `//`)   root-relative path on this origin
 *
 * Everything else — schemes, protocol-relative `//host`, backslash variants some
 * browsers normalise to `//`, and anything unrecognised — is treated as navigable and
 * neutralised.
 */
export function isInAppHref(href: string | undefined): boolean {
  if (!href) return false;
  const h = href.trim();
  if (h.startsWith("#")) return true;
  // Root-relative, but NOT protocol-relative. Backslashes are excluded because
  // several browsers normalise `\\host` and `/\host` to `//host`.
  if (/^\/(?![/\\])/.test(h)) return true;
  return false;
}

/**
 * True if the href points somewhere a click could actually reach off this origin.
 *
 * Retained as the inverse of {@link isInAppHref} so callers can read either way round;
 * the allowlist is the single source of truth.
 */
export function isNavigableHref(href: string | undefined): boolean {
  if (!href) return false;
  return !isInAppHref(href);
}
