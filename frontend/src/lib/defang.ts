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

/** Hosts that are noise rather than indicators — defanging these hurts readability. */
const SAFE_HOSTS = new Set([
  "e.g",
  "i.e",
  "etc.co", // guards against prose like "etc.company"
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
    if (SAFE_HOSTS.has(host.toLowerCase())) return match;
    const defangedHost = host.replace(/\./g, "[.]");
    const defangedPort = port ? port.replace(":", "[:]") : "";
    return `${defangScheme(scheme)}${defangedHost}${defangedPort}${rest ?? ""}`;
  });
}

/** True if the href points somewhere a click could actually reach. */
export function isNavigableHref(href: string | undefined): boolean {
  if (!href) return false;
  return /^\s*(https?|ftp|file|data|javascript|vbscript):/i.test(href);
}
