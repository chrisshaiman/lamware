#!/usr/bin/env node
// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// Dependency-audit gate for CI.
//
// `npm audit --audit-level=high` is all-or-nothing: one inapplicable advisory turns the
// job red, and the only lever npm offers is lowering the threshold for everything. That
// is how a security check becomes noise — and a red check that everyone merges over
// stops distinguishing a real finding from a stale one.
//
// This gate keeps the threshold at high/critical and requires every exception to be
// written down with a reason and an expiry, so accepting a finding is a visible,
// reviewable decision rather than a silently loosened flag.
//
// Exits non-zero on: any unlisted high/critical advisory, any expired exception, or an
// exception that no longer matches a real finding (so the list cannot accumulate cruft).

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const FRONTEND_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const BLOCKING = new Set(["high", "critical"]);

function loadExceptions() {
  const path = join(FRONTEND_DIR, "audit-exceptions.json");
  try {
    return JSON.parse(readFileSync(path, "utf8")).exceptions ?? [];
  } catch (err) {
    if (err.code === "ENOENT") return [];
    throw new Error(`could not parse audit-exceptions.json: ${err.message}`);
  }
}

function runAudit() {
  // npm audit exits non-zero when it finds anything, so a throw here is expected;
  // the JSON we need is still on stdout.
  try {
    return JSON.parse(
      execFileSync("npm", ["audit", "--json"], {
        cwd: FRONTEND_DIR,
        encoding: "utf8",
        maxBuffer: 64 * 1024 * 1024,
      }),
    );
  } catch (err) {
    if (err.stdout) return JSON.parse(err.stdout);
    throw new Error(`npm audit did not return JSON: ${err.message}`);
  }
}

// Collect blocking advisories as {id, package, title, severity}.
function blockingFindings(report) {
  const out = [];
  for (const [pkg, vuln] of Object.entries(report.vulnerabilities ?? {})) {
    if (!BLOCKING.has(vuln.severity)) continue;
    for (const via of vuln.via ?? []) {
      // A string `via` means "vulnerable only through another package" — the advisory
      // itself is reported on that other package, so counting it here double-reports.
      if (typeof via !== "object") continue;
      out.push({
        // Advisory URLs end in the GHSA id, e.g. .../advisories/GHSA-qwww-vcr4-c8h2
        id: String(via.url ?? "").split("/").pop(),
        package: pkg,
        title: via.title ?? "(no title)",
        severity: vuln.severity,
        url: via.url ?? "",
      });
    }
  }
  return out;
}

function main() {
  const exceptions = loadExceptions();
  const report = runAudit();
  const findings = blockingFindings(report);

  const today = new Date().toISOString().slice(0, 10);
  const problems = [];

  const expired = exceptions.filter((e) => e.reviewBy && e.reviewBy < today);
  for (const e of expired) {
    problems.push(`EXPIRED exception ${e.id} (${e.package}) — reviewBy ${e.reviewBy} has passed. Re-verify it still does not apply, then extend or remove it.`);
  }

  const allowed = new Set(exceptions.filter((e) => !e.reviewBy || e.reviewBy >= today).map((e) => e.id));
  const unlisted = findings.filter((f) => !allowed.has(f.id));
  for (const f of unlisted) {
    problems.push(`UNACCEPTED ${f.severity} advisory ${f.id} in ${f.package}: ${f.title}\n    ${f.url}`);
  }

  // An exception for something no longer reported is stale — drop it, so the file
  // reflects live risk rather than history.
  const live = new Set(findings.map((f) => f.id));
  for (const e of exceptions) {
    if (!live.has(e.id)) {
      problems.push(`STALE exception ${e.id} (${e.package}) — no longer reported by npm audit. Remove it.`);
    }
  }

  const counts = report.metadata?.vulnerabilities ?? {};
  console.log(`[audit-gate] npm audit: ${JSON.stringify(counts)}`);
  console.log(`[audit-gate] blocking advisories found: ${findings.length}, accepted exceptions: ${allowed.size}`);
  for (const e of exceptions) {
    if (allowed.has(e.id)) console.log(`[audit-gate]   accepted ${e.id} (${e.package}) until ${e.reviewBy}`);
  }

  if (problems.length) {
    console.error(`\n[audit-gate] FAILED — ${problems.length} problem(s):\n`);
    for (const p of problems) console.error(`  - ${p}`);
    console.error("\nTo accept a finding, add it to frontend/audit-exceptions.json with a reason it does not apply here and a reviewBy date.\n");
    process.exit(1);
  }

  console.log("[audit-gate] PASS — no unaccepted high/critical advisories.");
}

main();
