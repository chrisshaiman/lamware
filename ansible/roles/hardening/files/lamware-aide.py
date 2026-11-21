#!/usr/bin/python3
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""lamware-aide: run AIDE so that its result reaches someone, and keep its baseline current.

  lamware-aide check                  nightly (aidecheck.service): compare against the baseline,
                                      and absorb the differences only if all are expected
  lamware-aide rebaseline --reason R  after a deploy or a package change: report what changed
                                      since the baseline, then make the current state the baseline
  lamware-aide rules                  load and validate EXPECTED (the deploy runs this)

Before this, the nightly check compared against a baseline from 2026-04-25, found
about a million differences, exited 7, and nothing read it. A file-integrity check
that always fails is the same as no check. `check` sends an ntfy alert whenever
AIDE reports a difference or an error; `rebaseline` runs after every deploy and
every dpkg run, so a difference at night means a change that neither made.

`rebaseline` is `aide --update`, not `aide --init`: it reports the differences it
is about to absorb (a report file and a low-priority alert) before replacing the
baseline, so a change slipped in between two deploys is still named once.

`check` (ADR-035) scans once with `aide --update`, which reports the differences
from the baseline AND writes a new database from the same scan. Every difference is
classified against EXPECTED, the paths a detonation, a reboot or the container
runtime are allowed to change and which attributes may change (contents and times,
never owner, mode, type, ACLs, xattrs or capabilities). All expected: the new
database becomes the baseline and a low-priority line says so. Anything unexpected:
a high-priority alert naming only the unexpected entries, and the OLD baseline
stays, so the difference keeps alerting every night until a person looks. A report
that cannot be classified completely fails closed the same way. One scan, not a
check then a rebaseline: anything changed between two scans would be absorbed unseen.

The full AIDE report goes to a file under REPORT_DIR, not the journal: a
rebaseline's report runs to hundreds of thousands of lines, and journald cut the
first one off partway through /opt (2026-10-25). The journal gets the summary
and the file's path.

Managed by Ansible (roles/hardening). Runs as root.
"""
import argparse
import collections
import fcntl
import os
import re
import subprocess
import sys
import time

AIDE = "/usr/bin/aide"
CONFIG = "/etc/aide/aide.conf"
DB = "/var/lib/aide/aide.db"
DB_NEW = "/var/lib/aide/aide.db.new"
DB_PREV = "/var/lib/aide/aide.db.prev"
ENQUEUE = "/opt/ntfy-alerts/ntfy_enqueue.py"
LOCK = "/run/lamware-aide.lock"
# Excluded from AIDE in 99_lamware_exclusions: a report written tonight would
# otherwise be tomorrow's "added" difference.
REPORT_DIR = "/var/lib/lamware-aide/reports"
EXPECTED = "/etc/lamware-aide/expected-differences.conf"
UNEXPECTED_LISTED = 25
REPORTS_KEPT = 30
TOP_DIRS = 8
# AIDE's exit status: a bitmask of 1 added, 2 removed, 4 changed (so 0-7 is a
# completed comparison); 14 and above are errors.
AIDE_ERROR_MIN = 14

# AIDE's summary string, YlZbpugamcinHAXSEC (aide.conf(5), report_summarize_changes).
FLAG_LETTERS = "YlZbpugamcinHAXSEC"
_SECTION = re.compile(r"(Added|Removed|Changed) entries:\s*")   # used with fullmatch
_COUNT = re.compile(r"^\s*(Total number of entries|Added entries|Removed entries|Changed entries):\s*(\d+)", re.M)
_ENTRY = re.compile(r"^[^\s:]{6,}: (/\S.*)$", re.M)


def summarize(report: str) -> dict:
    """Counts and the busiest directories (first three path components) of an AIDE report."""
    counts = {k.split()[0].lower(): int(v) for k, v in _COUNT.findall(report)}
    dirs = collections.Counter("/".join(p.split("/")[:4]) for p in _ENTRY.findall(report))
    return {"total": counts.get("total", 0), "added": counts.get("added", 0),
            "removed": counts.get("removed", 0), "changed": counts.get("changed", 0),
            "top_dirs": dirs.most_common(TOP_DIRS)}


def parse_entries(report: str) -> list[tuple[str, str, str]]:
    """(section, summary string, path) for every entry in the Added, Removed and Changed
    sections. The detailed section that follows them is not parsed."""
    entries, section = [], None
    for line in report.splitlines():
        m = _SECTION.fullmatch(line)
        if m:
            section = m.group(1)
            continue
        if line.startswith("Detailed information") or line.startswith("The attributes of the"):
            section = None
            continue
        if section and ": /" in line:
            flags, path = line.split(": /", 1)
            entries.append((section, flags, "/" + path))
    return entries


def changed_letters(flags: str) -> set[str]:
    """The attributes a Changed entry's summary marks as changed. '!' (the file type
    changed) is reported as 'Y'; a size change ('<' or '>') as 'Z'; an attribute that
    appeared or disappeared ('+' or '-') as its own letter."""
    out = set()
    for i, ch in enumerate(flags.ljust(len(FLAG_LETTERS))[:len(FLAG_LETTERS)]):
        if i == 0:
            if ch == "!":
                out.add("Y")
        elif i == 2:
            if ch in "<>":
                out.add("Z")
        elif ch not in ". :=":
            out.add(FLAG_LETTERS[i])
    return out


def load_expected(path: str = None) -> list[tuple[str, str, set[str], "re.Pattern"]]:
    """Rules: `allow|deny SECTIONS LETTERS REGEX`, first match wins. SECTIONS is a
    subset of ARC (Added, Removed, Changed); LETTERS the attributes an allowed Changed
    entry may change ('-' for none). A missing or malformed file raises: the check then
    treats every difference as unexpected rather than guess."""
    rules = []
    with open(path or EXPECTED, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 3)
            if len(parts) != 4 or parts[0] not in ("allow", "deny") \
                    or not set(parts[1]) <= set("ARC") or not parts[1]:
                raise ValueError(f"{path or EXPECTED}:{n}: not `allow|deny ARC LETTERS REGEX`")
            letters = set() if parts[2] == "-" else set(parts[2])
            if not letters <= set(FLAG_LETTERS):
                raise ValueError(f"{path or EXPECTED}:{n}: unknown attribute letters {parts[2]}")
            rules.append((parts[0], parts[1], letters, re.compile(parts[3])))
    return rules


def is_expected(entry: tuple[str, str, str], rules) -> bool:
    section, flags, path = entry
    for action, sections, letters, rx in rules:
        if section[0] not in sections or not rx.fullmatch(path):
            continue
        if action == "deny":
            return False
        return section != "Changed" or changed_letters(flags) <= letters
    return False


def classify(report: str, rules) -> tuple[list, list, str]:
    """(expected, unexpected, problem). `problem` is non-empty when the entries parsed
    do not account for every difference AIDE counted: then nothing may be absorbed."""
    entries = parse_entries(report)
    s = summarize(report)
    counted = s["added"] + s["removed"] + s["changed"]
    if len(entries) != counted:
        return [], entries, f"parsed {len(entries)} entries but AIDE counted {counted}"
    expected = [e for e in entries if is_expected(e, rules)]
    unexpected = [e for e in entries if not is_expected(e, rules)]
    return expected, unexpected, ""


def describe(s: dict) -> str:
    lines = [f"{s['added']} added, {s['removed']} removed, {s['changed']} changed"]
    lines += [f"  {n:>7}  {d}" for d, n in s["top_dirs"]]
    return "\n".join(lines)


def alert(title: str, message: str, priority: str, tags: str) -> None:
    """Queue an ntfy alert; never let a delivery problem hide the AIDE result itself."""
    try:
        subprocess.run([sys.executable, ENQUEUE, title, message,
                        "--priority", priority, "--tags", tags],
                       check=True, timeout=30, capture_output=True)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"lamware-aide: could not queue the alert ({exc}); result follows", file=sys.stderr)
        print(f"{title}\n{message}", file=sys.stderr)


def save_report(mode: str, report: str) -> str:
    """Write the full report to REPORT_DIR (root only) and keep the newest REPORTS_KEPT."""
    os.makedirs(REPORT_DIR, mode=0o700, exist_ok=True)
    path = os.path.join(REPORT_DIR, f"{mode}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.txt")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(report)
    old = sorted((e for e in os.scandir(REPORT_DIR) if e.name.endswith(".txt")),
                 key=lambda e: e.stat().st_mtime, reverse=True)[REPORTS_KEPT:]
    for e in old:
        os.unlink(e.path)
    return path


def run_aide(mode: str) -> tuple[int, str, str]:
    proc = subprocess.run([AIDE, f"--{mode}", "--config", CONFIG],
                          capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    path = save_report(mode, out)
    s = summarize(out)
    print(f"lamware-aide: aide --{mode} exited {proc.returncode}: {describe(s)}\n"
          f"full report: {path}", flush=True)
    return proc.returncode, out, path


def _discard_new() -> None:
    if os.path.exists(DB_NEW):
        os.unlink(DB_NEW)


def _swap_baseline() -> None:
    if os.path.exists(DB):
        os.replace(DB, DB_PREV)
    os.replace(DB_NEW, DB)
    # AIDE writes into an existing aide.db.new as whoever owns it (_aide, left by
    # the package's own runs) and creates a new one as root. The next rebaseline
    # records aide.db's owner before the swap, so an owner that varies is a
    # difference every check reports. Pin it.
    os.chown(DB, 0, 0)
    os.chmod(DB, 0o600)


def check() -> int:
    """Nightly: one --update scan, classified; absorb only when every difference is expected."""
    rc, out, path = run_aide("update")
    if rc >= AIDE_ERROR_MIN:
        _discard_new()
        alert("AIDE check failed", f"aide --update exited {rc}; AIDE's output: {path}",
              "high", "warning")
        return rc
    if rc == 0:
        _discard_new()
        return 0
    try:
        rules = load_expected()
        expected, unexpected, problem = classify(out, rules)
    except (OSError, ValueError, re.error) as exc:
        expected, unexpected, problem = [], parse_entries(out), f"expected-differences rules: {exc}"
    if not unexpected and not problem and os.path.exists(DB_NEW):
        _swap_baseline()
        print(f"lamware-aide: absorbed {len(expected)} expected differences", flush=True)
        alert(f"AIDE: {len(expected)} expected differences absorbed",
              f"Detonation, reboot and container-runtime changes only. Full list: {path}",
              "low", "information_source")
        return 0
    _discard_new()
    listed = "\n".join(f"  {sec[0]} {flags.strip():<18} {p}"
                        for sec, flags, p in unexpected[:UNEXPECTED_LISTED])
    more = len(unexpected) - UNEXPECTED_LISTED
    reason = f"\nNOT CLASSIFIED: {problem}" if problem else ""
    print(f"lamware-aide: {len(unexpected)} unexpected, {len(expected)} expected; "
          f"baseline kept{reason}", flush=True)
    tail = f"\n  ... and {more} more" if more > 0 else ""
    alert(f"AIDE: {len(unexpected)} unexpected differences since the baseline",
          f"{listed}{tail}{reason}\n"
          f"({len(expected)} expected ones not listed.) Not made by a deploy, a package "
          f"change, a detonation or a reboot. The baseline is kept, so this alerts again "
          f"until a rebaseline. Full list: {path}", "high", "warning")
    return rc


def rebaseline(reason: str) -> int:
    rc, out, path = run_aide("update")
    if rc >= AIDE_ERROR_MIN or not os.path.exists(DB_NEW):
        alert("AIDE baseline NOT renewed", f"aide --update exited {rc} after {reason}; "
              f"the nightly check still compares against the old baseline. AIDE's output: {path}",
              "high", "warning")
        return rc or 1
    if rc:
        s = summarize(out)
        alert(f"AIDE baseline renewed after {reason}", f"{describe(s)}\nFull list: {path}",
              "low", "information_source")
    _swap_baseline()
    print(f"lamware-aide: baseline renewed after {reason}", flush=True)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="lamware-aide")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    rb = sub.add_parser("rebaseline")
    rb.add_argument("--reason", default="a manual run")
    sub.add_parser("rules")
    args = ap.parse_args(argv)
    if args.cmd == "rules":
        try:
            print(f"lamware-aide: {len(load_expected())} rules in {EXPECTED}")
        except (OSError, ValueError, re.error) as exc:
            print(f"lamware-aide: {exc}", file=sys.stderr)
            return 1
        return 0
    # One AIDE at a time: a check during a rebaseline would compare against a
    # baseline that is being replaced.
    with open(LOCK, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return check() if args.cmd == "check" else rebaseline(args.reason)


if __name__ == "__main__":
    sys.exit(main())
