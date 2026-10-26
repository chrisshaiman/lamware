#!/usr/bin/python3
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""lamware-aide: run AIDE so that its result reaches someone, and keep its baseline current.

  lamware-aide check                  nightly (aidecheck.service): compare against the baseline
  lamware-aide rebaseline --reason R  after a deploy or a package change: report what changed
                                      since the baseline, then make the current state the baseline

Before this, the nightly check compared against a baseline from 2026-04-25, found
about a million differences, exited 7, and nothing read it. A file-integrity check
that always fails is the same as no check. `check` sends an ntfy alert whenever
AIDE reports a difference or an error; `rebaseline` runs after every deploy and
every dpkg run, so a difference at night means a change that neither made.

`rebaseline` is `aide --update`, not `aide --init`: it reports the differences it
is about to absorb (a report file and a low-priority alert) before replacing the
baseline, so a change slipped in between two deploys is still named once.

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
REPORTS_KEPT = 30
TOP_DIRS = 8
# AIDE's exit status: a bitmask of 1 added, 2 removed, 4 changed (so 0-7 is a
# completed comparison); 14 and above are errors.
AIDE_ERROR_MIN = 14

_COUNT = re.compile(r"^\s*(Total number of entries|Added entries|Removed entries|Changed entries):\s*(\d+)", re.M)
_ENTRY = re.compile(r"^[^\s:]{6,}: (/\S.*)$", re.M)


def summarize(report: str) -> dict:
    """Counts and the busiest directories (first three path components) of an AIDE report."""
    counts = {k.split()[0].lower(): int(v) for k, v in _COUNT.findall(report)}
    dirs = collections.Counter("/".join(p.split("/")[:4]) for p in _ENTRY.findall(report))
    return {"total": counts.get("total", 0), "added": counts.get("added", 0),
            "removed": counts.get("removed", 0), "changed": counts.get("changed", 0),
            "top_dirs": dirs.most_common(TOP_DIRS)}


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


def check() -> int:
    rc, out, path = run_aide("check")
    if rc >= AIDE_ERROR_MIN:
        alert("AIDE check failed", f"aide --check exited {rc}; AIDE's output: {path}",
              "high", "warning")
    elif rc:
        s = summarize(out)
        alert(f"AIDE: {s['added'] + s['removed'] + s['changed']} differences since the baseline",
              describe(s) + "\nNot made by a deploy or a package change. "
              f"Full list: {path}", "high", "warning")
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
    if os.path.exists(DB):
        os.replace(DB, DB_PREV)
    os.replace(DB_NEW, DB)
    # AIDE writes into an existing aide.db.new as whoever owns it (_aide, left by
    # the package's own runs) and creates a new one as root. The next rebaseline
    # records aide.db's owner before the swap, so an owner that varies is a
    # difference every check reports. Pin it.
    os.chown(DB, 0, 0)
    os.chmod(DB, 0o600)
    print(f"lamware-aide: baseline renewed after {reason}", flush=True)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="lamware-aide")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    rb = sub.add_parser("rebaseline")
    rb.add_argument("--reason", default="a manual run")
    args = ap.parse_args(argv)
    # One AIDE at a time: a check during a rebaseline would compare against a
    # baseline that is being replaced.
    with open(LOCK, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return check() if args.cmd == "check" else rebaseline(args.reason)


if __name__ == "__main__":
    sys.exit(main())
