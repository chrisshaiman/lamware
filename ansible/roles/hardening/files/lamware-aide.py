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
is about to absorb (journal and a low-priority alert) before replacing the
baseline, so a change slipped in between two deploys is still named once.

Managed by Ansible (roles/hardening). Runs as root.
"""
import argparse
import collections
import fcntl
import os
import re
import subprocess
import sys

AIDE = "/usr/bin/aide"
CONFIG = "/etc/aide/aide.conf"
DB = "/var/lib/aide/aide.db"
DB_NEW = "/var/lib/aide/aide.db.new"
DB_PREV = "/var/lib/aide/aide.db.prev"
ENQUEUE = "/opt/ntfy-alerts/ntfy_enqueue.py"
LOCK = "/run/lamware-aide.lock"
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


def run_aide(mode: str) -> tuple[int, str]:
    proc = subprocess.run([AIDE, mode, "--config", CONFIG],
                          capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    print(out)  # the full report goes to the journal
    return proc.returncode, out


def check() -> int:
    rc, out = run_aide("--check")
    if rc >= AIDE_ERROR_MIN:
        alert("AIDE check failed", f"aide --check exited {rc}; see journalctl -u aidecheck",
              "high", "warning")
    elif rc:
        s = summarize(out)
        alert(f"AIDE: {s['added'] + s['removed'] + s['changed']} differences since the baseline",
              describe(s) + "\nNot made by a deploy or a package change. "
              "journalctl -u aidecheck for the full list.", "high", "warning")
    return rc


def rebaseline(reason: str) -> int:
    rc, out = run_aide("--update")
    if rc >= AIDE_ERROR_MIN or not os.path.exists(DB_NEW):
        alert("AIDE baseline NOT renewed", f"aide --update exited {rc} after {reason}; "
              "the nightly check still compares against the old baseline", "high", "warning")
        return rc or 1
    if rc:
        s = summarize(out)
        alert(f"AIDE baseline renewed after {reason}", describe(s), "low", "information_source")
    if os.path.exists(DB):
        os.replace(DB, DB_PREV)
    os.replace(DB_NEW, DB)
    os.chmod(DB, 0o600)
    print(f"lamware-aide: baseline renewed after {reason}")
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
