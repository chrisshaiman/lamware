#!/usr/bin/python3 -I
"""ADR-031 phase 0: aggregate fatrace events under the lamware group's trees.

Reads `fatrace -t -f ORW` lines on stdin ("HH:MM:SS.us comm(pid): OPS /path"),
looks up each event's uid from /proc/<pid>/status while the process is alive, drops
root, keeps paths under ROOTS, folds task ids and hashes, and counts
(uid, comm, path, op). Writes a JSON snapshot to OUT_DIR every hour and on exit.
Standard library only.
"""
from __future__ import annotations

import json
import os
import re
import signal
import sys
import time
from collections import Counter

ROOTS = (
    "/opt/pipeline/", "/opt/CAPEv2/storage/", "/opt/auto-feeder/", "/opt/sample-feeder/",
    "/opt/ntfy-alerts/", "/var/lib/lamware-notify/", "/opt/motif/", "/home/cape/",
    "/opt/interpret/", "/opt/triage/", "/opt/ghidra/", "/opt/volatility3/", "/opt/pcap-analysis/",
    "/opt/pdf-generation/", "/opt/dotnet-analysis/", "/opt/screenshot-analysis/",
    "/opt/python-sandbox/", "/opt/pyinstaller-analysis/", "/opt/java-analysis/",
    "/opt/powershell-analysis/", "/opt/go-analysis/", "/opt/office-macro-analysis/",
)
LINE = re.compile(r"^(?P<ts>\d\d:\d\d:\d\d\.\d+) (?P<comm>.*?)\((?P<pid>\d+)\): (?P<ops>[A-Z+<>]+)\s+(?P<path>/.*)\Z")
# fatrace prints file names raw, so a name containing a newline and a made-up event
# line yields a second, forged line (measured 2026-11-17). A line is rejected when its
# timestamp is far from the clock, or its pid is alive under a different program
# name. A pid that has already exited (a short-lived `cat` is gone before we look)
# keeps its event under uid "?": attributed to no account, so a forger cannot use it
# to impersonate one. Rejected and unattributed lines are both counted.
MAX_SKEW = 5.0
DEPTH = 6


def fold(path: str) -> str:
    """Keep DEPTH components; task ids, hex digests and dates become placeholders."""
    parts = path.split("/")[: DEPTH + 1]
    out = []
    for p in parts:
        p = re.sub(r"^[0-9a-f]{32,}$", "<hash>", p)
        p = re.sub(r"^\d+$", "<n>", p)
        p = re.sub(r"\d{6,}", "<n>", p)
        out.append(p)
    return "/".join(out) + ("/…" if path.count("/") > DEPTH else "")


def verdict(m: re.Match, now: float) -> str:
    """"ok", "gone" (the process exited before we looked) or "forged"."""
    h, mi, sec = m["ts"].split(":")
    stamp = int(h) * 3600 + int(mi) * 60 + float(sec)
    lt = time.localtime(now)  # fatrace prints local time of day
    clock = lt.tm_hour * 3600 + lt.tm_min * 60 + lt.tm_sec + (now % 1)
    skew = abs(stamp - clock)
    if min(skew, 86400 - skew) > MAX_SKEW:
        return "forged"
    try:
        with open(f"/proc/{m['pid']}/comm") as f:
            comm = f.read().strip()
    except OSError:
        return "gone"
    return "ok" if comm == m["comm"][:15] else "forged"


def uid_of(pid: str, cache: dict) -> str:
    hit = cache.get(pid)
    if hit and time.monotonic() - hit[1] < 30:
        return hit[0]
    try:
        with open(f"/proc/{pid}/status") as f:
            uid = next(ln.split()[1] for ln in f if ln.startswith("Uid:"))
    except (OSError, StopIteration):
        uid = "?"
    cache[pid] = (uid, time.monotonic())
    return uid


def main(out_dir: str) -> int:
    counts: Counter = Counter()
    cache: dict = {}
    last = time.monotonic()
    seen = kept = rejected = unattributed = 0

    def dump(final: bool = False) -> None:
        # Nanoseconds in the name: two snapshots in one second must not overwrite.
        stamp = time.strftime("%Y%m%dT%H%M%S") + f".{time.time_ns() % 10**9:09d}"
        rows = [{"uid": k[0], "comm": k[1], "path": k[2], "op": k[3], "n": n} for k, n in counts.most_common()]
        tmp = os.path.join(out_dir, f".flow-{stamp}.json")
        with open(tmp, "w") as f:
            json.dump({"at": stamp, "final": final, "events_seen": seen, "events_kept": kept,
                       "events_rejected": rejected, "events_unattributed": unattributed,
                       "rows": rows}, f)
        os.replace(tmp, os.path.join(out_dir, f"flow-{stamp}.json"))
        counts.clear()

    signal.signal(signal.SIGTERM, lambda *_: (dump(True), sys.exit(0)))
    # On demand, to check events are being kept: `systemctl kill -s USR1 lamware-flow-measure`.
    signal.signal(signal.SIGUSR1, lambda *_: dump())
    for line in sys.stdin:
        seen += 1
        m = LINE.match(line.rstrip("\n"))
        if m and m["path"].startswith(ROOTS):
            v = verdict(m, time.time())
            if v == "forged":
                rejected += 1
                continue
            uid = uid_of(m["pid"], cache) if v == "ok" else "?"
            unattributed += v == "gone"
            if uid != "0":
                kept += 1
                for op in set(m["ops"]) & set("ORW"):
                    counts[(uid, m["comm"], fold(m["path"]), op)] += 1
        if time.monotonic() - last >= 3600:
            dump()
            last = time.monotonic()
            if len(cache) > 50000:
                cache.clear()
    dump(True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
