# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""ADR-031 phase 0's fatrace reader: real events are kept, forged lines are not.

fatrace prints file names raw, so a crafted name can forge an event line (measured
on the host). The reader keeps an event only if its process exists with that program
name and its timestamp is near the clock; anything else is counted as rejected.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/flow-measure/flow-reader.py"


def _now() -> str:
    t = time.time()
    return time.strftime("%H:%M:%S", time.localtime(t)) + f".{int(t % 1 * 1e6):06d}"


def _run(tmp: Path, lines: list[str]) -> dict:
    subprocess.run([sys.executable, "-I", str(SCRIPT), str(tmp)], input="\n".join(lines) + "\n",
                   text=True, check=True, timeout=30)
    return json.loads(sorted(tmp.glob("flow-*.json"))[-1].read_text())


def _me() -> tuple[str, str]:
    """This test's own pid and program name, as fatrace would print them."""
    pid = str(os.getpid())
    return pid, Path(f"/proc/{pid}/comm").read_text().strip()


def test_a_real_event_is_kept(tmp_path):
    pid, comm = _me()
    d = _run(tmp_path, [f"{_now()} {comm}({pid}): O   /opt/pipeline/config.json"])
    assert d["events_kept"] == 1 and d["events_rejected"] == 0


def test_a_made_up_pid_is_kept_but_attributed_to_no_account(tmp_path):
    """A short-lived real process is gone before we look; so is a forger's made-up
    pid. Either way the event counts under uid "?", which impersonates no one."""
    pid, comm = _me()
    d = _run(tmp_path, [f"{_now()} {comm}({pid}): RO  /root/x/a",
                        f"{_now()} FAKE(424242): R /opt/pipeline/forged"])
    assert d["events_kept"] == 1 and d["events_unattributed"] == 1 and d["events_rejected"] == 0, d
    assert [r["uid"] for r in d["rows"]] == ["?"]


def test_a_forged_line_borrowing_a_real_pid_under_another_name_is_rejected(tmp_path):
    pid, _ = _me()
    d = _run(tmp_path, [f"{_now()} cat({pid}): R /opt/pipeline/forged"])
    assert d["events_kept"] == 0 and d["events_rejected"] == 1, d


def test_a_line_with_a_stale_timestamp_is_rejected(tmp_path):
    pid, comm = _me()
    stale = time.strftime("%H:%M:%S", time.localtime(time.time() - 600)) + ".000001"
    d = _run(tmp_path, [f"{stale} {comm}({pid}): R /opt/pipeline/forged"])
    assert d["events_kept"] == 0 and d["events_rejected"] == 1, d


def test_events_outside_the_trees_are_ignored_not_rejected(tmp_path):
    d = _run(tmp_path, [f"{_now()} FAKE(424242): R /etc/passwd"])
    assert d["events_kept"] == 0 and d["events_rejected"] == 0
