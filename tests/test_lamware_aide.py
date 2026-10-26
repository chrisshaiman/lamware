# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""lamware-aide must make AIDE's result reach someone, and keep its baseline current.

The nightly check compared against a baseline from April, failed every night with
about a million differences, and nobody read it. These tests run the real script
with a fake `aide` and a fake alert queue: a difference must alert, a clean run
must not, an error must alert as a failure, and a rebaseline must swap the
databases only when AIDE produced a new one. The host evidence (a rebaseline and
a check on the sandbox) is in the PR; this is what CI can observe.
"""
import importlib.util
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible" / "roles" / "hardening" / "files"

spec = importlib.util.spec_from_file_location("lamware_aide", FILES / "lamware-aide.py")
aide = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aide)

REPORT = """Start timestamp: 2026-10-26 00:00:01 -0700 (AIDE 0.18.6)
AIDE found differences between database and filesystem!!

Summary:
  Total number of entries:\t1069382
  Added entries:\t\t3
  Removed entries:\t\t1
  Changed entries:\t\t1

---------------------------------------------------
Added entries:
---------------------------------------------------

f++++++++++++++++: /usr/local/bin/implant
f++++++++++++++++: /usr/local/bin/implant2
d++++++++++++++++: /etc/cron.d/x
---------------------------------------------------
Removed entries:
---------------------------------------------------

f----------------: /etc/sudoers.d/old
---------------------------------------------------
Changed entries:
---------------------------------------------------

f   ...    .C... : /usr/bin/sudo
"""


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Fake aide (rc and output per test), a captured alert queue, temp databases."""
    state = {"rc": 0, "out": "", "alerts": [], "argv": [], "writes_new": True}
    db, new, prev = tmp_path / "aide.db", tmp_path / "aide.db.new", tmp_path / "aide.db.prev"
    db.write_text("OLD")
    monkeypatch.setattr(aide, "DB", str(db))
    monkeypatch.setattr(aide, "DB_NEW", str(new))
    monkeypatch.setattr(aide, "DB_PREV", str(prev))
    monkeypatch.setattr(aide, "LOCK", str(tmp_path / "lock"))

    def fake_run(argv, **kw):
        if argv[1] == aide.ENQUEUE:
            state["alerts"].append({"title": argv[2], "message": argv[3], "priority": argv[5]})
            return subprocess.CompletedProcess(argv, 0, "", "")
        state["argv"].append(argv)
        if "--update" in argv and state["writes_new"]:
            new.write_text("NEW")
        return subprocess.CompletedProcess(argv, state["rc"], state["out"], "")

    monkeypatch.setattr(aide.subprocess, "run", fake_run)
    state.update(db=db, new=new, prev=prev)
    return state


def test_summary_counts_and_directories():
    s = aide.summarize(REPORT)
    assert (s["added"], s["removed"], s["changed"], s["total"]) == (3, 1, 1, 1069382)
    assert dict(s["top_dirs"])["/usr/local/bin"] == 2


def test_a_clean_check_sends_nothing(env):
    env["rc"] = 0
    assert aide.main(["check"]) == 0
    assert env["alerts"] == []
    assert env["argv"][0][:2] == [aide.AIDE, "--check"]


def test_a_difference_alerts_high_with_the_counts(env):
    env["rc"], env["out"] = 7, REPORT
    assert aide.main(["check"]) == 7          # the unit still shows failed
    [a] = env["alerts"]
    assert a["priority"] == "high"
    assert "3 added, 1 removed, 1 changed" in a["message"]
    assert "/usr/local/bin" in a["message"]


def test_an_aide_error_alerts_as_a_failure(env):
    env["rc"] = 17
    assert aide.main(["check"]) == 17
    [a] = env["alerts"]
    assert a["title"] == "AIDE check failed" and a["priority"] == "high"


def test_rebaseline_reports_what_it_absorbs_then_swaps(env):
    env["rc"], env["out"] = 4, REPORT
    assert aide.main(["rebaseline", "--reason", "a deploy"]) == 0
    assert env["argv"][0][:2] == [aide.AIDE, "--update"]
    assert env["db"].read_text() == "NEW" and env["prev"].read_text() == "OLD"
    assert not env["new"].exists()
    [a] = env["alerts"]
    assert a["priority"] == "low" and "3 added" in a["message"]


def test_rebaseline_keeps_the_old_baseline_when_aide_wrote_nothing(env):
    env["rc"], env["writes_new"] = 17, False
    assert aide.main(["rebaseline"]) != 0
    assert env["db"].read_text() == "OLD"
    assert env["alerts"][0]["title"] == "AIDE baseline NOT renewed"


# --- exclusions: data out, code in ------------------------------------------------
RULES = [re.compile(line[1:]) for line in
         (FILES / "99_lamware_exclusions").read_text().splitlines()
         if line.startswith("!")]


def _excluded(path: str) -> bool:
    # AIDE matches rule regexes anchored at the start of the path.
    return any(r.match(path) for r in RULES)


@pytest.mark.parametrize("path", [
    "/home/pipeline/.local/share/containers/storage/overlay/x",
    "/var/lib/containers/storage/x", "/opt/CAPEv2/storage/analyses/1/binary",
    "/opt/pipeline/reports/abc/report.json", "/data/db/collection-1.wt",
    "/home/cape/.cache/pip/x", "/var/lib/postgresql/16/main/base/1",
])
def test_churning_data_is_excluded(path):
    assert _excluded(path)


@pytest.mark.parametrize("path", [
    "/opt/pipeline/venv/bin/python", "/opt/pipeline/run-pipeline.py", "/usr/bin/sudo",
    "/etc/passwd", "/etc/sudoers.d/x", "/home/cape/.ssh/authorized_keys",
    "/home/pipeline/.bashrc", "/home/pipeline/.local/bin/x", "/opt/CAPEv2/conf/cuckoo.conf",
    "/usr/local/sbin/lamware-aide", "/var/lib/aide/aide.db", "/root/.ssh/authorized_keys",
])
def test_code_and_configuration_stay_monitored(path):
    assert not _excluded(path)
