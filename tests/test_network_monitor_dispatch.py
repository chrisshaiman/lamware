# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The alert dispatcher must survive the input a QEMU breakout produces.

The status block builds a Python program by interpolating shell variables into
its source text. Two of those sites used single-quoted literals:

    'qemu_unexpected_children': '$qemu_unexpected'.split(chr(10)) ...
    'alert_message': '$alert_message' ...

`qemu_unexpected` is the raw output of `ps --ppid "$qpid" -o pid=,comm=` — one
line per child, never flattened — and `alert_message` embeds the same value. A
second unexpected child therefore put a literal newline inside a single-quoted
literal, and python3 died of SyntaxError before running a statement.

That block is the ONLY dispatcher for every queued alert as well as the writer
of status.json, so the failure was total and self-perpetuating:

  * zero pushes went out — including an unrelated AIR-GAP BREACH queued in the
    same run,
  * status.json kept its previous {"status": "ok"} for the dashboard,
  * and because the crash condition IS the alert condition, every subsequent
    5-minute run failed identically. The alarm stayed silent for as long as the
    breakout lasted.

The `.split(chr(10))` on that very line is the author's own statement that
multi-line was the expected shape.

Quoting was not a sufficient fix. `comm` names come from the escaped process,
so a hostile binary can be named with quotes or a backslash; triple-quoting
survives the newline but not `'''` or a trailing backslash. Values now cross
into Python through the ENVIRONMENT, where no shell string is ever parsed as
code.

These tests EXECUTE the rendered block. A test that only grepped for `'''`
would pass against a dispatcher that still cannot run.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[1]
MONITOR = (ROOT / "ansible" / "roles" / "network-monitor" / "templates"
           / "network-monitor.sh.j2")
SRC = MONITOR.read_text(encoding="utf-8")

# Two children of one qemu-system PID, exactly as `ps -o pid=,comm=` prints them.
TWO_CHILDREN = "  12345 evil.exe\n  12346 cmd.exe"
# A process the escapee got to name. Defeats triple-quoting, not the env.
HOSTILE_NAME = "  12345 a'''b\n  12346 c\"d\\"

BREACH = {"key": "breach_internet", "title": "NETWORK BREACH",
          "message": "AIR-GAP BREACH: 5 packets ACCEPTED", "priority": "urgent",
          "tags": "skull"}
BREAKOUT = {"key": "qemu_breakout", "title": "QEMU BREAKOUT",
            "message": "unexpected children of PID 900", "priority": "urgent",
            "tags": "rotating_light"}


def _run(tmp_path, qemu_unexpected, queued=(BREACH, BREAKOUT)):
    """Render, execute the whole dispatcher, and report what it did.

    Returns (returncode, alerts_sent, status_dict_or_None, stderr).
    """
    ntfy_dir = tmp_path / "ntfy"
    ntfy_dir.mkdir(exist_ok=True)
    sent = tmp_path / "sent.jsonl"
    sent.write_text("", encoding="utf-8")
    (ntfy_dir / "ntfy_notify.py").write_text(
        "import sys, json\n"
        f"open({str(sent)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n",
        encoding="utf-8")

    alerts = tmp_path / "alerts.jsonl"
    alerts.write_text("".join(json.dumps(a) + "\n" for a in queued), encoding="utf-8")
    status = tmp_path / "status.json"
    status.write_text(json.dumps({"status": "ok", "checks_since_baseline": 10,
                                  "notified": {}}), encoding="utf-8")

    rendered = jinja2.Template(SRC).render(
        management_interface="enp3s0f0",
        network_monitor_detonation_bridge="virbr-det",
        network_monitor_install_dir="/opt/network-monitor",
        network_monitor_pause_file="/opt/network-monitor/paused",
        ntfy_install_dir=str(ntfy_dir), cape_user="cape")
    start = rendered.index("# Dispatch queued alerts")
    block = rendered[start:]

    # The shell variables the dispatcher reads. Set them the way the script
    # itself does, so what runs is the real block against real values.
    preamble = "\n".join([
        "set -euo pipefail",
        f'STATUS_FILE={status}', f'ALERTS_FILE={alerts}',
        'RENOTIFY_SECONDS=21600', 'TIMESTAMP=2026-08-17T05:00:00Z',
        'det_eth0_accept=5', 'det_eth0_drop=0', 'det_wg0_accept=0',
        'det_wg0_drop=0', 'exposed_samples=0',
        'status=alert', 'rules_problem=', 'qemu_status=alert',
        'cape_process_status=ok', 'cape_unexpected=',
        'pipeline_process_status=ok', 'pipeline_unexpected=',
        'api_process_status=ok', 'api_unexpected=',
        'cape_storage_status=ok', 'cape_storage_problem=', 'exposed_where=',
        'cape_machines_status=ok', 'cape_machines_problem=',
        # Through the harness env, so the test's own quoting cannot be what is
        # under test — the script reads it as an ordinary shell variable.
        'qemu_unexpected="$LAMWARE_TEST_QEMU_CHILDREN"',
        'alert_message="QEMU BREAKOUT: children of PID 900: $qemu_unexpected"',
    ])
    proc = subprocess.run(
        ["bash", "-c", preamble + "\n" + block],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "LAMWARE_TEST_QEMU_CHILDREN": qemu_unexpected})
    alerts_sent = [json.loads(ln) for ln in sent.read_text().splitlines()]
    try:
        parsed = json.loads(status.read_text())
    except json.JSONDecodeError:  # pragma: no cover — only on a broken write
        parsed = None
    return proc.returncode, alerts_sent, parsed, proc.stderr


def test_one_unexpected_child_dispatches(tmp_path):
    """Positive control. The single-child case always worked — which is exactly
    what hid the bug — so without this a dispatcher that never runs at all would
    satisfy every assertion below."""
    rc, sent, status, err = _run(tmp_path, "  12345 evil.exe")
    assert rc == 0, err[-800:]
    assert len(sent) == 2, sent
    assert status["qemu_unexpected_children"] == ["  12345 evil.exe"]


def test_two_unexpected_children_still_dispatch_every_alert(tmp_path):
    """THE bug. A breakout with two children silenced the whole dispatcher."""
    rc, sent, status, err = _run(tmp_path, TWO_CHILDREN)
    assert rc == 0, f"dispatcher died on a two-child breakout: {err[-800:]}"
    titles = [s[0] for s in sent]
    assert "QEMU BREAKOUT" in titles, f"the breakout alert was lost: {sent}"
    assert "NETWORK BREACH" in titles, (
        "an unrelated queued alert was lost — this block dispatches all of them, "
        "so one bad field took the air-gap breach down with it")
    assert status["qemu_unexpected_children"] == ["  12345 evil.exe", "  12346 cmd.exe"]


def test_status_file_is_rewritten_when_children_are_multiline(tmp_path):
    """A stale status.json reports 'ok' to the dashboard during a live breakout,
    and `notified` never advances, so the alert cannot even re-fire."""
    _, _, status, _ = _run(tmp_path, TWO_CHILDREN)
    assert status["status"] == "alert", (
        "status.json still says ok during a breakout; the dashboard reads this")
    assert status["checks_since_baseline"] == 11, "status.json was not rewritten"
    assert status["alert_message"], "alert_message dropped from the status file"


def test_a_hostile_process_name_cannot_break_the_dispatcher(tmp_path):
    """The escapee names its own processes. Quoting the interpolation — even
    with triple quotes — leaves `'''` and a trailing backslash as live breaks;
    passing through the environment has no quoting to escape."""
    rc, sent, status, err = _run(tmp_path, HOSTILE_NAME)
    assert rc == 0, f"a crafted comm name killed the dispatcher: {err[-800:]}"
    assert len(sent) == 2, sent
    assert status["qemu_unexpected_children"] == ["  12345 a'''b", '  12346 c"d\\']


def test_free_text_reaches_python_through_the_environment_not_the_source():
    """The structural guard. Re-introducing a bare '$var' literal for any of
    these fields re-opens the crash — and the failure mode is silence, which no
    smoke test would surface."""
    start = SRC.index("# Dispatch queued alerts")
    block = SRC[start:]
    for var in ("qemu_unexpected", "alert_message", "rules_problem",
                "cape_unexpected", "pipeline_unexpected", "api_unexpected",
                "cape_storage_problem", "exposed_where", "status"):
        assert f"'${var}'" not in block, (
            f"${var} is interpolated into Python source again; a value containing "
            f"a newline or a quote makes the whole dispatcher a SyntaxError")
        assert f"'''${var}'''" not in block, (
            f"${var} is triple-quoted — that survives a newline but not a comm "
            f"name containing ''' or a trailing backslash; use the environment")
