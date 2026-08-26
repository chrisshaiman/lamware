# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Alert de-duplication in network-monitor (#378).

Six of the eight alert sites fired unconditionally on every check. The cron runs
every 5 minutes, so a standing warning produced 288 notifications a day — which
is not merely noise: it trains the operator to ignore the channel that also
carries AIR-GAP BREACH.

The trigger was a pattern with no trailing glob:

    allowlist: /usr/lib/systemd/systemd --user
    actual:    /usr/lib/systemd/systemd --user --deserialize=8

`--deserialize=N` appears after a daemon-reexec and N varies, so the exact
pattern could never match again.

These tests EXECUTE the rendered dispatcher against a fake ntfy_notify and a
real status.json, and assert what it SENDS. A dispatcher that suppressed
everything would satisfy any assertion phrased as "does not spam".
"""
import json
import re
import subprocess
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[1]
MONITOR = (ROOT / "ansible" / "roles" / "network-monitor" / "templates"
           / "network-monitor.sh.j2")
SRC = MONITOR.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The allowlist pattern that caused it
# ---------------------------------------------------------------------------

def test_the_systemd_pattern_is_globbed_for_every_user():
    """THE bug. Three allowlists carried the unglobbed pattern."""
    assert "'/usr/lib/systemd/systemd --user'" not in SRC, (
        "an exact systemd --user pattern is back; --deserialize=N will never match")
    assert SRC.count("'/usr/lib/systemd/systemd --user*'") == 3, (
        "expected the globbed pattern in all three user allowlists")


def test_the_real_process_string_matches_the_pattern():
    """Assert against the string observed on the host, not a guess."""
    import fnmatch
    observed = "/usr/lib/systemd/systemd --user --deserialize=8"
    assert fnmatch.fnmatch(observed, "/usr/lib/systemd/systemd --user*")
    assert not fnmatch.fnmatch(observed, "/usr/lib/systemd/systemd --user")


# ---------------------------------------------------------------------------
# Every alert goes through the queue
# ---------------------------------------------------------------------------

def test_no_alert_site_calls_ntfy_directly():
    """A site bypassing the queue keeps its old every-5-minutes behaviour, and
    would do so invisibly."""
    direct = [ln.strip() for ln in SRC.splitlines()
              if "ntfy_notify.py" in ln and "queue_alert" not in ln
              and "NTFY = " not in ln and not ln.strip().startswith("#")]
    assert not direct, f"alert sites bypassing the queue: {direct}"


def test_every_alert_key_is_unique():
    """Two sites sharing a key dedupe against each other — a pipeline warning
    would suppress a cape warning. This was a real defect in the first draft."""
    keys = re.findall(r"queue_alert ([a-z_]+)", SRC)
    # Count is a drift guard: a new alert site should make someone confirm its
    # key is distinct, since a collision silently suppresses the older alert.
    # 8 through #379; cape_storage added by #385; sample_exposure by #392;
    # cape_machines by #451; inetsim_dns by #464.
    assert len(keys) == 12, f"expected 12 alert sites, found {len(keys)}: {keys}"
    assert len(set(keys)) == len(keys), f"duplicate alert keys: {keys}"


# ---------------------------------------------------------------------------
# Behaviour: run the dispatcher
# ---------------------------------------------------------------------------

def _dispatcher() -> str:
    """The rendered dispatch block, as shell."""
    rendered = jinja2.Template(SRC).render(
        management_interface="enp3s0f0",
        network_monitor_detonation_bridge="virbr-det",
        network_monitor_install_dir="/opt/network-monitor",
        network_monitor_pause_file="/opt/network-monitor/paused",
        ntfy_install_dir="NTFY_DIR_PLACEHOLDER", cape_user="cape")
    start = rendered.index("# Dispatch queued alerts")
    # Stop before the status dict — it interpolates shell variables this
    # harness does not set, and they are not what is under test here.
    end = rendered.index("status = {", start)
    return rendered[start:end]


def _run(tmp_path, queued, prev_status, renotify=21600, timestamp="T0"):
    """Execute the dispatcher; return the list of alerts it actually sent."""
    ntfy_dir = tmp_path / "ntfy"
    ntfy_dir.mkdir(exist_ok=True)
    sent = tmp_path / "sent.jsonl"
    # Truncate per invocation: tests call _run twice on one tmp_path, and a
    # carried-over log would make the second run look like it resent.
    sent.write_text("", encoding="utf-8")
    (ntfy_dir / "ntfy_notify.py").write_text(
        "import sys, json\n"
        f"open({str(sent)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n",
        encoding="utf-8")

    alerts = tmp_path / "alerts.jsonl"
    alerts.write_text("".join(json.dumps(a) + "\n" for a in queued), encoding="utf-8")
    status = tmp_path / "status.json"
    status.write_text(json.dumps(prev_status), encoding="utf-8")

    block = (_dispatcher()
             .replace("NTFY_DIR_PLACEHOLDER", str(ntfy_dir))
             .replace("$STATUS_FILE", str(status))
             .replace("$ALERTS_FILE", str(alerts))
             .replace("$RENOTIFY_SECONDS", str(renotify))
             .replace("$TIMESTAMP", timestamp))
    # The block opens `python3 -c "`; close it so it is runnable standalone.
    script = block + '\nprint(json.dumps(notified))\n"\n'
    proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, f"dispatcher failed: {proc.stderr[-800:]}"
    out = [json.loads(l) for l in sent.read_text().splitlines()] if sent.exists() else []
    return out, json.loads(proc.stdout.strip().splitlines()[-1])


ALERT = {"key": "proc_cape", "title": "Unexpected Processes",
         "message": "cape user: /usr/lib/systemd/systemd --user --deserialize=8",
         "priority": "high", "tags": "warning"}


def test_a_new_condition_is_sent(tmp_path):
    """The positive control. Without it, a dispatcher that sends nothing at all
    would pass every suppression test below."""
    sent, state = _run(tmp_path, [ALERT], {})
    assert len(sent) == 1, sent
    assert sent[0][0] == "Unexpected Processes"
    assert "proc_cape" in state


def test_the_same_condition_is_not_resent(tmp_path):
    """THE fix: 288/day becomes 1."""
    sent1, state1 = _run(tmp_path, [ALERT], {})
    sent2, _ = _run(tmp_path, [ALERT], {"notified": state1})
    assert len(sent1) == 1
    assert sent2 == [], f"resent a standing condition: {sent2}"


def test_a_changed_detail_is_resent(tmp_path):
    """Suppression must be on the MESSAGE, not the key — a second unexpected
    process appearing is new information."""
    _, state = _run(tmp_path, [ALERT], {})
    worse = {**ALERT, "message": ALERT["message"] + " | /usr/bin/nc -e /bin/sh"}
    sent, _ = _run(tmp_path, [worse], {"notified": state})
    assert len(sent) == 1, "a changed alert detail was suppressed"
    assert "nc -e" in sent[0][1]


def test_a_standing_condition_is_re_notified_eventually(tmp_path):
    """Silence forever is its own failure — a real problem must resurface."""
    _, state = _run(tmp_path, [ALERT], {})
    state["proc_cape"]["at"] -= 22000          # older than the 21600s default
    sent, _ = _run(tmp_path, [ALERT], {"notified": state})
    assert len(sent) == 1, "a standing condition was never re-notified"


def test_clearing_a_condition_sends_one_resolved(tmp_path):
    """'No news' should not be the only signal that the air gap came back."""
    _, state = _run(tmp_path, [ALERT], {})
    sent, new_state = _run(tmp_path, [], {"notified": state})
    assert len(sent) == 1, sent
    assert sent[0][0] == "Resolved: proc_cape"
    assert new_state == {}, "resolved condition still tracked"


def test_resolved_is_sent_once_not_repeatedly(tmp_path):
    sent1, state1 = _run(tmp_path, [], {"notified": {
        "proc_cape": {"fp": "abc", "at": 1}}})
    sent2, _ = _run(tmp_path, [], {"notified": state1})
    assert len(sent1) == 1
    assert sent2 == [], "resolved notification repeats forever"


def test_independent_conditions_do_not_suppress_each_other(tmp_path):
    """The first draft collapsed pipeline and auto-feeder onto one key."""
    a = {**ALERT, "key": "proc_cape", "message": "cape user: x"}
    b = {**ALERT, "key": "proc_pipeline", "message": "pipeline user: y"}
    sent, _ = _run(tmp_path, [a, b], {})
    assert len(sent) == 2, f"one condition suppressed another: {sent}"


def test_a_breach_is_never_suppressed_by_an_unrelated_standing_warning(tmp_path):
    """The reason this issue matters. A noisy process warning must not stop an
    AIR-GAP BREACH reaching the phone."""
    warn = {**ALERT}
    _, state = _run(tmp_path, [warn], {})
    breach = {"key": "breach_internet", "title": "NETWORK BREACH",
              "message": "AIR-GAP BREACH: 4 packets ACCEPTED", "priority": "urgent",
              "tags": "skull"}
    sent, _ = _run(tmp_path, [warn, breach], {"notified": state})
    titles = [s[0] for s in sent]
    assert "NETWORK BREACH" in titles, f"breach was suppressed: {sent}"
    assert "Unexpected Processes" not in titles, "standing warning resent"
