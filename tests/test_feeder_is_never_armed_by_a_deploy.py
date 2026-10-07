"""A deploy must never arm the auto-feeder (it detonates live malware unattended).

Structural, and a memory of the 2026-10-07 incident: the operator's local
ansible/vars/main.yml (gitignored) set `auto_feeder_enabled: true`, overriding the
role default, so a deploy of the auto-feeder role (for an unrelated change, #720)
enabled and started the timer. The first cycle was stopped only by a months-old
PAUSE file. The local file was corrected by hand; this test checks it WHERE IT
EXISTS -- the deploy machine runs the suite before deploying -- and the tracked
example always. Parsed YAML, not text.
"""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _tasks():
    return yaml.safe_load((ROOT / "ansible/roles/auto-feeder/tasks/main.yml").read_text())


def test_the_example_vars_do_not_arm_the_feeder():
    v = yaml.safe_load((ROOT / "ansible/vars/main.yml.example").read_text()) or {}
    assert v.get("auto_feeder_enabled", False) is False


def test_the_local_vars_do_not_arm_the_feeder():
    local = ROOT / "ansible/vars/main.yml"
    if not local.exists():
        pytest.skip("no local vars file (CI); the deploy machine runs this check")
    v = yaml.safe_load(local.read_text()) or {}
    assert v.get("auto_feeder_enabled", False) is False, (
        "ansible/vars/main.yml arms the auto-feeder: a deploy of its role would start "
        "the timer and detonate unattended. Set auto_feeder_enabled: false.")


def test_the_role_default_keeps_the_feeder_off():
    d = yaml.safe_load((ROOT / "ansible/roles/auto-feeder/defaults/main.yml").read_text())
    assert d["auto_feeder_enabled"] is False


def test_disabled_means_stopped_and_disabled_not_merely_not_started():
    for unit in ("auto-feeder.timer", "auto-feeder-trigger.path"):
        stop = [t for t in _tasks() if t.get("ansible.builtin.systemd", {}).get("name") == unit
                and t.get("when") == "not auto_feeder_enabled"]
        assert stop, unit
        s = stop[0]["ansible.builtin.systemd"]
        assert s["enabled"] is False and s["state"] == "stopped", unit


def test_starting_is_gated_on_the_flag():
    for t in _tasks():
        s = t.get("ansible.builtin.systemd", {})
        if s.get("name", "").startswith("auto-feeder") and s.get("state") in ("started", "restarted"):
            assert t.get("when") == "auto_feeder_enabled", t.get("name")
