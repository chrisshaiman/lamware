# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""CAPE's rooter is not run (ADR-028).

It is a root daemon that takes commands from cape. CAPE's own processes could not
reach it from 2026-05-15 (they run with Group=lamware and its socket is root:cape
0620), so every detonation since, including every eval baseline, ran without it, and
the guests reach INetSim because it was unreachable: for route = none it would drop
the host's replies to the guest. The cape role masks it and removes #835's copy.

Behavioural: security-test check 15's own shell block is run against stub
`systemctl` and `pgrep`, for the retired state and for each way the rooter could
come back, plus the blind case. Structural for the role, whose effect is on the
host (check 15 is the host evidence).
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from jinja2 import Environment

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible/roles/cape"
TASKS = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
HANDLERS = yaml.safe_load((ROLE / "handlers/main.yml").read_text())
SMOKE = (ROOT / "ansible/roles/security-test/templates/security-smoke-test.sh.j2").read_text()
MONITOR = (ROOT / "ansible/roles/network-monitor/templates/network-monitor.sh.j2").read_text()

SYSTEMCTL = r'''#!/bin/sh
# show <unit> -p LoadState --value  |  is-active -q <unit>
case "$1" in
  show) case "$2" in
          cape-rooter) echo "$ROOTER_LOAD" ;;
          cape) echo "$CAPE_LOAD" ;;
        esac ;;
  is-active) [ "$ROOTER_ACTIVE" = yes ] && exit 0 || exit 3 ;;
esac
'''
PGREP = '#!/bin/sh\n[ -n "$ROOTER_PIDS" ] && echo "$ROOTER_PIDS" && exit 0\nexit 1\n'


def _check15(sock: str) -> str:
    start = SMOKE.index('echo "[15/22]')
    block = SMOKE[start:SMOKE.index("# ----", start)]
    return Environment().from_string(block).render(security_test_cape_rooter_socket=sock)


@pytest.fixture
def run(tmp_path):
    if not shutil.which("bash"):
        pytest.skip("bash not available")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in (("systemctl", SYSTEMCTL), ("pgrep", PGREP)):
        (bindir / name).write_text(body)
        (bindir / name).chmod(0o755)
    sock = tmp_path / "cuckoo-rooter"
    script = 'pass(){ echo "PASS: $*"; }\nfail(){ echo "FAIL: $*"; }\n' + _check15(str(sock))

    def go(load="masked", active="no", pids="", cape_load="loaded", socket=False):
        if socket:
            sock.write_text("")
        env = {"PATH": f"{bindir}:/usr/bin:/bin", "ROOTER_LOAD": load, "ROOTER_ACTIVE": active,
               "ROOTER_PIDS": pids, "CAPE_LOAD": cape_load}
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env).stdout
    return go


def test_the_retired_state_passes(run):
    out = run()
    assert "PASS: cape-rooter: masked" in out and "FAIL" not in out, out


@pytest.mark.parametrize("kw,expect", [
    ({"load": "loaded"}, "not masked"),
    ({"load": "not-found"}, "not masked"),
    ({"active": "yes"}, "unit is active"),
    ({"pids": "4242"}, "rooter process running"),
    ({"socket": True}, "exists"),
])
def test_each_way_back_fails(run, kw, expect):
    out = run(**kw)
    assert "FAIL: cape-rooter is back" in out and expect in out, out


def test_a_blind_systemctl_query_fails_rather_than_passes(run):
    """With systemctl unable to read units, every rooter test would find nothing."""
    out = run(load="masked", cape_load="")
    assert "FAIL: rooter probe is blind" in out, out


def _named(fragment: str) -> tuple[int, dict]:
    for i, t in enumerate(TASKS):
        if fragment.lower() in (t.get("name") or "").lower():
            return i, t
    raise AssertionError(f"no task {fragment!r}")


def test_the_role_masks_the_rooter_before_removing_its_files():
    i, t = _named("Stop, disable and mask CAPE's rooter")
    svc = t["ansible.builtin.systemd_service"]
    assert (svc["name"], svc["state"], svc["enabled"], svc["masked"]) == ("cape-rooter", "stopped", False, True)
    j, r = _named("Remove the retired rooter copy")
    assert i < j
    assert r["ansible.builtin.file"]["state"] == "absent"
    assert set(r["loop"]) >= {"{{ cape_rooter_retired_dir }}", "/etc/systemd/system/cape-rooter.service.d",
                              "/tmp/cuckoo-rooter", "/root/cape-rooter-staging"}


def test_nothing_in_the_role_starts_restarts_or_configures_the_rooter():
    text = (ROLE / "tasks/main.yml").read_text() + (ROLE / "handlers/main.yml").read_text()
    for t in TASKS + HANDLERS:
        body = yaml.safe_dump(t)
        if "cape-rooter" not in body:
            continue
        name = t.get("name", "")
        assert name.startswith(("Stop, disable and mask", "Remove the retired rooter")), name
    assert not re.search(r"cape-rooter\.service\.d/\S+\.conf", text), "a rooter drop-in is still installed"
    assert "Restart cape-rooter" not in text


def test_the_network_monitor_no_longer_allows_a_rooter_process():
    assert "rooter.py" not in MONITOR
