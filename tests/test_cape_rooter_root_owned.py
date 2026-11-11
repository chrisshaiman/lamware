# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""cape-rooter runs as root, so it must run only root-owned code.

ADR-025 applied to CAPE: cape2.sh runs the rooter from the cape-owned checkout
through its virtualenv; the cape role runs a root-owned, hash-pinned copy instead.

Structural, and only because the property lives on the host: it is a file
owner and a running process. The evidence that the role works is security-test
check 15, which reads the RUNNING rooter's /proc entry and asks the kernel what
cape can write. It fails before the cape role deploys and passes after (the PR
records both). These tests hold the shape that makes that true.
"""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "cape"
TASKS = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
SMOKE = (ROOT / "ansible" / "roles" / "security-test" / "templates"
         / "security-smoke-test.sh.j2").read_text()


def _task(name: str) -> tuple[int, dict]:
    for i, t in enumerate(TASKS):
        if t.get("name") == name:
            return i, t
    raise AssertionError(f"no task named {name!r}")


def test_every_file_of_the_import_closure_is_pinned():
    files = DEFAULTS["cape_rooter_files"]
    assert set(files) == {
        "utils/rooter.py", "lib/__init__.py", "lib/cuckoo/__init__.py",
        "lib/cuckoo/common/__init__.py", "lib/cuckoo/common/path_utils.py",
        "lib/cuckoo/common/constants.py"}
    assert all(re.fullmatch(r"[0-9a-f]{64}", h) for h in files.values())


def test_files_are_hashed_after_they_are_root_only_and_before_they_are_used():
    """Hashing the cape-owned source and then copying it would let cape swap the
    file in between. Stage root-only, hash there, refuse, then install."""
    stage, t_stage = _task("Stage the rooter's files root-only")
    hashed, _ = _task("Hash the staged rooter files")
    refuse, t_refuse = _task("Refuse rooter files that do not match the pinned CAPE commit")
    install, t_install = _task("Install the verified rooter files")
    assert stage < hashed < refuse < install
    assert t_stage["ansible.builtin.copy"]["dest"].startswith("/root/")
    assert t_install["ansible.builtin.copy"]["src"].startswith("/root/")
    assert "item.stat.checksum == item.item.value" in str(t_refuse["ansible.builtin.assert"]["that"])
    assert t_install["ansible.builtin.copy"]["owner"] == "root"


def test_the_unit_runs_the_copy_under_isolated_system_python():
    _, t = _task("Run cape-rooter from the root-owned copy")
    content = t["ansible.builtin.copy"]["content"]
    lines = [ln.strip() for ln in content.splitlines()]
    # Both list-valued settings are RESET before being set, or systemd appends
    # to cape2.sh's poetry ExecStartPre / ExecStart instead of replacing them.
    assert "ExecStartPre=" in lines and "ExecStart=" in lines
    start = [ln for ln in lines if ln.startswith("ExecStart=") and ln != "ExecStart="]
    assert start == ["ExecStart=/usr/bin/python3 -I -B {{ cape_rooter_dir }}/utils/rooter.py "
                     "-g {{ cape_user }}"]
    assert "poetry" not in "\n".join(ln for ln in lines if not ln.startswith("#"))
    assert "WorkingDirectory={{ cape_rooter_dir }}/utils" in lines


def test_the_role_checks_the_running_process_not_only_the_unit():
    _, t = _task("Assert cape-rooter runs the root-owned copy")
    that = " ".join(t["ansible.builtin.assert"]["that"])
    assert "poetry" in that and "-I" in that and "rooter.py" in that


def _check15() -> str:
    start = SMOKE.index('echo "[15/16]')
    return SMOKE[start:SMOKE.index("# Summary + ntfy alert on failure", start)]


def test_security_check_reads_the_running_rooter():
    body = _check15()
    assert "/proc/$RPID/cmdline" in body and "/proc/$RPID/exe" in body and "/proc/$RPID/cwd" in body
    assert "sudo -u cape find" in body and "-writable" in body
    assert "! -user root" in body


def test_security_check_is_not_blind():
    """A probe that cannot act as cape finds nothing writable and passes. The
    control: cape must be able to write its own checkout."""
    body = _check15()
    assert re.search(r'sudo -u cape test -w "\$CAPE_DIR/utils"', body)
    assert "probe is blind" in body


def test_the_checks_are_numbered_without_gaps():
    labels = [int(n) for n, _ in re.findall(r'^echo "\[(\d+)/(\d+)\]', SMOKE, re.M)]
    totals = set(re.findall(r'^echo "\[\d+/(\d+)\]', SMOKE, re.M))
    assert labels == list(range(1, len(labels) + 1)) and totals == {str(len(labels))}
