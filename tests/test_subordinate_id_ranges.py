# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""No two users share a subordinate uid or gid range (security-test check 16).

A rootless container maps its uids onto its owner's /etc/subuid range, so two
users whose ranges overlap share host uids. The check's own awk program is pulled
from the security-test template and run against fixtures (a file where cape's
ranges overlap two other users', the same file after the cape role's cleanup
regexp, and edge cases).
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SMOKE = (ROOT / "ansible/roles/security-test/templates/security-smoke-test.sh.j2").read_text()
CAPE_TASKS = yaml.safe_load((ROOT / "ansible/roles/cape/tasks/main.yml").read_text())

OVERLAPPING = """cape:1000:100
alice:1000:100
cape:1100:100
bob:1150:100
carol:1250:100
"""


def _awk_program() -> str:
    block = SMOKE[SMOKE.index('echo "[16/16]'):]
    m = re.search(r"awk -F: '(.*?)' \"\$f\"", block, re.S)
    assert m, "check 16's awk program not found in the template"
    return m.group(1)


def _overlaps(text: str, tmp_path) -> str:
    if not shutil.which("awk"):
        pytest.skip("awk not available")
    f = tmp_path / "subuid"
    f.write_text(text)
    return subprocess.run(["awk", "-F:", _awk_program(), str(f)], capture_output=True,
                          text=True, check=True).stdout


def test_both_overlaps_are_found(tmp_path):
    out = _overlaps(OVERLAPPING, tmp_path)
    assert "cape:1000+100/alice:1000+100" in out
    assert "cape:1100+100/bob:1150+100" in out
    assert "carol" not in out           # adjacent to bob, no overlap


def _cape_cleanup_regexp() -> str:
    task = next(t for t in CAPE_TASKS
                if "ansible.builtin.lineinfile" in t
                and "subordinate id range" in t.get("name", "").lower())
    params = task["ansible.builtin.lineinfile"]
    assert params["state"] == "absent" and task["loop"] == ["subuid", "subgid"]
    return params["regexp"].replace("{{ cape_user }}", "cape")


def test_after_the_cape_cleanup_no_two_users_overlap(tmp_path):
    rx = re.compile(_cape_cleanup_regexp())
    fixed = "".join(ln + "\n" for ln in OVERLAPPING.splitlines() if not rx.search(ln))
    assert "cape:" not in fixed and "bob:1150:100" in fixed
    assert _overlaps(fixed, tmp_path) == ""


@pytest.mark.parametrize("text,expect", [
    ("a:1000:10\nb:1009:5\n", "a:1000+10/b:1009+5"),      # one id in common
    ("a:1000:10\nb:1010:5\n", ""),                        # adjacent, no overlap
    ("a:1000:10\na:1005:10\n", ""),                       # same user may overlap itself
    ("a:1000:100\nb:1010:5\n", "a:1000+100/b:1010+5"),    # contained
    ("# comment\nbad line\na:x:10\n", ""),                # malformed lines ignored
])
def test_edge_cases(tmp_path, text, expect):
    assert _overlaps(text, tmp_path).strip() == expect
