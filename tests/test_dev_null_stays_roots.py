# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""/dev/null stays root's: check 17 watches it, and no probe chowns it.

From #853 until 2026-11-19 security-test check 23 ran `tcpdump -w /dev/null` as root.
tcpdump hands its output file to the tcpdump user when it drops root, so every
security-test run left /dev/null owned by tcpdump:tcpdump; AIDE named it. Check 17's
shell block is run here against a stub `stat`, and every tcpdump invocation in the
templates is checked for a `-w` that is not `-` (stdout, which nothing chowns).
"""
import re
import subprocess
from pathlib import Path

import jinja2
import pytest

ROOT = Path(__file__).resolve().parents[1]
SMOKE = (ROOT / "ansible/roles/security-test/templates/security-smoke-test.sh.j2").read_text()
GOOD = "0:0 666 1:3 character special file"


def _check17() -> str:
    env = jinja2.Environment()  # noqa: S701 - shell, not HTML
    env.filters["bool"] = bool
    out = env.from_string(SMOKE).render()
    return out[out.index('echo "[17/27]'):out.index('echo "[18/27]')]


def _run17(tmp_path: Path, devnull: str) -> str:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "stat"
    stub.write_text(f'#!/bin/bash\n[ "${{@: -1}}" = /dev/null ] && {{ echo "{devnull}"; exit 0; }}\n'
                    'exec /usr/bin/stat "$@"\n')
    stub.chmod(0o755)
    script = 'pass() { echo "PASS: $1"; }\nfail() { echo "FAIL: $1"; }\n' + _check17()
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,
                          env={"PATH": f"{bindir}:/usr/bin:/bin"}).stdout


def test_check17_passes_when_dev_null_is_roots(tmp_path):
    out = _run17(tmp_path, GOOD)
    assert "PASS:" in out and "/dev/null is root's" in out, out


@pytest.mark.parametrize("devnull", [
    "107:108 666 1:3 character special file",   # what tcpdump left (2026-11-19)
    "0:0 600 1:3 character special file",       # chmodded by its owner
    "0:0 666 0:0 regular file",                 # replaced by a file
])
def test_check17_fails_on_a_changed_dev_null(tmp_path, devnull):
    out = _run17(tmp_path, devnull)
    assert "FAIL:" in out and f"/dev/null is '{devnull}'" in out, out


def _tcpdump_invocations() -> list[tuple[str, str]]:
    found = []
    for path in (ROOT / "ansible/roles").rglob("*"):
        if not path.is_file() or path.suffix not in (".j2", ".sh", ".yml", ".py", ""):
            continue
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for line in text.splitlines():
            code = line.split("#", 1)[0] if path.suffix != ".py" else line
            if re.search(r"/usr/bin/tcpdump\s", code) or re.search(r"(^|[\s;(])tcpdump\s+-", code):
                found.append((str(path.relative_to(ROOT)), code.strip()))
    return found


def test_no_tcpdump_invocation_writes_to_a_file_path():
    invocations = _tcpdump_invocations()
    assert invocations, "no tcpdump invocation found: the check would pass vacuously"
    bad = [(p, c) for p, c in invocations
           if (m := re.search(r"\s-w\s+(\S+)", c)) and m.group(1) != "-"]
    assert bad == [], bad


def test_the_guard_catches_the_old_probe():
    """Guards the guard: the line that chowned /dev/null must be reported."""
    old = "timeout 3 /usr/bin/tcpdump -i lo -n -c 1 -w /dev/null >/dev/null 2>&1"
    m = re.search(r"\s-w\s+(\S+)", old)
    assert m and m.group(1) != "-"
