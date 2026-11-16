# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The network monitor runs its unprivileged reads with argv, not shell strings (V2).

It runs as root from cron and drops to pipeline, postgres or nobody to ask "can
this user read that?". Those used to be `su -s /bin/bash -c "... '$path' ..."`,
with $path a directory or file name cape chooses (under CAPE's analyses and
binaries). A name with a quote and `$(...)` in it ran as that user.

The real blocks are run here against fixture trees whose names carry a payload.
`runuser` and `su` are stubs that run their command as the test user, so an
injection would really execute and leave PWNED behind.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import jinja2

ROOT = Path(__file__).resolve().parents[1]
MONITOR_T = (ROOT / "ansible/roles/network-monitor/templates/network-monitor.sh.j2").read_text()
MONITOR = jinja2.Environment().from_string(MONITOR_T).render()  # noqa: S701 - shell, not HTML
# No "/" in a file name, so the target path comes from the environment ($PWN).
PAYLOAD = "x'$(touch \"$PWN\")'y"


def _stubs(tmp: Path) -> Path:
    """runuser -u U -- CMD... and su -s SH -c STR U: run as the caller, record argv."""
    bindir = tmp / "bin"
    bindir.mkdir()
    (bindir / "runuser").write_text(
        '#!/bin/bash\necho "runuser $*" >> "$STUB_LOG"\n'
        'while [ "$1" != "--" ]; do shift; done; shift; exec "$@"\n')
    (bindir / "su").write_text(
        '#!/bin/bash\necho "su $*" >> "$STUB_LOG"\n'
        'while [ "$1" != "-c" ]; do shift; done; exec /bin/bash -c "$2"\n')
    for f in bindir.iterdir():
        f.chmod(0o755)
    return bindir


def _run(tmp: Path, script: str) -> tuple[str, str]:
    env = {"PATH": f"{_stubs(tmp)}:/usr/bin:/bin", "STUB_LOG": str(tmp / "calls"),
           "PWN": str(tmp / "PWNED")}
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env,
                         cwd=tmp, timeout=30).stdout
    return out, (tmp / "calls").read_text() if (tmp / "calls").exists() else ""


def _storage_block() -> str:
    start = MONITOR.index('CAPE_ANALYSES="')
    return MONITOR[start:MONITOR.index("# CAPE has no usable machines", start)]


def _exposure_block() -> str:
    start = MONITOR.index("exposed_samples=0")
    return MONITOR[start:MONITOR.index('if [ "$exposed_samples" -gt 0 ]', start)]


def test_a_hostile_analysis_directory_name_is_listed_not_executed(tmp_path):
    pwned = tmp_path / "PWNED"
    analyses = tmp_path / "analyses"
    hostile = analyses / PAYLOAD / "CAPE"
    hostile.mkdir(parents=True)
    (hostile / "payload.bin").write_text("x")
    block = re.sub(r'^CAPE_ANALYSES=".*"$', f'CAPE_ANALYSES="{analyses}"', _storage_block(), count=1, flags=re.M)
    out, calls = _run(tmp_path, block + '\necho "status=$cape_storage_status probe=$probe_dir"\n')
    assert not pwned.exists(), "a directory name ran as code"
    assert f"status=ok probe={hostile}" in out, out
    assert calls.count("runuser -u pipeline --") == 2 and "su " not in calls, calls


def test_a_hostile_sample_file_name_is_read_not_executed(tmp_path):
    pwned = tmp_path / "PWNED"
    store = tmp_path / "binaries"
    store.mkdir()
    sample = store / PAYLOAD
    sample.write_text("MZ")
    sample.chmod(0o644)
    block = re.sub(r"^for store in .*?; do$", f'for store in "{store}"; do', _exposure_block(),
                   count=1, flags=re.M | re.S)
    out, calls = _run(tmp_path, block + '\necho "exposed=$exposed_samples"\n')
    assert not pwned.exists(), "a file name ran as code"
    assert "exposed=1" in out, out
    assert "runuser -u nobody -- head -c 1 --" in calls and "su " not in calls, calls


def test_no_su_shell_strings_remain_in_the_monitor():
    """A memory of V2: the monitor runs as root, so a `su -c` with a variable in it is
    the shape to keep out. runuser with argv is the replacement."""
    code = [ln for ln in MONITOR.splitlines() if not ln.lstrip().startswith("#")]
    offenders = [ln.strip() for ln in code if re.search(r"\bsu\s+(-s\s+\S+\s+)?-c\b", ln)]
    assert not offenders, offenders


def test_the_machine_count_query_drops_to_postgres_without_a_shell():
    block = MONITOR[MONITOR.index("cape_machines_status=\"ok\""):]
    m = re.search(r"machine_count=\$\((.*?)\)\n", block, re.S)
    assert m and "runuser -u postgres -- psql" in m.group(1)
    assert "bash -c" not in m.group(1)
