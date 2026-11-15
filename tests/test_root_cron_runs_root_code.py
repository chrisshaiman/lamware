# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Root's scheduled jobs run and name only paths that root owns (V7; security-test check 20).

CAPE's installer left `@reboot cd /opt/CAPEv2/utils/ && ./smtp_sinkhole.sh` in
root's crontab. cape owns that tree, so cape could rewrite the script and become root
at the next boot. The cape role removes that and two other dead cape2.sh lines; check
20 guards the class.

Behavioural: check 20's own Python checker is extracted from the template and run
against fixture crontabs and real files in a temp tree. TRUSTED_UID adds this test
user to the trusted owners, so "not root-owned" is exercised with TRUSTED_UID=0 and
"writable by others" with modes. The role's removal is exercised the same way: its
shell is rendered with the real patterns and run against a stub `crontab`.
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from jinja2 import Environment

ROOT = Path(__file__).resolve().parents[1]
SMOKE = (ROOT / "ansible/roles/security-test/templates/security-smoke-test.sh.j2").read_text()
CAPE_TASKS = yaml.safe_load((ROOT / "ansible/roles/cape/tasks/main.yml").read_text())
CAPE_DEFAULTS = yaml.safe_load((ROOT / "ansible/roles/cape/defaults/main.yml").read_text())
CHECKER = SMOKE[SMOKE.index("python3 -I - <<'PYEOF'\n") + len("python3 -I - <<'PYEOF'\n"):
                SMOKE.index("\nPYEOF\n")]

HOST_CRONTAB = """\
@reboot /bin/mkdir -p /data/configdb && /bin/mkdir -p /data/db && /bin/chown mongodb:mongodb /data -R
30 1 * * 0 cd /opt/CAPEv2 && sudo -u cape /etc/poetry/bin/poetry run python ./utils/cleaners.py --delete-unused-file-data-in-mongo
15 * * * * /usr/bin/suricata-update --suricata /usr/bin/suricata --suricata-conf /etc/suricata/suricata.yaml -o /etc/suricata/rules/ &>/dev/null
@reboot cd /opt/CAPEv2/utils/ && ./smtp_sinkhole.sh 2>/dev/null
00 */1 * * * (echo authenticate ''; echo signal newnym; echo quit) | nc localhost 9051 2>/dev/null
*/5 * * * * /opt/network-monitor/network-monitor.sh >> /opt/network-monitor/network-monitor.log 2>&1
"""


@pytest.fixture
def tree(tmp_path):
    """A trusted dir with a script, a world-writable dir, and a crontab stub."""
    (tmp_path / "bin").mkdir()
    good = tmp_path / "trusted"
    good.mkdir(mode=0o755)
    (good / "job.sh").write_text("#!/bin/sh\n")
    (good / "job.sh").chmod(0o755)
    open_dir = tmp_path / "open"
    open_dir.mkdir()
    open_dir.chmod(0o777)
    (open_dir / "job.sh").write_text("#!/bin/sh\n")
    (open_dir / "job.sh").chmod(0o755)
    grp = good / "group.sh"            # group-writable: the V8 shape (root:lamware 2770)
    grp.write_text("#!/bin/sh\n")
    grp.chmod(0o775)
    gdir = tmp_path / "groupdir"
    gdir.mkdir()
    gdir.chmod(0o2770)
    (gdir / "run.sh").write_text("#!/bin/sh\n")
    (gdir / "run.sh").chmod(0o755)
    loose = good / "loose.sh"
    loose.write_text("#!/bin/sh\n")
    loose.chmod(0o777)
    cron_d = tmp_path / "cron.d"
    cron_d.mkdir()
    return tmp_path


def _check(tree: Path, crontab: str, trusted: int, cron_d: dict | None = None) -> str:
    stub = tree / "bin" / "crontab"
    (tree / "crontab.txt").write_text(crontab)
    stub.write_text(f"#!/bin/sh\ncat {tree / 'crontab.txt'}\n")
    stub.chmod(0o755)
    for name, body in (cron_d or {}).items():
        (tree / "cron.d" / name).write_text(body)
    env = {"PATH": f"{tree / 'bin'}:/usr/bin:/bin", "TRUSTED_UID": str(trusted),
           "CRONTAB_FILE": str(tree / "no-crontab"), "CRON_D": str(tree / "cron.d")}
    return subprocess.run([sys.executable, "-I", "-c", CHECKER], capture_output=True, text=True,
                          env=env, timeout=30).stdout


ME = os.getuid()


def test_a_trusted_script_passes(tree):
    out = _check(tree, f"@reboot {tree}/trusted/job.sh\n", ME)
    assert "PARSED 1" in out and "BAD" not in out, out


def test_a_script_not_owned_by_a_trusted_user_fails(tree):
    """With only root trusted, this test user's own file is the 'service account' file."""
    out = _check(tree, f"@reboot {tree}/trusted/job.sh\n", 0)
    assert "BAD" in out and f"{tree}/trusted" in out, out


@pytest.mark.parametrize("line,why", [
    ("@reboot cd {t}/open && ./job.sh", "relative command after cd into a world-writable dir"),
    ("@reboot {t}/open/job.sh", "script in a world-writable dir"),
    ("*/5 * * * * {t}/trusted/loose.sh", "world-writable script"),
    ("0 1 * * * /bin/sh {t}/trusted/loose.sh", "world-writable script passed as an argument"),
    ("0 1 * * * (echo x; {t}/trusted/loose.sh) | logger", "inside a subshell and a pipe"),
    ("@reboot {t}/trusted/group.sh", "group-writable script"),
    ("@reboot {t}/groupdir/run.sh", "script in a group-writable (setgid 2770) dir"),
])
def test_untrusted_paths_fail(tree, line, why):
    out = _check(tree, line.format(t=tree) + "\n", ME)
    assert "BAD" in out, why


def test_a_segment_run_as_another_user_is_skipped(tree):
    """`cd` into another user's tree, then sudo -u that user: root runs nothing there."""
    out = _check(tree, f"30 1 * * 0 cd {tree}/open && sudo -u cape {tree}/open/job.sh\n", ME)
    assert "PARSED 1" in out and "BAD" not in out, out


def test_cron_d_lines_count_only_for_root(tree):
    out = _check(tree, "", ME, {"x": f"*/5 * * * * nobody {tree}/open/job.sh\n"
                                      f"*/5 * * * * root {tree}/trusted/job.sh\n"})
    assert "PARSED 1" in out and "BAD" not in out, out
    out = _check(tree, "", ME, {"y": f"*/5 * * * * root {tree}/open/job.sh\n"})
    assert "BAD" in out


def test_device_files_like_dev_null_are_not_flagged(tree):
    """/dev/null is root-owned 0666 by design; distro cron lines redirect to it."""
    out = _check(tree, "", ME, {"sysstat": "5-55/10 * * * * root command -v debian-sa1 > /dev/null && debian-sa1 1 1\n"})
    assert "PARSED 1" in out and "BAD" not in out, out


def test_comments_and_variables_are_not_jobs(tree):
    out = _check(tree, "# a comment\nSHELL=/bin/bash\n\n", ME)
    assert "PARSED 0" in out


def test_the_check_reports_blind_when_nothing_parses():
    block = SMOKE[SMOKE.index('echo "[20/20]'):SMOKE.index("# Summary + ntfy")]
    assert 'if [ -z "$CRON_SEEN" ] || [ "$CRON_SEEN" = "0" ]; then' in block
    assert "root cron probe is blind" in block


# --- the cape role's removal ---------------------------------------------------

def _cleanup_task() -> dict:
    return next(t for t in CAPE_TASKS
                if (t.get("name") or "").startswith("Remove root cron lines from cape2.sh"))


def test_the_role_removes_exactly_the_three_dead_lines(tmp_path):
    if not shutil.which("bash"):
        pytest.skip("bash not available")
    script = Environment().from_string(_cleanup_task()["ansible.builtin.shell"]).render(**CAPE_DEFAULTS)
    store = tmp_path / "crontab.txt"
    store.write_text(HOST_CRONTAB)
    stub = tmp_path / "crontab"
    stub.write_text(f'#!/bin/sh\nif [ "$1" = "-l" ]; then cat {store}; else cat > {store}; fi\n')
    stub.chmod(0o755)
    env = {"PATH": f"{tmp_path}:/usr/bin:/bin"}
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env).stdout
    assert "removed: 3" in out, out
    kept = store.read_text().splitlines()
    assert [ln for ln in kept if ln] == [
        ln for ln in HOST_CRONTAB.splitlines()
        if not re.search("smtp_sinkhole|signal newnym|chown mongodb:mongodb /data", ln)]
    again = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env).stdout
    assert "removed" not in again, "not idempotent"


def test_the_host_crontab_after_cleanup_passes_check_20_shape():
    """The three removed lines are exactly the ones check 20 would flag on the host:
    smtp_sinkhole under cape's tree, and /data owned by mongodb."""
    pats = [re.compile(p) for p in CAPE_DEFAULTS["cape_root_cron_retired"]]
    removed = [ln for ln in HOST_CRONTAB.splitlines() if any(p.search(ln) for p in pats)]
    assert len(removed) == 3
