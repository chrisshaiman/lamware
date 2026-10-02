# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A sample that fails must leave the spool, and every other sample must run (#534).

pipeline-spool.service ran

    for f in /opt/pipeline/spool/*; do [ -f "$f" ] && run-pipeline "$f" && rm -f "$f"; done

and run-pipeline exits 1 on any stage failure (#579). The failing sample stayed
in the spool, `DirectoryNotEmpty=` re-fired the unit the moment it stopped, and
the same live sample was re-detonated in a loop; when the failure was fast the
path unit hit its trigger limit and every later upload silently never started.

These tests EXECUTE the rendered runner against a temporary spool, with a fake
run-pipeline that exits 0, exits 1, is SIGKILLed, or is still running when the
unit is stopped, and a fake ntfy_notify.py that records what it was asked to
send. Nothing here greps the script for the word `mv`.
"""
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import time
from fnmatch import fnmatchcase
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")
yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "ansible" / "roles" / "api"
RUNNER_T = (API / "templates" / "pipeline-spool-run.sh.j2").read_text(encoding="utf-8")
MONITOR_T = (ROOT / "ansible" / "roles" / "network-monitor" / "templates"
             / "network-monitor.sh.j2").read_text(encoding="utf-8")

pytestmark = [
    pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash"),
    pytest.mark.skipif(shutil.which("python3") is None, reason="needs python3"),
]

# The fake pipeline decides what to do from the sample's CONTENT, and appends
# the path it was given to calls.log so ordering and "never called" are
# observable. Its stdout must reach the sidecar's tail.
FAKE_PIPELINE = r"""#!/bin/bash
echo "$1" >> "{calls}"
case "$(head -c 16 "$1" 2>/dev/null)" in
  ok*)   echo "processed $1"; exit 0 ;;
  fail*) for i in $(seq 1 100); do echo "log line $i"; done
         echo "FAILED STAGES: cape"; exit 1 ;;
  kill*) echo "about to be OOM-killed"; kill -KILL $$ ;;
  slow*) touch "{started}"; sleep 30; exit 0 ;;
  *)     exit 3 ;;
esac
"""


class Spool:
    """A rendered runner wired to a temp spool, quarantine dir and fake tools."""

    def __init__(self, tmp: Path, create_failed: bool = True):
        self.tmp = tmp
        self.spool = tmp / "spool"
        self.spool.mkdir()
        self.failed = tmp / "spool-failed"
        if create_failed:
            self.failed.mkdir(mode=0o750)
        self.calls = tmp / "calls.log"
        self.calls.write_text("")
        self.started = tmp / "started"
        self.sent = tmp / "sent.jsonl"
        self.sent.write_text("")
        ntfy = tmp / "ntfy"
        ntfy.mkdir()
        (ntfy / "ntfy_notify.py").write_text(
            "import sys, json\n"
            f"open({str(self.sent)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n")
        fake = tmp / "run-pipeline"
        fake.write_text(FAKE_PIPELINE.format(calls=self.calls, started=self.started))
        fake.chmod(0o755)
        self.script = tmp / "pipeline-spool-run"
        self.script.write_text(jinja2.Template(RUNNER_T).render(
            api_spool_dir=str(self.spool),
            api_spool_failed_dir=str(self.failed),
            pipeline_cmd=str(fake),
            ntfy_install_dir=str(ntfy)))

    def add(self, name: str, content: str, age: float = 0.0) -> Path:
        p = self.spool / name
        p.write_text(content)
        p.chmod(0o640)       # what the API writes
        if age:
            t = time.time() - age
            os.utime(p, (t, t))
        return p

    def run(self, timeout: float = 60) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(self.script)], capture_output=True,
                              text=True, timeout=timeout)

    def popen(self) -> subprocess.Popen:
        # Own process group, so the test can signal it the way systemd signals
        # the unit's cgroup: every process at once. `/bin/bash`, as ExecStart
        # spells it, because ps reports argv[0] verbatim.
        return subprocess.Popen(["/bin/bash", str(self.script)], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True,
                                start_new_session=True)

    def called(self) -> list[str]:
        return [Path(ln).name for ln in self.calls.read_text().splitlines()]

    def alerts(self) -> list[list[str]]:
        return [json.loads(ln) for ln in self.sent.read_text().splitlines()]

    def quarantined(self) -> list[str]:
        return sorted(p.name for p in self.failed.iterdir()
                      if not p.name.endswith(".failure") and p.name != ".run.log")

    def sidecar(self, name: str) -> dict[str, str]:
        text = (self.failed / f"{name}.failure").read_text()
        head, _, tail = text.partition("--- last ")
        kv = dict(ln.split("=", 1) for ln in head.splitlines() if "=" in ln)
        kv["_tail"] = tail
        return kv


@pytest.fixture
def sp(tmp_path):
    return Spool(tmp_path)


# --- the regression ---------------------------------------------------------

def test_a_failing_sample_is_quarantined_and_the_rest_still_run(sp):
    """THE bug: the failing sample must leave the spool; the good ones run."""
    sp.add("a-good", "ok", age=30)
    sp.add("b-bad", "fail", age=20)
    sp.add("c-good", "ok", age=10)
    proc = sp.run()
    assert proc.returncode == 0, proc.stderr
    assert sp.called() == ["a-good", "b-bad", "c-good"]
    assert list(sp.spool.iterdir()) == [], (
        "the spool is not empty after a run — DirectoryNotEmpty= re-fires on "
        "whatever is left, which is the loop #534 is about")
    assert sp.quarantined() == ["b-bad"]
    assert (sp.failed / "b-bad").read_text() == "fail", "quarantine altered the sample"


def test_the_sidecar_records_exit_code_time_and_log_tail(sp):
    sp.add("bad.exe", "fail")
    sp.run()
    side = sp.sidecar("bad.exe")
    assert side["exit_code"] == "1"
    assert side["signal"] == "none"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", side["quarantined_at"])
    assert side["original_path"] == str(sp.spool / "bad.exe")
    assert "FAILED STAGES: cape" in side["_tail"], "the tail lost the last line"
    assert "log line 100" in side["_tail"]
    assert "log line 1\n" not in side["_tail"], "the whole log was kept, not a tail"


def test_the_failure_is_alerted_and_logged(sp):
    sp.add("bad.exe", "fail")
    sp.add("good.exe", "ok")
    proc = sp.run()
    alerts = sp.alerts()
    assert len(alerts) == 1, alerts
    title, message = alerts[0][0], alerts[0][1]
    assert "quarantined" in title.lower()
    assert "exit 1" in message
    assert alerts[0][alerts[0].index("--priority") + 1] == "high"
    assert re.search(r"QUARANTINED sample=bad\.exe exit=1 ", proc.stderr), proc.stderr


# --- what leaves the host -------------------------------------------------------

UUID = "3f2b9c1e-7a4d-4e8b-9c0f-1a2b3c4d5e6f"
VICTIM = "Invoice-ACME-victim"


def test_the_alert_carries_the_submission_id_not_the_filename(sp):
    """The uploaded filename is attacker-supplied and can name a case or victim,
    and ntfy defaults to the public ntfy.sh. The push says which submission;
    the name stays in the journal and the sidecar, on the host."""
    sp.add(f"{UUID}_{VICTIM}.exe", "fail")
    proc = sp.run()
    alerts = sp.alerts()
    assert len(alerts) == 1, alerts
    sent = "\n".join(alerts[0])
    assert UUID in sent, "the alert no longer says which submission failed"
    assert VICTIM not in sent, f"the uploaded filename reached the push: {sent!r}"
    assert f"{sp.failed}/" in sent, "the alert should name the quarantine directory"
    # It stays on the host.
    assert f"{UUID}_{VICTIM}.exe" in proc.stderr
    assert sp.sidecar(f"{UUID}_{VICTIM}.exe")["sample"] == f"{UUID}_{VICTIM}.exe"


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory modes")
def test_the_unmovable_alert_carries_the_submission_id_not_the_filename(sp):
    sp.failed.chmod(0o500)
    try:
        sp.add(f"{UUID}_{VICTIM}.exe", "fail")
        sp.run()
    finally:
        sp.failed.chmod(0o750)
    alerts = sp.alerts()
    assert len(alerts) == 1, alerts
    sent = "\n".join(alerts[0])
    assert UUID in sent and VICTIM not in sent, sent


def test_a_name_without_a_submission_id_is_hashed_not_quoted(sp):
    """A dotfile or hand-dropped file has no uuid prefix to fall back on; the
    alert must not degrade to quoting the name, or any part of it."""
    import hashlib
    # A uuid with a trailing `_`, but not as the prefix: only the API's own
    # prefix identifies a submission.
    name = f".{VICTIM}_{UUID}_x.exe"
    sp.add(name, "fail")
    sp.run()
    sent = "\n".join(sp.alerts()[0])
    assert VICTIM not in sent and UUID not in sent, sent
    assert hashlib.sha256(name.encode()).hexdigest()[:12] in sent


def test_a_clean_run_alerts_nobody(sp):
    """Negative control: without it, an alert on every run would pass the above."""
    sp.add("good.exe", "ok")
    proc = sp.run()
    assert proc.returncode == 0
    assert sp.alerts() == []
    assert sp.quarantined() == []
    assert "done sample=good.exe" in proc.stderr


def test_a_sample_whose_pipeline_is_killed_is_quarantined_too(sp):
    """A crash (OOM-kill: SIGKILL to the pipeline only) is a failure like any
    other; the next sample still runs."""
    sp.add("a-crash", "kill", age=20)
    sp.add("b-good", "ok", age=10)
    proc = sp.run()
    assert proc.returncode == 0, proc.stderr
    assert sp.quarantined() == ["a-crash"]
    side = sp.sidecar("a-crash")
    assert side["exit_code"] == "137"
    assert side["signal"] == "SIGKILL"
    assert "about to be OOM-killed" in side["_tail"]
    assert sp.called() == ["a-crash", "b-good"]
    assert not (sp.spool / "b-good").exists()


def test_stopping_the_unit_leaves_the_sample_in_the_spool(sp):
    """systemd stops the unit by SIGTERMing the whole cgroup. The pipeline dies
    with 143 — the host going down, not the sample failing — so the sample must
    stay queued, unalerted, for the next activation."""
    sp.add("a-slow", "slow", age=20)
    sp.add("b-next", "ok", age=10)
    p = sp.popen()
    deadline = time.time() + 15
    while not sp.started.exists():
        assert time.time() < deadline, "fake pipeline never started"
        time.sleep(0.05)
    os.killpg(p.pid, signal.SIGTERM)
    _, err = p.communicate(timeout=30)
    assert (sp.spool / "a-slow").exists(), "an interrupted sample was consumed"
    assert (sp.spool / "b-next").exists()
    assert sp.quarantined() == []
    assert sp.alerts() == []
    assert sp.called() == ["a-slow"], "kept working after being told to stop"
    assert "stopping: left sample=a-slow" in err


def test_arrival_order_not_name_order(sp):
    """The API prefixes a random UUID, so name order is arbitrary. Oldest first."""
    sp.add("zzz", "ok", age=300)
    sp.add("mmm", "fail", age=200)
    sp.add("aaa", "ok", age=100)
    sp.run()
    assert sp.called() == ["zzz", "mmm", "aaa"]


def test_dotfiles_symlinks_and_directories_leave_the_spool_unrun(sp, tmp_path):
    """DirectoryNotEmpty= counts every entry. Anything the loop skips re-fires
    the unit forever, and a symlink must never reach the pipeline."""
    outside = tmp_path / "outside.bin"
    outside.write_text("ok")
    (sp.spool / "link").symlink_to(outside)
    (sp.spool / "subdir").mkdir()
    sp.add(".hidden", "ok")
    proc = sp.run()
    assert proc.returncode == 0, proc.stderr
    assert list(sp.spool.iterdir()) == []
    assert sp.called() == [".hidden"], "a non-regular entry was handed to the pipeline"
    assert sp.quarantined() == ["link", "subdir"]
    assert outside.read_text() == "ok", "the symlink target was touched"
    assert (sp.failed / "link").is_symlink()
    assert sp.sidecar("link")["reason"] == "not a regular file"


def test_a_requeued_sample_that_fails_again_keeps_the_first_record(sp):
    """Idempotence: re-queueing a quarantined sample and failing again must not
    clobber the earlier sample or sidecar."""
    sp.add("again.exe", "fail")
    sp.run()
    first = (sp.failed / "again.exe.failure").read_text()
    shutil.move(sp.failed / "again.exe", sp.spool / "again.exe")   # operator requeue
    sp.run()
    assert (sp.failed / "again.exe.failure").read_text() == first
    names = sp.quarantined()
    assert len(names) == 1 and names[0].startswith("again.exe."), names
    assert (sp.failed / f"{names[0]}.failure").exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory modes")
def test_an_unmovable_failure_is_loud_and_fails_the_unit(sp):
    """If the quarantine cannot take it, the sample is still in the spool: that
    is the wedge, so it must be urgent and the unit must fail."""
    sp.failed.chmod(0o500)
    try:
        sp.add("bad.exe", "fail")
        sp.add("good.exe", "ok")
        proc = sp.run()
    finally:
        sp.failed.chmod(0o750)
    assert proc.returncode == 1
    assert (sp.spool / "bad.exe").exists()
    assert not (sp.spool / "good.exe").exists(), "one stuck sample stopped the rest"
    prios = [a[a.index("--priority") + 1] for a in sp.alerts()]
    assert prios == ["urgent"], sp.alerts()


def test_nothing_quarantined_is_readable_by_others(tmp_path):
    """Quarantined samples are live malware. The runner's fallback directory and
    every file it writes are owner-only."""
    sp = Spool(tmp_path, create_failed=False)
    sp.add("bad.exe", "fail")
    sp.run()
    assert stat.S_IMODE(sp.failed.stat().st_mode) == 0o700
    side = sp.failed / "bad.exe.failure"
    assert stat.S_IMODE(side.stat().st_mode) & 0o077 == 0
    assert not (sp.failed / ".run.log").exists(), "the run log was left behind"


# --- what ships it -------------------------------------------------------------

def _tasks() -> list[dict]:
    return yaml.safe_load((API / "tasks" / "main.yml").read_text())


def test_the_unit_runs_the_deployed_runner():
    unit = jinja2.Template((API / "templates" / "pipeline-spool.service.j2")
                           .read_text()).render(api_spool_failed_dir="/x")
    execs = [ln.split("=", 1)[1] for ln in unit.splitlines()
             if ln.startswith("ExecStart=")]
    assert execs == ["/bin/bash /usr/local/bin/pipeline-spool-run"]
    deployed = {t["ansible.builtin.template"]["dest"]: t["ansible.builtin.template"]
                for t in _tasks() if "ansible.builtin.template" in t}
    runner = deployed.get("/usr/local/bin/pipeline-spool-run")
    assert runner and runner["src"] == "pipeline-spool-run.sh.j2"
    assert runner["owner"] == "root", "the pipeline user must not own what it runs"


def test_the_quarantine_dir_is_created_private_and_outside_the_spool():
    defaults = yaml.safe_load((API / "defaults" / "main.yml").read_text())
    qdir = defaults["api_spool_failed_dir"]
    assert not qdir.startswith("/opt/pipeline/spool/"), (
        "inside the spool, DirectoryNotEmpty= is true forever")
    files = [t["ansible.builtin.file"] for t in _tasks() if "ansible.builtin.file" in t]
    made = [f for f in files if f.get("path") == "{{ api_spool_failed_dir }}"]
    assert len(made) == 1, "no task creates the quarantine directory"
    assert made[0]["state"] == "directory"
    assert made[0]["owner"] == "pipeline" and made[0]["group"] == "pipeline"
    assert int(made[0]["mode"], 8) & 0o007 == 0


# --- the process allowlist ----------------------------------------------------

def _rendered_pipeline_patterns() -> list[str]:
    rendered = jinja2.Template(MONITOR_T).render(
        management_interface="enp3s0f0", network_monitor_detonation_bridge="virbr-det",
        network_monitor_install_dir="/opt/network-monitor",
        network_monitor_pause_file="/opt/network-monitor/paused", cape_user="cape")
    m = re.search(r"^pipeline_patterns=\((.*?)^\)", rendered, re.S | re.M)
    assert m
    body = "\n".join(ln for ln in m.group(1).splitlines()
                     if not ln.strip().startswith("#"))
    return re.findall(r"'([^']*)'", body)


def test_the_runners_real_processes_are_allowlisted(sp):
    """Capture the command lines the runner ACTUALLY produces (from ps, during a
    run) and check them against the rendered allowlist, after mapping the temp
    paths to the deployed ones. A pattern written from memory is how the old
    'bash -c for f in ...' entry never matched anything."""
    sp.add("slow", "slow")
    p = sp.popen()
    try:
        deadline = time.time() + 15
        while not sp.started.exists():
            assert time.time() < deadline
            time.sleep(0.05)
        out = subprocess.run(["ps", "-o", "args=", "-s", str(p.pid)],
                             capture_output=True, text=True, check=True).stdout
    finally:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait()
    mapped = sorted({ln.replace(str(sp.script), "/usr/local/bin/pipeline-spool-run")
                       .replace(str(sp.failed), "/opt/pipeline/spool-failed")
                     for ln in out.splitlines()
                     if str(sp.script) in ln or ln.startswith("tee ")})
    assert "/bin/bash /usr/local/bin/pipeline-spool-run" in mapped
    assert any(ln.startswith("tee ") for ln in mapped), mapped
    pats = _rendered_pipeline_patterns()
    for cmd in mapped:
        assert any(fnmatchcase(cmd, pat) for pat in pats), (
            f"network-monitor would alert on the spool runner: {cmd!r}")
