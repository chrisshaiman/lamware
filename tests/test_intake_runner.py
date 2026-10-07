"""scripts/lib/intake_run.sh, run for real against fakes.

The runner is what a night of detonations depends on, so it is executed here:
a fake `sudo` (drops `-u user`), a fake download helper and a fake pipeline that
creates a report dir. Nothing is downloaded or detonated.
"""

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "lib" / "intake_run.sh"

SHA_A, SHA_B = "a" * 64, "b" * 64


def _setup(tmp_path, fail_download=(), pipeline_rc=0):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "sudo").write_text('#!/bin/sh\n[ "$1" = "-u" ] && shift 2\nexec "$@"\n')
    reports = tmp_path / "reports"
    reports.mkdir()
    pipe_log = tmp_path / "pipeline_calls"
    (bin_ / "run-pipeline").write_text(
        f'#!/bin/sh\necho "$@" >> {pipe_log}\nmkdir -p {reports}/r_$(basename $(dirname "$1"))\nexit {pipeline_rc}\n')
    for f in bin_.iterdir():
        f.chmod(0o755)
    b = tmp_path / "batch"
    b.mkdir()
    (b / "manifest.json").write_text(json.dumps([
        {"sha256": SHA_A, "signature": "Stealc"}, {"sha256": SHA_B, "signature": "Vidar"}]))
    # Fake download helper with the real CLI: <sha> <out_dir> -> "<path>\t<name>"
    fails = " ".join(fail_download)
    (b / "intake_download.py").write_text(f'''import sys, os
sha, out = sys.argv[1], sys.argv[2]
if sha in "{fails}".split(): sys.exit(3)
os.makedirs(out, exist_ok=True)
p = os.path.join(out, "s.exe")
open(p, "w").write("x")
print(p + "\\t" + "s.exe")
''')
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}",
           "INTAKE_RUN_PIPELINE": str(bin_ / "run-pipeline"), "INTAKE_REPORTS_DIR": str(reports),
           "INTAKE_PAUSE_FILE": str(tmp_path / "PAUSE"), "INTAKE_PYTHON": "python3"}
    return b, env, pipe_log, reports


def _run(b, env):
    return subprocess.run(["bash", str(RUNNER), str(b)], env=env, capture_output=True, text=True, timeout=60)


def _status(b):
    return [line.split("\t") for line in (b / "status.tsv").read_text().splitlines()]


def test_each_sample_runs_the_pipeline_with_its_family(tmp_path):
    b, env, pipe_log, _ = _setup(tmp_path)
    _run(b, env)
    calls = pipe_log.read_text().splitlines()
    assert len(calls) == 2
    assert "--filename s.exe --bazaar-family Stealc" in calls[0]
    assert "--bazaar-family Vidar" in calls[1]
    st = _status(b)
    assert [s[0] for s in st] == [SHA_A, SHA_B] and all(s[2] == "rc=0" for s in st)
    assert st[0][3] == f"r_{SHA_A}"   # the new report dir is recorded


def test_the_staged_sample_is_removed_after_its_run(tmp_path):
    b, env, _, _ = _setup(tmp_path)
    _run(b, env)
    assert not (b / SHA_A).exists() and not (b / SHA_B).exists()


def test_a_rerun_skips_finished_samples(tmp_path):
    b, env, pipe_log, _ = _setup(tmp_path)
    _run(b, env)
    _run(b, env)
    assert len(pipe_log.read_text().splitlines()) == 2


def test_a_failed_download_is_recorded_and_the_batch_continues(tmp_path):
    b, env, pipe_log, _ = _setup(tmp_path, fail_download=(SHA_A,))
    _run(b, env)
    st = _status(b)
    assert st[0][:3] == [SHA_A, "Stealc", "download_failed"]
    assert st[1][2] == "rc=0" and len(pipe_log.read_text().splitlines()) == 1


def test_a_failing_pipeline_is_recorded_not_hidden(tmp_path):
    b, env, _, _ = _setup(tmp_path, pipeline_rc=4)
    _run(b, env)
    assert all(s[2] == "rc=4" for s in _status(b))


def test_the_pause_file_stops_the_batch(tmp_path):
    b, env, pipe_log, _ = _setup(tmp_path)
    (tmp_path / "PAUSE").write_text("")
    _run(b, env)
    assert not pipe_log.exists()
    assert "PAUSE file present" in (b / "intake.log").read_text()
