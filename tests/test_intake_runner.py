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
    sudo_log = tmp_path / "sudo_calls"
    # Fake sudo: records "<user> <command...>", drops `-u user`.
    (bin_ / "sudo").write_text(f'#!/bin/sh\n[ "$1" = "-u" ] && {{ echo "$2 $3 $4" >> {sudo_log}; shift 2; }}\nexec "$@"\n')
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
    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "intake_download.py").write_text(f'''import sys, os
sha, out = sys.argv[1], sys.argv[2]
if sha in "{fails}".split(): sys.exit(3)
os.makedirs(out, exist_ok=True)
p = os.path.join(out, "s.exe")
open(p, "w").write("x")
print(p + "\\t" + "s.exe")
''')
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}",
           "INTAKE_RUN_PIPELINE": str(bin_ / "run-pipeline"), "INTAKE_REPORTS_DIR": str(reports),
           "INTAKE_PAUSE_FILE": str(tmp_path / "PAUSE"), "INTAKE_PYTHON": "python3",
           "INTAKE_LIB": str(lib)}
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
    assert not (b / "dl" / SHA_A).exists() and not (b / "dl" / SHA_B).exists()


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


# --- ADR-025 for intake: root runs only root-owned code, writes only its own dir --

def test_nothing_in_the_batch_directory_is_executed(tmp_path):
    """The batch dir used to be lamware-group-writable and held the scripts root ran.
    A planted downloader there must never run; the real one comes from INTAKE_LIB."""
    b, env, pipe_log, _ = _setup(tmp_path)
    marker = tmp_path / "PLANTED_RAN"
    (b / "intake_download.py").write_text(f"open({str(marker)!r}, 'w').write('x')\n")
    _run(b, env)
    assert not marker.exists()
    assert len(pipe_log.read_text().splitlines()) == 2


def test_a_manifest_entry_that_is_not_a_sha256_is_skipped_before_any_download(tmp_path):
    b, env, pipe_log, _ = _setup(tmp_path)
    (b / "manifest.json").write_text(json.dumps([
        {"sha256": "../../../etc", "signature": "x"}, {"sha256": "A" * 64, "signature": "x"},
        {"sha256": "a" * 63, "signature": "x"}, {"sha256": SHA_B, "signature": "Vidar"}]))
    _run(b, env)
    calls = (tmp_path / "sudo_calls").read_text().splitlines()
    downloads = [c for c in calls if "intake_download.py" in c]
    assert len(downloads) == 1 and SHA_B in pipe_log.read_text()
    assert (b / "intake.log").read_text().count("not a sha256") == 3


def test_the_staged_sample_is_removed_as_auto_feeder_not_root(tmp_path):
    b, env, _, _ = _setup(tmp_path)
    _run(b, env)
    rms = [c for c in (tmp_path / "sudo_calls").read_text().splitlines() if " rm " in f" {c} "]
    assert rms and all(c.startswith("auto-feeder rm") for c in rms), rms


INTAKE_SH = (ROOT / "scripts" / "intake.sh").read_text()


def test_intake_sh_installs_the_code_root_owned_and_runs_it_from_there():
    assert "LIB=/usr/local/lib/lamware/intake" in INTAKE_SH
    assert "install -o root -g root -m 0755 /dev/stdin '$LIB/intake_run.sh'" in INTAKE_SH
    assert "install -o root -g root -m 0755 /dev/stdin '$LIB/intake_download.py'" in INTAKE_SH
    exec_lines = [ln for ln in INTAKE_SH.splitlines() if ln.startswith("ExecStart=")]
    assert exec_lines == ["ExecStart=/bin/bash $LIB/intake_run.sh $B"]


def test_intake_sh_gives_auto_feeder_only_the_download_dir():
    assert "install -d -o root -g root -m 0755 /usr/local/lib/lamware '$LIB' /opt/pipeline/intake '$B'" in INTAKE_SH
    assert "install -d -o auto-feeder -g lamware -m 2750 '$B/dl'" in INTAKE_SH
    assert "2770" not in "".join(ln for ln in INTAKE_SH.splitlines() if not ln.lstrip().startswith("#"))


def test_samples_are_staged_under_the_auto_feeder_dl_directory(tmp_path):
    """The batch dir is root's; only dl/ belongs to auto-feeder, so that is where
    the downloader writes and what the pipeline is pointed at."""
    b, env, pipe_log, _ = _setup(tmp_path)
    _run(b, env)
    for call in pipe_log.read_text().splitlines():
        assert call.split()[0].startswith(f"{b}/dl/"), call


def test_the_batch_directory_migration_reaches_its_target_and_stays_there(tmp_path):
    """Run the role's normalise script against a setgid tree (the host had 2770
    batch dirs). `chmod 0755` alone keeps setgid on a directory, so the first
    version never matched `755` and reported a change on every deploy."""
    import os
    import subprocess

    import yaml
    tasks = yaml.safe_load((ROOT / "ansible" / "roles" / "pipeline" / "tasks" / "main.yml").read_text())
    script = next(t for t in tasks if isinstance(t, dict) and t.get("name")
                  == "Make the intake directory and each batch directory root's (0755)")["ansible.builtin.shell"]
    me = f"{os.getuid()}"
    top = tmp_path / "intake"
    (top / "batch-a").mkdir(parents=True)
    os.symlink("/etc", top / "link")
    for d in (top, top / "batch-a"):
        os.chmod(d, 0o2770)
    # Run as the test user: root:root becomes the caller's own name and group.
    import grp
    import pwd
    owner = f"{pwd.getpwuid(os.getuid()).pw_name}:{grp.getgrgid(os.getgid()).gr_name}"
    script = (script.replace("/opt/pipeline/intake", str(top))
              .replace("chown -h root:root", f"chown -h {me}:{os.getgid()}")
              .replace("root:root 755", f"{owner} 755"))
    first = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    assert first.stdout.strip() == "normalised 2"
    for d in (top, top / "batch-a"):
        assert oct(d.stat().st_mode & 0o7777) == "0o755", d
    second = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    assert second.stdout.strip() == "normalised 0"


def test_a_named_profile_is_passed_to_every_run(tmp_path):
    b, env, pipe_log, _ = _setup(tmp_path)
    (b / "llm_profile").write_text("stub\n")
    _run(b, env)
    calls = pipe_log.read_text().splitlines()
    assert len(calls) == 2 and all(c.endswith("--llm-profile stub") for c in calls), calls


def test_no_profile_means_no_flag_so_the_deployment_default_applies(tmp_path):
    """ADR-038: an empty or absent llm_profile used to become `--llm-profile local`,
    which would override an operator's changed default."""
    for content in ("", None):
        root = tmp_path / ("empty" if content == "" else "absent")
        root.mkdir()
        b, env, pipe_log, _ = _setup(root)
        if content is not None:
            (b / "llm_profile").write_text(content)
        r = _run(b, env)
        calls = pipe_log.read_text().splitlines()
        assert len(calls) == 2, r.stderr
        assert not [c for c in calls if "--llm-profile" in c], calls
