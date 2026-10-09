# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The auto-feeder's code directory is root's, and its runtime files are not
opened through links.

/opt/auto-feeder was 2770 auto-feeder:lamware. Every lamware member (pipeline,
cape, lamware-api) could therefore replace auto-feeder.py by rename, shadow an
import (the script's directory is first on sys.path), write into the
group-writable __pycache__, or plant state.json / run.lock as symlinks that the
feeder then wrote through. The feeder is the one user with unrestricted egress
and sudo to run-pipeline.

The behavioural half renders the real feeder and runs its state and lock code
against real files and links, with run_cycle stubbed so nothing can reach the
network or sudo even if a guard regresses.
"""
import json
import os
import stat
import sys
from pathlib import Path

import jinja2
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "auto-feeder"
TASKS = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())


def _task(name: str) -> dict:
    return next(t for t in TASKS if isinstance(t, dict) and t.get("name") == name)


# --- deployment shape ---------------------------------------------------------

def test_the_code_directory_is_roots_and_not_group_writable():
    f = _task("Create auto-feeder directory")["ansible.builtin.file"]
    assert f["owner"] == "root"
    assert int(f["mode"], 8) & 0o022 == 0, f["mode"]


def test_the_script_is_roots():
    t = _task("Deploy auto-feeder script")["ansible.builtin.template"]
    assert t["owner"] == "root"
    assert int(t["mode"], 8) & 0o022 == 0


def test_only_the_state_directory_is_group_writable():
    items = {i["path"]: i["mode"] for i in
             _task("Create the feeder's runtime directories")["loop"]}
    assert items["{{ auto_feeder_run_dir }}"] == "2750"
    assert items["{{ auto_feeder_state_dir }}"] == "2770"


def test_the_writable_bytecode_cache_is_removed():
    f = _task("Remove the bytecode cache from the code directory")["ansible.builtin.file"]
    assert f["state"] == "absent" and f["path"].endswith("/__pycache__")


def test_the_api_can_write_the_state_directory_and_not_the_code():
    unit = jinja2.Template((ROOT / "ansible" / "roles" / "api" / "templates"
                            / "lamware-api.service.j2").read_text()).render(
        api_install_dir="/opt/lamware-api")
    rw = next(ln for ln in unit.splitlines() if ln.startswith("ReadWritePaths="))
    paths = rw.split("=", 1)[1].split()
    assert "/opt/auto-feeder/state" in paths
    assert "/opt/auto-feeder" not in paths


def test_the_api_reads_state_from_the_new_place():
    cfg = (ROOT / "api" / "app" / "config.py").read_text()
    assert '"/opt/auto-feeder/state/state.json"' in cfg
    assert '"/opt/auto-feeder/run/auto-feeder.log"' in cfg


# --- behaviour ------------------------------------------------------------------

@pytest.fixture
def feeder(tmp_path, monkeypatch):
    install, run, state = (tmp_path / n for n in ("code", "run", "state"))
    for d in (install, run, state):
        d.mkdir()
    env = jinja2.Environment()
    env.filters["to_json"] = json.dumps          # Ansible's filter, as rendered
    env.filters["bool"] = lambda v: str(v).lower() in ("1", "true", "yes", "on")
    src = env.from_string(
        (ROLE / "templates" / "auto-feeder.py.j2").read_text()).render(
            {**DEFAULTS, "auto_feeder_install_dir": str(install),
             "auto_feeder_run_dir": str(run), "auto_feeder_state_dir": str(state),
             "ntfy_install_dir": str(tmp_path / "no-ntfy"),
             "sample_feeder_dir": str(tmp_path / "sf"),
             "sample_feeder_state_file": str(tmp_path / "sf" / "seen.json")})
    monkeypatch.setattr(sys, "argv", ["auto-feeder.py"])
    ns: dict = {"__name__": "auto_feeder_under_test"}
    exec(compile(src, "auto-feeder.py", "exec"), ns)  # noqa: S102
    ns["run_cycle"] = lambda: ns.setdefault("_cycles", []).append(1)
    ns["_dirs"] = (install, run, state)
    return ns


def test_state_is_written_as_a_new_file_and_a_planted_link_is_not_followed(feeder, tmp_path):
    _, _, state = feeder["_dirs"]
    victim = tmp_path / "victim.json"
    victim.write_text("untouched")
    (state / "state.json").symlink_to(victim)
    feeder["save_state"]({"consecutive_failures": 3})
    p = state / "state.json"
    assert not p.is_symlink() and json.loads(p.read_text()) == {"consecutive_failures": 3}
    assert victim.read_text() == "untouched"
    assert stat.S_IMODE(p.stat().st_mode) == 0o664, "the API must keep group rw"


def test_state_is_not_read_through_a_link(feeder, tmp_path):
    _, _, state = feeder["_dirs"]
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"consecutive_failures": 99}))
    (state / "state.json").symlink_to(other)
    assert feeder["load_state"]().get("consecutive_failures") != 99


def test_a_planted_lock_link_stops_the_run_before_any_cycle(feeder, tmp_path):
    _, run, _ = feeder["_dirs"]
    victim = tmp_path / "victim"
    victim.write_text("untouched")
    (run / "run.lock").symlink_to(victim)
    with pytest.raises(OSError):
        feeder["main"]()
    assert victim.read_text() == "untouched"
    assert not feeder.get("_cycles"), "a cycle ran through a hijacked lock"


def test_a_normal_run_takes_the_lock_and_runs_one_cycle(feeder):
    feeder["main"]()
    _, run, _ = feeder["_dirs"]
    assert feeder.get("_cycles") == [1]
    assert (run / "run.lock").is_file()


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores the mode")
def test_nothing_is_written_in_the_code_directory(feeder):
    install, _, _ = feeder["_dirs"]
    install.chmod(0o550)          # as deployed: nobody but root may write
    try:
        feeder["save_state"]({"a": 1})
        feeder["main"]()
    finally:
        install.chmod(0o750)
    assert list(install.iterdir()) == []
