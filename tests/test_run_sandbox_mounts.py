"""run-sandbox's mounts, executed (2026-11-27).

Every payload the API mounted was unreadable inside the container (rootless podman
drops the lamware group), so the wrapper now passes `--group-add keep-groups`.
That makes whatever is mounted readable through lamware, so the mount allowlist
narrows to exactly a task's payload directories, and `--data` (a whole task
directory) is refused.

The REAL template is rendered and run with bash against a temporary storage tree,
with `lamware-podman` replaced by a fake that records its arguments. Nothing runs
a container.
"""
import os
import re
import subprocess
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "ansible/roles/python-sandbox/templates/run-sandbox.sh.j2"


@pytest.fixture
def sandbox(tmp_path):
    storage = tmp_path / "analyses"
    for d in ("CAPE", "files", "procdump", "dropped", "network", "memory"):
        (storage / "1337" / d).mkdir(parents=True)
    lib = tmp_path / "lib"
    lib.mkdir()
    calls = tmp_path / "podman_calls"
    fake = lib / "lamware-podman"
    fake.write_text(f'#!/bin/sh\n[ "$1 $2" = "image exists" ] && exit 0\necho "$@" >> {calls}\ncat >/dev/null\n')
    fake.chmod(0o755)
    script = tmp_path / "run-sandbox"
    script.write_text(jinja2.Environment().from_string(TEMPLATE.read_text()).render(  # noqa: S701
        python_sandbox_max_script_size=10240, python_sandbox_max_output_size=1048576,
        python_sandbox_container_memory="256m", python_sandbox_container_cpus="1",
        python_sandbox_container_timeout="30", python_sandbox_data_allowlist=str(storage),
        image_store_lib_dir=str(lib)))
    script.chmod(0o755)

    def run(*args):
        r = subprocess.run(["bash", str(script), *args], input="print(1)\n", text=True,
                           capture_output=True, timeout=30,
                           env={**os.environ, "LAMWARE_IN_USER_SESSION": "1"})
        return r, (calls.read_text() if calls.exists() else "")
    return run, storage


def test_payload_dirs_are_mounted_and_the_group_is_kept(sandbox):
    run, storage = sandbox
    r, podman = run("--data-as", f"CAPE={storage}/1337/CAPE", "--data-as", f"files={storage}/1337/files")
    assert r.returncode == 0, r.stderr
    assert "--group-add keep-groups" in podman
    assert f"-v {storage}/1337/CAPE:/data/CAPE:ro" in podman
    assert f"-v {storage}/1337/files:/data/files:ro" in podman


@pytest.mark.parametrize("arg", [
    "network={task}/network",          # not a payload directory
    "CAPE={task}",                     # the whole task directory
    "CAPE={storage}",                  # the storage root
    "files={task}/CAPE",               # name does not match the directory
    "CAPE={task}/CAPE/..",             # resolves to the task directory
])
def test_anything_but_a_payload_dir_is_refused(sandbox, arg):
    run, storage = sandbox
    r, podman = run("--data-as", arg.format(task=f"{storage}/1337", storage=storage))
    assert r.returncode == 1 and "must be NAME=" in r.stderr, (r.returncode, r.stderr)
    assert podman == "", "a refused mount must not reach podman"


def test_the_whole_directory_option_is_refused(sandbox):
    run, storage = sandbox
    r, podman = run("--data", f"{storage}/1337")
    assert r.returncode == 1 and "--data was removed" in r.stderr and podman == ""


def test_the_api_mounts_only_names_the_allowlist_admits():
    """The API's mount names are payload_dirs()' PAYLOAD_SUBDIRS; the wrapper's regex
    must admit exactly those, or the agent silently loses a payload directory."""
    src = (ROOT / "shared/lamware_shared/cape_payloads.py").read_text()
    names = re.search(r"PAYLOAD_SUBDIRS[^=]*=\s*\(([^)]*)\)", src).group(1)
    subdirs = sorted(re.findall(r'"([A-Za-z]+)"', names))
    allowed = sorted(re.search(r"\(([A-Za-z|]+)\)\$", TEMPLATE.read_text()).group(1).split("|"))
    assert subdirs == allowed, (subdirs, allowed)
