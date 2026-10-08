# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Container wrappers never make a work dir world-writable, and always remove it (#694).

Four wrappers ran `chmod a+rwx` (ghidra tool mode: `chmod -R a+rwX`) on their
mktemp dirs so the container's nobody (65534, mapped to a pipeline subuid) could
write. For the length of every job any local user could add or replace files in
the container's input/output, and a failed cleanup left 0777 pipeline dirs in
/tmp (two from 2026-09-21 were found on the host). Worse, `cp -a tmp/. out/`
copies the "." entry's mode onto the destination, so every real output dir the
copy-back wrote into was stamped 0777 as well.

Behavioural: each wrapper template is rendered with its role's defaults and RUN
against a stubbed `podman` (and a `chmod` shim that records the resulting
modes). The stub snapshots every directory under TMPDIR at the moment the
container would start, fakes the container's output, and executes
`podman unshare rm`. It does NOT perform `podman unshare chown` — that needs a
real user namespace — so the tests assert the chown CALL (target and uid), not
its effect on the host. That gap is the "Not verified" of the PR.
"""
from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import time
from pathlib import Path

import pytest
import yaml
from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "ansible" / "roles"

TEMPLATES = {
    "ghidra": "run-ghidra-wrapper.sh.j2",
    "pcap-analysis": "run-pcap-analysis-wrapper.sh.j2",
    "triage": "run-triage-wrapper.sh.j2",
}

# One recording podman: logs every call as a JSON line, snapshots TMPDIR when a
# container "starts", writes fake output into the rw mount, and runs
# `unshare rm` for real so cleanup is observable.
PODMAN_STUB = r'''#!/usr/bin/env python3
import json, os, sys, time
args = sys.argv[1:]
log = os.environ["STUB_LOG"]
def record(entry):
    with open(log, "a") as f:
        f.write(json.dumps(entry) + "\n")
if args[:1] == ["unshare"]:
    record({"call": "unshare", "argv": args[1:]})
    if args[1:2] == ["rm"]:
        os.execvp("rm", args[1:])
    sys.exit(0)  # chown needs a real userns; the call itself is what is asserted
if args[:1] != ["run"]:
    record({"call": args[:1], "argv": args})
    sys.exit(0)
mounts, user, i = [], None, 1
while i < len(args):
    if args[i] == "-v":
        src, dst, opts = args[i + 1].split(":")
        mounts.append({"src": src, "dst": dst, "opts": opts})
        i += 2
        continue
    if args[i] == "--user":
        user = args[i + 1]
        i += 2
        continue
    i += 1
tree = {}
for base, dirs, files in os.walk(os.environ["TMPDIR"]):
    for name in [""] + dirs + files:
        p = os.path.join(base, name) if name else base
        tree[p] = os.lstat(p).st_mode & 0o7777
record({"call": "run", "argv": args, "mounts": mounts, "user": user, "tree": tree})
open(os.environ["STUB_STARTED"], "w").close()
if os.environ.get("STUB_SLEEP"):
    time.sleep(float(os.environ["STUB_SLEEP"]))
if os.environ.get("STUB_FAIL"):
    sys.exit(1)
by_dst = {m["dst"]: m["src"] for m in mounts}
if "/output" in by_dst:
    out = by_dst["/output"]
    os.makedirs(os.path.join(out, "project", "analysis.rep"), exist_ok=True)
    with open(os.path.join(out, "result.json"), "w") as f:
        f.write("{}")
print("{}")
'''

# Records the mode each chmod LEFT behind, so a transient a+rwx later narrowed
# again is still caught.
CHMOD_SHIM = r'''#!/bin/bash
/bin/chmod "$@" || exit $?
for a in "$@"; do
    case "$a" in -*) continue ;; esac
    [ -e "$a" ] && stat -c '%a %n' "$a" >> "$CHMOD_LOG"
done
exit 0
'''


def _defaults(role: str) -> dict:
    data = yaml.safe_load((ROLES / role / "defaults" / "main.yml").read_text()) or {}
    env = Environment(undefined=StrictUndefined)
    for _ in range(3):  # defaults that reference other defaults
        data = {k: env.from_string(v).render(**data) if isinstance(v, str) else v
                for k, v in data.items()}
    return data


def _render(role: str, dest: Path) -> Path:
    src = (ROLES / role / "templates" / TEMPLATES[role]).read_text()
    text = Environment(undefined=StrictUndefined, keep_trailing_newline=True) \
        .from_string(src).render(**_defaults(role))
    dest.write_text(text)
    dest.chmod(0o755)
    return dest


class Run:
    """One wrapper execution and what the stubs observed."""

    def __init__(self, proc: subprocess.CompletedProcess | None, tmp: Path,
                 out: Path, returncode: int):
        self.proc = proc
        self.tmp = tmp
        self.out = out
        self.returncode = returncode
        log = tmp.parent / "podman.log"
        self.calls = [json.loads(line) for line in log.read_text().splitlines()] \
            if log.exists() else []
        chmod_log = tmp.parent / "chmod.log"
        self.chmods = chmod_log.read_text().splitlines() if chmod_log.exists() else []

    @property
    def run_call(self) -> dict:
        runs = [c for c in self.calls if c["call"] == "run"]
        assert len(runs) == 1, f"expected one podman run, got {self.calls}"
        return runs[0]

    def index(self, pred) -> int:
        return next(i for i, c in enumerate(self.calls) if pred(c))


# (case id, role, argv builder). The builder gets the scratch root and returns
# argv plus the output dir the wrapper should copy into (None: tool mode).
def _sample(root: Path) -> Path:
    p = root / "inputs" / "sample.bin"
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(b"MZ")
    return p


def _out(root: Path) -> Path:
    d = root / "reports" / "out"
    d.mkdir(parents=True)
    d.chmod(0o750)
    return d


def _ghidra_tool(root: Path):
    proj = root / "persisted" / "project"
    (proj / "analysis.rep").mkdir(parents=True)
    (proj / "analysis.gpr").write_text("x")
    for p in (proj, proj / "analysis.rep"):
        p.chmod(0o750)
    (proj / "analysis.gpr").chmod(0o640)
    return ["--tool", str(proj), "prog", "list_functions", "{}"], None


CASES = {
    "ghidra-analysis": ("ghidra", lambda r: ([str(_sample(r)), str(o := _out(r))], o)),
    "ghidra-shellcode": ("ghidra",
                         lambda r: (["--shellcode", str(_sample(r)), str(o := _out(r)), "0x1000"], o)),
    "ghidra-tool": ("ghidra", _ghidra_tool),
    "pcap-analysis": ("pcap-analysis", lambda r: ([str(_sample(r)), str(o := _out(r))], o)),
    "triage": ("triage", lambda r: ([str(_sample(r)), str(o := _out(r))], o)),
}


def _execute(case: str, root: Path, *, fail: bool = False, kill: signal.Signals | None = None) -> Run:
    role, build = CASES[case]
    stubs = root / "bin"
    stubs.mkdir()
    (stubs / "podman").write_text(PODMAN_STUB)
    (stubs / "podman").chmod(0o755)
    (stubs / "chmod").write_text(CHMOD_SHIM)
    (stubs / "chmod").chmod(0o755)
    tmp = root / "tmp"
    tmp.mkdir()
    wrapper = _render(role, root / "wrapper.sh")
    argv, out = build(root)
    env = {
        **os.environ,
        "PATH": f"{stubs}:{os.environ['PATH']}",
        "TMPDIR": str(tmp),
        "STUB_LOG": str(root / "podman.log"),
        "STUB_STARTED": str(root / "started"),
        "CHMOD_LOG": str(root / "chmod.log"),
        # ghidra tool mode re-execs through systemd-run unless already inside
        # the user session; the re-exec is not what is under test.
        "LAMWARE_IN_USER_SESSION": "1",
    }
    if fail:
        env["STUB_FAIL"] = "1"
    if kill is None:
        proc = subprocess.run([str(wrapper), *argv], env=env, capture_output=True,
                              text=True, timeout=60)
        return Run(proc, tmp, out, proc.returncode)
    env["STUB_SLEEP"] = "30"
    p = subprocess.Popen([str(wrapper), *argv], env=env, start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 20
    while not (root / "started").exists():
        assert time.time() < deadline, "the stubbed container never started"
        time.sleep(0.05)
    # What systemd does on a stop: signal the whole group, container included.
    os.killpg(p.pid, kill)
    rc = p.wait(timeout=20)
    return Run(None, tmp, out, rc)


@pytest.fixture(params=sorted(CASES))
def case(request):
    return request.param


def _mode(m: int) -> str:
    return oct(m)


def test_every_wrapper_template_is_exercised():
    """Guards the guard: a wrapper missing here would pass by not being run."""
    assert set(TEMPLATES) == {role for role, _ in CASES.values()}
    for role, name in TEMPLATES.items():
        assert (ROLES / role / "templates" / name).is_file()


def test_nothing_is_world_writable_while_the_container_runs(case, tmp_path):
    run = _execute(case, tmp_path)
    assert run.returncode == 0, run.proc.stderr
    tree = {Path(p): m for p, m in run.run_call["tree"].items()}
    writable = {str(p): _mode(m) for p, m in tree.items()
                if p != run.tmp and m & stat.S_IWOTH}
    assert not writable, f"world-writable while the job ran: {writable}"
    # The job dir is mktemp's private 0700 dir and every mount source is under it,
    # so no other local user can reach any of them whatever their own mode.
    job_dirs = [p for p in tree if p.parent == run.tmp]
    assert len(job_dirs) == 1, f"expected one private job dir, got {job_dirs}"
    assert tree[job_dirs[0]] == 0o700, _mode(tree[job_dirs[0]])
    for m in run.run_call["mounts"]:
        if m["src"].startswith(str(run.tmp)):
            assert Path(m["src"]).parent == job_dirs[0], m


def test_no_chmod_ever_leaves_a_world_writable_mode(case, tmp_path):
    run = _execute(case, tmp_path)
    assert run.returncode == 0, run.proc.stderr
    bad = [line for line in run.chmods if int(line.split()[0], 8) & stat.S_IWOTH]
    assert not bad, f"chmod granted other-write: {bad}"


def test_the_writable_mount_belongs_to_the_container_user_only(case, tmp_path):
    """The container must still be able to write: its rw mount is chowned (in the
    userns) to exactly the uid:gid it runs as, BEFORE the container starts."""
    run = _execute(case, tmp_path)
    assert run.returncode == 0, run.proc.stderr
    rc = run.run_call
    assert rc["user"] == "65534:65534", rc["user"]
    rw = [m for m in rc["mounts"] if m["opts"] == "rw"]
    assert len(rw) == 1, rc["mounts"]
    src = rw[0]["src"]
    assert rc["tree"][src] & 0o077 == 0, f"rw mount {src} is {_mode(rc['tree'][src])}"
    run_at = run.index(lambda c: c["call"] == "run")
    chowns = [i for i, c in enumerate(run.calls)
              if c["call"] == "unshare" and c["argv"][0] == "chown"
              and c["argv"][-1] == src and rc["user"] in c["argv"]]
    assert chowns and chowns[0] < run_at, (
        f"{src} was not chowned to {rc['user']} before the container ran: {run.calls}")


def test_output_is_handed_back_and_the_destination_keeps_its_mode(case, tmp_path):
    """`cp -a tmp/. dest/` copies the "." entry's mode onto dest: the old 0777 work
    dir stamped 0777 on every real output dir, and a 0700 one would hide it from
    the lamware group. The destination's own mode must survive the copy."""
    run = _execute(case, tmp_path)
    assert run.returncode == 0, run.proc.stderr
    if run.out is None:  # ghidra tool mode: answers on stdout, copies nothing back
        pytest.skip("tool mode has no output dir")
    run_at = run.index(lambda c: c["call"] == "run")
    rw_src = next(m["src"] for m in run.run_call["mounts"] if m["opts"] == "rw")
    back = [i for i, c in enumerate(run.calls)
            if c["call"] == "unshare" and c["argv"][:3] == ["chown", "-R", "0:0"]
            and c["argv"][-1] == rw_src]
    assert back and back[0] > run_at, "output was not chowned back to the pipeline user"
    assert stat.S_IMODE(run.out.stat().st_mode) == 0o750, oct(run.out.stat().st_mode)
    copied = sorted(p.name for p in run.out.iterdir())
    assert copied, "nothing was copied back"
    assert "result.json" in copied


def test_the_work_dir_is_removed_on_success(case, tmp_path):
    run = _execute(case, tmp_path)
    assert run.returncode == 0, run.proc.stderr
    assert not list(run.tmp.iterdir()), list(run.tmp.iterdir())


def test_the_work_dir_is_removed_when_the_container_fails(case, tmp_path):
    run = _execute(case, tmp_path, fail=True)
    assert run.returncode != 0
    assert not list(run.tmp.iterdir()), list(run.tmp.iterdir())


def test_the_work_dir_is_removed_when_the_job_is_terminated(case, tmp_path):
    """A unit stop sends TERM to the whole group, container included. bash runs
    the EXIT trap on a fatal TERM, so cleanup must survive that path too.
    SIGKILL (subprocess.run's timeout) cannot be trapped by anything; there the
    job dir's own 0700 mode is what keeps a leftover unreachable."""
    run = _execute(case, tmp_path, kill=signal.SIGTERM)
    assert run.returncode != 0
    assert not list(run.tmp.iterdir()), list(run.tmp.iterdir())


def test_a_sigkilled_job_leaves_nothing_reachable(case, tmp_path):
    """The pipeline stages call the wrappers with subprocess.run(timeout=...),
    which SIGKILLs: no trap runs and the job dir stays behind. What must hold
    then is that the leftover is mktemp's 0700 dir with nothing world-writable
    inside (the two 0777 dirs found on the host were such leftovers)."""
    run = _execute(case, tmp_path, kill=signal.SIGKILL)
    left = list(run.tmp.iterdir())
    assert len(left) == 1, left  # proves the kill really skipped cleanup
    assert stat.S_IMODE(left[0].stat().st_mode) == 0o700
    for base, dirs, _files in os.walk(run.tmp):
        for d in [base, *(os.path.join(base, x) for x in dirs)]:
            if Path(d) != run.tmp:
                assert not os.lstat(d).st_mode & stat.S_IWOTH, d


def test_cleanup_runs_inside_the_userns(case, tmp_path):
    """Files the container wrote are owned by the subuid, which the pipeline user
    cannot unlink; a plain `rm -rf` is what left dirs behind on the host."""
    run = _execute(case, tmp_path)
    assert run.returncode == 0, run.proc.stderr
    job = next(p for p in run.run_call["tree"] if Path(p).parent == run.tmp)
    assert any(c["call"] == "unshare" and c["argv"][:2] == ["rm", "-rf"]
               and c["argv"][-1] == job for c in run.calls), run.calls
