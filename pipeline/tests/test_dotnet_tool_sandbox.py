# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The agentic .NET tools execute in a sandbox, brokered by the pipeline (ADR-021).

Owner decision on #673 (2026-10-03): running the tools in the pipeline process
kept them interruptible but processed attacker-controlled C# with the
`pipeline` user's privileges — DB credentials, CAPE storage, every report,
podman. They now run like Ghidra's: the pipeline brokers each call, and
`run-dotnet-tools` executes it in a python-sandbox container.

What is observed here, all without a host:

  * the BROKER (`DotnetToolBroker`) against stand-in sandbox commands: a good
    answer passes through; a timeout, an OOM-style kill, a non-zero exit,
    garbage, a non-object or an oversized answer each become that call's
    error — and through `run_interpret`, the run goes on to the next call;
  * the WRAPPER, rendered from its template with the role's defaults and run
    with a stand-in `podman` that records its argv and then runs the
    container's command locally: every isolation flag is in the argv (parsed,
    not grepped), there is no host mount, and a real tool call round-trips
    through the real wrapper and the real bootstrap;
  * the pipeline process never builds the index: with `CSharpIndex` broken in
    this process, the map and a tool call still succeed.

A real podman run is skipped when podman is absent, and says so.
"""
import json
import shutil
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import jinja2
import pytest
import yaml
from stages import dotnet_agentic, dotnet_tools
from stages.dotnet_agentic import DotnetToolBroker, build_dotnet_interpret_init
from stages.dotnet_tools import CONTAINER_BOOTSTRAP
from stages.interpret import run_interpret

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "ansible" / "roles" / "pipeline"
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
SRC = 'class A {\n void M() {\n  Call("Load");\n }\n}\n'


def _script(tmp_path: Path, name: str, body: str) -> str:
    p = tmp_path / name
    p.write_text(body)
    p.chmod(0o755)
    return str(p)


# --- the broker: every sandbox failure is one call's error ------------------------

FAILURES = {
    "timeout": ("#!/bin/sh\ncat >/dev/null\nsleep 30\n", "did not answer"),
    # A child that outlives the wrapper and keeps stdout open, as podman does
    # when only the wrapper is killed: the whole group must go.
    "timeout_with_child": ("#!/bin/bash\ncat >/dev/null\nsleep 30 &\nsleep 30\n",
                           "did not answer"),
    "oom_kill": ("#!/bin/sh\ncat >/dev/null\nexit 137\n", "killed"),
    "non_zero": ("#!/bin/sh\ncat >/dev/null\necho boom >&2\nexit 3\n", "exit 3"),
    "garbage": ("#!/bin/sh\ncat >/dev/null\necho 'Traceback (most recent'\n", "no JSON"),
    "non_object": ("#!/bin/sh\ncat >/dev/null\necho '[1, 2]'\n", "non-object"),
    "oversized": ("#!/bin/sh\ncat >/dev/null\nhead -c 2000000 /dev/zero | tr '\\0' 'x'\n",
                  "larger than"),
}


@pytest.mark.parametrize("mode", list(FAILURES))
def test_a_failing_sandbox_is_one_calls_error(tmp_path, monkeypatch, mode):
    monkeypatch.setattr(dotnet_agentic, "STARTUP_GRACE_S", 0)
    body, expected = FAILURES[mode]
    broker = DotnetToolBroker(SRC, cmd=_script(tmp_path, "sandbox", body), timeout=2)
    t0 = time.monotonic()
    r = broker.call("list_classes", {})
    assert time.monotonic() - t0 < 10
    assert set(r) == {"error"}, r
    assert r["error"].startswith("tool failed:") and expected in r["error"], r


def test_a_missing_sandbox_is_one_calls_error(tmp_path):
    r = DotnetToolBroker(SRC, cmd=str(tmp_path / "absent")).call("list_classes", {})
    assert r["error"].startswith("tool failed: cannot run the sandbox")


def test_a_good_answer_passes_through():
    r = DotnetToolBroker(SRC).call("search_source", {"pattern": '"Load"'})
    assert r["total_hits"] == 1 and r["hits"][0]["location"] == "A.M"


def test_the_pipeline_process_never_builds_the_index(monkeypatch):
    """ADR-021, observed: break the index in THIS process; the map and a tool
    call still work, because both are computed in the sandbox's process."""
    def boom(self, source):
        raise AssertionError("the pipeline process parsed the sample's source")
    monkeypatch.setattr(dotnet_tools.CSharpIndex, "__init__", boom)
    init = build_dotnet_interpret_init({"decompilation": {"source": SRC}}, {}, [], "agentic")
    assert "dotnet_agentic_failed" not in init, init.get("dotnet_agentic_failed")
    assert init["suspicious_constructs"]["locations"][0]["location"] == "A.M"
    r = DotnetToolBroker.from_payload(init).call("get_method_source",
                                                 {"class_name": "A", "method_name": "M"})
    assert '"Load"' in r["source"]


def _flaky_sandbox(tmp_path: Path, failure_body: str) -> str:
    """Fails the first request the given way, then serves normally."""
    marker = tmp_path / "failed-once"
    real = dotnet_agentic.default_tools_cmd()
    failing = _script(tmp_path, "fail-once", failure_body)
    return _script(tmp_path, "flaky", textwrap.dedent(f"""\
        #!/bin/sh
        if [ ! -e {marker} ]; then touch {marker}; exec {failing}; fi
        exec {real}
    """))


@pytest.mark.parametrize("mode", ["timeout", "oom_kill", "garbage", "non_zero"])
def test_the_run_continues_after_a_failed_tool_call(tmp_path, monkeypatch, mode):
    """Through run_interpret: the first call's sandbox fails, the agent gets an
    error for that call only, its second call is served, and the final lands."""
    monkeypatch.setattr(dotnet_agentic, "STARTUP_GRACE_S", 0)
    init = build_dotnet_interpret_init({"decompilation": {"source": SRC}}, {}, [], "agentic")
    agent = _script(tmp_path, "agent", f"#!{sys.executable}\n" + textwrap.dedent("""
        import json, sys
        json.loads(sys.stdin.readline())
        replies = []
        for n in (1, 2):
            print(json.dumps({"type": "tool_call", "id": str(n), "tool": "list_classes",
                              "args": {}}), flush=True)
            replies.append(json.loads(sys.stdin.readline()))
        print(json.dumps({"type": "final", "analysis": {"replies": replies},
                          "model_used": "m", "tool_calls_used": 2}), flush=True)
    """))
    out = tmp_path / "out"
    out.mkdir()
    cfg = {"model": "m", "dotnet_tools_cmd": _flaky_sandbox(tmp_path, FAILURES[mode][0]),
           "dotnet_tools_timeout": 2}
    res = run_interpret(init, out, agent, True, 60, cfg, "/nonexistent/run-ghidra")
    assert "error" not in res, res.get("error")
    first, second = res["analysis"]["replies"]
    assert first["type"] == "tool_result" and first["result"]["error"].startswith("tool failed")
    assert second["type"] == "tool_result" and second["result"]["classes"][0]["class"] == "A"


# --- the wrapper: isolation flags, observed in the argv it passes to podman ---------

def _render(template: str, **extra) -> str:
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=False)
    return env.from_string((ROLE / "templates" / template).read_text()).render(
        **{**DEFAULTS, **extra})


@pytest.fixture
def wrapper(tmp_path, monkeypatch):
    """The rendered run-dotnet-tools, with a stand-in podman on PATH that records
    its argv and runs the container's command with this interpreter."""
    path = _script(tmp_path, "run-dotnet-tools", _render("run-dotnet-tools.sh.j2"))
    log = tmp_path / "podman-argv.json"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _script(bindir, "podman", f"#!{sys.executable}\n" + textwrap.dedent(f"""
        import json, os, sys
        args = sys.argv[1:]
        if args[:2] == ["image", "exists"]:
            sys.exit(0)
        with open({str(log)!r}, "a") as f:
            f.write(json.dumps(args) + "\\n")
        image = args.index("localhost/python-sandbox:latest")
        cmd = args[image + 1:]
        assert cmd[0] == "python3", cmd
        os.execv(sys.executable, [sys.executable] + cmd[1:])
    """))
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    monkeypatch.setenv("LAMWARE_IN_USER_SESSION", "1")   # skip the systemd re-exec
    return path, log


def _podman_run_argv(log: Path) -> list[str]:
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(calls) == 1 and calls[0][0] == "run", calls
    return calls[0]


def test_a_tool_call_round_trips_through_the_real_wrapper(wrapper):
    path, log = wrapper
    r = DotnetToolBroker(SRC, cmd=path).call("get_method_source",
                                             {"class_name": "A", "method_name": "M"})
    assert '"Load"' in r["source"], r
    assert _podman_run_argv(log)


def test_the_container_carries_every_isolation_flag(wrapper):
    path, log = wrapper
    DotnetToolBroker(SRC, cmd=path).call("list_classes", {})
    argv = _podman_run_argv(log)
    image = argv.index("localhost/python-sandbox:latest")
    opts, command = argv[1:image], argv[image + 1:]
    flags = {}
    i = 0
    while i < len(opts):
        o = opts[i]
        if "=" in o:
            k, v = o.split("=", 1)
            flags.setdefault(k, []).append(v)
        elif o in ("--user", "--tmpfs", "-v", "--volume", "--mount"):
            flags.setdefault(o, []).append(opts[i + 1])
            i += 1
        else:
            flags.setdefault(o, []).append(True)
        i += 1
    assert flags["--network"] == ["none"]
    assert flags["--read-only"] == [True]
    assert flags["--cap-drop"] == ["ALL"]
    assert flags["--security-opt"] == ["no-new-privileges"]
    assert flags["--memory"] == [DEFAULTS["pipeline_dotnet_tools_container_memory"]]
    assert flags["--pids-limit"] == [str(DEFAULTS["pipeline_dotnet_tools_container_pids"])]
    assert flags["--timeout"] == [str(DEFAULTS["pipeline_dotnet_tools_timeout"])]
    assert flags["--user"] == ["65534:65534"]
    assert flags["--rm"] == [True] and flags["-i"] == [True]
    for mount in ("-v", "--volume", "--mount"):
        assert mount not in flags, f"host mount {flags[mount]} in the tool sandbox"
    assert not [o for o in opts if o.startswith(("--privileged", "--network=host",
                                                 "--userns=host", "--pid=host"))]
    assert command == ["python3", "-I", "-u", "-c", CONTAINER_BOOTSTRAP]


def test_the_broker_timeout_outlasts_the_containers():
    """podman's --timeout fires first; the broker's backstop is the same
    configured value plus a grace, from the same role variable."""
    cfg = json.loads(_render_config())["interpret"]
    assert cfg["dotnet_tools_timeout"] == DEFAULTS["pipeline_dotnet_tools_timeout"]
    assert cfg["dotnet_tools_cmd"] == f"{DEFAULTS['pipeline_install_dir']}/run-dotnet-tools"
    assert dotnet_agentic.STARTUP_GRACE_S > 0
    assert DEFAULTS["pipeline_dotnet_tools_max_output"] == dotnet_agentic.MAX_RESULT_BYTES


def _render_config() -> str:
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_cfgr", Path(__file__).parent / "test_config_template_renders.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m._render()


def test_the_wrapper_is_deployed_where_the_config_points():
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
    deploys = [t["ansible.builtin.template"] for t in tasks
               if isinstance(t, dict)
               and (t.get("ansible.builtin.template") or {}).get("src") == "run-dotnet-tools.sh.j2"]
    assert len(deploys) == 1
    assert deploys[0]["dest"] == "{{ pipeline_install_dir }}/run-dotnet-tools"
    assert deploys[0]["mode"] == "0750"


@pytest.mark.skipif(shutil.which("podman") is None,
                    reason="podman is not installed on this machine; the real-container run "
                           "is a host check (deploy, then a .NET sample) — see the PR body")
def test_a_tool_call_in_a_real_container(tmp_path, monkeypatch):  # pragma: no cover
    path = _script(tmp_path, "run-dotnet-tools", _render("run-dotnet-tools.sh.j2"))
    monkeypatch.setenv("LAMWARE_IN_USER_SESSION", "1")
    if subprocess.run(["podman", "image", "exists", "localhost/python-sandbox:latest"]).returncode:
        pytest.skip("localhost/python-sandbox:latest is not built here")
    r = DotnetToolBroker(SRC, cmd=path).call("list_classes", {})
    assert r["classes"][0]["class"] == "A"
