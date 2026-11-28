"""The auto-feeder runs the pipeline only through lamware-feeder-submit (#357).

The sudoers rule was `run-pipeline *`: any argument vector. These tests run the
REAL rendered wrapper (with a fake run-pipeline that records what it got) and the
feeder's REAL argv builder, taken out of the rendered template with `ast`.
"""
import ast
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")
yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible/roles/auto-feeder"
DEFAULTS = yaml.safe_load((ROLE / "defaults/main.yml").read_text())


def _wrapper(tmp: Path, max_bytes: int = 1000) -> tuple[Path, Path]:
    log = tmp / "calls.jsonl"
    fake = tmp / "run-pipeline"
    fake.write_text(
        "#!/usr/bin/env python3\nimport json, sys, os\n"
        f"open({str(log)!r}, 'a').write(json.dumps({{'argv': sys.argv[1:], "
        "'data': open(sys.argv[1], 'rb').read().decode('latin-1'), "
        "'mode': oct(os.stat(sys.argv[1]).st_mode & 0o777)}) + '\\n')\n"
        "sys.exit(int(os.environ.get('FAKE_RC', '0')))\n")
    fake.chmod(0o755)
    src = jinja2.Environment().from_string((ROLE / "templates/lamware-feeder-submit.j2").read_text()).render(
        ansible_managed="test", sample_feeder_pipeline_cmd=str(fake),
        auto_feeder_max_sample_size_bytes=max_bytes)
    w = tmp / "lamware-feeder-submit"
    w.write_text(src)
    return w, log


def _submit(w: Path, args: list[str], data: bytes = b"MZ sample", env: dict | None = None):
    return subprocess.run([sys.executable, "-I", str(w), *args], input=data,
                          capture_output=True, timeout=30, env=env)


def _calls(log: Path) -> list[dict]:
    return [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []


def test_a_sample_runs_from_a_private_copy_that_is_removed_afterwards(tmp_path):
    w, log = _wrapper(tmp_path)
    r = _submit(w, ["--filename", "evil.exe", "--bazaar-family", "AgentTesla"])
    assert r.returncode == 0, r.stderr
    (call,) = _calls(log)
    path = call["argv"][0]
    assert call["argv"][1:] == ["--filename", "evil.exe", "--bazaar-family", "AgentTesla"]
    assert call["data"] == "MZ sample" and call["mode"] == "0o640"
    assert re.search(r"/lamware-feeder-[^/]+/evil\.exe$", path)
    assert not Path(path).parent.exists(), "the private copy was left behind"


def test_run_pipelines_exit_code_is_passed_back(tmp_path):
    import os
    w, log = _wrapper(tmp_path)
    r = _submit(w, ["--filename", "a.exe"], env={**os.environ, "FAKE_RC": "3"})
    assert r.returncode == 3


@pytest.mark.parametrize("args", [
    [],                                                      # nothing
    ["/tmp/x", "--filename", "a"],                           # the old shape: a path
    ["--filename"],
    ["--filename", "-x"],                                    # an option in disguise
    ["--filename", ".hidden"],
    ["--filename", "../../etc/passwd"],
    ["--filename", "a/b"],
    ["--filename", "a", "--bazaar-family", "--task-id=1"],   # #357's case
    ["--filename", "a", "--bazaar-family", "-v"],
    ["--filename", "a", "--task-id", "123"],
    ["--filename", "a", "--bazaar-family", "x" * 65],
    ["--filename", "a", "--bazaar-family", "Agent\nTesla"],
    ["--filename", "a", "--bazaar-family", "fam", "--extra", "y"],
    ["--filename", "ünïcode.exe"],
])
def test_anything_but_the_one_shape_is_refused_before_the_pipeline_runs(tmp_path, args):
    w, log = _wrapper(tmp_path)
    r = _submit(w, args)
    assert r.returncode == 2, (args, r.returncode, r.stderr)
    assert _calls(log) == []


@pytest.mark.parametrize("data", [b"", b"x" * 1001])
def test_an_empty_or_oversized_sample_is_refused(tmp_path, data):
    w, log = _wrapper(tmp_path, max_bytes=1000)
    r = _submit(w, ["--filename", "a.exe"], data=data)
    assert r.returncode == 2 and _calls(log) == []


# --- the feeder's side ---------------------------------------------------------------

def _feeder() -> dict:
    ctx = {}
    for role in ("auto-feeder", "sample-feeder", "pipeline"):
        ctx.update(yaml.safe_load((ROOT / "ansible/roles" / role / "defaults/main.yml").read_text()) or {})
    env = jinja2.Environment(undefined=jinja2.ChainableUndefined)  # noqa: S701 - Python, not HTML
    env.filters["to_json"] = lambda v: json.dumps(None if isinstance(v, jinja2.Undefined) else v)
    env.filters["mandatory"] = lambda v: v
    tree = ast.parse(env.from_string((ROLE / "templates/auto-feeder.py.j2").read_text()).render(**ctx))
    want_f, want_v = {"safe_name", "submit_argv"}, {"SUBMIT_CMD", "FAMILY_RE"}
    body = [n for n in tree.body
            if (isinstance(n, ast.FunctionDef) and n.name in want_f)
            or (isinstance(n, ast.Assign) and {getattr(t, "id", "") for t in n.targets} & want_v)]
    assert len(body) == 4, [getattr(n, "name", None) for n in body]

    class Log:
        warnings: list = []

        def warning(self, m):
            self.warnings.append(m)
    ns = {"re": re, "Path": Path, "log": Log()}
    exec(compile(ast.Module(body=body, type_ignores=[]), "auto-feeder", "exec"), ns)  # noqa: S102
    return ns


F = _feeder()


def test_the_feeder_calls_only_the_wrapper_and_sends_no_path():
    argv = F["submit_argv"]("evil.exe", "AgentTesla")
    assert argv == ["sudo", "-n", "-u", "pipeline", DEFAULTS["auto_feeder_submit_cmd"],
                    "--filename", "evil.exe", "--bazaar-family", "AgentTesla"]


@pytest.mark.parametrize("sig", ["", None, "unknown", "N/A", "none", "--task-id=1", "-v", "a" * 65, "x\ny"])
def test_a_signature_the_wrapper_would_refuse_is_dropped_not_sent(sig):
    argv = F["submit_argv"]("a.exe", sig)
    assert "--bazaar-family" not in argv and argv[-2:] == ["--filename", "a.exe"]


@pytest.mark.parametrize("raw, want", [
    ("evil.exe", "evil.exe"), ("dir/sub/evil.exe", "evil.exe"), ("-x.exe", "x.exe"),
    (".hidden", "hidden"), ("ünï cöde.exe", "_n__c_de.exe"), ("...", "sample.bin"), ("a" * 300, "a" * 200),
])
def test_feeder_names_are_ones_the_wrapper_accepts(raw, want, tmp_path):
    got = F["safe_name"](raw)
    assert got == want
    w, log = _wrapper(tmp_path)
    assert _submit(w, ["--filename", got]).returncode == 0


def test_sudoers_names_the_wrapper_and_nothing_else():
    tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
    (rule,) = [t for t in tasks if t.get("ansible.builtin.copy", {}).get("dest") == "/etc/sudoers.d/auto-feeder"]
    lines = [x for x in rule["ansible.builtin.copy"]["content"].splitlines() if x and not x.startswith("#")]
    assert lines == ["{{ auto_feeder_user }} ALL=(pipeline) NOPASSWD: {{ auto_feeder_submit_cmd }}"]
    names = [t.get("name", "") for t in tasks]
    wrapper = next(i for i, t in enumerate(tasks)
                   if t.get("ansible.builtin.template", {}).get("src") == "lamware-feeder-submit.j2")
    assert wrapper < names.index(rule["name"]), "the rule must not name a file not yet installed"
    assert tasks[wrapper]["ansible.builtin.template"]["owner"] == "root"


# --- security check 29 against a fake host -----------------------------------------

SMOKE = (ROOT / "ansible/roles/security-test/templates/security-smoke-test.sh.j2").read_text()


def _run29(tmp, *, run_pipeline_allowed=False, wrapper_rc=2, owner="root 755",
           rules=("(pipeline) NOPASSWD: /usr/local/sbin/lamware-feeder-submit",)):
    env = jinja2.Environment()  # noqa: S701 - shell, not HTML
    env.filters["bool"] = bool
    out = env.from_string(SMOKE).render()
    body = out[out.index('echo "[29/29]'):out.index("# Summary + ntfy alert on failure")]
    b = tmp / "bin"
    b.mkdir()
    listing = "\\n".join("    " + r for r in rules)
    stubs = {
        "id": "#!/bin/bash\nexit 0\n",
        "runuser": "#!/bin/bash\nshift 3\nexec \"$@\"\n",      # runuser -u U -- CMD...
        "sudo": ("#!/bin/bash\n"
                 f'if [ "$1" = -l ]; then printf "User may run:\\n{listing}\\n"; exit 0; fi\n'
                 'case "$4" in\n'
                 f'  */run-pipeline) exit {0 if run_pipeline_allowed else 1} ;;\n'
                 f'  */lamware-feeder-submit) cat >/dev/null; exit {wrapper_rc} ;;\n'
                 "esac\nexit 1\n"),
        "stat": f"#!/bin/bash\necho '{owner}'\n",
    }
    for n, t in stubs.items():
        (b / n).write_text(t)
        (b / n).chmod(0o755)
    script = 'pass() { echo "PASS: $1"; }\nfail() { echo "FAIL: $1"; }\n' + body
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                          env={"PATH": f"{b}:/usr/bin:/bin"}).stdout


def test_check29_passes_on_the_intended_host(tmp_path):
    assert "PASS: auto-feeder: sudo refuses run-pipeline" in _run29(tmp_path)


@pytest.mark.parametrize("kw, want", [
    ({"run_pipeline_allowed": True}, "sudo-allows-run-pipeline"),               # the old rule
    ({"wrapper_rc": 1}, "wrapper-probe-exit=1"),                                 # sudo refused: blind
    ({"wrapper_rc": 0}, "wrapper-probe-exit=0"),                                 # wrapper accepts -x
    ({"owner": "pipeline 755"}, "wrapper-not-root-755"),
    ({"rules": ("(pipeline) NOPASSWD: /usr/local/bin/run-pipeline *",)}, "rule-not-the-wrapper"),
    ({"rules": ("(pipeline) NOPASSWD: /usr/local/sbin/lamware-feeder-submit",
                "(pipeline) NOPASSWD: /bin/bash")}, "pipeline-rules=2"),
])
def test_check29_fails_each_way_it_should(tmp_path, kw, want):
    out = _run29(tmp_path, **kw)
    assert "FAIL" in out and want in out, out
