"""The feeders open shared files without following links (ADR-031 phase 2).

PAUSE (in the control directory) and the seen-hash file are shared with another
service account. A planted symlink would redirect a write; a planted FIFO would
block. The REAL templates are rendered, their helper functions are taken out with
`ast` (importing the auto-feeder would open its log under /opt) and run against a
temporary directory.
"""
import ast
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")
yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "ansible/roles"


def _functions(template: str, names: set[str]) -> dict:
    ctx = {}
    for role in ("auto-feeder", "sample-feeder", "pipeline"):
        ctx.update(yaml.safe_load((ROLES / role / "defaults/main.yml").read_text()) or {})
    env = jinja2.Environment(undefined=jinja2.ChainableUndefined)  # noqa: S701 - Python, not HTML
    env.filters["to_json"] = lambda v: json.dumps(None if isinstance(v, jinja2.Undefined) else v)
    env.filters["mandatory"] = lambda v: v
    src = env.from_string((ROLES / template).read_text()).render(**ctx)
    tree = ast.parse(src)
    picked = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    assert {n.name for n in picked} == names, f"missing in {template}: {names - {n.name for n in picked}}"
    ns = {"os": os, "stat": stat, "json": json}
    exec(compile(ast.Module(body=picked, type_ignores=[]), template, "exec"), ns)  # noqa: S102
    return ns


AUTO = _functions("auto-feeder/templates/auto-feeder.py.j2",
                  {"_open_shared", "read_json_shared", "write_json_shared", "touch_shared"})
SAMPLE = _functions("sample-feeder/templates/sample_feeder.py.j2",
                    {"_open_shared", "load_seen_hashes", "save_seen_hashes"})


def test_a_regular_file_is_read_and_written(tmp_path):
    p = tmp_path / "seen.json"
    AUTO["write_json_shared"](p, ["a", "b"])
    assert AUTO["read_json_shared"](p) == ["a", "b"]
    AUTO["write_json_shared"](p, ["c"])             # shorter: truncated, not appended
    assert json.loads(p.read_text()) == ["c"]


@pytest.mark.parametrize("op", ["read", "write", "touch"])
def test_a_planted_symlink_is_refused_and_its_target_untouched(tmp_path, op):
    target = tmp_path / "victim"
    target.write_text("precious")
    link = tmp_path / "PAUSE"
    link.symlink_to(target)
    call = {"read": lambda: AUTO["read_json_shared"](link),
            "write": lambda: AUTO["write_json_shared"](link, []),
            "touch": lambda: AUTO["touch_shared"](link)}[op]
    with pytest.raises(OSError):
        call()
    assert target.read_text() == "precious"


@pytest.mark.parametrize("op", ["read", "write"])
def test_a_planted_fifo_is_refused_without_blocking(tmp_path, op):
    fifo = tmp_path / "seen.json"
    os.mkfifo(fifo)
    call = {"read": lambda: AUTO["read_json_shared"](fifo),
            "write": lambda: AUTO["write_json_shared"](fifo, [])}[op]
    with pytest.raises(OSError):
        call()


def test_touch_creates_the_pause_file(tmp_path):
    p = tmp_path / "PAUSE"
    AUTO["touch_shared"](p)
    assert p.is_file() and not p.is_symlink()


def test_the_sample_feeder_cli_uses_the_same_rule(tmp_path):
    p = tmp_path / "seen.json"
    assert SAMPLE["load_seen_hashes"](str(p)) == set()
    SAMPLE["save_seen_hashes"]({"x", "y"}, str(p))
    assert SAMPLE["load_seen_hashes"](str(p)) == {"x", "y"}
    link = tmp_path / "link.json"
    link.symlink_to(p)
    with pytest.raises(OSError):
        SAMPLE["save_seen_hashes"]({"z"}, str(link))
    assert SAMPLE["load_seen_hashes"](str(p)) == {"x", "y"}


# --- security check 28, run for real against a fake host (ADR-031 phase 2) ---------

SMOKE = (ROLES / "security-test/templates/security-smoke-test.sh.j2").read_text()
GOOD = {  # what the host should allow: (path, test) -> members
    ("/opt/pipeline/spool", "-w"): {"lamware-api", "pipeline"},
    ("/opt/pipeline/spool-claim", "-w"): {"pipeline"},
    ("/opt/pipeline/control", "-w"): {"lamware-api", "auto-feeder"},
    ("/opt/auto-feeder/state/state.json", "-r"): {"lamware-api", "auto-feeder"},
    ("/opt/auto-feeder/run/auto-feeder.log", "-r"): {"lamware-api", "auto-feeder"},
    ("/opt/sample-feeder/seen_hashes.json", "-w"): {"pipeline", "auto-feeder"},
}


def _check28() -> str:
    env = jinja2.Environment()  # noqa: S701 - shell, not HTML
    env.filters["bool"] = bool
    out = env.from_string(SMOKE).render()
    return out[out.index('echo "[28/28]'):out.index("# Summary + ntfy alert on failure")]


def _run28(tmp, allowed=GOOD, live_groups="1000 2001 2002", sudo_works=True):
    bindir, proc = tmp / "bin", tmp / "proc"
    bindir.mkdir()
    (proc / "42").mkdir(parents=True)
    (proc / "42" / "status").write_text(f"Name:\tuvicorn\nGroups:\t{live_groups}\n")
    table = "\n".join(f"{u}|{t}|{p}" for (p, t), us in allowed.items() for u in us)
    (tmp / "allowed").write_text(table + "\n")
    stubs = {
        # sudo -u USER test FLAG PATH  -> allowed iff the line is in the table
        "sudo": (f"#!/bin/bash\n{'' if sudo_works else 'exit 1'}\n"
                 f'grep -qxF -- "$2|$4|$5" {tmp / "allowed"}\n'),
        "id": "#!/bin/bash\nexit 0\n",
        "systemctl": "#!/bin/bash\necho 42\n",
        "getent": "#!/bin/bash\ncase $2 in lamware-spool) echo x:x:2001: ;; lamware-feeder) echo x:x:2002: ;; esac\n",
    }
    for name, body in stubs.items():
        (bindir / name).write_text(body)
        (bindir / name).chmod(0o755)
    body = _check28().replace('"/proc/$F_PID/status"', f'"{proc}/$F_PID/status"')
    assert str(proc) in body, "the check no longer reads /proc/$F_PID/status"
    script = 'pass() { echo "PASS: $1"; }\nfail() { echo "FAIL: $1"; }\n' + body
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                          env={"PATH": f"{bindir}:/usr/bin:/bin"}).stdout


def test_check28_passes_on_the_intended_host(tmp_path):
    out = _run28(tmp_path)
    assert "PASS: flow paths: 24 account/path probes as expected" in out, out


@pytest.mark.parametrize("change, want", [
    # the old shared group: the pipeline can still write PAUSE
    (("/opt/pipeline/control", "-w", "pipeline"), "pipeline:-w:/opt/pipeline/control(got=yes)"),
    (("/opt/pipeline/spool", "-w", "auto-feeder"), "auto-feeder:-w:/opt/pipeline/spool(got=yes)"),
    (("/opt/sample-feeder/seen_hashes.json", "-w", "cape"), "cape:-w:/opt/sample-feeder/seen_hashes.json(got=yes)"),
])
def test_check28_fails_when_a_non_member_gets_in(tmp_path, change, want):
    p, t, u = change
    allowed = {k: set(v) for k, v in GOOD.items()}
    allowed[(p, t)].add(u)
    out = _run28(tmp_path, allowed=allowed)
    assert "FAIL" in out and want in out, out


def test_check28_fails_when_a_member_is_locked_out(tmp_path):
    allowed = {k: set(v) for k, v in GOOD.items()}
    allowed[("/opt/auto-feeder/state/state.json", "-r")].discard("lamware-api")
    out = _run28(tmp_path, allowed=allowed)
    assert "FAIL" in out and "lamware-api:-r:/opt/auto-feeder/state/state.json(got=no)" in out, out


def test_check28_is_not_blind_when_sudo_is_refused(tmp_path):
    out = _run28(tmp_path, sudo_works=False)
    assert "FAIL" in out and "got=no" in out, out


def test_check28_fails_when_the_running_api_lacks_a_flow_group(tmp_path):
    out = _run28(tmp_path, live_groups="1000 2001")
    assert "FAIL: the running API lacks its flow groups: lamware-feeder" in out, out
