# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A final the container sends after force_final must be read (#240).

Observed on the host, 2026-09-27, in both redet644 .NET runs. The trail for
redet644_1f2b22638ddb (quasarrat) is one request and then the timeout:

    seq 3  t=0.67     request         request_phase=dotnet
    seq 4  t=5447.87  request_result  usage.input_tokens=57751 output_tokens=1123
    seq 5  t=5448.21  interpret_timeout  budget_s=3600  returncode=0

and the report said "did not produce a forced final within 600s ... exited
cleanly (0) without sending a final result". The .NET single-shot path emits
`final` straight after `request_result` and exits 0, so the final was written.
The loop checked the clock only between stdout lines, so the budget could not
fire during the 5,447s request; when the request_result line finally arrived it
sent force_final, waited for the process, and broke WITHOUT reading stdout again.
The final sat unread in the pipe.

These tests run run_interpret() against a real child process — a small Python
script standing in for the interpret container, speaking the same JSON-lines
protocol — with budgets scaled down to fractions of a second. They observe what
the loop reads and returns, not what its source says.
"""
import json
import sys
import textwrap
import time
from pathlib import Path

import pytest
from stages.interpret import run_interpret

# The salvaged request's real usage, so a dropped or rewritten usage block is a
# visible difference (CLAUDE.md §10: a salvaged final still has to be priced).
QUASAR_USAGE = {"input_tokens": 57751, "output_tokens": 1123}

_PRELUDE = '''
import json, sys, time

def emit(obj):
    print(json.dumps(obj), flush=True)

def read():
    line = sys.stdin.readline()
    return json.loads(line) if line.strip() else None

init = read()
assert init and init["type"] == "init", init
'''


def _fake_container(tmp_path: Path, body: str) -> str:
    """Write an executable stand-in for run-interpret and return its path."""
    path = tmp_path / "fake-run-interpret"
    path.write_text(f"#!{sys.executable}\n" + _PRELUDE + textwrap.dedent(body))
    path.chmod(0o755)
    return str(path)


def _run(tmp_path: Path, body: str, *, budget: float, grace: float,
         reserve: float = 0) -> tuple[dict, float]:
    cmd = _fake_container(tmp_path, body)
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    t0 = time.time()
    res = run_interpret(
        {"analysis_type": "dotnet"}, out, cmd, True,
        interpret_timeout=budget, interpret_config={"model": "fake-model"},
        ghidra_cmd="/nonexistent/run-ghidra", force_final_grace=grace,
        synthesis_reserve=reserve)
    return res, time.time() - t0


def _trail(res: dict) -> list[dict]:
    path = Path(res["audit"]["turn_trail"])
    return [json.loads(line) for line in path.read_text().splitlines()]


# --- (a) a final that arrives in the grace window is used --------------------

def test_a_single_shot_final_after_the_budget_is_salvaged_with_its_usage(tmp_path):
    """The redet644 shape: one blocking request outlives the budget, then the
    container emits request_result + final and exits 0. Its stdin is never read."""
    res, _ = _run(tmp_path, f'''
        emit({{"type": "request", "phase": "dotnet", "wire": "openai"}})
        time.sleep(1.0)                      # one request, silent, past the budget
        usage = {QUASAR_USAGE!r}
        emit({{"type": "request_result", "request_phase": "dotnet",
               "wire": "openai", "usage": usage, "elapsed_s": 1.0}})
        emit({{"type": "final", "analysis": {{"summary": "quasar"}},
               "model_used": "fake-model", "tool_calls_used": 0, "usage": usage}})
        sys.exit(0)
    ''', budget=0.4, grace=3.0)

    assert "error" not in res, res.get("error")
    assert res["analysis"] == {"summary": "quasar"}
    assert res["usage"] == QUASAR_USAGE, "the salvaged final lost its usage"
    assert res["forced_final"]["reason"] == "timeout"
    assert res["forced_final"]["answered"] is True
    assert "timed_out" not in res, "a salvaged analysis is not a timeout failure"
    finals = [r for r in _trail(res) if r["event"] == "final"]
    assert finals and finals[0]["usage"] == QUASAR_USAGE


def test_an_agentic_final_written_after_force_final_is_salvaged(tmp_path):
    """The tool-loop shape: force_final arrives as the answer to a tool call and
    the container synthesises from what it gathered."""
    res, _ = _run(tmp_path, f'''
        n = 0
        while True:
            n += 1
            emit({{"type": "tool_call", "id": str(n), "tool": "list_functions",
                   "args": {{}}}})
            reply = read()
            if reply["type"] == "force_final":
                time.sleep(0.5)              # synthesis takes time
                emit({{"type": "final", "analysis": {{"calls_before_stop": n}},
                       "model_used": "fake-model", "tool_calls_used": n,
                       "usage": {QUASAR_USAGE!r}}})
                sys.exit(0)
            time.sleep(0.2)
    ''', budget=0.8, grace=3.0)

    assert "error" not in res, res.get("error")
    assert res["analysis"]["calls_before_stop"] >= 2
    assert res["usage"] == QUASAR_USAGE
    assert res["forced_final"]["reason"] == "timeout"


# --- (b) a container that never answers is reported as exactly that -----------

def test_a_container_that_exits_without_answering_is_reported_honestly(tmp_path):
    res, elapsed = _run(tmp_path, '''
        emit({"type": "tool_call", "id": "1", "tool": "list_functions", "args": {}})
        read()                               # tool_error
        time.sleep(0.8)
        emit({"type": "tool_call", "id": "2", "tool": "list_functions", "args": {}})
        reply = read()
        assert reply["type"] == "force_final", reply
        sys.exit(0)                          # no final
    ''', budget=0.4, grace=5.0)

    assert res["timed_out"] is True
    assert res["forced_final"]["answered"] is False
    assert res["forced_final"]["ended"] == "exited_without_final"
    assert res["container_returncode"] == 0
    assert "closed stdout without sending a final" in res["error"]
    assert elapsed < 4.0, "the loop waited out the grace for a process that had exited"


def test_a_container_still_working_at_the_deadline_is_stopped_on_time(tmp_path):
    res, elapsed = _run(tmp_path, '''
        emit({"type": "status", "message": "thinking"})
        time.sleep(30)                       # one request that never returns
    ''', budget=0.5, grace=1.0)

    assert elapsed < 4.0, f"took {elapsed:.1f}s against a 1.5s budget+grace"
    assert res["timed_out"] is True
    assert res["forced_final"]["ended"] == "still_running_at_deadline"
    assert res["container_returncode"] is None, "it was running when we stopped it"
    assert "was still running and the pipeline stopped it" in res["error"]
    assert "exited cleanly" not in res["container_exit_note"]


# --- (c) the budget fires while the container is silent ----------------------

def test_the_budget_fires_without_a_newline(tmp_path):
    """A partial line with no newline blocked readline() — and so the budget —
    until the process wrote one or died."""
    res, elapsed = _run(tmp_path, '''
        sys.stdout.write('{"type": "status", "message": "half a li')
        sys.stdout.flush()
        time.sleep(30)
    ''', budget=0.5, grace=1.0)

    assert elapsed < 4.0, f"took {elapsed:.1f}s: the budget waited on a newline"
    assert res["timed_out"] is True
    assert res["forced_final"]["reason"] == "timeout"
    assert res["forced_final"]["ended"] == "still_running_at_deadline"
    sent = [r for r in _trail(res) if r["event"] == "force_final_sent"]
    assert sent and 0.4 <= sent[0]["t"] < 1.5, sent


# --- the synthesis reserve ----------------------------------------------------

_TWO_CALLS = f'''
    received = []
    for n in (1, 2):
        emit({{"type": "tool_call", "id": str(n), "tool": "list_functions", "args": {{}}}})
        reply = read()
        received.append(reply["type"])
        if reply["type"] == "force_final":
            break
        time.sleep(0.7)
    emit({{"type": "final", "analysis": {{"received": received}},
           "model_used": "fake-model", "tool_calls_used": len(received),
           "usage": {QUASAR_USAGE!r}}})
'''


def test_the_reserve_stops_granting_tool_calls(tmp_path):
    """Budget 3.0s, reserve 2.5s: the first call (3.0s left) runs; the second
    (~2.3s left) is answered with force_final instead of a tool result."""
    res, _ = _run(tmp_path, _TWO_CALLS, budget=3.0, grace=2.0, reserve=2.5)

    assert "error" not in res, res.get("error")
    assert res["analysis"]["received"] == ["tool_error", "force_final"]
    assert res["forced_final"]["reason"] == "synthesis_reserve"
    assert res["usage"] == QUASAR_USAGE
    assert "timed_out" not in res
    refused = [r for r in _trail(res) if r["event"] == "tool_call_refused_for_reserve"]
    assert len(refused) == 1


def test_no_reserve_grants_every_call_inside_the_budget(tmp_path):
    """The control: the same container with the reserve off gets both calls, so
    the refusal above is the reserve and not something else in the loop."""
    res, _ = _run(tmp_path, _TWO_CALLS, budget=3.0, grace=2.0, reserve=0)

    assert res["analysis"]["received"] == ["tool_error", "tool_error"]
    assert "forced_final" not in res


# --- config path --------------------------------------------------------------

def test_a_reserve_at_or_above_the_budget_is_refused_at_load(tmp_path):
    """It would refuse every tool call while every run still looked healthy."""
    from lamware_pipeline.config import PipelineConfig

    fixture = json.loads((Path(__file__).parent / "fixtures" / "config.json").read_text())
    fixture["interpret_synthesis_reserve"] = fixture["interpret_timeout"]
    with pytest.raises(ValueError, match="no tool call is ever granted"):
        PipelineConfig.model_validate(fixture)
    fixture["interpret_synthesis_reserve"] = fixture["interpret_timeout"] - 1
    assert PipelineConfig.model_validate(fixture).interpret_synthesis_reserve > 0


def test_the_shipped_reserve_reaches_config_json_and_loads():
    """Rendered with BOTH roles' defaults, as a deploy does: the value lives in
    roles/interpret/defaults and the template that carries it in roles/pipeline.
    A Jinja `| default()` would hide a missing variable, so assert the value."""
    import jinja2
    import yaml
    from lamware_pipeline.config import PipelineConfig

    roles = Path(__file__).resolve().parents[2] / "ansible" / "roles"
    ctx = {}
    for role in ("pipeline", "interpret"):
        ctx.update(yaml.safe_load(
            (roles / role / "defaults" / "main.yml").read_text(encoding="utf-8")) or {})

    def _placeholder(v):
        return "placeholder" if isinstance(v, jinja2.Undefined) else v

    env = jinja2.Environment(undefined=jinja2.ChainableUndefined, autoescape=False)
    env.filters["to_json"] = lambda v: json.dumps(_placeholder(v))
    env.filters["mandatory"] = _placeholder
    rendered = json.loads(env.from_string(
        (roles / "pipeline" / "templates" / "config.json.j2").read_text(encoding="utf-8")
    ).render(**ctx))

    shipped = ctx["interpret_synthesis_reserve"]
    assert rendered["interpret_synthesis_reserve"] == shipped
    assert 0 < shipped < int(ctx["interpret_timeout"])
    cfg = PipelineConfig.model_validate(rendered)
    assert cfg.interpret_synthesis_reserve == shipped


# --- moved from test_interpret_stderr_capture.py, now behavioural -------------

def test_a_timeout_is_not_reported_as_a_death(tmp_path):
    """salat_d26bc055, 2026-09-08: the timeout and EOF paths shared "Interpret
    container exited without final result", and three investigations chased a
    crash that never happened."""
    res, _ = _run(tmp_path, '''
        time.sleep(30)
    ''', budget=0.3, grace=0.5)

    assert res["timed_out"] is True
    assert res["error"] != "Interpret container exited without final result"
    assert "exceeded its" in res["error"] and "budget" in res["error"]
    assert "Not a crash" in res["error"]


def test_the_default_grace_fits_a_local_synthesis():
    """30s was the old hardcoded grace, which a local synthesis could never meet."""
    import inspect
    params = inspect.signature(run_interpret).parameters
    assert params["force_final_grace"].default == 300
    assert params["synthesis_reserve"].default == 0, \
        "the eval/A-B harnesses call without a reserve and must keep their tool depth"


def test_every_production_call_passes_the_configured_reserve():
    """Structural, because nothing short of a pipeline run observes it: a
    run_interpret() call in run-pipeline.py that omits synthesis_reserve silently
    runs with no reserve. Parsed, not grepped."""
    import ast
    src = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline"
           / "files" / "run-pipeline.py").read_text(encoding="utf-8")
    calls = [n for n in ast.walk(ast.parse(src))
             if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "run_interpret"]
    assert len(calls) >= 10, f"found only {len(calls)} run_interpret calls"
    missing = [c.lineno for c in calls
               if not any(k.arg == "synthesis_reserve"
                          and isinstance(k.value, ast.Name)
                          and k.value.id == "SYNTHESIS_RESERVE" for k in c.keywords)]
    assert not missing, f"run_interpret calls without the reserve at lines {missing}"


def test_a_tool_call_after_force_final_is_not_run(tmp_path):
    """force_final sent mid-request waits in stdin and becomes the answer to the
    agent's next tool call. That call must not also be executed and answered: the
    container reads one message per call, so a second one is a stray line, and
    the Ghidra time is spent on a result nobody reads."""
    res, _ = _run(tmp_path, f'''
        time.sleep(0.6)                      # mid-request when the budget passes
        emit({{"type": "tool_call", "id": "1", "tool": "list_functions", "args": {{}}}})
        reply = read()
        emit({{"type": "final", "analysis": {{"reply": reply["type"]}},
               "model_used": "fake-model", "tool_calls_used": 1,
               "usage": {QUASAR_USAGE!r}}})
    ''', budget=0.3, grace=3.0)

    assert res["analysis"] == {"reply": "force_final"}
    events = [r["event"] for r in _trail(res)]
    assert "tool" not in events, "the tool was run after force_final was sent"
    assert events.count("tool_call_after_force_final") == 1
