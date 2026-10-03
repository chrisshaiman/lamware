# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Production gives the RE agent the behavioural evidence the eval's `+corr` arm measured (#674).

Before #674, `run_interpret(..., extra_evidence=...)` was called with evidence
only by the eval (`lamware_eval.runner`). No call in run-pipeline.py passed it,
and cross_correlate ran AFTER Stage 4.5, so the findings did not exist yet when
the agent ran. #630 measured the difference: on the 2026-10-03 re-measure,
`+corr` turned empty answers into grounded claims in both server sessions with
zero fabrications.

What is checked here, and how:

* The builder moved from lamware_eval.runner to stages/correlated_evidence.py.
  The eval must keep building byte-identical evidence for its existing corpus,
  or every `+corr` cell after this change measures something else. Checked by
  calling the moved builder on recorded inputs and comparing with the OLD
  builder's output, recorded before the move (fixtures/correlated_evidence_golden.json).
  One input is a real report from the host (rm630_591d32aeae05, the 2026-10-03
  re-measure), trimmed to the four sections the builder reads and with the
  Volatility insight lists cut to three entries each.
* The eval imports the builder, it does not copy it (#380).
* The switch, the single-shot decision and the input record: behavioural, by
  calling evidence_for_interpret and run_interpret against a stand-in container
  that echoes the init it received.
* run-pipeline's call sites: structural (ast). run_pipeline() needs CAPE, Ghidra
  and the interpret container to reach Stage 4.5, so no test can call it; the
  call sites are the only observable. These are memories of the wiring, not
  tests of the host. What the host does is the PR's Host evidence.
"""
import ast
import json
import sys
import textwrap
from pathlib import Path

import pytest
from stages import correlated_evidence as ce
from stages.interpret import run_interpret

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "ansible/roles/pipeline/files"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
GOLDEN = json.loads((FIXTURES / "correlated_evidence_golden.json").read_text())


def _case_report(case: dict) -> dict:
    if "report_file" in case:
        return json.loads((FIXTURES / case["report_file"]).read_text())
    return case["report"]


# --- the moved builder is the old builder ------------------------------------


@pytest.mark.parametrize("name", sorted(GOLDEN["cases"]))
def test_moved_builder_is_byte_identical_to_the_old_one(name):
    case = GOLDEN["cases"][name]
    assert json.dumps(ce.correlated_evidence(_case_report(case))) == case["old_output"]


def test_the_golden_covers_a_real_report_and_the_strip():
    """Without these the identity test above could pass on trivial inputs."""
    real = json.loads(GOLDEN["cases"]["rm630_591d32aeae05"]["old_output"])
    assert {"cape_signatures", "volatility_insights"} <= set(real)
    assert len(real["cape_signatures"]) == 24
    stripped = GOLDEN["cases"]["mitre_stripped"]
    assert "T1055" in json.dumps(stripped["report"])
    assert "T1055" not in stripped["old_output"]


def test_the_eval_imports_the_builder_rather_than_copying_it():
    from lamware_eval import runner
    assert runner.correlated_evidence is ce.correlated_evidence
    tree = ast.parse((FILES / "lamware_eval/runner.py").read_text())
    defined = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert not defined & {"correlated_evidence", "strip_technique_ids"}, (
        "a second copy of the evidence builder in the eval (#380)")


# --- the switch, the path decision, the record --------------------------------


REPORT = _case_report(GOLDEN["cases"]["rm630_591d32aeae05"])


def test_enabled_and_agentic_gives_the_eval_s_evidence_and_records_it():
    evidence, rec = ce.evidence_for_interpret(REPORT, enabled=True, agentic=True)
    assert evidence == ce.correlated_evidence(REPORT)
    assert rec == {
        "given": True,
        "keys": ["cape_signatures", "volatility_insights"],
        "bytes": len(json.dumps(evidence)),
        "counts": {"cape_signatures": 24, "volatility_insights": 4},
    }


def test_switch_off_gives_nothing_and_says_why():
    evidence, rec = ce.evidence_for_interpret(REPORT, enabled=False, agentic=True)
    assert evidence is None
    assert rec == {"given": False, "reason": "disabled_by_config"}


def test_a_single_shot_path_is_not_sent_what_it_never_reads():
    evidence, rec = ce.evidence_for_interpret(REPORT, enabled=True, agentic=False)
    assert evidence is None
    assert rec == {"given": False, "reason": "single_shot_path"}


def test_a_report_with_no_evidence_records_that_not_a_success():
    evidence, rec = ce.evidence_for_interpret({"cape": {}}, enabled=True, agentic=True)
    assert evidence is None
    assert rec == {"given": False, "reason": "report_has_none"}


def test_production_builds_what_the_eval_reads_back_from_report_json():
    """report.json is written with default=str; the eval builds from that file.
    A non-JSON value in memory (a Path, a set) must reach the agent as the file
    will hold it, and must not make run_interpret's json.dumps raise."""
    report = {"cross_correlations": [{"title": "t", "detail": Path("/x/T1055.bin"),
                                      "mitre": "T1055"}],
              "cape": {"signatures": [{"name": "n", "pids": {4}}]}}
    evidence, rec = ce.evidence_for_interpret(report, enabled=True, agentic=True)
    as_file = json.loads(json.dumps(report, default=str))
    assert evidence == ce.correlated_evidence(as_file)
    assert json.dumps(evidence) and rec["given"] is True
    assert "T1055" not in json.dumps(evidence)


def _echo_container(tmp_path: Path) -> Path:
    """A stand-in interpret container that returns the init it read (the
    JSON-lines protocol, as in test_agent_payload_has_no_host_paths)."""
    fake = tmp_path / "fake-run-interpret"
    fake.write_text(f"#!{sys.executable}\n" + textwrap.dedent('''
        import json, sys
        init = json.loads(sys.stdin.readline())
        print(json.dumps({"type": "final", "analysis": {"init_keys": sorted(init),
                          "evidence": init.get("correlated_evidence")},
                          "model_used": "m", "tool_calls_used": 0}), flush=True)
    '''))
    fake.chmod(0o755)
    return fake


@pytest.mark.parametrize("enabled", [True, False])
def test_what_the_container_receives_follows_the_switch(tmp_path, enabled):
    """Observed on the init a container actually reads, not on the arguments."""
    evidence, _ = ce.evidence_for_interpret(REPORT, enabled=enabled, agentic=True)
    out = tmp_path / "out"
    out.mkdir()
    res = run_interpret({"program_name": "p", "functions_count": 1}, out,
                        str(_echo_container(tmp_path)), True, 30, {"model": "m"},
                        "/nonexistent/run-ghidra", extra_evidence=evidence)
    seen = res["analysis"]
    if enabled:
        assert seen["evidence"] == ce.correlated_evidence(REPORT)
    else:
        assert "correlated_evidence" not in seen["init_keys"]


def test_the_container_renders_production_s_evidence():
    """The agentic loop's first message carries it (interpret-ghidra.py)."""
    src = (ROOT / "ansible/roles/interpret/files/interpret-ghidra.py").read_text()
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == "_correlated_evidence_context")
    ns: dict = {"json": json}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "<x>", "exec"), ns)
    evidence, _ = ce.evidence_for_interpret(REPORT, enabled=True, agentic=True)
    text = ns["_correlated_evidence_context"]({"correlated_evidence": evidence})
    assert "stealth_network" in text and "Memory analysis:" in text


# --- run-pipeline's wiring (structural; see the module docstring) ------------


PIPELINE = ast.parse((FILES / "run-pipeline.py").read_text())
RUN_PIPELINE = next(n for n in ast.walk(PIPELINE)
                    if isinstance(n, ast.FunctionDef) and n.name == "run_pipeline")


def _calls(tree: ast.AST, name: str) -> list[ast.Call]:
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name) and n.func.id == name]


def _kw(call: ast.Call, name: str) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def _evidence_sources() -> dict[str, ast.Call]:
    """`ev, rec = evidence_for_interpret(...)` -> {ev: call, rec: call}."""
    out = {}
    for n in ast.walk(RUN_PIPELINE):
        if (isinstance(n, ast.Assign) and isinstance(n.value, ast.Call)
                and isinstance(n.value.func, ast.Name)
                and n.value.func.id == "evidence_for_interpret"):
            for elt in n.targets[0].elts:
                out[elt.id] = n.value
    return out


#: run_interpret's first argument on each Stage 4.5 call -> whether that path is
#: the container's agentic loop. `target` is _interpret_ghidra_program's
#: parameter (the routed payload and the native canonical program).
AGENTIC = {"target": True, "dotnet_init": True}
SINGLE_SHOT = {"java_init", "office_init", "ps_init", "script_init",
               "py_init", "go_init", "evasion_init", "visual_init"}


def test_every_run_interpret_call_site_is_classified():
    """A new call site has to be decided, not inherit "no evidence" silently."""
    calls = _calls(RUN_PIPELINE, "run_interpret")
    assert all(c.args and isinstance(c.args[0], ast.Name) for c in calls), (
        "a run_interpret call whose payload is not a plain name: classify it by hand")
    firsts = [c.args[0].id for c in calls]
    # 10 on 2026-10-03: the shared Ghidra helper (routed payload + native),
    # .NET, Java, Office, PowerShell, scripts, PyInstaller, Go, evasion, visual.
    assert len(firsts) == 10, firsts
    assert set(firsts) == set(AGENTIC) | SINGLE_SHOT, (
        f"unclassified: {set(firsts) - set(AGENTIC) - SINGLE_SHOT}; "
        f"stale: {(set(AGENTIC) | SINGLE_SHOT) - set(firsts)}")


def test_every_agentic_call_passes_the_evidence_and_no_single_shot_call_does():
    sources = _evidence_sources()
    for call in _calls(RUN_PIPELINE, "run_interpret"):
        first = call.args[0].id
        ev = _kw(call, "extra_evidence")
        if first in AGENTIC:
            assert isinstance(ev, ast.Name) and ev.id in sources, (
                f"run_interpret({first}, ...) is agentic and is not passed the evidence")
        else:
            assert ev is None, f"run_interpret({first}, ...) is single-shot; it never reads it"


def test_the_evidence_follows_the_switch_and_the_path_actually_sent():
    sources = {id(c): c for c in _evidence_sources().values()}.values()
    assert len(sources) == 2, "expected one builder call for Ghidra and one for .NET"
    for call in sources:
        assert ast.unparse(call.args[0]) == "report"
        assert ast.unparse(call.args[1]) == "CORRELATED_EVIDENCE"
    agentic = sorted(ast.unparse(_kw(c, "agentic")) for c in sources)
    # .NET: decided on the init after any fallback to single-shot.
    assert agentic == ["True", "is_agentic_dotnet(dotnet_init)"]


def test_the_switch_comes_from_config():
    assigns = [n for n in PIPELINE.body if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == "CORRELATED_EVIDENCE"
                       for t in n.targets)]
    assert [ast.unparse(a.value) for a in assigns] == [
        "_PIPELINE_CONFIG.interpret_correlated_evidence"]


def test_correlation_runs_before_the_evidence_is_built():
    """Otherwise the evidence silently lacks cross_correlations and warnings.

    Every call, not the first: a second cross_correlate after Stage 4.5 would
    overwrite the findings the agent was shown with ones it was not.
    """
    correlate = [c.lineno for c in _calls(RUN_PIPELINE, "cross_correlate")]
    build = min(c.lineno for c in _calls(RUN_PIPELINE, "evidence_for_interpret"))
    assert correlate and max(correlate) < build, (correlate, build)


def test_each_agentic_branch_records_what_the_agent_was_given():
    """llm_interpretation.input carries the record on all three agentic branches."""
    recs = {name for name, call in _evidence_sources().items()}
    records = []
    for n in ast.walk(RUN_PIPELINE):
        if isinstance(n, ast.Dict):
            for k, v in zip(n.keys, n.values, strict=True):
                if isinstance(k, ast.Constant) and k.value == "correlated_evidence":
                    records.append(v.id if isinstance(v, ast.Name) else None)
    # routed payload + native share the Ghidra record; .NET has its own.
    assert len(records) == 3, records
    assert set(records) <= recs and None not in records


# --- config chain -------------------------------------------------------------


def test_the_switch_survives_defaults_template_and_model():
    import jinja2
    import yaml
    from lamware_pipeline.config import PipelineConfig

    role = ROOT / "ansible/roles/pipeline"
    defaults = yaml.safe_load((role / "defaults/main.yml").read_text())
    assert defaults["pipeline_interpret_correlated_evidence"] is True
    tpl = (role / "templates/config.json.j2").read_text()
    line = next(ln for ln in tpl.splitlines() if '"interpret_correlated_evidence"' in ln)
    env = jinja2.Environment(autoescape=False)
    env.filters["to_json"] = json.dumps
    for value in (True, False):
        rendered = env.from_string("{" + line.rstrip(",") + "}").render(
            pipeline_interpret_correlated_evidence=value)
        assert json.loads(rendered) == {"interpret_correlated_evidence": value}
    assert PipelineConfig.model_fields["interpret_correlated_evidence"].default is True
    assert "interpret_correlated_evidence" not in PipelineConfig.model_fields["interpret"].annotation.model_fields, (
        "it is an orchestrator decision; the interpret section is sent to the container")


def test_the_new_stage_module_ships():
    import yaml
    tasks = yaml.safe_load((ROOT / "ansible/roles/pipeline/tasks/main.yml").read_text())
    stage = next(t for t in tasks if t.get("name") == "Deploy pipeline stage modules")
    assert "correlated_evidence.py" in stage["loop"]
