# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""LLM profiles (ADR-036): a run chooses its models explicitly, or gets the deployed defaults.

- The config model: "local" is the interpret block and cannot be redefined; a profile
  replaces only the model and transport fields; an unknown name is refused, never
  defaulted.
- run-pipeline, loaded as a module against a config with profiles: applying a profile
  changes INTERPRET_CONFIG (which every stage reads at call time) and the report
  records the profile, cloud or not, and the models.
- main() applies the profile before any stage, and the intake front door passes it.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from lamware_pipeline.config import LOCAL_PROFILE, MODEL_FIELDS, PROFILE_FIELDS, PipelineConfig
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "config.json"
RUN_PIPELINE = ROOT / "ansible/roles/pipeline/files/run-pipeline.py"
STUB = {"description": "test", "cloud": False, "model": "stub",
        "summary_model": "stub", "plain_english_model": "stub"}
HAIKU = {"cloud": True, "model": "eval-haiku55",
         "summary_model": "eval-haiku55", "plain_english_model": "eval-haiku55",
         "re_backend": "router", "single_shot_backend": "router"}


def _cfg(**profiles) -> PipelineConfig:
    data = json.loads(FIXTURE.read_text())
    data["llm_profiles"] = profiles
    return PipelineConfig.model_validate(data)


def test_a_config_without_profiles_still_loads_and_has_only_local():
    data = json.loads(FIXTURE.read_text())
    data.pop("llm_profiles", None)
    cfg = PipelineConfig.model_validate(data)
    assert cfg.profile_names() == [LOCAL_PROFILE]
    assert cfg.interpret_for(LOCAL_PROFILE) == cfg.interpret


def test_local_cannot_be_redefined():
    with pytest.raises(ValidationError, match="may not define"):
        _cfg(local=STUB)


@pytest.mark.parametrize("name", ["Stub", "has space", "a/b", "", "x" * 40])
def test_profile_names_are_one_safe_token(name):
    with pytest.raises(ValidationError):
        _cfg(**{name: STUB})


def test_an_unknown_profile_is_refused_not_defaulted():
    with pytest.raises(ValueError, match="unknown LLM profile 'haiku'; defined: local, stub"):
        _cfg(stub=STUB).interpret_for("haiku")


def test_a_profile_replaces_only_models_and_transport():
    cfg = _cfg(stub=STUB)
    base, got = cfg.interpret.model_dump(), cfg.interpret_for("stub").model_dump()
    changed = {k for k in base if base[k] != got[k]}
    assert changed <= set(PROFILE_FIELDS) and {got[f] for f in MODEL_FIELDS} == {"stub"}
    assert got["max_tool_calls"] == base["max_tool_calls"] and got["dotnet_mode"] == base["dotnet_mode"]


@pytest.mark.parametrize("model", ["eval-haiku55", "claude-sonnet-4-6", "local-qwen-llamacpp/../x", "stubby"])
def test_a_profile_that_names_a_remote_model_must_say_cloud(model):
    """A mislabelled profile would send malware off the host while reports said local."""
    with pytest.raises(ValidationError, match="has cloud: false but names"):
        _cfg(x={**STUB, "summary_model": model})


def test_a_well_formed_cloud_profile_loads():
    assert _cfg(haiku=HAIKU).profile_is_cloud("haiku")


@pytest.mark.parametrize("model", ["claude-sonnet-4-6", "claude-haiku-4-5", "stub", "eval_haiku"])
def test_a_cloud_profile_names_only_eval_aliases(model):
    """The eval-* entries carry no production key; a cloud profile cannot borrow the analyst's."""
    with pytest.raises(ValidationError, match="names only eval-"):
        _cfg(x={**HAIKU, "summary_model": model})


@pytest.mark.parametrize("transports", [("local", "local"), ("router", "local"), ("cloud", "router")])
def test_a_cloud_profile_uses_the_router_transports(transports):
    """#722: a cloud model on the local transports takes paths that bill nothing."""
    with pytest.raises(ValidationError, match="needs re_backend"):
        _cfg(x={**HAIKU, "re_backend": transports[0], "single_shot_backend": transports[1]})


@pytest.mark.parametrize("transports", [("router", "router"), ("local", "cloud")])
def test_a_local_profile_uses_the_local_transports(transports):
    with pytest.raises(ValidationError, match="a local profile needs"):
        _cfg(x={**STUB, "re_backend": transports[0], "single_shot_backend": transports[1]})


def test_a_profile_must_declare_whether_it_is_cloud():
    with pytest.raises(ValidationError, match="cloud"):
        _cfg(x={k: v for k, v in STUB.items() if k != "cloud"})


# --- run-pipeline, loaded as a module -------------------------------------------------

@pytest.fixture
def rp(tmp_path, monkeypatch):
    data = json.loads(FIXTURE.read_text())
    data["llm_profiles"] = {"stub": STUB, "haiku": HAIKU}
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps(data))
    monkeypatch.setenv("LAMWARE_PIPELINE_CONFIG", str(cfg))
    sys.path.insert(0, str(RUN_PIPELINE.parent))
    spec = importlib.util.spec_from_file_location("run_pipeline_under_test", RUN_PIPELINE)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.path.remove(str(RUN_PIPELINE.parent))
    return mod


def test_without_the_flag_the_run_is_local_and_says_so(rp):
    assert rp.LLM_PROFILE == LOCAL_PROFILE
    rec = rp.llm_profile_record()
    assert rec["name"] == "local" and rec["cloud"] is False
    assert rec["models"]["model"] == rp._PIPELINE_CONFIG.interpret.model


def test_applying_a_profile_reaches_what_the_stages_read(rp):
    rp.apply_llm_profile("stub")
    assert {rp.INTERPRET_CONFIG[f] for f in MODEL_FIELDS} == {"stub"}
    assert rp.llm_profile_record() == {"name": "stub", "cloud": False,
                                       "models": {f: "stub" for f in MODEL_FIELDS}}


def test_a_cloud_profile_is_recorded_as_cloud_and_warned(rp, caplog):
    with caplog.at_level("WARNING", logger="pipeline"):
        rp.apply_llm_profile("haiku")
    assert rp.llm_profile_record()["cloud"] is True
    assert any("CLOUD profile" in r.getMessage() and "eval-haiku55" in r.getMessage()
               for r in caplog.records)


def test_an_unknown_profile_stops_the_run(rp):
    with pytest.raises(SystemExit, match="unknown LLM profile 'mythos'"):
        rp.apply_llm_profile("mythos")
    assert rp.LLM_PROFILE == LOCAL_PROFILE


# --- main() and the front doors (structural: the order of calls is the property) ------

def _main() -> ast.FunctionDef:
    tree = ast.parse(RUN_PIPELINE.read_text())
    return next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")


def _calls(node) -> list[str]:
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            out.append((f.id if isinstance(f, ast.Name) else getattr(f, "attr", ""), n.lineno))
    return out


def test_main_applies_the_profile_before_any_stage_runs():
    calls = _calls(_main())
    applied = min(line for name, line in calls if name == "apply_llm_profile")
    for stage in ("run_pipeline", "run_replay"):
        assert applied < min(line for name, line in calls if name == stage), stage


def test_the_report_and_a_replayed_report_record_the_profile():
    src = RUN_PIPELINE.read_text()
    assert '"llm_profile": llm_profile_record(),' in src
    assert 'report["replay_llm_profile"] = llm_profile_record()' in src


def test_intake_passes_the_profile_to_every_pipeline_run():
    runner = (ROOT / "scripts/lib/intake_run.sh").read_text()
    runs = [ln for ln in runner.splitlines() if '"$RUN_PIPELINE"' in ln and not ln.lstrip().startswith("#")]
    assert runs, "no run-pipeline call found: the check would pass vacuously"
    joined = runner.replace("\\\n", " ")
    assert all('--llm-profile "$PROFILE"' in joined.split(r)[1].split("\n")[0]
               for r in ['"$RUN_PIPELINE" "$path"']), joined
    front = (ROOT / "scripts/intake.sh").read_text()
    assert "'$B/llm_profile'" in front and "*[!a-z0-9-]*" in front
    assert 'LLM_PROFILE="$(LLM_PROFILE)"' in (ROOT / "Makefile").read_text()


@pytest.mark.parametrize("key", ["escalation_model", "escalation_threshold"])
def test_a_profile_naming_escalation_is_refused_with_the_reason(key):
    """ADR-038 removed escalation; an operator's old profile gets told why, by name."""
    with pytest.raises(ValueError, match="ADR-038"):
        _cfg(old=dict(STUB, **{key: "stub" if key == "escalation_model" else 5}))
