# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The frontier eval arms are eval-only, on the eval workspace key, and priced.

Renders the real LiteLLM templates with the role's defaults (as
test_requested_models_exist.py does) and asserts on the parsed config:
  - every `eval-*` alias authenticates with ANTHROPIC_RESEARCH_API_KEY (the
    spend-capped Lamware eval workspace), never the production ANTHROPIC_API_KEY,
    and NO other entry uses the eval key, so production traffic cannot bill it;
  - the env file renders that key EMPTY until the vault defines it (a call then
    fails with an auth error instead of falling back to production's key);
  - no production setting (interpret, pipeline, vars, their config templates, or
    a literal in the code that sends requests) names an eval alias or its model,
    so the automated RE stage cannot drift onto one through a default or
    escalation;
  - each eval arm routes to its alias and has a rate (CLAUDE.md section 10).

Structural (rendered templates and parsed source), because the property is about
configuration that no runtime test reaches: production never REQUESTS these
models, which is exactly what is being guarded.
"""

import ast
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[1]
LITELLM = ROOT / "ansible/roles/litellm"
DEFAULTS = yaml.safe_load((LITELLM / "defaults/main.yml").read_text()) or {}
EVAL_KEY = "os.environ/ANTHROPIC_RESEARCH_API_KEY"
PROD_KEY = "os.environ/ANTHROPIC_API_KEY"
# The arms this PR adds, and what they must resolve to.
EXPECTED = {"eval-opus55": "anthropic/claude-opus-5-5",
            "eval-fable51": "anthropic/claude-fable-5-1"}


def _render(name: str, **extra) -> str:
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.filters.setdefault("mandatory", lambda v: v)
    return env.from_string((LITELLM / "templates" / name).read_text()).render(
        **{**DEFAULTS, "litellm_master_key": "test-key", **extra})


def _model_list() -> list[dict]:
    return yaml.safe_load(_render("config.yaml.j2"))["model_list"]


def _eval_entries() -> list[dict]:
    return [m for m in _model_list() if m["model_name"].startswith("eval-")]


def _forbidden() -> set[str]:
    """Every eval alias and the upstream model behind it."""
    out: set[str] = set()
    for m in _eval_entries():
        out.add(m["model_name"])
        out.add(m["litellm_params"]["model"].removeprefix("anthropic/"))
    return out


def test_the_eval_aliases_exist_and_resolve_to_their_models():
    got = {m["model_name"]: m["litellm_params"]["model"] for m in _eval_entries()}
    assert got == EXPECTED


def test_eval_aliases_use_the_eval_key_and_nothing_else_does():
    """Both directions: an eval alias on the production key bills the wrong org;
    a production entry on the eval key spends the eval cap on production work."""
    entries = _model_list()
    assert len(entries) > len(EXPECTED), "rendered model_list lost its production entries"
    for m in entries:
        key = m["litellm_params"].get("api_key")
        if m["model_name"].startswith("eval-"):
            assert key == EVAL_KEY, f"{m['model_name']} authenticates with {key}"
        else:
            assert key != EVAL_KEY, f"{m['model_name']} (not an eval alias) uses the eval key"


def test_the_eval_key_renders_empty_until_the_vault_defines_it():
    base = dict(anthropic_api_key="prod", litellm_db_user="u",
                litellm_db_password="p", litellm_db_name="d")
    lines = _render("litellm.env.j2", **base).splitlines()
    assert "ANTHROPIC_RESEARCH_API_KEY=" in lines, "must render empty, not fall back"
    assert "ANTHROPIC_API_KEY=prod" in lines
    lines = _render("litellm.env.j2", **base, anthropic_research_api_key="research").splitlines()
    assert "ANTHROPIC_RESEARCH_API_KEY=research" in lines
    assert "ANTHROPIC_API_KEY=prod" in lines


def _all_values(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _all_values(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _all_values(v)
    else:
        yield obj


def test_no_production_setting_names_an_eval_model():
    forbidden = _forbidden()
    assert {"eval-opus55", "claude-opus-5-5", "eval-fable51", "claude-fable-5-1"} <= forbidden
    # vars/main.yml is gitignored (a clean checkout or CI has only the
    # .example), so the real one is checked only where it exists.
    files = [ROOT / "ansible/roles/interpret/defaults/main.yml",
             ROOT / "ansible/roles/pipeline/defaults/main.yml",
             ROOT / "ansible/vars/main.yml.example"]
    files += [f for f in [ROOT / "ansible/vars/main.yml"] if f.exists()]
    for f in files:
        data = yaml.safe_load(f.read_text()) or {}
        hits = [v for v in _all_values(data) if isinstance(v, str) and v in forbidden]
        assert not hits, f"{f.relative_to(ROOT)} names {hits}"


def test_no_production_template_names_an_eval_model():
    """The config templates are Jinja, not YAML/JSON, until rendered with the
    host's vars; a quoted literal is the only way one could name the model."""
    for rel in ("ansible/roles/pipeline/templates/config.json.j2",
                "ansible/roles/interpret/templates/interpret-config.json.j2"):
        text = (ROOT / rel).read_text()
        hits = [m for m in _forbidden() if f'"{m}"' in text or f"'{m}'" in text]
        assert not hits, f"{rel} names {hits}"


def test_no_request_sending_code_names_an_eval_model():
    """String constants (not comments) in the code that sends model requests,
    and in the analyst-facing API."""
    forbidden = _forbidden()
    senders = [ROOT / "ansible/roles/interpret/files/interpret-ghidra.py",
               ROOT / "ansible/roles/pipeline/files/run-pipeline.py",
               *sorted((ROOT / "ansible/roles/pipeline/files/stages").glob("*.py")),
               *sorted((ROOT / "api/app").rglob("*.py"))]
    for path in senders:
        for n in ast.walk(ast.parse(path.read_text())):
            if isinstance(n, ast.Constant) and n.value in forbidden:
                raise AssertionError(f"{path.relative_to(ROOT)}:{n.lineno} names {n.value}")


@pytest.mark.parametrize("arm_name,alias", [("opus55@10", "eval-opus55"),
                                            ("fable51@10", "eval-fable51")])
def test_the_eval_arms_route_to_their_aliases_and_are_priced(monkeypatch, arm_name, alias):
    # lamware_eval.runner imports the pipeline stages, which need lamware_shared.
    # CI's top-level test job does not install it; the pipeline job does, and
    # pipeline/tests/test_frontier_arms.py pins the same routing and exact rates.
    pytest.importorskip("lamware_shared")
    monkeypatch.syspath_prepend(str(ROOT / "ansible/roles/pipeline/files"))
    from lamware_eval.arms import resolve_arm
    from lamware_eval.runner import _RATES
    arm = resolve_arm(arm_name)
    assert arm.model == alias and arm.re_backend == "router" and arm.max_tool_calls == 10
    assert alias in _RATES


def test_no_mythos_alias_is_configured():
    """Mythos access must not use a static API key; it returns with its own
    token forwarder (ADR-022), not as a model_list entry on a key."""
    for m in _model_list():
        assert "mythos" not in m["model_name"] and "mythos" not in m["litellm_params"]["model"]
