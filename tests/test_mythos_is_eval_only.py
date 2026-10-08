# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The Mythos 5.1 arm is eval-only, reaches Anthropic only through WIF, and is priced.

Renders the real LiteLLM template with the role's defaults and asserts on the parsed
config, not on template text:

  - no model_list entry for a CVP-grant model (the eval-mythos alias, or any entry
    whose model is in the forwarder's allowlist) names a static key. CVP Defense
    Access forbids static keys (ADR-022); the entry points at the anthropic-wif
    forwarder with a placeholder the forwarder drops. The checker is run against a
    synthetic static-key entry too, so a checker that matches nothing fails here;
  - the forwarder base in the litellm role and the forwarder's listen port agree, and
    the alias's model is one the forwarder will forward;
  - no production setting (interpret, pipeline, vars) names the alias or its model;
  - the eval arm routes to the alias on the router backend and has a rate
    (CLAUDE.md §10).
"""

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[1]
LITELLM = ROOT / "ansible/roles/litellm"
WIF = ROOT / "ansible/roles/anthropic-wif"
DEFAULTS = yaml.safe_load((LITELLM / "defaults/main.yml").read_text()) or {}
WIF_DEFAULTS = yaml.safe_load((WIF / "defaults/main.yml").read_text()) or {}
PLACEHOLDER = "sk-anthropic-wif-placeholder"


def _render_config() -> dict:
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.filters.setdefault("mandatory", lambda v: v)
    text = (LITELLM / "templates/config.yaml.j2").read_text()
    return yaml.safe_load(env.from_string(text).render(
        **{**DEFAULTS, "litellm_master_key": "test-key"}))


def _grant_entries(model_list: list[dict]) -> list[dict]:
    grant = set(WIF_DEFAULTS["anthropic_wif_allowed_models"])
    return [m for m in model_list
            if m["model_name"] == "eval-mythos"
            or m["litellm_params"].get("model", "").removeprefix("anthropic/") in grant]


def _static_key_violations(model_list: list[dict]) -> list[str]:
    """Grant entries that carry a static key or bypass the forwarder."""
    base = DEFAULTS["litellm_anthropic_wif_base"]
    bad = []
    for m in _grant_entries(model_list):
        p = m["litellm_params"]
        if str(p.get("api_key", "")).startswith("os.environ/") or p.get("api_key") != PLACEHOLDER:
            bad.append(f"{m['model_name']}: api_key {p.get('api_key')!r}")
        if p.get("api_base") != base:
            bad.append(f"{m['model_name']}: api_base {p.get('api_base')!r} is not {base}")
    return bad


def test_no_grant_entry_uses_a_static_key():
    cfg = _render_config()
    assert [m["model_name"] for m in _grant_entries(cfg["model_list"])] == ["eval-mythos"]
    assert _static_key_violations(cfg["model_list"]) == []


@pytest.mark.parametrize("bad", [
    {"model_name": "eval-mythos", "litellm_params": {
        "model": "anthropic/claude-mythos-5-1",
        "api_key": "os.environ/ANTHROPIC_RESEARCH_API_KEY"}},
    {"model_name": "eval-mythos", "litellm_params": {
        "model": "anthropic/claude-mythos-5-1", "api_key": PLACEHOLDER}},
    {"model_name": "some-other-alias", "litellm_params": {
        "model": "anthropic/claude-mythos-5-1", "api_base": "http://127.0.0.1:4010",
        "api_key": "os.environ/ANTHROPIC_API_KEY"}},
])
def test_the_checker_catches_a_static_key_or_a_bypass(bad):
    """Guards the guard: the shapes #719 first shipped, and a second alias for the
    same model, must each be reported."""
    assert _static_key_violations([bad])


def test_litellm_points_at_the_port_the_forwarder_listens_on():
    host_port = DEFAULTS["litellm_anthropic_wif_base"].removeprefix("http://")
    assert host_port == (f"{WIF_DEFAULTS['anthropic_wif_listen_host']}:"
                         f"{WIF_DEFAULTS['anthropic_wif_listen_port']}")


def test_the_alias_model_is_one_the_forwarder_forwards():
    assert DEFAULTS["litellm_eval_mythos_model"] in WIF_DEFAULTS["anthropic_wif_allowed_models"]


def test_no_static_research_key_is_rendered_into_litellm_env():
    """#719's first shape put ANTHROPIC_RESEARCH_API_KEY in litellm.env; under CVP there
    is no static key to put there."""
    text = (LITELLM / "templates/litellm.env.j2").read_text()
    names = [ln.split("=", 1)[0] for ln in text.splitlines() if "=" in ln
             and not ln.lstrip().startswith("#")]
    assert "ANTHROPIC_RESEARCH_API_KEY" not in names


def _all_values(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _all_values(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _all_values(v)
    else:
        yield obj


def test_no_production_setting_names_mythos():
    forbidden = {"eval-mythos", DEFAULTS["litellm_eval_mythos_model"]}
    # vars/main.yml is gitignored (CI has only the .example), so the real one is
    # checked only where it exists.
    files = [ROOT / "ansible/roles/interpret/defaults/main.yml",
             ROOT / "ansible/roles/pipeline/defaults/main.yml",
             ROOT / "ansible/vars/main.yml.example"]
    files += [f for f in [ROOT / "ansible/vars/main.yml"] if f.exists()]
    for f in files:
        data = yaml.safe_load(f.read_text()) or {}
        hits = [v for v in _all_values(data) if isinstance(v, str) and v in forbidden]
        assert not hits, f"{f.relative_to(ROOT)} names {hits}"


def test_the_eval_arm_routes_to_the_alias_and_is_priced(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "ansible/roles/pipeline/files"))
    from lamware_eval.arms import resolve_arm
    from lamware_eval.runner import _RATES
    arm = resolve_arm("mythos@10")
    assert (arm.model, arm.re_backend, arm.max_tool_calls) == ("eval-mythos", "router", 10)
    assert _RATES["eval-mythos"] == (10.0, 50.0, 12.5, 0.25)


def test_the_eval_arm_runs_on_the_router_backend(monkeypatch):
    """DEPENDS ON #719. Production's config.json says re_backend=local; an arm that
    inherited it would send the alias down the local synthesis paths. #719's
    arm_config sets both backend keys to "router". Until #719 is merged this fails
    with an ImportError, on purpose: the arm is not runnable without it."""
    monkeypatch.syspath_prepend(str(ROOT / "ansible/roles/pipeline/files"))
    from lamware_eval.arms import resolve_arm
    from lamware_eval.runner import arm_config
    cfg = arm_config(resolve_arm("mythos@10"),
                     {"re_backend": "local", "single_shot_backend": "local"}, "agentic")
    assert (cfg["re_backend"], cfg["single_shot_backend"]) == ("router", "router")
    assert cfg["model"] == cfg["escalation_model"] == "eval-mythos"
