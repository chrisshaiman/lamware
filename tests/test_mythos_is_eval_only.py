# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The forwarder-only eval arms (Mythos 5.1/5.2, Fable 5.2) never carry a key.

Renders the real LiteLLM template with the role's defaults and parses the Ansible roles,
asserting on structure rather than text (ADR-033, superseding the route of ADR-026):

  - every model_list entry for one of these models points at the anthropic-wif eval
    route with the placeholder it drops, in EVERY configuration of
    litellm_anthropic_wif_routes (so the eval arms' key fallback never reaches them).
    The checker is also run against synthetic bad entries, so a checker that matches
    nothing fails here;
  - their models are on the eval route's allowlist and on no other route;
  - nothing points at the old forwarder's port any more, and its role only tears
    it down (ADR-034): a revert or copy-paste would otherwise reinstall a second
    credential path to the same workspace, and nothing on the host would flag a
    forwarder that answers.
"""

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[1]
LITELLM = ROOT / "ansible/roles/litellm"
ROLE = ROOT / "ansible/roles/claude-platform-aws"
OLD_FORWARDER = "http://127.0.0.1:4010"   # retired (ADR-034)
WIF = ROOT / "ansible/roles/anthropic-wif"
DEFAULTS = yaml.safe_load((LITELLM / "defaults/main.yml").read_text()) or {}
PLACEHOLDER = "sk-anthropic-wif-placeholder"
ALIASES = {"eval-mythos": DEFAULTS["litellm_eval_mythos_model"],
           "eval-mythos52": DEFAULTS["litellm_eval_mythos52_model"],
           "eval-fable52": DEFAULTS["litellm_eval_fable52_model"]}
ROUTE_CONFIGS = ([], ["eval"], ["production"], ["production", "eval"])


def _render_config(routes=()) -> dict:
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.filters.setdefault("mandatory", lambda v: v)
    text = (LITELLM / "templates/config.yaml.j2").read_text()
    return yaml.safe_load(env.from_string(text).render(
        **{**DEFAULTS, "litellm_master_key": "test-key",
           "litellm_anthropic_wif_routes": list(routes)}))


def _forwarded_entries(model_list: list[dict]) -> list[dict]:
    models = set(ALIASES.values())
    return [m for m in model_list
            if m["model_name"] in ALIASES
            or m["litellm_params"].get("model", "").removeprefix("anthropic/") in models]


def _violations(model_list: list[dict]) -> list[str]:
    """Entries for a forwarder-only model that carry a key or bypass the eval route."""
    base = DEFAULTS["litellm_anthropic_wif_eval_base"]
    bad = []
    for m in _forwarded_entries(model_list):
        p = m["litellm_params"]
        if p.get("api_key") != PLACEHOLDER:
            bad.append(f"{m['model_name']}: api_key {p.get('api_key')!r}")
        if p.get("api_base") != base:
            bad.append(f"{m['model_name']}: api_base {p.get('api_base')!r} is not {base}")
    return bad


@pytest.mark.parametrize("routes", ROUTE_CONFIGS)
def test_the_forwarded_entries_carry_no_key_in_any_configuration(routes):
    cfg = _render_config(routes)
    assert [m["model_name"] for m in _forwarded_entries(cfg["model_list"])] == list(ALIASES)
    assert _violations(cfg["model_list"]) == []


@pytest.mark.parametrize("bad", [
    {"model_name": "eval-mythos", "litellm_params": {
        "model": "anthropic/claude-mythos-5-1",
        "api_key": "os.environ/ANTHROPIC_RESEARCH_API_KEY"}},
    {"model_name": "eval-mythos", "litellm_params": {
        "model": "anthropic/claude-mythos-5-1", "api_key": PLACEHOLDER}},
    {"model_name": "eval-mythos", "litellm_params": {
        "model": "anthropic/claude-mythos-5-1", "api_base": "http://127.0.0.1:4011",
        "api_key": PLACEHOLDER}},
    {"model_name": "some-other-alias", "litellm_params": {
        "model": "anthropic/claude-mythos-5-1", "api_base": "http://127.0.0.1:4012",
        "api_key": "os.environ/ANTHROPIC_API_KEY"}},
])
def test_the_checker_catches_a_key_or_a_bypass(bad):
    """Guards the guard: a keyed entry, one that skips the forwarder, one on the
    production route, and a second keyed alias for the same model are each reported."""
    assert _violations([bad])


def _wif_routes() -> dict[str, list[str]]:
    """The anthropic-wif routes' allowlists, with role-default Jinja resolved."""
    raw = yaml.safe_load((WIF / "defaults/main.yml").read_text())
    env = jinja2.Environment()
    ctx = {**DEFAULTS, **raw}
    return {r["name"]: [env.from_string(m).render(**ctx) for m in r["allowed_models"]]
            for r in raw["anthropic_wif_routes"]}


def test_their_models_are_on_the_eval_route_only():
    routes = _wif_routes()
    for model in ALIASES.values():
        assert model in routes["eval"], model
        assert model not in routes["production"], model


def test_nothing_points_at_the_old_aws_forwarder():
    for routes in ROUTE_CONFIGS:
        hits = [m["model_name"] for m in _render_config(routes)["model_list"]
                if m["litellm_params"].get("api_base") == OLD_FORWARDER]
        assert hits == [], hits


# --- the old forwarder's role only tears it down (ADR-034) -------------------------

TASKS = yaml.safe_load((ROLE / "tasks/main.yml").read_text())


def _modules(task: dict) -> dict:
    return {k: v for k, v in task.items() if "." in k}


def test_no_task_starts_enables_or_installs_the_old_forwarder():
    for task in TASKS:
        for module, args in _modules(task).items():
            name = task.get("name", "")
            if module == "ansible.builtin.systemd" and isinstance(args, dict):
                assert args.get("state") in (None, "stopped"), name
                assert args.get("enabled") in (None, False), name
            assert module not in ("ansible.builtin.template", "ansible.builtin.copy",
                                  "ansible.builtin.get_url", "ansible.builtin.apt",
                                  "community.crypto.openssl_privatekey",
                                  "community.crypto.x509_certificate_pipe"), f"{name}: installs"
            if module in ("ansible.builtin.user", "ansible.builtin.group"):
                assert args.get("state") == "absent", name


def test_units_code_config_and_user_are_removed():
    defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
    absent = [_modules(t)["ansible.builtin.file"] for t in TASKS
              if _modules(t).get("ansible.builtin.file", {}).get("state") == "absent"]
    loops = [t.get("loop") for t in TASKS
             if _modules(t).get("ansible.builtin.file", {}).get("state") == "absent"]
    assert "{{ claude_platform_aws_retired_units }}" in loops
    assert "{{ claude_platform_aws_retired_dirs }}" in loops
    assert set(defaults["claude_platform_aws_retired_dirs"]) == {
        "/opt/claude-platform-aws", "/etc/claude-platform-aws"}
    assert "claude-platform-aws.service" in defaults["claude_platform_aws_retired_units"]
    assert absent, "no removal task found: the checks above would pass vacuously"


def test_the_role_has_no_handlers_templates_or_files_left():
    for sub in ("handlers", "templates", "files"):
        assert not (ROLE / sub).exists(), sub
