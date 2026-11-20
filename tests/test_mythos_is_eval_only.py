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
  - nothing points at the old AWS forwarder any more.

The old AWS forwarder's own deploy properties (its CA key stays on the controller,
its host key reaches the service only through LoadCredential) stay guarded below
until that role is retired.
"""

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[1]
LITELLM = ROOT / "ansible/roles/litellm"
ROLE = ROOT / "ansible/roles/claude-platform-aws"
WIF = ROOT / "ansible/roles/anthropic-wif"
DEFAULTS = yaml.safe_load((LITELLM / "defaults/main.yml").read_text()) or {}
ROLE_DEFAULTS = yaml.safe_load((ROLE / "defaults/main.yml").read_text()) or {}
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
    old = DEFAULTS["litellm_claude_platform_aws_base"]
    for routes in ROUTE_CONFIGS:
        hits = [m["model_name"] for m in _render_config(routes)["model_list"]
                if m["litellm_params"].get("api_base") == old]
        assert hits == [], hits


# --- the old AWS forwarder role, until it is retired ---------------------------------

def test_the_role_is_off_by_default_and_in_site_yml():
    assert ROLE_DEFAULTS["claude_platform_aws_enabled"] is False
    plays = yaml.safe_load((ROOT / "ansible/site.yml").read_text())
    roles = [r["role"] if isinstance(r, dict) else r
             for p in plays for r in p.get("roles", [])]
    assert "claude-platform-aws" in roles


def _tasks(tasks=None):
    tasks = tasks if tasks is not None else yaml.safe_load((ROLE / "tasks/main.yml").read_text())
    for t in tasks:
        yield t
        yield from _tasks(t.get("block", []))


META = {"name", "when", "register", "delegate_to", "become", "notify", "loop",
        "changed_when", "failed_when", "block", "tags"}


def _module(task: dict) -> tuple[str, object]:
    (key,) = [k for k in task if k not in META]
    return key, task[key]


def test_the_ca_key_is_used_only_on_the_controller():
    """Anchored on what a task DOES with the path (module parameters and loop items),
    not on prose: an assert whose message names ca.key is not a use of it."""
    uses = [t for t in _tasks() if "block" not in t
            and _module(t)[0] != "ansible.builtin.assert"
            and "ca.key" in yaml.safe_dump([_module(t)[1], t.get("loop")])]
    assert uses, "no task signs with the CA: the checker would pass vacuously"
    for t in uses:
        assert t.get("delegate_to") == "localhost", f"{t['name']} touches ca.key on the host"
        assert not any(k.endswith((".copy", ".template")) for k in t), t["name"]


def test_the_host_key_reaches_the_services_only_through_loadcredential():
    for unit in ("claude-platform-aws.service.j2", "claude-platform-aws-check.service.j2"):
        text = (ROLE / "templates" / unit).read_text()
        lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
        assert any(ln.startswith("LoadCredential=host.key:") for ln in lines), unit
        assert not any("Environment=" in ln and "AWS_" in ln for ln in lines), unit
    key_task = next(t for t in _tasks() if "openssl_privatekey" in str(list(t)))
    params = key_task["community.crypto.openssl_privatekey"]
    assert (params["owner"], params["mode"], params["regenerate"]) == ("root", "0400", "never")
