# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The anthropic-wif role and LiteLLM's switch to it agree (ADR-033).

Renders the real templates with both roles' defaults and asserts on parsed values:
  - with both routes in litellm_anthropic_wif_routes, every Anthropic entry that is
    not local and not on the separate eval forwarder goes to a WIF route, and its
    model is in that route's allowlist (or the forwarder would 403 it), production on
    the production route and eval-* on the eval route; with only eval listed,
    production keeps its key;
  - the rendered forwarder config passes the forwarder's own validator;
  - a listed route's key is left out of the env file, and with the list empty
    LiteLLM's config is the same as before the switch existed (the rollback);
  - a route is active in the forwarder only when its workspace id is set;
  - the signing key is generated once and never overwritten, and reaches the units
    only through LoadCredential.
Behaviour of the forwarder itself is in test_anthropic_wif_forwarder.py.
"""

import importlib.util
import json
import sys
from pathlib import Path

import jinja2
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible/roles/anthropic-wif"
LITELLM = ROOT / "ansible/roles/litellm"
spec = importlib.util.spec_from_file_location("anthropic_wif", ROLE / "files/anthropic_wif.py")
wif = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = wif
spec.loader.exec_module(wif)

LITELLM_DEFAULTS = yaml.safe_load((LITELLM / "defaults/main.yml").read_text())
INTERPRET_DEFAULTS = yaml.safe_load((ROOT / "ansible/roles/interpret/defaults/main.yml").read_text())
TASKS = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
# Always on the eval route, with no key in any configuration (test_mythos_is_eval_only.py).
FORWARDER_ONLY = {"eval-mythos", "eval-mythos52", "eval-fable52"}
IDS = {"anthropic_wif_organization_id": "00000000-0000-4000-8000-000000000001",
       "anthropic_wif_federation_rule_id": "fdrl_X", "anthropic_wif_service_account_id": "svac_X",
       "anthropic_wif_production_workspace_id": "wrkspc_PROD",
       "anthropic_wif_eval_workspace_id": "wrkspc_EVAL"}


def _env(trim=True):
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, trim_blocks=trim)
    env.filters.setdefault("mandatory", lambda v: v)
    env.filters["to_nice_json"] = lambda v: json.dumps(v, indent=4)
    return env


def _resolve(value, ctx):
    """Render nested Jinja in role defaults, as Ansible does lazily."""
    if isinstance(value, str):
        return _env().from_string(value).render(**ctx) if "{{" in value else value
    if isinstance(value, list):
        return [_resolve(v, ctx) for v in value]
    if isinstance(value, dict):
        return {k: _resolve(v, ctx) for k, v in value.items()}
    return value


def _wif_vars(**over):
    ctx = {**INTERPRET_DEFAULTS, **LITELLM_DEFAULTS, **IDS, **over}
    raw = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
    ctx.update(raw)
    ctx.update(IDS)
    ctx.update(over)
    return {k: _resolve(v, ctx) for k, v in ctx.items()}


def _litellm(name, trim=True, **over):
    ctx = {**INTERPRET_DEFAULTS, **LITELLM_DEFAULTS, "litellm_master_key": "k",
           "anthropic_api_key": "PRODKEY", "anthropic_research_api_key": "EVALKEY",
           "litellm_db_user": "u", "litellm_db_password": "p", "litellm_db_name": "n", **over}
    return _env(trim).from_string((LITELLM / "templates" / name).read_text()).render(**ctx)


def _routes():
    v = _wif_vars()
    return {r["name"]: r for r in v["anthropic_wif_routes"]}


def _cloud_entries(**over):
    out = []
    for m in yaml.safe_load(_litellm("config.yaml.j2", **over))["model_list"]:
        p = m["litellm_params"]
        if p["model"].startswith("anthropic/") and p.get("api_base") not in (
                LITELLM_DEFAULTS["litellm_llamacpp_anthropic_base"],
                LITELLM_DEFAULTS["litellm_claude_platform_aws_base"]):
            out.append((m["model_name"], p))
    return out


def test_the_litellm_bases_are_the_routes_ports():
    r = _routes()
    assert LITELLM_DEFAULTS["litellm_anthropic_wif_production_base"] == (
        f"http://127.0.0.1:{r['production']['listen_port']}")
    assert LITELLM_DEFAULTS["litellm_anthropic_wif_eval_base"] == (
        f"http://127.0.0.1:{r['eval']['listen_port']}")


def test_switched_on_every_cloud_entry_reaches_a_route_that_allows_its_model():
    r = _routes()
    port_to_route = {f"http://127.0.0.1:{x['listen_port']}": x for x in r.values()}
    entries = _cloud_entries(litellm_anthropic_wif_routes=["production", "eval"])
    # 5 production, 5 keyed eval arms, 3 forwarder-only eval arms, haiku-fallback
    assert len(entries) == 14, [n for n, _ in entries]
    for name, p in entries:
        route = port_to_route.get(p.get("api_base"))
        assert route, f"{name} is not on a WIF route: {p}"
        assert p["api_key"] == "sk-anthropic-wif-placeholder", name
        assert route["name"] == ("eval" if name.startswith("eval-") else "production"), name
        assert p["model"].removeprefix("anthropic/") in route["allowed_models"], name


def test_switched_on_no_entry_names_an_env_key():
    text = _litellm("config.yaml.j2", litellm_anthropic_wif_routes=["production", "eval"])
    assert "os.environ/ANTHROPIC" not in text


def test_switched_off_entries_use_the_workspace_keys_as_before():
    entries = [(n, p) for n, p in _cloud_entries(litellm_anthropic_wif_routes=[])
               if n not in FORWARDER_ONLY]
    assert len(entries) == 11
    for name, p in entries:
        want = "ANTHROPIC_RESEARCH_API_KEY" if name.startswith("eval-") else "ANTHROPIC_API_KEY"
        assert p == {"model": p["model"], "api_key": f"os.environ/{want}"}, name


@pytest.mark.parametrize("trim", [False, True])
def test_the_switch_renders_valid_yaml_with_and_without_trim_blocks(trim):
    for routes in ([], ["eval"], ["production", "eval"]):
        assert yaml.safe_load(_litellm("config.yaml.j2", trim, litellm_anthropic_wif_routes=routes))


def _env_keys(routes):
    text = _litellm("litellm.env.j2", litellm_anthropic_wif_routes=routes)
    return {ln.split("=", 1)[0]: ln.split("=", 1)[1] for ln in text.splitlines()
            if "=" in ln and not ln.lstrip().startswith("#") and ln.startswith("ANTHROPIC")}


def test_a_listed_routes_key_is_left_out_of_the_env_file():
    assert _env_keys([]) == {"ANTHROPIC_API_KEY": "PRODKEY", "ANTHROPIC_RESEARCH_API_KEY": "EVALKEY"}
    assert _env_keys(["eval"]) == {"ANTHROPIC_API_KEY": "PRODKEY"}
    assert _env_keys(["production", "eval"]) == {}


def test_eval_only_moves_the_eval_arms_and_leaves_production_on_its_key():
    """The first step (ADR-033): the eval workspace is federated, production is not."""
    for name, p in _cloud_entries(litellm_anthropic_wif_routes=["eval"]):
        if name.startswith("eval-"):  # keyed and forwarder-only eval arms alike
            assert p["api_base"] == LITELLM_DEFAULTS["litellm_anthropic_wif_eval_base"], name
            assert p["api_key"] == "sk-anthropic-wif-placeholder", name
        else:
            assert p == {"model": p["model"], "api_key": "os.environ/ANTHROPIC_API_KEY"}, name


def test_a_route_without_a_workspace_id_is_not_configured(tmp_path):
    v = _wif_vars(anthropic_wif_production_workspace_id="")
    text = _env().from_string((ROLE / "templates/config.json.j2").read_text()).render(**v)
    p = tmp_path / "config.json"
    p.write_text(text)
    assert [r.name for r in wif.load_config(str(p), environ={}).routes] == ["eval"]


def test_the_rendered_forwarder_config_passes_the_forwarders_validator(tmp_path):
    v = _wif_vars()
    text = _env().from_string((ROLE / "templates/config.json.j2").read_text()).render(**v)
    p = tmp_path / "config.json"
    p.write_text(text)
    cfg = wif.load_config(str(p), environ={})
    assert {r.name: r.workspace_id for r in cfg.routes} == {
        "production": "wrkspc_PROD", "eval": "wrkspc_EVAL"}
    assert cfg.issuer == "https://wif.lamware.internal" and cfg.allowed_peer_uids == (0,)


def test_the_validator_would_refuse_a_model_on_both_routes(tmp_path):
    """Guards the guard: the test above means something only if overlap fails."""
    v = _wif_vars()
    v["anthropic_wif_routes"][1]["allowed_models"].append("claude-sonnet-5")
    text = _env().from_string((ROLE / "templates/config.json.j2").read_text()).render(**v)
    p = tmp_path / "config.json"
    p.write_text(text)
    with pytest.raises(wif.ConfigError, match="claude-sonnet-5 is on routes production and eval"):
        wif.load_config(str(p), environ={})


def _task(name):
    return next(t for t in TASKS if t.get("name") == name)


def test_the_signing_key_is_generated_once_and_kept_root_only():
    gen = _task("Generate the signing key once (EC P-256, root only)")["ansible.builtin.shell"]
    assert gen["creates"].endswith("/signing-key.pem")
    assert gen["cmd"].startswith("umask 077 && openssl ecparam -name prime256v1 -genkey")
    keep = _task("Keep the signing key root-only")["ansible.builtin.file"]
    assert (keep["owner"], keep["group"], keep["mode"]) == ("root", "root", "0600")
    # Nothing else in the role writes the key.
    writers = [t["name"] for t in TASKS if "signing-key.pem" in json.dumps(t)
               and any(k in t for k in ("ansible.builtin.copy", "ansible.builtin.template"))]
    assert writers == []


@pytest.mark.parametrize("unit", ["anthropic-wif.service.j2", "anthropic-wif-check.service.j2"])
def test_the_units_get_the_key_only_through_loadcredential(unit):
    text = (ROLE / "templates" / unit).read_text()
    lines = [ln for ln in text.splitlines() if not ln.startswith("#")]
    assert "LoadCredential=signing-key.pem:{{ anthropic_wif_config_dir }}/signing-key.pem" in lines
    assert "User={{ anthropic_wif_user }}" in lines and "NoNewPrivileges=yes" in lines


def test_the_role_runs_before_litellm_in_site_yml():
    play = yaml.safe_load((ROOT / "ansible/site.yml").read_text())
    roles = [r["role"] if isinstance(r, dict) else r
             for p in play for r in (p.get("roles") or [])]
    assert roles.index("anthropic-wif") < roles.index("litellm")
