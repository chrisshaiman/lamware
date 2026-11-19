# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The anthropic-wif role and LiteLLM's switch to it agree (ADR-033).

Renders the real templates with both roles' defaults and asserts on parsed values:
  - with litellm_anthropic_via_wif on, every Anthropic entry that is not local and
    not on the separate eval forwarder goes to a WIF route, and its model is in that
    route's allowlist (or the forwarder would 403 it), production on the production
    route and eval-* on the eval route;
  - the rendered forwarder config passes the forwarder's own validator;
  - with the switch on the env file has no Anthropic key, and with it off LiteLLM's
    config is the same as before the switch existed (the rollback);
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
    entries = _cloud_entries(litellm_anthropic_via_wif=True)
    assert len(entries) == 11, [n for n, _ in entries]   # 5 production, 5 eval, haiku-fallback
    for name, p in entries:
        route = port_to_route.get(p.get("api_base"))
        assert route, f"{name} is not on a WIF route: {p}"
        assert p["api_key"] == "sk-anthropic-wif-placeholder", name
        assert route["name"] == ("eval" if name.startswith("eval-") else "production"), name
        assert p["model"].removeprefix("anthropic/") in route["allowed_models"], name


def test_switched_on_no_entry_names_an_env_key():
    text = _litellm("config.yaml.j2", litellm_anthropic_via_wif=True)
    assert "os.environ/ANTHROPIC" not in text


def test_switched_off_entries_use_the_workspace_keys_as_before():
    for name, p in _cloud_entries(litellm_anthropic_via_wif=False):
        want = "ANTHROPIC_RESEARCH_API_KEY" if name.startswith("eval-") else "ANTHROPIC_API_KEY"
        assert p == {"model": p["model"], "api_key": f"os.environ/{want}"}, name


@pytest.mark.parametrize("trim", [False, True])
def test_the_switch_renders_valid_yaml_with_and_without_trim_blocks(trim):
    for on in (False, True):
        assert yaml.safe_load(_litellm("config.yaml.j2", trim, litellm_anthropic_via_wif=on))


def test_switched_on_the_env_file_holds_no_anthropic_key():
    on = _litellm("litellm.env.j2", litellm_anthropic_via_wif=True)
    off = _litellm("litellm.env.j2", litellm_anthropic_via_wif=False)
    assert "PRODKEY" not in on and "EVALKEY" not in on and "ANTHROPIC_" not in on.replace("# ", "")
    assert "ANTHROPIC_API_KEY=PRODKEY" in off and "ANTHROPIC_RESEARCH_API_KEY=EVALKEY" in off


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
