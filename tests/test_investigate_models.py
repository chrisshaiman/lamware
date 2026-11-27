"""The investigation panel's models are one operator list (ADR-038, PR 5).

`api_investigate_models` (the api role) is the panel's dropdown, the API's allow-list
and the scoped `investigate` LiteLLM key. These render the REAL templates with every
role's defaults and assert on parsed values:
  - every listed name is a model LiteLLM serves, or the panel would offer a model
    whose every call fails;
  - the scoped key allows exactly the listed names;
  - the env file carries the list as single-quoted JSON systemd passes through
    verbatim (api/tests/test_investigate_models_env.py parses it with Settings).
"""
import json
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "ansible/roles"


def _defaults(*roles: str) -> dict:
    ctx = {}
    for r in roles:
        ctx.update(yaml.safe_load((ROLES / r / "defaults/main.yml").read_text()) or {})
    return ctx


def _env():
    env = jinja2.Environment(undefined=jinja2.ChainableUndefined)  # noqa: S701 - YAML/env, not HTML
    env.filters["mandatory"] = lambda v: "placeholder" if isinstance(v, jinja2.Undefined) else v
    env.filters["to_json"] = json.dumps
    return env


def _ctx(**over) -> dict:
    return {**_defaults("interpret", "pipeline", "litellm", "api"), "litellm_master_key": "k", **over}


def _served(ctx) -> set[str]:
    text = _env().from_string((ROLES / "litellm/templates/config.yaml.j2").read_text()).render(**ctx)
    return {m["model_name"] for m in yaml.safe_load(text)["model_list"]}


def _key_models(ctx) -> list[str]:
    spec = next(s for s in _defaults("litellm")["litellm_scoped_keys"] if s["name"] == "investigate")
    rendered = _env().from_string(spec["models"]).render(**ctx)
    return yaml.safe_load(rendered)


def test_every_listed_model_is_served_by_litellm():
    ctx = _ctx()
    names = [m["name"] for m in ctx["api_investigate_models"]]
    assert names, "the shipped list is empty: the panel would offer nothing"
    assert set(names) <= _served(ctx), set(names) - _served(ctx)


def test_the_investigate_key_allows_exactly_the_listed_models():
    ctx = _ctx()
    assert _key_models(ctx) == [m["name"] for m in ctx["api_investigate_models"]]


def test_an_operator_list_reaches_the_key():
    ctx = _ctx(api_investigate_models=[{"name": "local-qwen-llamacpp", "label": "Local"}])
    assert _key_models(ctx) == ["local-qwen-llamacpp"]
    assert "local-qwen-llamacpp" in _served(ctx)


def test_the_env_file_carries_the_list_as_single_quoted_json():
    ctx = _ctx()
    # Only this line is rendered: the rest of the template uses Ansible-only filters
    # (ipaddr) that have nothing to do with the model list.
    (tmpl,) = [ln for ln in (ROLES / "api/templates/lamware-api.env.j2").read_text().splitlines()
               if ln.startswith("LAMWARE_INVESTIGATE_MODELS=")]
    line = _env().from_string(tmpl).render(**ctx)
    value = line.split("=", 1)[1]
    assert value.startswith("'") and value.endswith("'") and "'" not in value[1:-1]
    assert json.loads(value[1:-1]) == ctx["api_investigate_models"]


def test_every_shipped_label_is_safe_inside_single_quotes():
    for m in _defaults("api")["api_investigate_models"]:
        assert set(m) == {"name", "label"} and "'" not in m["label"] + m["name"], m
